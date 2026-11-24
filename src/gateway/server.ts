import { createHash, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer, type Server } from "node:http";
import type { GatewayConfig, GatewayIdentity } from "./config.js";
import { METHOD_RULE_ID, evaluateToolCall, type Decision } from "./authorize.js";
import { LedgerWriter, type LedgerRecord } from "./ledger.js";
import { readProvenanceRegistry, type ProvenanceFact } from "../provenance.js";
import { isJsonObject, type JsonObject } from "../lib/json.js";

export const JSONRPC_PARSE_ERROR = -32700;
export const JSONRPC_INVALID_REQUEST = -32600;
export const POLICY_DENIED_CODE = -32003;

const FORWARD_HEADERS = ["mcp-session-id", "mcp-protocol-version", "traceparent"] as const;
const ACCEPT = "application/json, text/event-stream";
const MAX_BODY_BYTES = 10 * 1024 * 1024;

export interface GatewayHandle {
  readonly server: Server;
  readonly url: string;
  /** Binds the configured loopback address and resolves once listening. */
  listen(): Promise<void>;
  close(): Promise<void>;
}

/**
 * Builds the gateway on injected dependencies (`resolveEnv`, ledger file) so
 * the whole enforcement path runs in tests against a mock upstream without
 * touching process state. The bind address is a config concern, and the
 * config loader limits it to loopback: enforcement tooling that is externally
 * reachable is itself a finding, not a feature.
 */
export async function createGateway(config: GatewayConfig, resolveEnv: (name: string) => string | undefined): Promise<GatewayHandle> {
  const writer = await LedgerWriter.open(config.ledgerPath);
  const upstream = resolveUpstreamCredential(config, resolveEnv);
  const identities = new Map<string, GatewayIdentity>(config.identities.map((identity) => [identity.name, identity]));

  const server = createServer((request, response) => {
    void mediateOne(config, writer, upstream, identities, request, response).catch((error) => {
      process.stderr.write(`rulehouse gateway: unhandled mediation error: ${(error as Error).message}\n`);
    });
  });
  return {
    server,
    get url(): string {
      if (config.listen.port === 0) {
        const address = server.address();
        if (typeof address !== "object" || address === null) throw new Error("gateway is not listening");
        return `http://${address.address}:${address.port}`;
      }
      return `http://${config.listen.host}:${config.listen.port}`;
    },
    listen: () => new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(config.listen.port, config.listen.host, () => resolve());
    }),
    close: () => new Promise((resolve, reject) => {
      server.closeAllConnections();
      server.close((error: Error | undefined) => (error === undefined ? resolve() : reject(error)));
    }),
  };
}

interface UpstreamCredential {
  readonly header: string | null;
  readonly problem: string | null;
}

function resolveUpstreamCredential(config: GatewayConfig, resolveEnv: (name: string) => string | undefined): UpstreamCredential {
  const raw = resolveEnv(config.upstream.credentialEnv);
  if (raw === undefined || raw.length === 0) {
    return { header: null, problem: `no upstream credential is available (${config.upstream.credentialEnv} is unset in the gateway process)` };
  }
  return { header: config.upstream.credentialScheme === null ? raw : `${config.upstream.credentialScheme} ${raw}`, problem: null };
}

async function mediateOne(
  config: GatewayConfig,
  writer: LedgerWriter,
  upstream: UpstreamCredential,
  identities: ReadonlyMap<string, GatewayIdentity>,
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  try {
    if (request.method !== "POST") {
      respondPlain(response, 405, "rulehouse gateway mediates POST only\n", "POST");
      return;
    }
    if (new URL(request.url ?? "/", "http://loopback.invalid").pathname !== config.listen.path) {
      respondPlain(response, 404, "not found\n");
      return;
    }

    const body = await readBody(request);
    const presentedKey = extractBearerKey(request.headers.authorization);
    const identity = presentedKey === null ? null : authenticate(identities, presentedKey);
    if (identity === null) {
      response.setHeader("WWW-Authenticate", "Bearer");
      await reject(response, writer, {
        identity: null,
        method: parseMethodSafely(body),
        tool: null,
        decision: { kind: "denied", ruleId: "RH-GW-AUTH", reason: "client presented no key matching a configured identity" },
        provenance: null,
        status: 401,
      }, decisionIdOf(null, parseMethodSafely(body), null, ""), null);
      return;
    }

    const parsed = parseJsonRpcRequest(body);
    if (typeof parsed === "string") {
      respondJsonRpc(response, 400, null, { code: JSONRPC_PARSE_ERROR, message: parsed });
      return;
    }

    const sessionHeaders = sessionHeadersOf(request);
    if (parsed.method === "tools/call") {
      await mediateToolCall(config, writer, upstream, identity, parsed, body, sessionHeaders, response);
    } else {
      await mediatePassthrough(config, writer, upstream, identity, parsed, body, sessionHeaders, response);
    }
  } catch (error) {
    process.stderr.write(`rulehouse gateway: mediation failed without forwarding: ${(error as Error).message}\n`);
    respondJsonRpc(response, 500, null, { code: JSONRPC_INVALID_REQUEST, message: "gateway internal error; nothing was forwarded" });
  }
}

/**
 * The tool-call boundary — the single point in the architecture where an
 * operation is prevented *before* it executes. Policy is evaluated first; on
 * a denial the upstream never sees the request, which is what makes the
 * enforcement result provable rather than aspirational. Approval-required
 * rules deny until their derived decision id appears in the approvals file,
 * which is re-read per request so revocation is immediate.
 */
async function mediateToolCall(
  config: GatewayConfig,
  writer: LedgerWriter,
  upstream: UpstreamCredential,
  identity: GatewayIdentity,
  parsed: ParsedRequest,
  body: string,
  sessionHeaders: Record<string, string>,
  response: ServerResponse,
): Promise<void> {
  if (parsed.tool === null || parsed.tool.length === 0) {
    respondJsonRpc(response, 400, parsed.id, { code: JSONRPC_INVALID_REQUEST, message: "tools/call requires params.name: string" });
    return;
  }

  const decisionId = decisionIdOf(identity.name, parsed.method, parsed.tool, parsed.argumentsDigest);
  const registry = config.provenancePath === null ? null : await readProvenanceRegistry(config.provenancePath);
  const decision = evaluateToolCall(config.policies, identity.name, parsed.tool, parsed.arguments, registry);

  if (decision.kind === "denied") {
    await reject(response, writer, {
      identity: identity.name,
      method: parsed.method,
      tool: parsed.tool,
      decision: { kind: "denied" as const, ruleId: decision.ruleId, reason: decision.reason },
      provenance: decision.provenance.length === 0 ? null : decision.provenance,
      status: 403,
    }, decisionId, parsed.id);
    return;
  }

  if (decision.approvalRequired) {
    const approved = await readApprovals(config);
    if (!approved.has(decisionId)) {
      await reject(response, writer, {
        identity: identity.name,
        method: parsed.method,
        tool: parsed.tool,
        decision: { kind: "denied", ruleId: decision.ruleId, reason: `rule ${decision.ruleId} requires human approval; decision ${decisionId} is not approved yet` },
        provenance: decision.provenance.length === 0 ? null : decision.provenance,
        status: 403,
      }, decisionId, parsed.id);
      return;
    }
    await forwardAndRecord(config, writer, upstream, identity, parsed, body, decisionId, decision, `${decision.reason}; executed under operator approval ${decisionId}`, sessionHeaders, response);
    return;
  }

  await forwardAndRecord(config, writer, upstream, identity, parsed, body, decisionId, decision, decision.reason, sessionHeaders, response);
}

async function mediatePassthrough(
  config: GatewayConfig,
  writer: LedgerWriter,
  upstream: UpstreamCredential,
  identity: GatewayIdentity,
  parsed: ParsedRequest,
  body: string,
  sessionHeaders: Record<string, string>,
  response: ServerResponse,
): Promise<void> {
  const decisionId = decisionIdOf(identity.name, parsed.method, null, "");
  const outcome = await forward(config, upstream, body, sessionHeaders);
  await writer.append({
    decisionId,
    identity: identity.name,
    method: parsed.method,
    tool: null,
    provenance: null,
    decision: outcome.forwarded
      ? { kind: "allowed", ruleId: METHOD_RULE_ID, reason: `${parsed.method} mediated for ${identity.kind} ${identity.name}; non-tool traffic is mediated, tool policy does not apply` }
      : { kind: "denied", ruleId: METHOD_RULE_ID, reason: `upstream was unreachable for ${parsed.method}` },
    enforcement: outcome.forwarded ? "forwarded-to-upstream" : "failed-forwarding",
    upstreamStatus: outcome.forwarded ? outcome.status : null,
  }, new Date().toISOString());
  deliver(response, parsed.id, outcome);
}

interface ParsedRequest {
  readonly id: string | number | null;
  readonly method: string;
  readonly tool: string | null;
  /** The structured tool-call arguments, when they parse as a JSON object. */
  readonly arguments: JsonObject | null;
  readonly argumentsDigest: string;
}

function parseMethodSafely(body: string): string | null {
  const parsed = parseJsonRpcRequest(body);
  return typeof parsed === "string" ? null : parsed.method;
}

function parseJsonRpcRequest(body: string): ParsedRequest | string {
  let document: unknown;
  try {
    document = JSON.parse(body);
  } catch {
    return "request body is not valid JSON";
  }
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    return "request body is not a JSON-RPC object";
  }
  const record = document as { readonly [key: string]: unknown };
  if (record["jsonrpc"] !== "2.0") {
    return 'request is not JSON-RPC 2.0 (jsonrpc must be "2.0")';
  }
  const id = record["id"];
  if (typeof id !== "string" && typeof id !== "number" && id !== null) {
    return "JSON-RPC id must be a string, a number, or null";
  }
  const method = record["method"];
  if (typeof method !== "string") {
    return "JSON-RPC method must be a string";
  }
  const params = record["params"];
  const paramsObject = typeof params === "object" && params !== null && !Array.isArray(params)
    ? (params as { readonly [key: string]: unknown })
    : null;
  const tool = paramsObject === null ? null : asString(paramsObject["name"]);
  const rawArguments = paramsObject === null ? null : paramsObject["arguments"] ?? null;
  const invocation = tool !== null ? { name: tool, arguments: rawArguments } : null;
  return {
    id,
    method,
    tool,
    arguments: isJsonObject(rawArguments) ? rawArguments : null,
    argumentsDigest: invocation === null ? "" : createHash("sha256").update(stableJson(invocation)).digest("hex"),
  };
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

/**
 * Deterministic JSON serialization for hashing composite values into
 * decision ids — the same canonical-JSON idea as `lib/json`, applied to
 * untyped wire objects.
 */
function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (typeof value === "object" && value !== null) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson((value as { readonly [key: string]: unknown })[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function extractBearerKey(header: string | undefined): string | null {
  if (header === undefined) return null;
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
  return match === null ? null : match[1]!;
}

/**
 * Verifies the presented key by constant-time digest comparison. The raw key
 * outlives exactly one hash call; only the derived digest ever enters the
 * comparison loop.
 */
function authenticate(identities: ReadonlyMap<string, GatewayIdentity>, presentedKey: string): GatewayIdentity | null {
  const presented = Buffer.from(createHash("sha256").update(presentedKey).digest("hex"), "utf8");
  for (const identity of identities.values()) {
    const configuredBuffer = identity.keyHash.slice("sha256:".length);
    if (configuredBuffer.length !== 64) continue;
    if (timingSafeEqual(Buffer.from(configuredBuffer, "utf8"), presented)) return identity;
  }
  return null;
}

/**
 * The decision id is derived, not random: hashing identity, method, tool, and
 * the invocation digest makes the same operation proposed under the same
 * identity regenerate the same id. That one property is what lets the
 * approval workflow be stateless — an operator approves an id that a client
 * retry reproduces byte-for-byte — while every execution still gets its own
 * ledger sequence number.
 */
function decisionIdOf(identity: string | null, method: string | null, tool: string | null, argumentsDigest: string): string {
  return `sha256:${createHash("sha256").update(stableJson({ identity, method, tool, argumentsDigest })).digest("hex")}`;
}

/**
 * approvals are re-read on every evaluation — never cached — so granting or
 * revoking a line in the plain-text decision-id list takes effect on the very
 * next request, with no restart.
 */
async function readApprovals(config: GatewayConfig): Promise<ReadonlySet<string>> {
  if (config.approvalsPath === null) return new Set();
  const text = await readFile(config.approvalsPath, "utf8").catch(() => "");
  return new Set(
    text.split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith("#")),
  );
}

interface UpstreamOutcome {
  readonly forwarded: boolean;
  readonly status: number;
  readonly body: string;
  readonly contentType: string | null;
}

/**
 * The request body is forwarded byte-for-byte: the gateway mediates, it does
 * not rewrite, so the upstream answer is exactly what a client holding the
 * upstream credential itself would have received. Any body-level rewrite
 * would need its own evidence discipline before shipping, so there is none.
 */
async function forward(config: GatewayConfig, upstream: UpstreamCredential, body: string, sessionHeaders: Record<string, string>): Promise<UpstreamOutcome> {
  const headers: Record<string, string> = {
    accept: ACCEPT,
    "content-type": "application/json",
    authorization: upstream.header ?? "",
    ...sessionHeaders,
  };
  try {
    const response = await fetch(config.upstream.url, { method: "POST", headers, body });
    return { forwarded: true, status: response.status, body: await response.text(), contentType: response.headers.get("content-type") };
  } catch (error) {
    process.stderr.write(`rulehouse gateway: upstream unreachable: ${(error as Error).message}\n`);
    return { forwarded: false, status: 0, body: "", contentType: null };
  }
}

function sessionHeadersOf(request: IncomingMessage): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const name of FORWARD_HEADERS) {
    const value = request.headers[name];
    if (typeof value === "string") headers[name] = value;
  }
  return headers;
}

async function forwardAndRecord(
  config: GatewayConfig,
  writer: LedgerWriter,
  upstream: UpstreamCredential,
  identity: GatewayIdentity,
  parsed: ParsedRequest,
  body: string,
  decisionId: string,
  decision: Decision,
  reason: string,
  sessionHeaders: Record<string, string>,
  response: ServerResponse,
): Promise<void> {
  const outcome = await forward(config, upstream, body, sessionHeaders);
  await writer.append({
    decisionId,
    identity: identity.name,
    method: parsed.method,
    tool: parsed.tool,
    provenance: decision.provenance.length === 0 ? null : decision.provenance,
    decision: { kind: outcome.forwarded && outcome.status < 400 ? "allowed" : "denied", ruleId: decision.ruleId, reason },
    enforcement: outcome.forwarded ? "forwarded-to-upstream" : "failed-forwarding",
    upstreamStatus: outcome.forwarded ? outcome.status : null,
  }, new Date().toISOString());
  deliver(response, parsed.id, outcome);
}

/**
 * Delivers the upstream answer verbatim — including upstream 4xx/5xx, which
 * belongs to the upstream and must reach the client unedited. Only a gateway
 * to upstream failure produces a gateway-authored JSON-RPC error, because
 * that is the one case the client would otherwise read as a silent hang.
 */
function deliver(response: ServerResponse, id: string | number | null, outcome: UpstreamOutcome): void {
  if (!outcome.forwarded) {
    respondJsonRpc(response, 502, id, { code: POLICY_DENIED_CODE, message: "upstream was unreachable; the operation was not executed" });
    return;
  }
  respondRaw(response, outcome.status, outcome.body, outcome.contentType ?? "application/json");
}

interface Rejection {
  readonly identity: string | null;
  readonly method: string | null;
  readonly tool: string | null;
  readonly decision: { readonly kind: "denied"; readonly ruleId: string; readonly reason: string };
  readonly provenance: readonly ProvenanceFact[] | null;
  readonly status: number;
}

async function reject(
  response: ServerResponse,
  writer: LedgerWriter,
  rejection: Rejection,
  decisionId: string,
  jsonRpcId: string | number | null,
): Promise<void> {
  const record: LedgerRecord = {
    decisionId,
    identity: rejection.identity,
    method: rejection.method,
    tool: rejection.tool,
    decision: rejection.decision,
    enforcement: "blocked-at-gateway",
    upstreamStatus: null,
    provenance: rejection.provenance,
  };
  await writer.append(record, new Date().toISOString());
  respondJsonRpc(response, rejection.status, jsonRpcId, {
    code: POLICY_DENIED_CODE,
    message: rejection.decision.reason,
    data: { decisionId, ruleId: rejection.decision.ruleId, enforcement: record.enforcement },
  });
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = chunk as Buffer;
    total += buffer.length;
    if (total > MAX_BODY_BYTES) {
      throw new Error(`request body exceeds ${MAX_BODY_BYTES} bytes`);
    }
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function respondRaw(response: ServerResponse, status: number, body: string, contentType: string): void {
  if (response.headersSent) {
    response.end();
    return;
  }
  response.writeHead(status, { "content-type": contentType, "content-length": Buffer.byteLength(body) });
  response.end(body);
}

function respondPlain(response: ServerResponse, status: number, body: string, allow: string | null = null): void {
  if (allow !== null) response.setHeader("allow", allow);
  respondRaw(response, status, body, "text/plain");
}

function respondJsonRpc(
  response: ServerResponse,
  status: number,
  id: string | number | null,
  error: { readonly code: number; readonly message: string; readonly data?: unknown },
): void {
  respondRaw(response, status, JSON.stringify({
    jsonrpc: "2.0",
    id,
    error: error.data === undefined
      ? { code: error.code, message: error.message }
      : { code: error.code, message: error.message, data: error.data },
  }), "application/json");
}
