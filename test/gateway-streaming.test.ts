import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:http";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createGateway, POLICY_DENIED_CODE } from "../src/gateway/server.js";
import { readLedger, verifyLedger } from "../src/gateway/ledger.js";
import type { GatewayConfig } from "../src/gateway/config.js";

const UPSTREAM_TOKEN = "Basic cnVob3VzZS10ZXN0OnVwc3RyZWFtLXRva2Vu";
const CLIENT_KEY = "RHO-SYNTHETIC-CLIENT-KEY-0001";
const STREAMED_RESULT = { jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "streamed-saw-this" }] } };
const STREAMED_BODY = `event: message\ndata: ${JSON.stringify(STREAMED_RESULT)}\n\n`;

interface UpstreamObservation {
  readonly authorization: string | undefined;
  readonly body: string;
  readonly sessionId: string | undefined;
}

interface Stack {
  readonly base: string;
  readonly upstream: readonly UpstreamObservation[];
  readonly ledgerPath: string;
  stop(): Promise<void>;
}

/**
 * Starts a mock upstream that always answers as an MCP streamable-HTTP
 * server would: `text/event-stream`, written in two frames after the
 * request is complete, optionally minting a session id. The two-frame write
 * is what makes the test able to distinguish a live stream from a buffered
 * reply: a gateway that buffers would still deliver the bytes but would
 * also have to invent a `content-length`, which a true pass-through never
 * carries.
 */
async function startStreamingStack(options: { readonly sessionId?: string; readonly deadUpstream?: boolean } = {}): Promise<Stack> {
  const requests: UpstreamObservation[] = [];
  const unreachable = options.deadUpstream === true;
  const mock = createServer((request: IncomingMessage, response: ServerResponse) => {
    let body = "";
    request.on("data", (chunk: Buffer) => { body += chunk.toString("utf8"); });
    request.on("end", () => {
      const sessionId = request.headers["mcp-session-id"];
      requests.push({ authorization: request.headers.authorization, body, sessionId: typeof sessionId === "string" ? sessionId : undefined });
      if (unreachable) return;
      response.writeHead(200, {
        "content-type": "text/event-stream",
        ...(options.sessionId === undefined ? {} : { "mcp-session-id": options.sessionId }),
      });
      response.write(STREAMED_BODY.slice(0, 20));
      setTimeout(() => response.end(STREAMED_BODY.slice(20)), 25);
    });
  });
  await new Promise<void>((resolve, reject) => {
    mock.once("error", reject);
    mock.listen(0, "127.0.0.1", () => resolve());
  });
  const upstreamPort = (mock.address() as { port: number }).port;
  if (unreachable) {
    await new Promise<void>((resolve) => mock.close(() => resolve()));
  }

  const dir = await mkdtemp(join(tmpdir(), "rh-gateway-stream-"));
  const ledgerPath = join(dir, "ledger.jsonl");
  const config: GatewayConfig = {
    source: "test",
    listen: { host: "127.0.0.1", port: 0, path: "/mcp" },
    upstream: { url: `http://127.0.0.1:${upstreamPort}/v2/mcp`, credentialEnv: "TEST_UPSTREAM_CREDENTIAL", credentialScheme: null },
    identities: [{ name: "amara", kind: "user", keyHash: `sha256:${createHash("sha256").update(CLIENT_KEY).digest("hex")}` }],
    policies: {
      defaultEffect: "deny",
      rules: [
        { id: "RH-GW-BLOCK-DELETE", identities: null, tools: ["delete_*"], effect: "deny", approvalRequired: false, provenanceChecks: [] },
        { id: "RH-GW-READ", identities: null, tools: ["get_*", "search_*"], effect: "allow", approvalRequired: false, provenanceChecks: [] },
      ],
    },
    ledgerPath,
    provenancePath: null,
    approvalsPath: null,
    trustForwardedIdentity: null,
  };
  const gateway = await createGateway(config, (name) => (name === "TEST_UPSTREAM_CREDENTIAL" ? UPSTREAM_TOKEN : undefined));
  await gateway.listen();

  return {
    base: gateway.url,
    upstream: requests,
    ledgerPath,
    stop: async () => {
      await gateway.close();
      if (unreachable) return;
      return await new Promise<void>((resolve, reject) => {
        mock.closeAllConnections();
        mock.close((error?: Error) => (error === undefined ? resolve() : reject(error)));
      });
    },
  };
}

async function post(stack: Stack, body: unknown, clientKey?: string, sessionId?: string): Promise<{ readonly status: number; readonly headers: Headers; readonly body: string }> {
  const response = await fetch(`${stack.base}/mcp`, {
    method: "POST",
    headers: {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      ...(clientKey === undefined ? {} : { authorization: `Bearer ${clientKey}` }),
      ...(sessionId === undefined ? {} : { "mcp-session-id": sessionId }),
    },
    body: JSON.stringify(body),
  });
  return { status: response.status, headers: response.headers, body: await response.text() };
}

test("a streamed upstream answer passes through live and verbatim, and the ledger records it like any forwarded call", async () => {
  const stack = await startStreamingStack();
  try {
    const streamed = await post(stack, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_page", arguments: { id: "doc-1" } } }, CLIENT_KEY);
    assert.equal(streamed.status, 200);
    assert.equal(streamed.headers.get("content-type"), "text/event-stream");
    assert.equal(streamed.headers.get("content-length"), null, "the gateway never invents a length for a live stream");
    assert.equal(streamed.body, STREAMED_BODY, "SSE framing leaves the gateway byte-for-byte");
    assert.equal(stack.upstream.length, 1);
    assert.equal(stack.upstream[0]!.authorization, UPSTREAM_TOKEN);
  } finally {
    await stack.stop();
  }
  const read = await readLedger(stack.ledgerPath);
  assert.equal(read.entries.length, 1);
  assert.equal(read.entries[0]!.record.enforcement, "forwarded-to-upstream");
  assert.equal(read.entries[0]!.record.upstreamStatus, 200);
  assert.equal(read.entries[0]!.record.decision.kind, "allowed");
  assert.equal(read.entries[0]!.record.tool, "get_page");
  assert.equal((await verifyLedger(stack.ledgerPath)).ok, true);
});

test("a denied tool call is blocked even when the upstream would answer with a stream, and the denial stays a gateway JSON-RPC error", async () => {
  const stack = await startStreamingStack();
  try {
    const blocked = await post(stack, { jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: "delete_page", arguments: { id: "doc-1" } } }, CLIENT_KEY);
    assert.equal(blocked.status, 403);
    assert.notEqual(blocked.headers.get("content-type"), "text/event-stream");
    assert.equal(stack.upstream.length, 0, "a denied streamable call never reaches the upstream");
    const denial = JSON.parse(blocked.body) as { error: { code: number; data: { enforcement: string } } };
    assert.equal(denial.error.code, POLICY_DENIED_CODE);
    assert.equal(denial.error.data.enforcement, "blocked-at-gateway");
  } finally {
    await stack.stop();
  }
  const read = await readLedger(stack.ledgerPath);
  assert.equal(read.entries.length, 1);
  assert.equal(read.entries[0]!.record.enforcement, "blocked-at-gateway");
  assert.equal((await verifyLedger(stack.ledgerPath)).ok, true);
});

test("the upstream-minted session id reaches the client, and the client's session id is forwarded on later calls", async () => {
  const stack = await startStreamingStack({ sessionId: "sess-atlassian-7f3a" });
  try {
    const initialize = await post(stack, { jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-06-18" } }, CLIENT_KEY);
    assert.equal(initialize.status, 200);
    assert.equal(initialize.headers.get("mcp-session-id"), "sess-atlassian-7f3a", "the gateway must relay the session the upstream minted");
    assert.equal(initialize.body, STREAMED_BODY);

    const followUp = await post(stack, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "get_page", arguments: {} } }, CLIENT_KEY, "sess-atlassian-7f3a");
    assert.equal(followUp.status, 200);
    assert.equal(stack.upstream.length, 2);
    assert.equal(stack.upstream[1]!.sessionId, "sess-atlassian-7f3a", "the gateway mediates inside the client's session, not around it");
    assert.equal(stack.upstream[1]!.authorization, UPSTREAM_TOKEN);
  } finally {
    await stack.stop();
  }
  const read = await readLedger(stack.ledgerPath);
  assert.equal(read.entries.length, 2);
  for (const entry of read.entries) assert.equal(entry.record.enforcement, "forwarded-to-upstream");
  assert.equal((await verifyLedger(stack.ledgerPath)).ok, true);
});

test("an unreachable upstream on a streamable call records failed-forwarding and answers with the gateway's JSON-RPC error", async () => {
  const stack = await startStreamingStack({ deadUpstream: true });
  try {
    const failure = await post(stack, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "get_page", arguments: {} } }, CLIENT_KEY);
    assert.equal(failure.status, 502);
    assert.equal(stack.upstream.length, 0);
    const error = JSON.parse(failure.body) as { error: { code: number; message: string } };
    assert.equal(error.error.code, POLICY_DENIED_CODE);
    assert.ok(error.error.message.includes("not executed"));
  } finally {
    await stack.stop();
  }
  const read = await readLedger(stack.ledgerPath);
  assert.equal(read.entries.length, 1);
  assert.equal(read.entries[0]!.record.enforcement, "failed-forwarding");
  assert.equal(read.entries[0]!.record.upstreamStatus, null);
  assert.equal((await verifyLedger(stack.ledgerPath)).ok, true);
});

test("a request body that could be a tool call but does not parse fails closed against a streaming upstream", async () => {
  const stack = await startStreamingStack();
  try {
    const response = await fetch(`${stack.base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${CLIENT_KEY}` },
      body: '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name"',
    });
    assert.equal(response.status, 400);
    const error = JSON.parse(await response.text()) as { error: { code: number } };
    assert.equal(error.error.code, -32700);
    assert.equal(stack.upstream.length, 0, "an unparseable possible tool call is never forwarded");
  } finally {
    await stack.stop();
  }
  const read = await readLedger(stack.ledgerPath);
  assert.equal(read.entries.length, 0, "the parse failure occurred before any identity or policy stage");
});
