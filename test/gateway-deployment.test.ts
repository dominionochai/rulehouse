import test from "node:test";
import assert from "node:assert/strict";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer, request as httpRequest, type RequestOptions } from "node:http";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createGateway, POLICY_DENIED_CODE } from "../src/gateway/server.js";
import { readGatewayConfig } from "../src/gateway/config.js";
import { readLedger, verifyLedger } from "../src/gateway/ledger.js";
import type { GatewayConfig } from "../src/gateway/config.js";

const UPSTREAM_TOKEN = "Basic cnVob3VzZS10ZXN0OnVwc3RyZWFtLXRva2Vu";
const IDENTITY_HEADER = "x-rulehouse-identity";

/**
 * Task-2's reference deployment, in miniature: an authenticating proxy
 * terminates the client-side connection and forwards to a loopback-bound
 * gateway with proxy-asserted identity enabled. The proxy runs plain HTTP
 * here because TLS is its own front channel — the contract under test is
 * what the gateway can and cannot rely on behind such a proxy, which is
 * exactly what docs/deployment.md documents.
 */
test("a reference proxy that sets (not appends, never passes through) the identity header yields clean forwarded-header attribution", async () => {
  const scenario = await startReferencedDeployment("set");
  try {
    const listing = await post(scenario.proxyBase, { jsonrpc: "2.0", id: 1, method: "tools/list" });
    assert.equal(listing.status, 200, `the proxied client is authenticated by the proxy's assertion: ${listing.body}`);
    assert.equal(scenario.upstream.length, 1, "the mediated request reached the upstream");
  } finally {
    await scenario.stop();
  }
  const read = await readLedger(scenario.ledgerPath);
  assert.equal(read.entries.length, 1);
  assert.equal(read.entries[0]!.record.identity, "amara");
  assert.equal(read.entries[0]!.record.identitySource, "forwarded-header");
  assert.equal((await verifyLedger(scenario.ledgerPath)).ok, true);
});

test("a misconfigured proxy that appends a second assertion turns impersonation attempts into refusals, never success", async () => {
  const scenario = await startReferencedDeployment("append");
  try {
    const smuggled = await post(
      scenario.proxyBase,
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      { [IDENTITY_HEADER]: ["amara", "amara"] },
    );
    assert.equal(smuggled.status, 401, "two assertions are an unresolvable identity, and the gateway must not pick one");
  } finally {
    await scenario.stop();
  }
  const read = await readLedger(scenario.ledgerPath);
  assert.equal(read.entries.length, 1);
  assert.equal(read.entries[0]!.record.enforcement, "blocked-at-gateway");
  assert.equal(read.entries[0]!.record.identitySource, null);
});

test("a proxy that neither sets nor strips the header hands assertion authority to the client", async () => {
  const scenario = await startReferencedDeployment("none");
  try {
    const smuggled = await post(scenario.proxyBase, { jsonrpc: "2.0", id: 1, method: "tools/list" }, { [IDENTITY_HEADER]: "amara" });
    assert.equal(smuggled.status, 200, "this is the documented hazard: the deployment, not the gateway, owns the header channel");

    const denied = await post(scenario.proxyBase, { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "delete_page", arguments: {} } }, { [IDENTITY_HEADER]: "amara" });
    assert.equal(denied.status, 403);
    assert.equal(scenario.policyCode, POLICY_DENIED_CODE, "even a stolen assertion does not escape tool policy");
  } finally {
    await scenario.stop();
  }
  const read = await readLedger(scenario.ledgerPath);
  const forwarded = read.entries.filter((entry) => entry.record.enforcement === "forwarded-to-upstream");
  const blocked = read.entries.filter((entry) => entry.record.enforcement === "blocked-at-gateway");
  assert.equal(forwarded.length, 1);
  assert.equal(blocked.length, 1);
  for (const entry of read.entries) {
    assert.equal(entry.record.identity, "amara");
    assert.equal(entry.record.identitySource, "forwarded-header");
  }
  assert.equal((await verifyLedger(scenario.ledgerPath)).ok, true);
});

test("the bind contract holds at config load: loopback is accepted in both spellings, everything else is refused", () => {
  const base = {
    upstream: { url: "https://mcp.atlassian.com/v2/mcp", credentialEnv: "K", credentialScheme: "Bearer" },
    identities: [{ name: "amara", kind: "user", keyHash: `sha256:${"a".repeat(64)}` }],
    policies: { defaultEffect: "deny", rules: [] },
    ledger: { path: "ledger.jsonl" },
  };
  const env = (name: string): string | undefined => (name === "K" ? "token" : undefined);
  for (const host of ["127.0.0.1", "localhost"]) {
    const accepted = readGatewayConfig(JSON.stringify({ ...base, listen: { host, port: 8080 } }), "config.json", env);
    assert.equal(accepted.config?.listen.host, host, `"${host}" is loopback and must be accepted`);
    assert.equal(accepted.diagnostics.length, 0);
  }
  for (const host of ["0.0.0.0", "::", "192.168.1.10"]) {
    const refused = readGatewayConfig(JSON.stringify({ ...base, listen: { host, port: 8080 } }), "config.json", env);
    assert.ok(refused.diagnostics.some((d) => d.message.includes("loopback")), `"${host}" must be refused: a gateway that is externally reachable by default is a finding, not a feature`);
  }
});

interface Deployment {
  readonly proxyBase: string;
  readonly upstream: readonly { readonly body: string }[];
  readonly ledgerPath: string;
  readonly policyCode: number;
  stop(): Promise<void>;
}

/**
 * Builds gateway + proxy. The proxy authenticates with a trivial header
 * (`x-employee-principal`, standing in for the proxy's own auth) and then
 * treats the identity header per `mode`:
 * - `set`:    always set from the authenticated principal (nginx contract)
 * - `append`: forward the client's copy *and* add its own (the failure)
 * - `none`:   pass the client's copy straight through (the other failure)
 */
async function startReferencedDeployment(mode: "set" | "append" | "none"): Promise<Deployment> {
  const upstreamRequests: { readonly body: string }[] = [];
  const mock = createServer((request: IncomingMessage, response: ServerResponse) => {
    let body = "";
    request.on("data", (chunk: Buffer) => { body += chunk.toString("utf8"); });
    request.on("end", () => {
      upstreamRequests.push({ body });
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { tools: [] } }));
    });
  });
  await new Promise<void>((resolve, reject) => {
    mock.once("error", reject);
    mock.listen(0, "127.0.0.1", () => resolve());
  });

  const dir = await mkdtemp(join(tmpdir(), "rh-gateway-deploy-"));
  const ledgerPath = join(dir, "ledger.jsonl");
  const config: GatewayConfig = {
    source: "deployment-reference",
    listen: { host: "127.0.0.1", port: 0, path: "/mcp" },
    upstream: { url: `http://127.0.0.1:${(mock.address() as { port: number }).port}/v2/mcp`, credentialEnv: "TEST_UPSTREAM_CREDENTIAL", credentialScheme: null },
    identities: [{ name: "amara", kind: "user", keyHash: `sha256:${"a".repeat(64)}` }],
    policies: {
      defaultEffect: "deny",
      rules: [
        { id: "RH-GW-BLOCK-DELETE", identities: null, tools: ["delete_*"], effect: "deny", approvalRequired: false, provenanceChecks: [] },
        { id: "RH-GW-READ", identities: null, tools: ["*"], effect: "allow", approvalRequired: false, provenanceChecks: [] },
      ],
    },
    ledgerPath,
    provenancePath: null,
    approvalsPath: null,
    trustForwardedIdentity: { header: IDENTITY_HEADER },
  };
  const gateway = await createGateway(config, (name) => (name === "TEST_UPSTREAM_CREDENTIAL" ? UPSTREAM_TOKEN : undefined));
  await gateway.listen();

  const proxy = createServer((clientRequest: IncomingMessage, clientResponse: ServerResponse) => {
    const chunks: Buffer[] = [];
    clientRequest.on("data", (chunk: Buffer) => chunks.push(chunk));
    clientRequest.on("end", () => {
      const headers: Record<string, string | string[]> = {
        "content-type": clientRequest.headers["content-type"] ?? "application/json",
        accept: clientRequest.headers.accept ?? "application/json, text/event-stream",
      };
      const sessionId = clientRequest.headers["mcp-session-id"];
      if (typeof sessionId === "string") headers["mcp-session-id"] = sessionId;
      const smuggled = clientRequest.headers[IDENTITY_HEADER];
      if (mode === "set") {
        headers[IDENTITY_HEADER] = "amara";
      } else if (mode === "append") {
        const copies = (Array.isArray(smuggled) ? smuggled : smuggled === undefined ? [] : [smuggled]).concat("amara");
        headers[IDENTITY_HEADER] = copies;
      } else if (typeof smuggled === "string") {
        headers[IDENTITY_HEADER] = smuggled;
      }
      const target = new URL(`${gateway.url}/mcp`);
      const options: RequestOptions = { host: target.hostname, port: target.port, path: target.pathname, method: "POST", headers };
      const upstreamRequest = httpRequest(options, (upstreamResponse: IncomingMessage) => {
        clientResponse.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
        upstreamResponse.pipe(clientResponse);
      });
      upstreamRequest.on("error", () => {
        clientResponse.writeHead(502, { "content-type": "application/json" });
        clientResponse.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32003, message: "proxy could not reach the gateway" } }));
      });
      upstreamRequest.end(Buffer.concat(chunks));
    });
  });
  await new Promise<void>((resolve, reject) => {
    proxy.once("error", reject);
    proxy.listen(0, "127.0.0.1", () => resolve());
  });

  return {
    proxyBase: `http://127.0.0.1:${(proxy.address() as { port: number }).port}`,
    upstream: upstreamRequests,
    ledgerPath,
    policyCode: POLICY_DENIED_CODE,
    stop: async () => {
      await gateway.close();
      await new Promise<void>((resolve, reject) => {
        proxy.closeAllConnections();
        proxy.close((error?: Error) => (error === undefined ? resolve() : reject(error)));
      });
      await new Promise<void>((resolve, reject) => {
        mock.closeAllConnections();
        mock.close((error?: Error) => (error === undefined ? resolve() : reject(error)));
      });
    },
  };
}

async function post(base: string, body: unknown, extraHeaders: Record<string, string | string[]> = {}): Promise<{ readonly status: number; readonly body: string }> {
  const response = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", ...extraHeaders },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.text() };
}
