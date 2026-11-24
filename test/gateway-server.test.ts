import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { Server } from "node:http";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { appendFile, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createGateway, POLICY_DENIED_CODE } from "../src/gateway/server.js";
import { readLedger, verifyLedger } from "../src/gateway/ledger.js";
import type { GatewayConfig } from "../src/gateway/config.js";

const UPSTREAM_TOKEN = "Basic cnVob3VzZS10ZXN0OnVwc3RyZWFtLXRva2Vu";
const CLIENT_KEY = "RHO-SYNTHETIC-CLIENT-KEY-0001";

interface Stack {
  readonly base: string;
  readonly upstream: readonly { readonly authorization: string | undefined; readonly body: string }[];
  readonly ledgerPath: string;
  readonly approvalsPath: string;
  stop(): Promise<void>;
}

async function startStack(): Promise<Stack> {
  const requests: { authorization: string | undefined; body: string }[] = [];
  const mock = createServer((request: IncomingMessage, response: ServerResponse) => {
    let body = "";
    request.on("data", (chunk: Buffer) => { body += chunk.toString("utf8"); });
    request.on("end", () => {
      requests.push({ authorization: request.headers.authorization, body });
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "upstream-saw-this" }] } }));
    });
  });
  await new Promise<void>((resolve, reject) => {
    mock.once("error", reject);
    mock.listen(0, "127.0.0.1", () => resolve());
  });

  const dir = await mkdtemp(join(tmpdir(), "rh-gateway-"));
  const ledgerPath = join(dir, "ledger.jsonl");
  const approvalsPath = join(dir, "approvals.txt");
  const config: GatewayConfig = {
    source: "test",
    listen: { host: "127.0.0.1", port: 0, path: "/mcp" },
    upstream: { url: `http://127.0.0.1:${(mock.address() as { port: number }).port}/v2/mcp`, credentialEnv: "TEST_UPSTREAM_CREDENTIAL", credentialScheme: null },
    identities: [{ name: "amara", kind: "user", keyHash: `sha256:${createHash("sha256").update(CLIENT_KEY).digest("hex")}` }],
    policies: {
      defaultEffect: "deny",
      rules: [
        { id: "RH-GW-BLOCK-DELETE", identities: null, tools: ["delete_*"], effect: "deny", approvalRequired: false },
        { id: "RH-GW-READ", identities: null, tools: ["get_*", "search_*"], effect: "allow", approvalRequired: false },
        { id: "RH-GW-MUTATE-APPROVED", identities: ["amara"], tools: ["update_*"], effect: "allow", approvalRequired: true },
      ],
    },
    ledgerPath,
    approvalsPath,
  };
  const gateway = await createGateway(config, (name) => (name === "TEST_UPSTREAM_CREDENTIAL" ? UPSTREAM_TOKEN : undefined));
  await gateway.listen();

  return {
    base: gateway.url,
    upstream: requests,
    ledgerPath,
    approvalsPath,
    stop: async () => {
      await gateway.close();
      return await new Promise<void>((resolve, reject) => {
        mock.closeAllConnections();
        mock.close((error?: Error) => (error === undefined ? resolve() : reject(error)));
      });
    },
  };
}

async function post(stack: Stack, path: string, body: unknown, clientKey?: string, sessionId?: string): Promise<{ readonly status: number; readonly headers: Headers; readonly body: string }> {
  const response = await fetch(`${stack.base}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(clientKey === undefined ? {} : { authorization: `Bearer ${clientKey}` }),
      ...(sessionId === undefined ? {} : { "mcp-session-id": sessionId }),
    },
    body: JSON.stringify(body),
  });
  return { status: response.status, headers: response.headers, body: await response.text() };
}

function toolCall(id: number, name: string, args?: unknown): object {
  return args === undefined
    ? { jsonrpc: "2.0", id, method: "tools/call", params: { name } }
    : { jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } };
}

test("an unauthenticated client is refused before any upstream traffic, and the decision is recorded", async () => {
  const stack = await startStack();
  try {
    assert.equal((await post(stack, "/mcp", { jsonrpc: "2.0", id: 7, method: "tools/list" })).status, 401);
    assert.equal((await post(stack, "/mcp", { jsonrpc: "2.0", id: 7, method: "tools/list" }, "imposter-key")).status, 401);
    assert.equal(stack.upstream.length, 0, "the upstream observed nothing");
  } finally {
    await stack.stop();
  }
  const read = await readLedger(stack.ledgerPath);
  assert.equal(read.entries.length, 2);
  for (const entry of read.entries) {
    assert.equal(entry.record.decision.ruleId, "RH-GW-AUTH");
    assert.equal(entry.record.identity, null);
    assert.equal(entry.record.enforcement, "blocked-at-gateway");
  }
  assert.equal((await verifyLedger(stack.ledgerPath)).ok, true);
});

test("an authenticated session is forwarded with the gateway's upstream credential, not the client's key", async () => {
  const stack = await startStack();
  try {
    const listing = await post(stack, "/mcp", { jsonrpc: "2.0", id: 7, method: "tools/list" }, CLIENT_KEY);
    assert.equal(listing.status, 200);
    assert.ok(listing.body.includes("upstream-saw-this"), "the upstream answer reaches the client verbatim");
    assert.deepEqual(stack.upstream.length, 1);
    assert.equal(stack.upstream[0]!.authorization, UPSTREAM_TOKEN);
  } finally {
    await stack.stop();
  }
  const read = await readLedger(stack.ledgerPath);
  assert.equal(read.entries.length, 1);
  assert.equal(read.entries[0]!.record.identity, "amara");
  assert.equal(read.entries[0]!.record.method, "tools/list");
  assert.equal(read.entries[0]!.record.tool, null, "non-tool traffic is mediated, not tool-policy-evaluated");
});

test("a policy-denied tool call is blocked before execution: the upstream never sees it", async () => {
  const stack = await startStack();
  try {
    const denied = await post(stack, "/mcp", toolCall(7, "delete_jira_issue", { id: "SEC-1" }), CLIENT_KEY);
    assert.equal(denied.status, 403);
    assert.equal(stack.upstream.length, 0, "enforcement happened without execution");
    const error = JSON.parse(denied.body) as { error: { code: number; data: { ruleId: string; decisionId: string; enforcement: string } } };
    assert.equal(error.error.code, POLICY_DENIED_CODE);
    assert.equal(error.error.data.ruleId, "RH-GW-BLOCK-DELETE");
    assert.equal(error.error.data.enforcement, "blocked-at-gateway");
    assert.match(error.error.data.decisionId, /^sha256:[0-9a-f]{64}$/);
  } finally {
    await stack.stop();
  }
  const read = await readLedger(stack.ledgerPath);
  assert.equal(read.entries.length, 1);
  assert.equal(read.entries[0]!.record.tool, "delete_jira_issue");
  assert.equal(read.entries[0]!.record.decision.kind, "denied");
  assert.ok(read.entries[0]!.record.decision.reason.includes("delete_jira_issue"));
});

test("a tool call matching no rule falls through to the default effect", async () => {
  const stack = await startStack();
  try {
    const response = await post(stack, "/mcp", toolCall(7, "set_jira_label", { key: "value" }), CLIENT_KEY);
    assert.equal(response.status, 403);
    assert.equal(stack.upstream.length, 0);
    const error = JSON.parse(response.body) as { error: { data: { ruleId: string } } };
    assert.equal(error.error.data.ruleId, "RH-GW-DEFAULT");
  } finally {
    await stack.stop();
  }
});

test("an allowed tool call executes, and its exact arguments are part of the decision", async () => {
  const stack = await startStack();
  try {
    const allowed = await post(stack, "/mcp", toolCall(7, "get_jira_issue", { id: "SEC-1" }), CLIENT_KEY);
    assert.equal(allowed.status, 200);
    assert.deepEqual(stack.upstream.length, 1);
    const forwarded = JSON.parse(stack.upstream[0]!.body) as { params: { name: string; arguments: { id: string } } };
    assert.equal(forwarded.params.name, "get_jira_issue", "the forwarded body reaches upstream unwritten");
    assert.equal(forwarded.params.arguments.id, "SEC-1");
  } finally {
    await stack.stop();
  }
  const read = await readLedger(stack.ledgerPath);
  assert.equal(read.entries[0]!.record.decision.kind, "allowed");
  assert.equal(read.entries[0]!.record.decision.ruleId, "RH-GW-READ");
});

test("approval-required calls deny by default, pass once approved, and are denied again on revocation", async () => {
  const stack = await startStack();
  try {
    const first = await post(stack, "/mcp", toolCall(7, "update_jira_issue", { id: "SEC-1" }), CLIENT_KEY);
    assert.equal(first.status, 403);
    assert.equal(stack.upstream.length, 0);
    const denied = JSON.parse(first.body) as { error: { data: { decisionId: string; ruleId: string } } };
    assert.equal(denied.error.data.ruleId, "RH-GW-MUTATE-APPROVED");
    await appendFile(stack.approvalsPath, `${denied.error.data.decisionId}\n`, "utf8");

    const second = await post(stack, "/mcp", toolCall(7, "update_jira_issue", { id: "SEC-1" }), CLIENT_KEY);
    assert.equal(second.status, 200);
    assert.equal(stack.upstream.length, 1, "the approved call executed");

    const missingApproval = await post(stack, "/mcp", toolCall(7, "update_jira_issue", { id: "SEC-2" }), CLIENT_KEY);
    assert.equal(missingApproval.status, 403, "approval binds to the exact invocation, not to the tool");

    await writeFile(stack.approvalsPath, "", "utf8");
    const revoked = await post(stack, "/mcp", toolCall(7, "update_jira_issue", { id: "SEC-1" }), CLIENT_KEY);
    assert.equal(revoked.status, 403, "revoking the grant line re-blocks the identical call immediately");
  } finally {
    await stack.stop();
  }
  const read = await readLedger(stack.ledgerPath);
  assert.equal(read.entries.length, 4);
  assert.equal(read.entries[1]!.record.decision.kind, "allowed");
  assert.ok(read.entries[1]!.record.decision.reason.includes("operator approval"));
  assert.equal((await verifyLedger(stack.ledgerPath)).ok, true);
});

test("malformed JSON-RPC bodies get a parse error and never reach policy or upstream", async () => {
  const stack = await startStack();
  try {
    const response = await fetch(`${stack.base}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${CLIENT_KEY}` },
      body: "{not json",
    });
    assert.equal(response.status, 400);
    const error = JSON.parse(await response.text()) as { error: { code: number } };
    assert.equal(error.error.code, -32700);
    assert.equal(stack.upstream.length, 0);
  } finally {
    await stack.stop();
  }
});

test("the gateway only accepts POST on its configured path", async () => {
  const stack = await startStack();
  try {
    const get = await fetch(`${stack.base}/mcp`, {
      method: "GET",
      headers: { authorization: `Bearer ${CLIENT_KEY}` },
    });
    assert.equal(get.status, 405);
    assert.equal(get.headers.get("allow"), "POST");

    const wrongPath = await post(stack, "/other", { jsonrpc: "2.0", id: 1, method: "tools/list" }, CLIENT_KEY);
    assert.equal(wrongPath.status, 404);
    assert.equal(stack.upstream.length, 0);
  } finally {
    await stack.stop();
  }
});
