import test from "node:test";
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createGateway, POLICY_DENIED_CODE } from "../src/gateway/server.js";
import { readLedger, verifyLedger } from "../src/gateway/ledger.js";
import type { GatewayConfig } from "../src/gateway/config.js";
import { isJsonObject } from "../src/lib/json.js";

/**
 * Live validation against a real Atlassian MCP endpoint. Nothing here runs
 * unless the operator opts in with environment variables, so normal
 * `npm test` and CI never touch the network or any credential:
 *
 *   RULEHOUSE_LIVE_UPSTREAM_URL       e.g. https://mcp.atlassian.com/v2/mcp
 *   RULEHOUSE_LIVE_UPSTREAM_CREDENTIAL  bearer token for a test site
 *   RULEHOUSE_LIVE_UPSTREAM_SCHEME    optional, default "Bearer"
 *
 * The upstream credential is read straight from the environment and only
 * ever forwarded inside the gateway's Authorization header — it is never
 * logged, echoed, or written to the ledger. The client-side key is random
 * per run, so only its ephemeral digest exists anywhere. What the run
 * observes is printed as one JSON observation block for the results note
 * (docs/live-atlassian-mcp.md); tool publication data is not secret.
 */

const UPSTREAM_URL = process.env["RULEHOUSE_LIVE_UPSTREAM_URL"];
const UPSTREAM_CREDENTIAL = process.env["RULEHOUSE_LIVE_UPSTREAM_CREDENTIAL"];
const UPSTREAM_SCHEME = process.env["RULEHOUSE_LIVE_UPSTREAM_SCHEME"] ?? "Bearer";
const missing = [
  UPSTREAM_URL === undefined ? "RULEHOUSE_LIVE_UPSTREAM_URL" : null,
  UPSTREAM_CREDENTIAL === undefined ? "RULEHOUSE_LIVE_UPSTREAM_CREDENTIAL" : null,
].filter((name): name is string => name !== null);

test(
  "live Atlassian MCP upstream behaves the way the mock assumes",
  { skip: missing.length > 0 ? `live validation not requested (set ${missing.join(" and ")})` : false },
  async () => {
    const upstreamUrl = UPSTREAM_URL!;
    const credential = UPSTREAM_CREDENTIAL!;
    const dir = await mkdtemp(join(tmpdir(), "rh-gateway-live-"));
    const ledgerPath = join(dir, "ledger.jsonl");
    const clientKey = randomBytes(24).toString("base64url");
    const config: GatewayConfig = {
      source: "live-validation",
      listen: { host: "127.0.0.1", port: 0, path: "/mcp" },
      upstream: { url: upstreamUrl, credentialEnv: "TEST_UPSTREAM_CREDENTIAL", credentialScheme: UPSTREAM_SCHEME },
      identities: [{ name: "live-probe", kind: "service-account", keyHash: `sha256:${createHash("sha256").update(clientKey).digest("hex")}` }],
      policies: {
        defaultEffect: "deny",
        rules: [
          { id: "RH-LIVE-PROBE-DENIED", identities: null, tools: ["rulehouse_forbidden_*"], effect: "deny", approvalRequired: false, provenanceChecks: [] },
          { id: "RH-LIVE-PROBE-ALLOWED", identities: null, tools: ["*"], effect: "allow", approvalRequired: false, provenanceChecks: [] },
        ],
      },
      ledgerPath,
      provenancePath: null,
      approvalsPath: null,
      trustForwardedIdentity: null,
    };
    const gateway = await createGateway(config, (name) => (name === "TEST_UPSTREAM_CREDENTIAL" ? credential : undefined));
    await gateway.listen();

    const observations: Record<string, unknown> = { upstreamUrl: upstreamUrl, scheme: UPSTREAM_SCHEME };
    const mediate = async (body: unknown, sessionId?: string): Promise<{
      readonly status: number;
      readonly contentType: string | null;
      readonly sessionIdRelayed: string | null;
      readonly payload: unknown;
    }> => {
      const response = await fetch(`${gateway.url}/mcp`, {
        method: "POST",
        headers: {
          accept: "application/json, text/event-stream",
          "content-type": "application/json",
          ...(sessionId === undefined ? {} : { "mcp-session-id": sessionId }),
        },
        body: JSON.stringify(body),
      });
      const contentType = response.headers.get("content-type");
      const raw = await response.text();
      return {
        status: response.status,
        contentType,
        sessionIdRelayed: response.headers.get("mcp-session-id"),
        payload: jsonRpcPayloadOf(contentType, raw),
      };
    };

    try {
      const initialize = await mediate({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-06-18", clientInfo: { name: "rulehouse-live-validation", version: "0.5.0" } } });
      observations["initialize"] = { status: initialize.status, contentType: initialize.contentType, sessionIdRelayed: initialize.sessionIdRelayed };
      if (initialize.status === 401 || initialize.status === 403) {
        assert.fail(`the live upstream rejected the configured credential with ${initialize.status}; check RULEHOUSE_LIVE_UPSTREAM_CREDENTIAL (its value is never logged)`);
      }
      assert.equal(initialize.status, 200, `initialize did not succeed: ${JSON.stringify(initialize.payload)}`);
      assert.ok(isJsonObject(initialize.payload), "initialize response is not a JSON-RPC payload");
      const sessionId = initialize.sessionIdRelayed;

      const listing = await mediate({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }, sessionId ?? undefined);
      observations["toolsList"] = { status: listing.status, contentType: listing.contentType, toolCount: toolCountOf(listing.payload), toolsPreview: toolNamesOf(listing.payload).slice(0, 10) };
      assert.equal(listing.status, 200, `tools/list did not succeed: ${JSON.stringify(listing.payload)}`);

      const readable = toolNamesOf(listing.payload).find((name) => /^(list|search|get|read)/i.test(name)) ?? toolNamesOf(listing.payload)[0] ?? null;
      const allowedCall = await mediate({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: readable ?? "tools", arguments: {} } }, sessionId ?? undefined);
      observations["allowedCall"] = { tool: readable, status: allowedCall.status, upstreamAccepted: allowedCall.contentType, decision: "allowed (policy), upstream answered" };
      assert.equal(allowedCall.status, 200, `the allowed call should reach the upstream: ${JSON.stringify(allowedCall.payload)}`);

      const deniedCall = await mediate({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "rulehouse_forbidden_probe", arguments: {} } }, sessionId ?? undefined);
      observations["deniedCall"] = { tool: "rulehouse_forbidden_probe", status: deniedCall.status, expectedCode: POLICY_DENIED_CODE };
      assert.equal(deniedCall.status, 403, "a denied call must be blocked at the gateway, never forwarded");

      const unauthenticated = await mediate({ jsonrpc: "2.0", id: 4, method: "tools/list", params: {} });
      observations["unauthenticatedClient"] = { status: unauthenticated.status };
      assert.equal(unauthenticated.status, 401, "an unauthenticated request must be refused before any upstream traffic");
    } finally {
      await gateway.close();
    }

    const read = await readLedger(ledgerPath);
    const enforcement = read.entries.map((entry) => entry.record.enforcement);
    observations["ledger"] = { entries: enforcement, chainVerified: (await verifyLedger(ledgerPath)).ok, identities: read.entries.map((entry) => entry.record.identity) };
    assert.equal((await verifyLedger(ledgerPath)).ok, true);
    assert.deepEqual(enforcement, ["forwarded-to-upstream", "forwarded-to-upstream", "forwarded-to-upstream", "blocked-at-gateway", "blocked-at-gateway"]);

    process.stdout.write(`\n${JSON.stringify(observations, null, 2)}\n\n`);
  },
);

/**
 * The live upstream may answer any request as buffered JSON or as an SSE
 * stream — which is exactly the behavior this test exists to observe.
 * Both shapes carry the same JSON-RPC payload, so the reader normalizes
 * them: SSE is reduced to its last `data:` frame.
 */
function jsonRpcPayloadOf(contentType: string | null, raw: string): unknown {
  if (contentType === null || !contentType.includes("text/event-stream")) return JSON.parse(raw);
  const frames = raw.split("\n").filter((line) => line.startsWith("data:"));
  const lastFrame = frames[frames.length - 1];
  if (lastFrame === undefined) throw new Error("the upstream's SSE answer carried no data frame");
  return JSON.parse(lastFrame.slice("data:".length).trim());
}

function isToolList(payload: unknown): payload is { readonly result: { readonly tools: readonly unknown[] } } {
  if (!isJsonObject(payload) || !isJsonObject(payload["result"])) return false;
  const result = payload["result"];
  return Array.isArray(result["tools"]) && result["tools"].every((tool) => isJsonObject(tool) && typeof tool["name"] === "string");
}

function toolNamesOf(payload: unknown): readonly string[] {
  if (!isToolList(payload)) return [];
  return payload.result.tools.map((tool) => (isJsonObject(tool) ? String(tool["name"]) : "")).filter((name) => name.length > 0);
}

function toolCountOf(payload: unknown): number {
  return toolNamesOf(payload).length;
}
