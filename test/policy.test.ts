import test from "node:test";
import assert from "node:assert/strict";
import { evaluatePolicy, parityVerdicts } from "../src/policy.js";
import { fingerprintInlineSecret, fingerprintEnvSecret } from "../src/lib/secrets.js";
import type { InventoryEntry, AuthView } from "../src/model.js";

function entry(overrides: Partial<InventoryEntry> & { readonly serverName?: string; readonly client?: InventoryEntry["client"] }): InventoryEntry {
  const base: InventoryEntry = {
    client: overrides.client ?? "claude-code",
    serverName: overrides.serverName ?? "atlassian",
    transport: "remote",
    url: "https://mcp.atlassian.com/v2/mcp",
    serverKey: "atlassian:https://mcp.atlassian.com",
    endpointClass: "atlassian-v2",
    auth: { kind: "oauth" },
    toolsOverride: null,
    disabledTools: null,
    source: { file: "a.json", pointer: "/mcpServers/atlassian", format: "claude-code" },
  };
  return { ...base, ...overrides, source: overrides.source ?? base.source } as InventoryEntry;
}

const ids = (evaluation: { readonly verdicts: readonly { readonly ruleId: string; readonly status: string }[] }, ruleId: string, status: string) =>
  evaluation.verdicts.filter((v) => v.ruleId === ruleId && v.status === status).length;

test("inline credential material is a finding; env-origin is a pass", () => {
  const inline = entry({ auth: { kind: "api-token", scheme: "basic", username: "u@x", credential: fingerprintInlineSecret("secret-material"), problem: null } });
  const envResolvable = entry({ auth: { kind: "api-token", scheme: "bearer", username: null, credential: fingerprintEnvSecret("secret-material", "KEY"), problem: null } });
  const evaluated = evaluatePolicy([inline, envResolvable], null);
  assert.equal(ids(evaluated, "RH-CRED-INLINE", "finding"), 1);
  assert.equal(ids(evaluated, "RH-CRED-INLINE", "pass"), 1);
  const finding = evaluated.verdicts.find((v) => v.ruleId === "RH-CRED-INLINE" && v.status === "finding");
  assert.ok(finding !== undefined && finding.message.includes("fingerprint"));
});

test("unresolved env credentials are surfaced as findings; resolved ones pass", () => {
  const unresolved = entry({ auth: { kind: "api-token", scheme: "bearer", username: null, credential: fingerprintEnvSecret("", "MISSING"), problem: "environment variable MISSING is not set in this shell" } });
  const resolved = entry({ auth: { kind: "api-token", scheme: "bearer", username: null, credential: fingerprintEnvSecret("material", "PRESENT"), problem: null } });
  const evaluated = evaluatePolicy([unresolved, resolved], null);
  assert.equal(ids(evaluated, "RH-CRED-UNRESOLVED", "finding"), 1);
  assert.equal(ids(evaluated, "RH-CRED-UNRESOLVED", "pass"), 1);
});

test("oauth entries are out of scope for credential rules but rule presence is recorded", () => {
  const evaluated = evaluatePolicy([entry({})], null);
  assert.equal(ids(evaluated, "RH-CRED-INLINE", "not-applicable"), 1);
  assert.equal(ids(evaluated, "RH-CRED-UNRESOLVED", "not-applicable"), 1);
});

test("endpoint generation rules classify v1, sse, and v2 correctly", () => {
  const entries = [
    entry({ url: "https://mcp.atlassian.com/v2/mcp", endpointClass: "atlassian-v2" }),
    entry({ url: "https://mcp.atlassian.com/v1/mcp", endpointClass: "atlassian-v1", serverName: "old" }),
    entry({ url: "https://mcp.atlassian.com/v1/sse", endpointClass: "atlassian-sse-legacy", serverName: "older" }),
  ];
  const evaluated = evaluatePolicy(entries, null);
  assert.equal(ids(evaluated, "RH-ENDPOINT-V1", "finding"), 1);
  assert.equal(ids(evaluated, "RH-ENDPOINT-SSE-LEGACY", "finding"), 1);
  assert.equal(ids(evaluated, "RH-ENDPOINT-V1", "pass"), 2);
  assert.equal(ids(evaluated, "RH-ENDPOINT-SSE-LEGACY", "pass"), 2);
});

test("plaintext transport is critical", () => {
  const evaluated = evaluatePolicy([entry({ url: "http://x.example.com/mcp", endpointClass: "insecure-remote" })], null);
  const finding = evaluated.verdicts.find((v) => v.ruleId === "RH-ENDPOINT-INSECURE" && v.status === "finding");
  assert.ok(finding !== undefined && finding.severity === "critical");
});

test("tools=all is a finding with the values in the message", () => {
  const evaluated = evaluatePolicy([entry({ toolsOverride: ["all"] })], null);
  const finding = evaluated.verdicts.find((v) => v.ruleId === "RH-TOOLS-ALL" && v.status === "finding");
  assert.ok(finding !== undefined && finding.message.includes("tools=all"));
});

test("parity: oauth in one client, basic token in another is a high finding", () => {
  const oauth = entry({ client: "claude-desktop" });
  const basic = entry({ client: "cursor", auth: { kind: "api-token", scheme: "basic", username: "u@x", credential: fingerprintInlineSecret("m"), problem: null } });
  const findings = parityVerdicts([oauth, basic]).filter((v) => v.status === "finding");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.severity, "high");
  assert.ok(findings[0]!.message.includes("OAuth 2.1") && findings[0]!.message.includes("API token (basic)"));
});

test("parity: uniform registrations pass with count evidence", () => {
  const a = entry({ client: "claude-desktop" });
  const b = entry({ client: "cursor" });
  const verdicts = parityVerdicts([a, b]).filter((v) => v.status === "pass");
  assert.equal(verdicts.length, 3);
  assert.ok(verdicts.every((v) => v.message.includes("all 2 registrations")));
});

test("parity: v1 in one client and v2 in another is caught even though urls differ", () => {
  const v2 = entry({ client: "claude-desktop" });
  const v1 = entry({ client: "cursor", url: "https://mcp.atlassian.com/v1/mcp", endpointClass: "atlassian-v1" });
  const verdicts = parityVerdicts([v2, v1]);
  const endpointFinding = verdicts.find((v) => v.status === "finding" && v.message.includes("endpoint generation"));
  assert.ok(endpointFinding !== undefined);
  assert.ok(endpointFinding.subject.includes("atlassian:"));
});

test("parity: tools divergence is caught", () => {
  const a = entry({ client: "claude-desktop" });
  const b = entry({ client: "cursor", toolsOverride: ["all"] });
  const verdicts = parityVerdicts([a, b]);
  assert.ok(verdicts.some((v) => v.status === "finding" && v.message.includes("tool exposure")));
});

test("parity: single registrations are marked not-applicable, not silently skipped", () => {
  const verdicts = parityVerdicts([entry({})]);
  assert.equal(verdicts.length, 1);
  assert.equal(verdicts[0]!.status, "not-applicable");
});

test("allowlist enforcement flags unapproved servers and stays silent when unset", () => {
  const listed = entry({});
  const unlisted = entry({ client: "cursor", serverName: "gw", url: "https://gw.example.com/mcp", serverKey: "remote:https://gw.example.com/mcp", endpointClass: "https-remote" });
  const withList = evaluatePolicy([listed, unlisted], { urlPrefixes: ["https://mcp.atlassian.com/"], source: "allowlist.json" });
  assert.equal(ids(withList, "RH-ALLOWLIST", "finding"), 1);
  assert.equal(ids(withList, "RH-ALLOWLIST", "pass"), 1);
  const withoutList = evaluatePolicy([listed], null);
  assert.equal(ids(withoutList, "RH-ALLOWLIST", "not-applicable"), 1);
});

test("unknown auth is grouped distinctly rather than passing as oauth", () => {
  const a = entry({ client: "claude-desktop", auth: { kind: "unknown", reason: "malformed Authorization header" } });
  const b = entry({ client: "cursor", auth: { kind: "unknown", reason: "malformed Authorization header" } });
  const verdicts = parityVerdicts([a, b]);
  assert.ok(verdicts.some((v) => v.status === "pass" && v.message.includes("unclassified (malformed Authorization header)")));
});
