import test from "node:test";
import assert from "node:assert/strict";
import { matchesPattern, matchesAnyPattern } from "../src/gateway/match.js";
import { DEFAULT_RULE_ID, METHOD_RULE_ID, evaluateToolCall } from "../src/gateway/authorize.js";
import { readGatewayConfig } from "../src/gateway/config.js";
import type { GatewayPolicies } from "../src/gateway/config.js";
import { contentDigestOf, type ProvenanceRecord, type ProvenanceRegistry, type ProvenanceTrust } from "../src/provenance.js";
import type { Decision } from "../src/gateway/authorize.js";
import { parseLooseJson, type JsonObject } from "../src/lib/json.js";

test("tool patterns match literally except for the star wildcard", () => {
  assert.equal(matchesPattern("get_issue", "get_issue"), true);
  assert.equal(matchesPattern("get_issue", "get_issues"), false);
  assert.equal(matchesPattern("get_*", "get_issue"), true);
  assert.equal(matchesPattern("get_*", "get_"), true);
  assert.equal(matchesPattern("get_*", "set_issue"), false);
  assert.equal(matchesPattern("*_issue", "create_issue"), true);
  assert.equal(matchesPattern("*", "anything.at.all"), true);
  assert.equal(matchesPattern("*", ""), true);
  assert.equal(matchesPattern("update_*_field", "update_jira_custom_field"), true);
  assert.equal(matchesPattern("*", "prefix__suffix%20middle"), true);
  assert.equal(matchesPattern("a.c", "abc"), false, "dot must not act as a wildcard");
  assert.equal(matchesAnyPattern(["get_*", "search_*"], "search_pages"), true);
  assert.equal(matchesAnyPattern(["get_*", "search_*"], "delete_pages"), false);
});

const POLICIES: GatewayPolicies = {
  defaultEffect: "deny",
  rules: [
    { id: "RH-GW-BLOCK-DELETE", identities: null, tools: ["delete_*"], effect: "deny", approvalRequired: false, provenanceChecks: [] },
    { id: "RH-GW-READ-ALL", identities: null, tools: ["get_*", "search_*"], effect: "allow", approvalRequired: false, provenanceChecks: [] },
    { id: "RH-GW-MUTATE-APPROVED", identities: ["amara"], tools: ["update_*"], effect: "allow", approvalRequired: true, provenanceChecks: [] },
    { id: "RH-GW-BOT-READ", identities: ["runbook-agent"], tools: ["search_*"], effect: "allow", approvalRequired: false, provenanceChecks: [] },
  ],
};

test("first matching rule wins in written order", () => {
  const blocked = evaluateToolCall(POLICIES, "amara", "delete_jira_issue");
  assert.equal(blocked.kind, "denied");
  assert.equal(blocked.ruleId, "RH-GW-BLOCK-DELETE");

  const readable = evaluateToolCall(POLICIES, "amara", "get_jira_issue");
  assert.equal(readable.kind, "allowed");
  assert.equal(readable.ruleId, "RH-GW-READ-ALL");
  assert.equal(readable.approvalRequired, false);

  const mutation = evaluateToolCall(POLICIES, "amara", "update_jira_issue");
  assert.equal(mutation.kind, "allowed");
  assert.equal(mutation.ruleId, "RH-GW-MUTATE-APPROVED");
  assert.equal(mutation.approvalRequired, true);
});

test("identity-restricted rules do not apply to other identities", () => {
  const mutation = evaluateToolCall(POLICIES, "runbook-agent", "update_jira_issue");
  assert.equal(mutation.kind, "denied");
  assert.equal(mutation.ruleId, DEFAULT_RULE_ID, "falls through to the default effect");
});

test("the configured default effect governs unmatched calls", () => {
  const denied = evaluateToolCall(POLICIES, null, "list_spaces");
  assert.equal(denied.ruleId, DEFAULT_RULE_ID);
  assert.equal(denied.reason.includes("default effect is deny"), true);

  const allowAll: GatewayPolicies = { defaultEffect: "allow", rules: [] };
  const allowed = evaluateToolCall(allowAll, "amara", "anything_else");
  assert.equal(allowed.kind, "allowed");
  assert.equal(allowed.ruleId, DEFAULT_RULE_ID);
  assert.equal(allowed.approvalRequired, false);
});

function gatewayConfigText(): string {
  return `
  // comments and a trailing comma are accepted
  {
    "listen": { "host": "127.0.0.1", "port": 0 },
    "upstream": {
      "url": "https://mcp.atlassian.com/v2/mcp",
      "credentialEnv": "TEST_UPSTREAM_CREDENTIAL",
    },
    "identities": [
      { "name": "amara", "kind": "user", "keyHash": "sha256:${"a".repeat(64)}" }
    ],
    "policies": { "defaultEffect": "deny", "rules": [] },
    "ledger": { "path": "t.jsonl" },
    "approvals": { "path": "t-approvals.txt" },
  }
  `;
}

test("a valid gateway config parses with no diagnostics", () => {
  const result = readGatewayConfig(gatewayConfigText(), "gateway.jsonc", (name) =>
    name === "TEST_UPSTREAM_CREDENTIAL" ? "Basic YW1hcmFAZXhhbXBsZS5jb206dG9rZW4tbm90LXJlYWw=" : undefined);
  assert.deepEqual(result.diagnostics, []);
  const config = result.config;
  assert.ok(config !== null);
  assert.equal(config.listen.port, 0);
  assert.equal(config.upstream.credentialEnv, "TEST_UPSTREAM_CREDENTIAL");
  assert.equal(config.ledgerPath, "t.jsonl");
  assert.equal(config.approvalsPath, "t-approvals.txt");
});

test("config validation gives each defect a precise diagnostic and fails closed", () => {
  const base = () => ({
    upstream: { url: "https://mcp.atlassian.com/v2/mcp", credentialEnv: "K" },
    identities: [{ name: "amara", kind: "user", keyHash: `sha256:${"a".repeat(64)}` }],
    policies: { defaultEffect: "deny", rules: [{ id: "R1", identities: null, tools: ["*"], effect: "allow" }] },
  });
  const env = (): string | undefined => undefined;
  const run = (document: unknown): readonly string[] => {
    const result = readGatewayConfig(JSON.stringify(document), "config.json", env);
    return result.diagnostics.map((d) => `${d.subject}: ${d.message}`);
  };

  const missingUpstream = run({ identities: [], policies: { rules: [] } });
  assert.ok(missingUpstream.some((d) => d.includes("/upstream")));

  const badHash = run({ ...base(), identities: [{ name: "amara", kind: "user", keyHash: "deadbeef" }] });
  assert.ok(badHash.some((d) => d.includes("keyHash")));

  const unknownIdentity = run({
    ...base(),
    policies: { defaultEffect: "deny", rules: [{ id: "R1", identities: ["nobody"], tools: ["get_*"], effect: "allow" }] },
  });
  assert.ok(unknownIdentity.some((d) => d.includes("unknown identity")));

  const duplicateRule = run({
    ...base(),
    policies: {
      defaultEffect: "deny",
      rules: [
        { id: "R1", identities: null, tools: ["get_*"], effect: "allow" },
        { id: "R1", identities: null, tools: ["set_*"], effect: "allow" },
      ],
    },
  });
  assert.ok(duplicateRule.some((d) => d.includes('duplicates rule id "R1"')));

  const denyApproval = run({
    ...base(),
    policies: { defaultEffect: "deny", rules: [{ id: "R1", identities: null, tools: ["*"], effect: "deny", approval: "required" }] },
  });
  assert.ok(denyApproval.some((d) => d.includes("approval cannot be required on a deny rule")));

  const nonLoopback = (() => {
    const result = readGatewayConfig(JSON.stringify({
      ...base(),
      listen: { host: "0.0.0.0", port: 8080 },
    }), "config.json", env);
    return result.diagnostics.map((d) => d.message);
  })();
  assert.ok(nonLoopback.some((d) => d.includes("loopback")), "the gateway refuses to invent an externally reachable default");

  const configResult = readGatewayConfig(JSON.stringify(base()), "config.json", env);
  assert.equal(configResult.config?.policies.defaultEffect, "deny");

  const malformedCredential = readGatewayConfig(JSON.stringify({
    ...base(),
    upstream: { url: "https://mcp.atlassian.com/v2/mcp", credentialEnv: "K", credentialScheme: "bearer" },
  }), "config.json", (name) => (name === "K" ? "Bearer ${HALF_OPEN}" : undefined));
  assert.ok(malformedCredential.diagnostics.some((d) => d.message.includes("cannot classify")),
    "an unclassifiable upstream credential is refused at load time, not at request time");
});

test("the mediated-method rule id is distinct and specific", () => {
  assert.notEqual(METHOD_RULE_ID, DEFAULT_RULE_ID);
});

function digest(content: string | JsonObject): string {
  return contentDigestOf(content);
}

function registry(entries: Record<string, ProvenanceTrust>): ProvenanceRegistry {
  const records = new Map<string, ProvenanceRecord>();
  for (const [contentSha256, trust] of Object.entries(entries)) {
    records.set(contentSha256, {
      contentSha256,
      trust,
      origin: "external",
      source: "test-fixture",
      labeledBy: "test",
      labeledAt: "2026-01-01T00:00:00.000Z",
    });
  }
  return { records, corrupt: null };
}

function emptyRegistry(): ProvenanceRegistry {
  return { records: new Map(), corrupt: null };
}

test("a provenance condition is satisfied only by accepted declared trust", () => {
  const policies: GatewayPolicies = {
    defaultEffect: "deny",
    rules: [
      {
        id: "RH-GW-POST-DECLARED",
        identities: null,
        tools: ["post_comment"],
        effect: "allow",
        approvalRequired: false,
        provenanceChecks: [{ argument: "body", requireTrust: ["trusted"] }],
      },
    ],
  };
  const trusted = evaluateToolCall(policies, "amara", "post_comment",
    { body: "approved runbook text" }, registry({ [digest("approved runbook text")]: "trusted" }));
  assert.equal(trusted.kind, "allowed");
  assert.equal(trusted.ruleId, "RH-GW-POST-DECLARED");
  assert.equal(trusted.provenance.length, 1);
  assert.equal(trusted.provenance[0]?.trust, "trusted");
  assert.equal(trusted.provenance[0]?.argument, "body");
});

test("untrusted content does not ride on an allow rule written for trusted work", () => {
  const policies: GatewayPolicies = {
    defaultEffect: "deny",
    rules: [
      {
        id: "RH-GW-POST-DECLARED",
        identities: null,
        tools: ["post_comment"],
        effect: "allow",
        approvalRequired: false,
        provenanceChecks: [{ argument: "body", requireTrust: ["trusted"] }],
      },
    ],
  };
  const denied = evaluateToolCall(policies, "amara", "post_comment",
    { body: "attacker text" }, registry({ [digest("attacker text")]: "untrusted" }));
  assert.equal(denied.kind, "denied");
  assert.equal(denied.ruleId, DEFAULT_RULE_ID, "the allow rule is skipped, and the default denies");
  assert.ok(denied.reason.includes("RH-GW-POST-DECLARED"), "the denial explains why the allow rule was skipped");
  assert.ok(denied.reason.includes("untrusted"));
});

test("structured content resolves through canonical digesting, key order included", () => {
  const policies: GatewayPolicies = {
    defaultEffect: "deny",
    rules: [
      {
        id: "RH-GW-STRUCT",
        identities: null,
        tools: ["post_comment"],
        effect: "allow",
        approvalRequired: false,
        provenanceChecks: [{ argument: "body", requireTrust: ["trusted"] }],
      },
    ],
  };
  const trusted = evaluateToolCall(policies, "amara", "post_comment",
    { body: { text: "a", meta: { b: 1, a: 2 } } }, registry({ [digest({ text: "a", meta: { a: 2, b: 1 } })]: "trusted" }));
  assert.equal(trusted.kind, "allowed", "canonically equal structures resolve to the same digest");
});

test("unclassified and unavailable content satisfies no trust requirement", () => {
  const policies: GatewayPolicies = {
    defaultEffect: "deny",
    rules: [
      {
        id: "RH-GW-POST-DECLARED",
        identities: null,
        tools: ["post_comment"],
        effect: "allow",
        approvalRequired: false,
        provenanceChecks: [{ argument: "body", requireTrust: ["trusted"] }],
      },
    ],
  };
  const checks = (registry: ProvenanceRegistry | null, args: JsonObject | null = { body: "x" }): "allowed" | "denied" =>
    evaluateToolCall(policies, "amara", "post_comment", args, registry).kind;

  assert.equal(checks(null, { body: "x" }), "denied", "no registry configured");
  assert.equal(checks(emptyRegistry()), "denied", "healthy registry, digest not present");
  assert.equal(checks(emptyRegistry(), null), "denied", "call carries no arguments to inspect");
  assert.equal(checks(emptyRegistry(), { other: "x" }), "denied", "checked argument is absent");
  assert.equal(checks({ records: new Map(), corrupt: "line 1 problem" }, { body: "x" }), "denied", "corrupt registry");
});

test("a deny rule gated on untrusted content enforces exactly that content", () => {
  const policies: GatewayPolicies = {
    defaultEffect: "allow",
    rules: [
      {
        id: "RH-GW-NO-UNTRUSTED",
        identities: null,
        tools: ["run_workflow"],
        effect: "deny",
        approvalRequired: false,
        provenanceChecks: [{ argument: "input", requireTrust: ["untrusted"] }],
      },
    ],
  };
  const denied = evaluateToolCall(policies, "amara", "run_workflow",
    { input: "external form text" }, registry({ [digest("external form text")]: "untrusted" }));
  assert.equal(denied.kind, "denied");
  assert.equal(denied.ruleId, "RH-GW-NO-UNTRUSTED");

  const allowed = evaluateToolCall(policies, "amara", "run_workflow",
    { input: "internal text" }, registry({ [digest("internal text")]: "trusted" }));
  assert.equal(allowed.kind, "allowed", "declared-trusted content escapes the deny rule");
});

test("config validation refuses provenance checks it could never satisfy", () => {
  const base = () => ({
    listen: { host: "127.0.0.1", port: 8080 },
    upstream: { url: "https://mcp.atlassian.com/v2/mcp", credentialEnv: "K" },
    identities: [{ name: "amara", kind: "user", keyHash: `sha256:${"a".repeat(64)}` }],
    policies: {
      defaultEffect: "deny",
      rules: [{
        id: "R", identities: ["amara"], tools: ["post_*"], effect: "allow",
        provenanceChecks: [{ argument: "body", requireTrust: ["trusted"] }],
      }],
    },
  });
  const env = (): string | undefined => undefined;

  const missingRegistry = readGatewayConfig(JSON.stringify(base()), "config.json", env);
  assert.ok(missingRegistry.diagnostics.some((d) => d.message.includes("no top-level \"provenance\" path")),
    "checks without a configured registry are dead rules");

  const badTrust = readGatewayConfig(JSON.stringify({
    ...base(),
    provenance: { path: "provenance.jsonl" },
    policies: { defaultEffect: "deny", rules: [{
      id: "R", identities: ["amara"], tools: ["post_*"], effect: "allow",
      provenanceChecks: [{ argument: "body", requireTrust: ["unclassified"] }],
    }] },
  }), "config.json", env);
  assert.ok(badTrust.diagnostics.some((d) => d.message.includes("unknown trust value")),
    "unclassified/unavailable are observed states, not declarations an operator can require");
});


test("proxy-asserted identity is off unless opted in, and validates its header", () => {
  const env = (): string | undefined => undefined;
  const baseDocument = (): Record<string, unknown> => {
    const loose = parseLooseJson(gatewayConfigText(), "cfg");
    assert.deepEqual(loose.diagnostics, []);
    return JSON.parse(JSON.stringify(loose.value)) as Record<string, unknown>;
  };
  const run = (document: Record<string, unknown>) =>
    readGatewayConfig(JSON.stringify(document), "config.json", env);

  const off = run(baseDocument());
  assert.ok(off.config !== null);
  assert.equal(off.config.trustForwardedIdentity, null);

  const optedIn = run({ ...baseDocument(), trustForwardedIdentity: { header: "X-Rulehouse-Identity" } });
  assert.ok(optedIn.config !== null);
  assert.deepEqual(optedIn.config.trustForwardedIdentity, { header: "x-rulehouse-identity" });
  assert.deepEqual(optedIn.diagnostics, []);

  const problems = (subject: unknown): readonly string[] => {
    const result = run({ ...baseDocument(), trustForwardedIdentity: subject });
    assert.ok(result.config !== null || result.diagnostics.some((d) => d.message.length > 0));
    return result.diagnostics.map((d) => `${d.subject}: ${d.message}`);
  };

  const usurped = problems({ header: "Authorization" });
  assert.ok(usurped.some((d) => d.includes("cannot carry a proxy-asserted identity")));

  const invalid = problems({ header: "not a header name" });
  assert.ok(invalid.some((d) => d.includes("is not a valid header name")));

  const unnamed = problems({ header: "" });
  assert.ok(unnamed.some((d) => d.includes("/trustForwardedIdentity/header")));

  const shapeless = problems("X-Rulehouse-Identity");
  assert.ok(shapeless.some((d) => d.includes("/trustForwardedIdentity")));
});
