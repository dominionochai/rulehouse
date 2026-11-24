import test from "node:test";
import assert from "node:assert/strict";
import { matchesPattern, matchesAnyPattern } from "../src/gateway/match.js";
import { DEFAULT_RULE_ID, METHOD_RULE_ID, evaluateToolCall } from "../src/gateway/authorize.js";
import { readGatewayConfig } from "../src/gateway/config.js";
import type { GatewayPolicies } from "../src/gateway/config.js";

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
    { id: "RH-GW-BLOCK-DELETE", identities: null, tools: ["delete_*"], effect: "deny", approvalRequired: false },
    { id: "RH-GW-READ-ALL", identities: null, tools: ["get_*", "search_*"], effect: "allow", approvalRequired: false },
    { id: "RH-GW-MUTATE-APPROVED", identities: ["amara"], tools: ["update_*"], effect: "allow", approvalRequired: true },
    { id: "RH-GW-BOT-READ", identities: ["runbook-agent"], tools: ["search_*"], effect: "allow", approvalRequired: false },
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
