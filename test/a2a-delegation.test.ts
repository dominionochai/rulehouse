import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { appendDelegationRecord, evaluateDelegatedToolCall, grantIdOf,
  readDelegationRegistry, type DelegationGrant } from "../src/a2a/delegation.js";
import { evaluateToolCall, type Decision } from "../src/gateway/authorize.js";
import type { GatewayPolicies } from "../src/gateway/config.js";
import type { ProvenanceRegistry } from "../src/provenance.js";
import { contentDigestOf } from "../src/provenance.js";
import type { JsonObject } from "../src/lib/json.js";

const POLICIES: GatewayPolicies = {
  defaultEffect: "deny",
  rules: [
    { id: "RH-GW-BLOCK-DELETE", identities: null, tools: ["delete_*"], effect: "deny", approvalRequired: false, provenanceChecks: [] },
    { id: "RH-GW-READ-ALL", identities: null, tools: ["get_*", "search_*"], effect: "allow", approvalRequired: false, provenanceChecks: [] },
    { id: "RH-GW-AMARA-APPROVED-MUTATE", identities: ["amara"], tools: ["update_*"], effect: "allow", approvalRequired: true, provenanceChecks: [] },
    { id: "RH-GW-BOT-SEARCH", identities: ["runbook-agent"], tools: ["search_*"], effect: "allow", approvalRequired: false, provenanceChecks: [] },
  ],
};

const NOW = "2026-08-01T12:00:00.000Z";

async function withRegistry(): Promise<{ dir: string; path: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), "rh-a2a-"));
  return { dir, path: join(dir, "delegations.jsonl"), cleanup: () => rm(dir, { recursive: true, force: true }) };
}

async function grantFile(path: string, grantSpec: Omit<DelegationGrant, "grantId">): Promise<string> {
  const grantId = grantIdOf(grantSpec);
  await appendDelegationRecord(path, { kind: "grant", grantId, ...grantSpec }, grantSpec.grantedAt);
  return grantId;
}

function grant(overrides: Partial<Omit<DelegationGrant, "grantId">> = {}): Omit<DelegationGrant, "grantId"> {
  return {
    delegator: "amara",
    delegatee: "runbook-agent",
    tools: ["search_*"],
    grantedBy: "secops",
    grantedAt: "2026-07-01T00:00:00.000Z",
    expiresAt: null,
    ...overrides,
  };
}

type DelegationRegistry = Awaited<ReturnType<typeof readDelegationRegistry>>;

function delegated(
  delegations: DelegationRegistry,
  overrides: Partial<Parameters<typeof evaluateDelegatedToolCall>[0]> = {},
) {
  return evaluateDelegatedToolCall({
    policies: POLICIES,
    delegations,
    presented: [grantIdOf(grant())],
    identity: "runbook-agent",
    tool: "search_pages",
    args: null,
    registry: null,
    now: NOW,
    ...overrides,
  });
}

test("grant ids are content-addressed: same issuance, same id; any real difference, new id", () => {
  const id = grantIdOf(grant());
  assert.match(id, /^delegation:[0-9a-f]{64}$/);
  assert.equal(grantIdOf(grant()), id, "identical issuances share the id");
  assert.notEqual(grantIdOf(grant({ grantedAt: "2026-07-01T00:00:01.000Z" })), id, "a re-grant is a new issuance");
  assert.notEqual(grantIdOf(grant({ grantedBy: "someone-else" })), id, "attribution is part of the identity");
});

test("the registry reads back latest-wins, and proves it is intact before being believed", async () => {
  const { path, cleanup } = await withRegistry();
  try {
    const first = await grantFile(path, grant());
    const second = await grantFile(path, grant({ grantedAt: "2026-07-02T00:00:00.000Z" }));
    const registry = await readDelegationRegistry(path);
    assert.equal(registry.corrupt, null);
    assert.equal(registry.entries, 2);
    assert.equal(registry.grants.size, 2);
    assert.notEqual(first, second);

    const emptyDir = await mkdtemp(join(tmpdir(), "rh-a2a-"));
    const missing = await readDelegationRegistry(join(emptyDir, "none.jsonl"));
    assert.equal(missing.corrupt, null, "absence is an empty registry, not a broken one");

    const lines = (await readFile(path, "utf8")).split("\n").filter((line) => line.length > 0);
    await writeFile(path, lines.map((line) => line.replace('"delegatee":"runbook-agent"', '"delegatee":"attacker-agent"')).join("\n") + "\n", "utf8");
    const tampered = await readDelegationRegistry(path);
    assert.ok(tampered.corrupt !== null, "a re-written delegatee breaks the chain, and the registry refuses to pretend otherwise");
  } finally {
    await cleanup();
  }
});

test("a stored grantId that its own content does not own is unparseable, so the whole registry fails closed", async () => {
  const { path, cleanup } = await withRegistry();
  try {
    await grantFile(path, grant());
    const lines = (await readFile(path, "utf8")).split("\n").filter((line) => line.length > 0);
    const entry = JSON.parse(lines[0]!) as { record: { grantId: string } };
    entry.record.grantId = `delegation:${"0".repeat(64)}`;
    await writeFile(path, `${JSON.stringify(entry)}\n`, "utf8");
    const registry = await readDelegationRegistry(path);
    assert.ok(registry.corrupt !== null);
    assert.equal(registry.grants.size, 0);
  } finally {
    await cleanup();
  }
});

test("revocation is terminal for its issuance and a re-grant is a new decision", async () => {
  const { path, cleanup } = await withRegistry();
  try {
    const id = await grantFile(path, grant());
    await appendDelegationRecord(path, { kind: "revocation", grantId: id, revokedBy: "secops" }, "2026-07-15T00:00:00.000Z");
    const revoked = await readDelegationRegistry(path);
    assert.equal(revoked.grants.get(id)?.revoked, true);
    assert.equal(revoked.grants.get(id)?.revokedBy, "secops");

    const replacement = await grantFile(path, grant({ grantedAt: "2026-07-20T00:00:00.000Z" }));
    const reground = await readDelegationRegistry(path);
    assert.equal(reground.grants.get(id)?.revoked, true, "the revoked issuance stays revoked");
    assert.equal(reground.grants.get(replacement)?.revoked, false);
  } finally {
    await cleanup();
  }
});

test("an allowed delegated call composes every ceiling on the chain", async () => {
  const { path, cleanup } = await withRegistry();
  try {
    const id = await grantFile(path, grant());
    const registry = await readDelegationRegistry(path);
    const decision = delegated(registry);
    assert.equal(decision.allowed, true);
    assert.deepEqual(decision.chain, [{ grantId: id, delegator: "amara", delegatee: "runbook-agent" }]);
    assert.deepEqual(decision.ceilings.map((ceiling) => ceiling.identity), ["runbook-agent", "amara"]);
    assert.equal(decision.approvalRequired, false);
    assert.ok(decision.reason.includes("runbook-agent -> amara"));
  } finally {
    await cleanup();
  }
});

test("a delegatee can never exceed its delegator: the first denying ceiling is named", async () => {
  const { path, cleanup } = await withRegistry();
  try {
    const id = await grantFile(path, grant({ tools: ["*"] }));
    const registry = await readDelegationRegistry(path);
    const decision = delegated(registry, { presented: [id], tool: "delete_jira_issue" });
    assert.equal(decision.allowed, false);
    assert.ok(decision.reason.includes("denied at ceiling runbook-agent"), "the acting agent's own RH-GW-BLOCK-DELETE still binds");
    assert.equal(decision.reason.includes("RH-GW-BLOCK-DELETE"), true);
    assert.equal(decision.ceilings.length, 1, "evaluation stops at the first denial");
  } finally {
    await cleanup();
  }
});

test("the delegatee's own narrow rules still bind even when delegating broadly", async () => {
  const { path, cleanup } = await withRegistry();
  try {
    const id = await grantFile(path, grant({ tools: ["update_*"] }));
    const registry = await readDelegationRegistry(path);
    const decision = delegated(registry, { presented: [id], tool: "update_page", identity: "runbook-agent" });
    assert.equal(decision.allowed, false);
    assert.ok(decision.reason.includes("denied at ceiling runbook-agent"));
    assert.equal(decision.reason.includes("no rule matches"), true, "runbook-agent has no update rule; the denial is its own, not the delegator's");
  } finally {
    await cleanup();
  }
});

test("approval requirements escalate: every ceiling allows but any one requiring approval holds the call", async () => {
  const { path, cleanup } = await withRegistry();
  try {
    const policies: GatewayPolicies = {
      defaultEffect: "deny",
      rules: [
        { id: "RH-GW-CHIEF-UPDATE", identities: ["chief-agent"], tools: ["update_*"], effect: "allow", approvalRequired: false, provenanceChecks: [] },
        { id: "RH-GW-AMARA-APPROVED-MUTATE", identities: ["amara"], tools: ["update_*"], effect: "allow", approvalRequired: true, provenanceChecks: [] },
      ],
    };
    const id = await grantFile(path, grant({ delegatee: "chief-agent", tools: ["update_*"] }));
    const registry = await readDelegationRegistry(path);
    const decision = delegated(registry, { policies, presented: [id], tool: "update_page", identity: "chief-agent" });
    const chiefCeiling = decision.ceilings.find((ceiling) => ceiling.identity === "chief-agent");
    const amaraCeiling = decision.ceilings.find((ceiling) => ceiling.identity === "amara");
    assert.equal(chiefCeiling?.decision.kind, "allowed");
    assert.equal(chiefCeiling?.decision.approvalRequired, false, "the delegatee's own rule does not require approval");
    assert.equal(amaraCeiling?.decision.approvalRequired, true, "the delegator's does");
    assert.equal(decision.allowed, true);
    assert.equal(decision.approvalRequired, true, "the stricter ceiling wins for approval, not the looser one");
  } finally {
    await cleanup();
  }
});

test("a chain that does not connect, or revisits a participant, is refused", async () => {
  const { path, cleanup } = await withRegistry();
  try {
    const bottom = await grantFile(path, grant({ delegator: "amara", delegatee: "runbook-agent", tools: ["relabel_*"] }));
    const forged = await grantFile(path, grant({
      delegator: "someone-else",
      delegatee: "other-agent",
      grantedAt: "2026-07-03T00:00:00.000Z",
    }));
    const registry = await readDelegationRegistry(path);
    const disconnected = delegated(registry, { presented: [bottom, forged] });
    assert.equal(disconnected.allowed, false);
    assert.ok(disconnected.reason.includes("the chain does not connect"), "the upper grant hands to other-agent, but the grant below acts for amara");
    assert.ok(disconnected.reason.includes("other-agent"));

    const connected = await grantFile(path, grant({
      delegator: "someone-else",
      delegatee: "amara",
      tools: ["relabel_*"],
      grantedAt: "2026-07-09T00:00:00.000Z",
    }));
    const current = await readDelegationRegistry(path);
    const unpoliciedPolicies: GatewayPolicies = {
      defaultEffect: "deny",
      rules: [
        { id: "RH-GW-RUNBOOK-RELABEL", identities: ["runbook-agent"], tools: ["relabel_*"], effect: "allow", approvalRequired: false, provenanceChecks: [] },
        { id: "RH-GW-AMARA-RELABEL", identities: ["amara"], tools: ["relabel_*"], effect: "allow", approvalRequired: false, provenanceChecks: [] },
      ],
    };
    const hijacked = delegated(current, {
      policies: unpoliciedPolicies,
      presented: [bottom, connected],
      tool: "relabel_issue",
    });
    assert.equal(hijacked.allowed, false, "it connects, but the root delegator has no policies of its own");
    assert.ok(hijacked.reason.includes("denied at ceiling someone-else"), "an unpolicied identity delegates nothing usable under a deny-default control plane");

    const first = await grantFile(path, grant({ delegator: "amara", delegatee: "agent-a", grantedAt: "2026-07-04T00:00:00.000Z" }));
    const second = await grantFile(path, grant({ delegator: "agent-a", delegatee: "amara", grantedAt: "2026-07-05T00:00:00.000Z" }));
    const final = await readDelegationRegistry(path);
    const cyclic = delegated(final, { presented: [first, second], identity: "agent-a", tool: "search_pages" });
    assert.equal(cyclic.allowed, false);
    assert.ok(cyclic.reason.includes("delegation cycle"), "amara appears both as leaf delegator and as agent-a's delegator");
  } finally {
    await cleanup();
  }
});

test("expiry is anchored to the evaluation instant and the bound is inclusive", async () => {
  const { path, cleanup } = await withRegistry();
  try {
    await grantFile(path, grant({ expiresAt: "2026-08-01T12:00:00.000Z" }));
    const id = grantIdOf(grant({ expiresAt: "2026-08-01T12:00:00.000Z" }));
    const expired = delegated(await readDelegationRegistry(path), { presented: [id] });
    const registry = await readDelegationRegistry(path);
    assert.equal(expired.allowed, false, "expiresAt itself is already past");
    assert.ok(expired.reason.includes("expired at"));
    assert.equal(delegated(registry, { presented: [id], now: "2026-08-01T11:59:59.999Z" }).allowed, true);
  } finally {
    await cleanup();
  }
});

test("scope, identity, unknown-grant, empty-presentation, and revocation each name their defect", async () => {
  const { path, cleanup } = await withRegistry();
  try {
    const id = await grantFile(path, grant({ tools: ["search_*"] }));
    const registry = await readDelegationRegistry(path);

    const outOfScope = delegated(registry, { tool: "get_issue" });
    assert.equal(outOfScope.allowed, false);
    assert.ok(outOfScope.reason.includes(`does not cover tool "get_issue"`));

    const wrongIdentity = delegated(registry, { identity: "attacker-agent" });
    assert.equal(wrongIdentity.allowed, false);
    assert.ok(wrongIdentity.reason.includes("grants authority to runbook-agent but the call presents identity attacker-agent"));

    const unknown = delegated(registry, { presented: [`delegation:${"f".repeat(64)}`] });
    assert.equal(unknown.allowed, false);
    assert.ok(unknown.reason.includes("is not in the delegation registry"));

    const empty = delegated(registry, { presented: [] });
    assert.equal(empty.allowed, false);
    assert.ok(empty.reason.includes("no delegation presented"));

    await appendDelegationRecord(path, { kind: "revocation", grantId: id, revokedBy: "secops" }, "2026-07-16T00:00:00.000Z");
    const revokedNow = await readDelegationRegistry(path);
    const revoked = delegated(revokedNow);
    assert.equal(revoked.allowed, false);
    assert.ok(revoked.reason.includes("was revoked by secops"));
  } finally {
    await cleanup();
  }
});

test("a corrupt registry fails closed even for an otherwise valid presentation", async () => {
  const { path, cleanup } = await withRegistry();
  try {
    await grantFile(path, grant());
    const lines = (await readFile(path, "utf8")).split("\n").filter((line) => line.length > 0);
    await writeFile(path, lines.map((line) => line.replace("search_*", "revoke_*")).join("\n") + "\n", "utf8");
    const registry = await readDelegationRegistry(path);
    const decision = delegated(registry);
    assert.equal(decision.allowed, false);
    assert.ok(decision.reason.includes("delegation registry is unavailable"));
    assert.deepEqual(decision.chain, []);
  } finally {
    await cleanup();
  }
});

test("delegation composes with provenance: an untrusted argument is denied at the ceiling, not waved through", async () => {
  const { path, cleanup } = await withRegistry();
  try {
    await grantFile(path, grant({
      tools: ["post_comment"],
      grantedAt: "2026-07-06T00:00:00.000Z",
    }));
    const id = grantIdOf(grant({ tools: ["post_comment"], grantedAt: "2026-07-06T00:00:00.000Z" }));
    const registry = await readDelegationRegistry(path);
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
    const body = "vendor advisory text";
    const args: JsonObject = { body };
    const digest = contentDigestOf(body);
    const recordOf = (trust: "trusted" | "untrusted"): ProvenanceRegistry => ({
      corrupt: null,
      records: new Map([[digest, {
        contentSha256: digest,
        origin: "external",
        trust,
        source: "vendor-portal",
        labeledBy: "dso",
        labeledAt: "2026-01-01T00:00:00.000Z",
      }]]),
    });

    const deniedDecision = delegated(registry, { presented: [id], policies, args, registry: recordOf("untrusted"), tool: "post_comment" });
    assert.equal(deniedDecision.allowed, false);
    assert.ok(deniedDecision.reason.includes("resolved untrusted"));

    const allowed = delegated(registry, { presented: [id], policies, args, registry: recordOf("trusted"), tool: "post_comment" });
    assert.equal(allowed.allowed, true);
    assert.deepEqual(allowed.provenance, [{ argument: "body", contentSha256: digest, trust: "trusted" }]);
  } finally {
    await cleanup();
  }
});

test("the same call against the same state always produces the same reason", async () => {
  const { path, cleanup } = await withRegistry();
  try {
    await grantFile(path, grant({ tools: ["*"] }));
    const registry = await readDelegationRegistry(path);
    assert.deepEqual(delegated(registry, { tool: "get_issue" }), delegated(registry, { tool: "get_issue" }));
  } finally {
    await cleanup();
  }
});

test("a deeper chain accumulates the ceilings of every hop", async () => {
  const { path, cleanup } = await withRegistry();
  try {
    const root = await grantFile(path, grant({ delegator: "amara", delegatee: "runbook-agent", grantedAt: "2026-07-07T00:00:00.000Z" }));
    const leaf = await grantFile(path, grant({
      delegator: "runbook-agent",
      delegatee: "intern-agent",
      tools: ["search_*"],
      grantedAt: "2026-07-08T00:00:00.000Z",
    }));
    const registry = await readDelegationRegistry(path);
    const decision = delegated(registry, {
      presented: [leaf, root],
      identity: "intern-agent",
      tool: "search_pages",
    });
    assert.equal(decision.allowed, true);
    assert.deepEqual(decision.ceilings.map((ceiling) => ceiling.identity), ["intern-agent", "runbook-agent", "amara"]);
    assert.deepEqual(decision.chain.map((link) => link.delegator), ["runbook-agent", "amara"]);
  } finally {
    await cleanup();
  }
});
