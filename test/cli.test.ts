import test from "node:test";
import assert from "node:assert/strict";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { main } from "../src/cli.js";
import { LedgerWriter } from "../src/gateway/ledger.js";
import { writeFileSync } from "node:fs";

const REPO = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..");
const FLEET = join(REPO, "examples", "fleet");
const DRIFT = join(REPO, "examples", "fleet-drift-after");

async function withTempScan(inplace: string, command: readonly string[]) {
  const originalStdout = process.stdout.write.bind(process.stdout);
  const originalStderr = process.stderr.write.bind(process.stderr);
  const collected: string[] = [];
  const collect = (chunk: string | Uint8Array): true => {
    collected.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    return true;
  };
  process.stdout.write = collect as typeof process.stdout.write;
  process.stderr.write = collect as typeof process.stderr.write;
  try {
    const code = await main(command);
    return { code, stdout: collected.join("") };
  } finally {
    process.stdout.write = originalStdout;
    process.stderr.write = originalStderr;
  }
}

test("scan inventories the fleet, writes outputs, and exits 0 without --strict", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-cli-"));
  try {
    const out = join(dir, "out");
    const result = await withTempScan(FLEET, ["scan", FLEET, "--out", out]);
    assert.equal(result.code, 0);
    assert.match(result.stdout, /7 registration\(s\)/);
    const snapshot = JSON.parse(await readFile(join(out, "snapshot.json"), "utf8"));
    const report = JSON.parse(await readFile(join(out, "report.json"), "utf8"));
    const markdown = await readFile(join(out, "report.md"), "utf8");
    assert.equal(snapshot.format, "rulehouse.snapshot");
    assert.equal(report.inventory.length, 7);
    assert.ok(report.verdicts.length > 0);
    assert.ok(markdown.includes("## Evidence"));
    assert.ok(!markdown.includes("RHO-SYNTHETIC-TOKEN-0002"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("ledger verification exits 0 on an intact chain and 1 at the first falsified entry", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-cli-"));
  try {
    const path = join(dir, "ledger.jsonl");
    const writer = await LedgerWriter.open(path);
    await writer.append({
      decisionId: "sha256:" + "1".repeat(64),
      identity: "amara",
      method: "tools/call",
      tool: "get_issue",
      decision: { kind: "allowed", ruleId: "RH-GW-READ", reason: "read" },
      provenance: null,
      enforcement: "forwarded-to-upstream",
      upstreamStatus: 200,
      identitySource: "bearer-key",
    }, "2026-01-01T00:00:00.000Z");

    const intact = await withTempScan(path, ["ledger", path]);
    assert.equal(intact.code, 0);
    assert.ok(intact.stdout.includes("chain intact"));

    const lines = (await readFile(path, "utf8")).split("\n").filter((line) => line.length > 0);
    const falsified = lines.map((line) => line.replace("get_issue", "delete_issue"));
    writeFileSync(path, falsified.join("\n") + "\n", "utf8");
    const broken = await withTempScan(path, ["ledger", path]);
    assert.equal(broken.code, 1);
    assert.ok(broken.stdout.includes("BROKEN at entry 0"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("serve refuses an unenforceable gateway config with exit 2", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-cli-"));
  try {
    const path = join(dir, "gateway.json");
    writeFileSync(path, JSON.stringify({ listen: { host: "0.0.0.0" } }), "utf8");
    const result = await withTempScan(path, ["serve", "--config", path]);
    assert.equal(result.code, 2);
    assert.ok(result.stdout.includes("/upstream"), "the refusal names the first missing section");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan --strict exits 1 when findings exist", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-cli-"));
  try {
    const result = await withTempScan(FLEET, ["scan", FLEET, "--out", join(dir, "out"), "--strict"]);
    assert.equal(result.code, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("diff between the fleet and its drifted copy detects the changes and exits 1", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-cli-"));
  try {
    await main(["scan", FLEET, "--out", join(dir, "before")]);
    await main(["scan", DRIFT, "--out", join(dir, "after")]);
    const result = await withTempScan(dir, ["diff", join(dir, "before", "snapshot.json"), join(dir, "after", "snapshot.json")]);
    assert.equal(result.code, 1);
    assert.ok(!result.stdout.includes("no changes detected"));
    assert.match(result.stdout, /registration\(s\)/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("diff with identical snapshots exits 0", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-cli-"));
  try {
    await main(["scan", FLEET, "--out", join(dir, "before")]);
    await main(["scan", FLEET, "--out", join(dir, "after")]);
    const result = await withTempScan(dir, ["diff", join(dir, "before", "snapshot.json"), join(dir, "after", "snapshot.json")]);
    assert.equal(result.code, 0);
    assert.match(result.stdout, /no changes detected/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("verify confirms unmodified inputs and detects tampering", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-cli-"));
  try {
    const fleetCopy = join(dir, "fleet");
    await cp(FLEET, fleetCopy, { recursive: true });
    const scan = await withTempScan(fleetCopy, ["scan", fleetCopy, "--out", join(dir, "out")]);
    assert.equal(scan.code, 0);
    const verified = await withTempScan(dir, ["verify", join(dir, "out", "snapshot.json"), "--root", fleetCopy]);
    assert.equal(verified.code, 0);
    assert.match(verified.stdout, /fingerprint verified/);

    const target = join(fleetCopy, "ops", "mcp.json");
    await writeFile(target, '{ "mcpServers": { "retiring-connector": { "url": "https://mcp.atlassian.com/v2/mcp" } } }\n', "utf8");
    const tampered = await withTempScan(dir, ["verify", join(dir, "out", "snapshot.json"), "--root", fleetCopy]);
    assert.equal(tampered.code, 1);
    assert.match(tampered.stdout, /MODIFIED/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("usage and unknown commands exit 2 with guidance", async () => {
  const originalStderr = process.stderr.write.bind(process.stderr);
  const collected: string[] = [];
  process.stderr.write = ((chunk: string | Uint8Array) => {
    collected.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    return true;
  }) as typeof process.stderr.write;
  try {
    assert.equal(await main(["scan"]), 2);
    assert.match(collected.join(""), /scan requires/);
    collected.length = 0;
    assert.equal(await main(["transmogrify"]), 2);
    assert.match(collected.join(""), /unknown command/);
    collected.length = 0;
    assert.equal(await main([]), 2);
    assert.match(collected.join(""), /Usage/);
  } finally {
    process.stderr.write = originalStderr;
  }
});

test("allowlist enforcement changes the RH-ALLOWLIST verdict", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-cli-"));
  try {
    const allowlist = join(dir, "allowlist.json");
    await writeFile(allowlist, JSON.stringify({ urlPrefixes: ["https://mcp.atlassian.com/"] }), "utf8");
    const result = await withTempScan(dir, ["scan", FLEET, "--out", join(dir, "out"), "--allowlist", allowlist]);
    const report = JSON.parse(await readFile(join(dir, "out", "report.json"), "utf8"));
    const verdicts = report.verdicts.filter((v: { ruleId: string }) => v.ruleId === "RH-ALLOWLIST");
    assert.ok(verdicts.some((v: { status: string }) => v.status === "finding"), "wiki-loader and legacy-monitoring are not on the list");
    assert.ok(verdicts.some((v: { status: string }) => v.status === "pass"));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("provenance register and inspect round-trips through a verified chain", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-cli-"));
  try {
    const contentPath = join(dir, "instruction.txt");
    const registryPath = join(dir, "provenance.jsonl");
    await writeFile(contentPath, "run maintenance mode on call-out hours");

    const registered = await withTempScan(dir, ["provenance", "register", registryPath, contentPath,
      "--origin", "external", "--trust", "untrusted", "--source", "webform:vendor-portal", "--labeled-by", "dso"]);
    assert.equal(registered.code, 0);
    assert.match(registered.stdout, /registered sha256:[0-9a-f]{64} as trust=untrusted/);

    const chain = await withTempScan(dir, ["ledger", registryPath]);
    assert.equal(chain.code, 0, "the registry is a verifiable rulehouse chain");

    const inspected = await withTempScan(dir, ["provenance", "inspect", registryPath, contentPath]);
    assert.equal(inspected.code, 0);
    assert.match(inspected.stdout, /"trust": "untrusted"/);
    assert.match(inspected.stdout, /"labeledBy": "dso"/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("provenance inspect reports unclassified for unknown content, and register refuses a broken chain", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-cli-"));
  try {
    const registryPath = join(dir, "provenance.jsonl");
    const unknown = await withTempScan(dir, ["provenance", "inspect", registryPath, join(dir, "never-registered.txt")]);
    assert.equal(unknown.code, 2, "unreadable content is a usage error, not a classification");
    await writeFile(join(dir, "never-registered.txt"), "some content");
    const missing = await withTempScan(dir, ["provenance", "inspect", registryPath, join(dir, "never-registered.txt")]);
    assert.equal(missing.code, 1);

    const contentPath = join(dir, "never-registered.txt");
    const poisoned = await withTempScan(dir, ["provenance", "register", registryPath, contentPath,
      "--origin", "external", "--trust", "untrusted", "--source", "web", "--labeled-by", "dso"]);
    assert.equal(poisoned.code, 0);
    const intact = await readFile(registryPath, "utf8");
    await writeFile(registryPath, intact.replace(/"trust":"untrusted"/, '"trust":"trusted"'), "utf8");
    const refused = await withTempScan(dir, ["provenance", "register", registryPath, contentPath,
      "--origin", "external", "--trust", "trusted", "--source", "web", "--labeled-by", "dso"]);
    assert.equal(refused.code, 1, "a tampered registry must never be appended to");
    assert.match(refused.stdout, /refusing to append/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a2a validate accepts a conforming card file and pinpoints defects otherwise", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-a2a-"));
  try {
    const cardPath = join(dir, "card.json");
    await writeFile(cardPath, JSON.stringify({
      name: "Ops Agent",
      description: "Runs runbook procedures.",
      version: "1.0.0",
      protocolVersion: "1.0",
      supportedInterfaces: [{ url: "https://agents.example.internal/a2a", protocolBinding: "JSONRPC", protocolVersion: "1.0" }],
      capabilities: { streaming: true, pushNotifications: false, stateTransitionHistory: true },
      skills: [{ id: "runbook", name: "Runbook", description: "Executes a runbook.", tags: ["jira"] }],
      signatures: [{ protected: "b64header", signature: "b64sig" }],
    }, null, 2));
    const clean = await withTempScan(dir, ["a2a", "validate", cardPath]);
    assert.equal(clean.code, 0);
    assert.match(clean.stdout, /Ops Agent v1\.0\.0 \(protocol 1\.0, v1\)/);

    const unsigned = JSON.parse(await readFile(cardPath, "utf8"));
    delete unsigned.signatures;
    await writeFile(cardPath, JSON.stringify(unsigned, null, 2));
    const flagged = await withTempScan(dir, ["a2a", "validate", cardPath]);
    assert.equal(flagged.code, 1, "an unsigned card validates only with a finding: its authenticity rests on the retrieval channel");
    assert.match(flagged.stdout, /FINDING \/a2a-card\/signatures/);

    await writeFile(cardPath, JSON.stringify({ name: "Ops Agent" }));
    const broken = await withTempScan(dir, ["a2a", "validate", cardPath]);
    assert.equal(broken.code, 1);
    assert.match(broken.stdout, /\/a2a-card\/description/);

    const unreadable = await withTempScan(dir, ["a2a", "validate", join(dir, "absent.json")]);
    assert.equal(unreadable.code, 2);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a2a delegate, inspect, and revoke round-trip through a verified registry", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-a2a-"));
  try {
    const registryPath = join(dir, "delegations.jsonl");
    const granted = await withTempScan(dir, ["a2a", "delegate", registryPath,
      "--from", "amara", "--to", "runbook-agent", "--tools", "search_*, get_*", "--granted-by", "secops"]);
    assert.equal(granted.code, 0);
    const grantId = /grant (delegation:[0-9a-f]{64})/.exec(granted.stdout)?.[1];
    assert.ok(grantId, "the grant id is reported so it can be revoked by name");
    assert.match(granted.stdout, /granted authority of amara over tools search_\*, get_\* to runbook-agent/);

    const chain = await withTempScan(dir, ["ledger", registryPath]);
    assert.equal(chain.code, 0, "the delegation registry is a verifiable rulehouse chain");

    const inspected = await withTempScan(dir, ["a2a", "inspect", registryPath]);
    assert.equal(inspected.code, 0);
    assert.match(inspected.stdout, new RegExp(grantId!.slice(0, 24)));
    assert.match(inspected.stdout, /amara -> runbook-agent scope: search_\*, get_\*/);
    assert.match(inspected.stdout, /active/);

    const selfRevoke = await withTempScan(dir, ["a2a", "revoke", registryPath, grantId!, "--revoked-by", "secops"]);
    assert.equal(selfRevoke.code, 0);
    const after = await withTempScan(dir, ["a2a", "inspect", registryPath]);
    assert.match(after.stdout, /REVOKED by secops/);

    const unknown = await withTempScan(dir, ["a2a", "revoke", registryPath, `delegation:${"0".repeat(64)}`, "--revoked-by", "secops"]);
    assert.equal(unknown.code, 1, "only an actual issuance can be revoked");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a2a delegate refuses to append to a tampered registry", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-a2a-"));
  try {
    const registryPath = join(dir, "delegations.jsonl");
    await withTempScan(dir, ["a2a", "delegate", registryPath,
      "--from", "amara", "--to", "runbook-agent", "--tools", "search_*", "--granted-by", "secops"]);
    const intact = await readFile(registryPath, "utf8");
    await writeFile(registryPath, intact.replace('"delegatee":"runbook-agent"', '"delegatee":"attacker-agent"'), "utf8");
    const refused = await withTempScan(dir, ["a2a", "delegate", registryPath,
      "--from", "amara", "--to", "runbook-agent", "--tools", "search_*", "--granted-by", "secops"]);
    assert.equal(refused.code, 1);
    assert.match(refused.stdout, /refusing to append/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a2a simulate evaluates a delegated call against real gateway policies", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-a2a-"));
  try {
    const configPath = join(dir, "gateway.jsonc");
    await writeFile(configPath, JSON.stringify({
      upstream: { url: "https://mcp.atlassian.com/v2/mcp", credentialEnv: "ATLASSIAN_SERVICE_KEY", credentialScheme: "basic" },
      identities: [
        { name: "amara", kind: "user", keyHash: "sha256:4668394217a24a1c5914795245de61547d5ff1d331bb487901815b74dd471533" },
        { name: "runbook-agent", kind: "agent", keyHash: "sha256:bbcb7ee72e6737204641e124c11267293a04ab25e055d73b84c66126929a747d" },
      ],
      policies: {
        defaultEffect: "deny",
        rules: [{ id: "RH-GW-READ", identities: null, tools: ["get_*", "search_*"], effect: "allow" }],
      },
    }, null, 2));
    const registryPath = join(dir, "delegations.jsonl");
    const granted = await withTempScan(dir, ["a2a", "delegate", registryPath,
      "--from", "amara", "--to", "runbook-agent", "--tools", "search_*", "--granted-by", "secops"]);
    const grantId = /grant (delegation:[0-9a-f]{64})/.exec(granted.stdout)?.[1];
    assert.ok(grantId);

    const allowed = await withTempScan(dir, ["a2a", "simulate", registryPath, "--config", configPath,
      "--identity", "runbook-agent", "--tool", "search_pages", "--via", grantId!]);
    assert.equal(allowed.code, 0);
    const rendered = JSON.parse(allowed.stdout);
    assert.equal(rendered.allowed, true);
    assert.deepEqual(rendered.ceilings.map((c: { identity: string }) => c.identity), ["runbook-agent", "amara"]);

    const uncompensated = await withTempScan(dir, ["a2a", "simulate", registryPath, "--config", configPath,
      "--identity", "attacker-agent", "--tool", "search_pages", "--via", grantId!]);
    assert.equal(uncompensated.code, 1, "a grant cannot be presented by an identity it does not name");

    const bare = await withTempScan(dir, ["a2a", "simulate", registryPath, "--config", configPath,
      "--identity", "runbook-agent", "--tool", "search_pages", "--now", "2026-08-01T00:00:00.000Z"]);
    assert.equal(bare.code, 1, "without a presented grant there is nothing to govern");
    assert.match(bare.stdout, /no delegation presented/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
