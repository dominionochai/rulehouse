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
      enforcement: "forwarded-to-upstream",
      upstreamStatus: 200,
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
