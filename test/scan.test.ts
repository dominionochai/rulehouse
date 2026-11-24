import test from "node:test";
import assert from "node:assert/strict";
import { scanRoot } from "../src/discover.js";
import { evaluatePolicy } from "../src/policy.js";
import { findingsOf, renderMarkdownReport, scanReportOf } from "../src/report.js";
import { snapshotOf } from "../src/snapshot.js";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const FLEET = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "examples", "fleet");
const NO_ENV = () => undefined;

async function scanFleet() {
  return scanRoot(FLEET, NO_ENV);
}

test("the fleet fixture yields the full expected inventory", async () => {
  const scan = await scanFleet();
  assert.equal(scan.inputs.length, 5);
  assert.equal(scan.inventory.length, 7);
  assert.deepEqual(scan.diagnostics, []);
  const byName = scan.inventory.map((entry) => `${entry.client}:${entry.serverName}`).sort();
  assert.deepEqual(byName, [
    "claude-code:atlassian",
    "claude-desktop:atlassian",
    "claude-desktop:runbook-automation",
    "cursor:atlassian",
    "mcp-json:retiring-connector",
    "vscode:legacy-monitoring",
    "vscode:wiki-loader",
  ]);
});

test("every Atlassian registration shares one canonical server key", async () => {
  const scan = await scanFleet();
  const atlassian = scan.inventory.filter((entry) => entry.url?.includes("mcp.atlassian.com"));
  assert.equal(atlassian.length, 5);
  assert.equal(new Set(atlassian.map((entry) => entry.serverKey)).size, 1);
});

test("the policy evaluation exercises every Phase-1 wedge on the fixture", async () => {
  const scan = await scanFleet();
  const evaluation = evaluatePolicy(scan.inventory, null);
  const findings = evaluation.verdicts.filter((v) => v.status === "finding");

  const parity = findings.find((v) => v.ruleId === "RH-PARITY" && v.message.includes("authentication differs"));
  assert.ok(parity !== undefined, "expected an auth-path parity finding");
  assert.ok(parity.message.includes("OAuth 2.1"));
  assert.ok(parity.message.includes("API token (basic)"));

  assert.ok(findings.some((v) => v.ruleId === "RH-PARITY" && v.message.includes("endpoint generation")));
  assert.ok(findings.some((v) => v.ruleId === "RH-PARITY" && v.message.includes("tool exposure")));
  assert.ok(findings.some((v) => v.ruleId === "RH-TOOLS-ALL"));
  assert.ok(findings.some((v) => v.ruleId === "RH-ENDPOINT-SSE-LEGACY"));
  assert.ok(findings.some((v) => v.ruleId === "RH-ENDPOINT-INSECURE"));
  assert.ok(findings.some((v) => v.ruleId === "RH-CRED-INLINE"));
  assert.ok(findings.some((v) => v.ruleId === "RH-CRED-UNRESOLVED" && v.message.includes("ATLASSIAN_SERVICE_KEY")));
});

test("no synthetic credential material escapes into any output", async () => {
  const scan = await scanFleet();
  const evaluation = evaluatePolicy(scan.inventory, null);
  const report = scanReportOf(snapshotOf(scan, "2026-01-01T00:00:00Z"), evaluation, "2026-01-01T00:00:00Z");
  const markdown = renderMarkdownReport(report, findingsOf(report));
  const serialized = `${JSON.stringify(scan)}\n${JSON.stringify(report)}\n${markdown}\n${JSON.stringify(evaluation)}`;
  for (const secret of ["RHO-SYNTHETIC-TOKEN-0001", "RHO-SYNTHETIC-TOKEN-0002", "RHO-SYNTHETIC-INLINE-KEY-7741", "c3ZjLXJ1bmJvb2tAY29ycC5leGFtcGxlOlJITy1TWU5USEVUSUMtVE9LRU4tMDAwMQ=="]) {
    assert.ok(!serialized.includes(secret), `raw material leaked: ${secret}`);
  }
  assert.ok(serialized.includes("svc-runbook@corp.example"), "attribution username should be retained");
});

test("the report is evidence-grade: hashes, pointers, fingerprint", async () => {
  const scan = await scanFleet();
  const evaluation = evaluatePolicy(scan.inventory, null);
  const snapshot = snapshotOf(scan, "t");
  const report = scanReportOf(snapshot, evaluation, "t");
  const markdown = renderMarkdownReport(report, findingsOf(report));
  assert.ok(markdown.includes("## Evidence"));
  assert.ok(markdown.includes(snapshot.fingerprint));
  for (const input of scan.inputs) {
    assert.ok(markdown.includes(input.sha256));
    assert.ok(markdown.includes(input.path));
  }
  assert.ok(markdown.includes("/mcpServers/runbook-automation"));
  assert.ok(markdown.includes("sha256sum"));
});
