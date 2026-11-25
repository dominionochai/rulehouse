import test from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { scanRoot } from "../src/discover.js";
import { evaluatePolicy } from "../src/policy.js";

const FLEET = join(fileURLToPath(new URL(".", import.meta.url)), "..", "..", "examples", "fleet-extended");
const NO_ENV = () => undefined;

test("every Phase-5 client vocabulary is discovered and inventoried", async () => {
  const scan = await scanRoot(FLEET, NO_ENV);
  assert.deepEqual(scan.inputs.map((input) => input.path).sort(), [
    "codex/.codex/config.toml",
    "devin/.config/devin/mcp_config.json",
    "gemini/.gemini/settings.json",
    "windsurf/.codeium/windsurf/mcp_config.json",
    "zed/.zed/settings.json",
  ]);
  assert.equal(scan.diagnostics.length, 1);
  assert.match(scan.diagnostics[0]!.message, /"httpUrl" and "url"/);
  assert.deepEqual([...new Set(scan.inventory.map((entry) => entry.client))].sort(), [
    "codex",
    "devin",
    "gemini-cli",
    "windsurf",
    "zed",
  ]);
  assert.equal(scan.inventory.length, 9);
});

test("Windsurf's serverUrl and disabledTools are both on the record", async () => {
  const scan = await scanRoot(FLEET, NO_ENV);
  const atlassian = scan.inventory.find((entry) => entry.client === "windsurf" && entry.serverName === "atlassian")!;
  assert.equal(atlassian.transport, "remote");
  assert.equal(atlassian.url, "https://mcp.atlassian.com/v2/mcp");
  assert.deepEqual(atlassian.disabledTools, ["delete_issue", "delete_page"]);
  const loader = scan.inventory.find((entry) => entry.client === "windsurf" && entry.serverName === "wiki-loader")!;
  assert.equal(loader.transport, "local");
  assert.equal(loader.disabledTools, null);
  assert.ok(loader.auth.kind === "credential-header" && loader.auth.header === "API_KEY");
  assert.ok(loader.auth.kind === "credential-header" && loader.auth.credential?.origin === "unresolved");
});

test("Devin is attributed from its install path, with its URL tool override intact", async () => {
  const scan = await scanRoot(FLEET, NO_ENV);
  const devin = scan.inventory.find((entry) => entry.client === "devin")!;
  assert.equal(devin.serverName, "atlassian");
  assert.deepEqual(devin.toolsOverride, ["read_jira", "search_jira"]);
});

test("Zed's context_servers vocabulary parses local and remote registrations", async () => {
  const scan = await scanRoot(FLEET, NO_ENV);
  const zed = scan.inventory.filter((entry) => entry.client === "zed");
  assert.deepEqual(zed.map((entry) => entry.serverName).sort(), ["atlassian", "runbook-loader"]);
  const atlassian = zed.find((entry) => entry.serverName === "atlassian")!;
  assert.equal(atlassian.transport, "remote");
  assert.ok(atlassian.auth.kind === "api-token" && atlassian.auth.credential?.origin === "unresolved");
});

test("Gemini's httpUrl takes precedence over url, and the ambiguity is stated", async () => {
  const scan = await scanRoot(FLEET, NO_ENV);
  const diagnostic = scan.diagnostics.find((d) => d.message.includes("httpUrl") && d.message.includes('"url"'));
  assert.ok(diagnostic !== undefined, "expected a precedence diagnostic for the doubled URL fields");
  const atlassian = scan.inventory.find((entry) => entry.client === "gemini-cli" && entry.serverName === "atlassian")!;
  assert.equal(atlassian.url, "https://mcp.atlassian.com/v2/mcp");
  const legacy = scan.inventory.find((entry) => entry.client === "gemini-cli" && entry.serverName === "legacy-atlassian")!;
  assert.equal(legacy.endpointClass, "atlassian-sse-legacy");
});

test("Codex config.toml flows through the TOML subset into the same inventory shape", async () => {
  const scan = await scanRoot(FLEET, NO_ENV);
  const codex = scan.inventory.filter((entry) => entry.client === "codex");
  assert.deepEqual(codex.map((entry) => entry.serverName).sort(), ["atlassian", "retiring-connector"]);
  assert.equal(codex.find((entry) => entry.serverName === "atlassian")!.endpointClass, "atlassian-v2");
  assert.equal(codex.find((entry) => entry.serverName === "retiring-connector")!.endpointClass, "atlassian-sse-legacy");
});

test("all seven Atlassian registrations share one canonical server key and produce parity findings", async () => {
  const scan = await scanRoot(FLEET, NO_ENV);
  const atlassian = scan.inventory.filter((entry) => entry.url?.includes("mcp.atlassian.com"));
  assert.equal(atlassian.length, 7);
  assert.equal(new Set(atlassian.map((entry) => entry.serverKey)).size, 1);

  const evaluation = evaluatePolicy(scan.inventory, null);
  const findings = evaluation.verdicts.filter((v) => v.status === "finding");
  const authentication = findings.find((v) => v.ruleId === "RH-PARITY" && v.message.includes("authentication differs"));
  assert.ok(authentication !== undefined, "expected an authentication-path parity finding");
  assert.ok(findings.some((v) => v.ruleId === "RH-PARITY" && v.message.includes("tool exposure")));
  assert.ok(findings.some((v) => v.ruleId === "RH-ENDPOINT-SSE-LEGACY"));
  assert.ok(findings.some((v) => v.ruleId === "RH-CRED-UNRESOLVED" && v.message.includes("ZED_ATLASSIAN_KEY")));
});

test("no synthetic credential material escapes into any output", async () => {
  const scan = await scanRoot(FLEET, NO_ENV);
  const evaluation = evaluatePolicy(scan.inventory, null);
  const serialized = JSON.stringify(scan) + JSON.stringify(evaluation);
  for (const material of ["RHO-SYNTHETIC-CODEX-TOKEN", "RHO-SYNTHETIC-GEMINI-TOKEN", "c3ZjQGNvcnAuZXhhbXBsZTp"]) {
    assert.ok(!serialized.includes(material), `raw material "${material}" leaked into scan output`);
  }
});
