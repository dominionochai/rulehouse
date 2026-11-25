import test from "node:test";
import assert from "node:assert/strict";
import { parseToml } from "../src/lib/toml.js";

function parseOk(text: string): { readonly [key: string]: import("../src/lib/json.js").Json } {
  const result = parseToml(text, "config.toml");
  assert.deepEqual(result.diagnostics, []);
  return result.value as { readonly [key: string]: import("../src/lib/json.js").Json };
}

function diagnosticsOf(text: string): readonly string[] {
  return parseToml(text, "config.toml").diagnostics.map((d) => d.message);
}

test("an empty file, comments, and blank lines yield an empty document", () => {
  assert.deepEqual(parseOk(""), {});
  assert.deepEqual(parseOk("# only a comment\n\n  # another\n"), {});
});

test("a top-level key-value belongs to the root table", () => {
  assert.deepEqual(parseOk("model = \"o3\"\n"), { model: "o3" });
});

test("tables and nested tables route subsequent keys", () => {
  const value = parseOk(`
title = "t"
[owner]
name = "ops"
[database.server]
host = "db.internal"
port = 5432
`);
  assert.deepEqual(value, { title: "t", owner: { name: "ops" }, database: { server: { host: "db.internal", port: 5432 } } });
});

test("a super-table may be opened after it was created implicitly by a sub-table", () => {
  const value = parseOk(`
[a.b]
x = 1
[a]
y = 2
`);
  assert.deepEqual(value, { a: { b: { x: 1 }, y: 2 } });
});

test("basic strings decode escapes and leave URLs intact", () => {
  const value = parseOk('url = "https://mcp.atlassian.com/v2/mcp?s=1"\nesc = "a\\tb\\u00e9\\\\c"\n');
  assert.deepEqual(value, { url: "https://mcp.atlassian.com/v2/mcp?s=1", esc: "a\tbé\\c" });
});

test("literal strings keep backslashes byte for byte", () => {
  const value = parseOk(String.raw`regex = '[a-z]+\d'` + "\n");
  assert.deepEqual(value, { regex: "[a-z]+\\d" });
});

test("integers with underscore grouping parse; the literal digit form survives", () => {
  const value = parseOk("small = 7\nbig = 1_000_000\nnegative = -12\nsigned = +3\n");
  assert.deepEqual(value, { small: 7, big: 1000000, negative: -12, signed: 3 });
});

test("booleans parse", () => {
  assert.deepEqual(parseOk("on = true\noff = false\n"), { on: true, off: false });
});

test("arrays parse across lines with comments and trailing commas", () => {
  const value = parseOk(`
args = [
  "--verbose",   # noise
  "--port",
  "8443",
]
empty = [ ]
`);
  assert.deepEqual(value, { args: ["--verbose", "--port", "8443"], empty: [] });
});

test("nested arrays parse", () => {
  assert.deepEqual(parseOk("pairs = [[1, 2], [3]]\n"), { pairs: [[1, 2], [3]] });
});

test("quoted keys may contain dots and dashes", () => {
  const value = parseOk('[mcp_servers."a.b-c"]\ncommand = "npx"\n');
  assert.deepEqual(value, { mcp_servers: { "a.b-c": { command: "npx" } } });
});

test("dotted keys create the tables they name", () => {
  const value = parseOk('[mcp_servers.atlassian]\nurl = "https://mcp.example/v2/mcp"\n[mcp_servers.atlassian.env]\nKEY = "ref"\n');
  assert.deepEqual(value, { mcp_servers: { atlassian: { url: "https://mcp.example/v2/mcp", env: { KEY: "ref" } } } });
});

test("a duplicate table header is diagnosed and dropped", () => {
  const messages = diagnosticsOf(`
[a]
x = 1
[a]
y = 2
`);
  assert.equal(messages.length, 1);
  assert.match(messages[0]!, /duplicate table header \["a"\]/);
  assert.deepEqual(parseToml("[a]\nx = 1\n[a]\ny = 2\n", "c").value, { a: { x: 1 } });
});

test("a duplicate key keeps the first value, not the last", () => {
  const messages = diagnosticsOf("mode = \"read\"\nmode = \"write\"\n");
  assert.equal(messages.length, 1);
  assert.match(messages[0]!, /duplicate key "mode"/);
  assert.deepEqual(parseToml("mode = \"read\"\nmode = \"write\"\n", "c").value, { mode: "read" });
});

test("a table cannot redefine an existing scalar", () => {
  const messages = diagnosticsOf(`
a = 1
[a.b]
x = 2
`);
  assert.match(messages[0]!, /conflicts with an existing non-table value/);
  assert.deepEqual(parseToml("a = 1\n[a.b]\nx = 2\n", "c").value, { a: 1 });
});

test("a dotted key cannot descend through a scalar", () => {
  const messages = diagnosticsOf(`
a = 1
a.b = 2
`);
  assert.match(messages[0]!, /descends through/);
  assert.deepEqual(parseToml("a = 1\na.b = 2\n", "c").value, { a: 1 });
});

test("inline tables are diagnosed as outside the subset", () => {
  const messages = diagnosticsOf("point = { x = 1 }\n");
  assert.equal(messages.length, 1);
  assert.match(messages[0]!, /inline tables/);
});

test("array-of-tables headers are diagnosed and skipped wholesale", () => {
  const messages = diagnosticsOf(`
[[items]]
x = 1
after = true
`);
  assert.equal(messages.length, 1);
  assert.match(messages[0]!, /array-of-tables/);
  assert.deepEqual(parseToml("[[items]]\nx = 1\nafter = true\n", "c").value, {});
});

test("floats, dates, and other number shapes are diagnosed as outside the subset", () => {
  const float = diagnosticsOf("ratio = 3.14\n");
  assert.match(float[0]!, /floats/);
  const date = diagnosticsOf("stamp = 2026-01-01\n");
  assert.match(date[0]!, /dates and times/);
  const exponent = diagnosticsOf("n = 1e9\n");
  assert.match(exponent[0]!, /floats/);
  const hex = diagnosticsOf("n = 0xff\n");
  assert.equal(hex.length, 1);
  const bad = diagnosticsOf("n = 1__0\n");
  assert.match(bad[0]!, /misuses underscores/);
});

test("statements malformed mid-line resync instead of poisoning later keys", () => {
  const result = parseToml(`
good = 1
broken = { x = 1 }
also_good = 2
`, "c");
  assert.deepEqual(result.value, { good: 1, also_good: 2 });
  assert.equal(result.diagnostics.length, 1);
});

test("unterminated strings and arrays are diagnosed once, not infinitely", () => {
  const unterminated = parseToml('a = "no close\nb = 2\n', "c");
  assert.match(unterminated.diagnostics[0]!.message, /unterminated basic string/);
  assert.deepEqual(unterminated.value, { b: 2 });

  const array = parseToml("a = [1, 2\nb = 3\n", "c");
  assert.match(array.diagnostics[0]!.message, /"," or "\]"/);
  assert.deepEqual(array.value, {});
  assert.deepEqual(parseToml("b = 3\n", "c").value, { b: 3 });
});

test("junk after a value is rejected rather than parsed as a new key", () => {
  const messages = diagnosticsOf("a = 1 b = 2\n");
  assert.match(messages[0]!, /unexpected content after the statement/);
  assert.deepEqual(parseToml("a = 1 b = 2\n", "c").value, { a: 1 });
});

test("a value may carry a trailing comment", () => {
  assert.deepEqual(parseOk("a = 1 # the answer\n"), { a: 1 });
  assert.deepEqual(parseOk("[t] # header comment\nb = 'x'\n"), { t: { b: "x" } });
});

test("CRLF files parse like LF files", () => {
  assert.deepEqual(parseOk("[a]\r\nx = 1\r\ny = 'z'\r\n"), { a: { x: 1, y: "z" } });
});

test("a UTF-8 BOM is tolerated", () => {
  assert.deepEqual(parseToml("\ufeffx = 1\n", "c").value, { x: 1 });
});

test("a codex-shaped configuration parses end to end", () => {
  const value = parseOk(`
model = "gpt-5.1-codex"

[mcp_servers.atlassian]
url = "https://mcp.atlassian.com/v2/mcp"

[mcp_servers.atlassian.env]
JIRA_EMAIL = "svc@corp.example"
JIRA_TOKEN = "ref-to-secret-store"

[mcp_servers.local-helper]
command = "npx"
args = ["-y", "mcp-helper"]

[mcp_servers.local-helper.env]
HELPER_TOKEN = "env-ref"
`);
  const servers = value["mcp_servers"] as { readonly [key: string]: import("../src/lib/json.js").Json };
  assert.deepEqual(servers["atlassian"], { url: "https://mcp.atlassian.com/v2/mcp", env: { JIRA_EMAIL: "svc@corp.example", JIRA_TOKEN: "ref-to-secret-store" } });
  assert.deepEqual(servers["local-helper"], { command: "npx", args: ["-y", "mcp-helper"], env: { HELPER_TOKEN: "env-ref" } });
});
