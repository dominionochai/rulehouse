import test from "node:test";
import assert from "node:assert/strict";
import { parseDocument, formatForPath, resolveFromProcessEnv, type ResolveEnv } from "../src/parse.js";
import { parseLooseJson } from "../src/lib/json.js";

const noEnv = () => undefined;

function parse(text: string, file = "mcp.json", resolveEnv: ResolveEnv = noEnv) {
  const loose = parseLooseJson(text, file);
  assert.deepEqual(loose.diagnostics, []);
  return parseDocument(loose.value, file, resolveEnv);
}

test("claude desktop vocabulary parses a remote oauth entry", () => {
  const result = parse('{"mcpServers": {"atlassian": {"url": "https://mcp.atlassian.com/v2/mcp"}}}', "/conf/claude_desktop_config.json");
  assert.equal(result.entries.length, 1);
  const entry = result.entries[0]!;
  assert.equal(entry.client, "claude-desktop");
  assert.equal(entry.endpointClass, "atlassian-v2");
  assert.deepEqual(entry.auth, { kind: "oauth" });
  assert.equal(entry.toolsOverride, null);
  assert.deepEqual(entry.source.pointer, "/mcpServers/atlassian");
});

test("vscode vocabulary parses http, sse, and stdio transports", () => {
  const result = parse(
    '{"servers": {"a": {"type": "http", "url": "https://mcp.atlassian.com/v2/mcp"}, "b": {"type": "stdio", "command": "npx", "args": ["-y", "pkg"]}}}',
    "/proj/.vscode/mcp.json",
  );
  assert.deepEqual(result.entries.map((entry) => [entry.serverName, entry.transport, entry.endpointClass]), [
    ["a", "remote", "atlassian-v2"],
    ["b", "local", "local"],
  ]);
  assert.equal(result.entries[0]!.client, "vscode");
  assert.equal(result.entries[1]!.serverKey, "local:npx -y pkg");
});

test("cursor files get cursor provenance", () => {
  const result = parse('{"mcpServers": {"atlassian": {"url": "https://mcp.atlassian.com/v2/mcp"}}}', "/home/me/.cursor/mcp.json");
  assert.equal(result.entries[0]!.client, "cursor");
});

test("tools=all is captured from the URL query", () => {
  const result = parse('{"mcpServers": {"a": {"url": "https://mcp.atlassian.com/v2/mcp?tools=all"}}}');
  assert.deepEqual(result.entries[0]!.toolsOverride, ["all"]);
  const repeated = parse('{"mcpServers": {"a": {"url": "https://x.example.com/mcp?tools=read_jira&tools=search_jira"}}}');
  assert.deepEqual(repeated.entries[0]!.toolsOverride, ["read_jira", "search_jira"]);
});

test("basic auth inline header yields fingerprinted api-token with attribution username", () => {
  const encoded = Buffer.from("svc@corp.example:TOKEN-MATERIAL", "utf8").toString("base64");
  const result = parse(`{"mcpServers": {"a": {"url": "https://mcp.atlassian.com/v2/mcp", "headers": {"Authorization": "Basic ${encoded}"}}}}`);
  const auth = result.entries[0]!.auth;
  assert.equal(auth.kind, "api-token");
  assert.equal(auth.scheme, "basic");
  assert.ok(auth.kind === "api-token" && auth.username === "svc@corp.example");
  assert.ok(auth.kind === "api-token" && auth.credential !== null && auth.credential.origin === "inline");
  assert.ok(!JSON.stringify(result).includes("TOKEN-MATERIAL"));
});

test("whole-value env authorization becomes an env-origin credential", () => {
  const result = parse(
    '{"mcpServers": {"a": {"url": "https://mcp.atlassian.com/v2/mcp", "headers": {"Authorization": "Bearer ${SVC_KEY}"}}}}',
    "mcp.json",
    (name) => (name === "SVC_KEY" ? "env-material" : undefined),
  );
  const auth = result.entries[0]!.auth;
  assert.ok(auth.kind === "api-token" && auth.credential?.origin === "environment" && auth.credential.envVar === "SVC_KEY");
  assert.equal(auth.problem, null);
  assert.ok(!JSON.stringify(result).includes("env-material"));
});

test("unresolved env authorization is surfaced honestly", () => {
  const result = parse('{"mcpServers": {"a": {"url": "https://mcp.atlassian.com/v2/mcp", "headers": {"Authorization": "Bearer ${SVC_KEY}"}}}}');
  const auth = result.entries[0]!.auth;
  assert.ok(auth.kind === "api-token" && auth.credential?.origin === "unresolved");
  assert.match(auth.problem ?? "", /SVC_KEY/);
});

test("credential-bearing non-Authorization headers are fingerprinted under the header name", () => {
  const result = parse('{"mcpServers": {"a": {"url": "https://mcp.atlassian.com/v2/mcp", "headers": {"X-API-Key": "inline-key-material"}}}}');
  const auth = result.entries[0]!.auth;
  assert.ok(auth.kind === "credential-header" && auth.header === "X-API-Key");
  assert.ok(!JSON.stringify(result).includes("inline-key-material"));
});

test("innocuous headers are not treated as credentials", () => {
  const result = parse('{"mcpServers": {"a": {"url": "https://mcp.atlassian.com/v2/mcp", "headers": {"X-Team": "platform"}}}}');
  assert.deepEqual(result.entries[0]!.auth, { kind: "oauth" });
});

test("stdio env blocks are credential carriers exactly like headers", () => {
  const result = parse('{"mcpServers": {"a": {"command": "loader", "env": {"API_KEY": "inline-material"}}}}');
  const auth = result.entries[0]!.auth;
  assert.ok(auth.kind === "credential-header" && auth.header === "API_KEY");
  assert.ok(!JSON.stringify(result).includes("inline-material"));
});

test("malformed authorization headers become unknown auth, not a crash", () => {
  const result = parse('{"mcpServers": {"a": {"url": "https://mcp.atlassian.com/v2/mcp", "headers": {"Authorization": "garbage"}}}}');
  const auth = result.entries[0]!.auth;
  assert.ok(auth.kind === "unknown" && /malformed Authorization/.test(auth.reason));
});

test("entries without url or command are diagnosed and skipped", () => {
  const result = parse('{"mcpServers": {"a": {"attempt": true}, "b": {"command": "loader"}}}');
  assert.deepEqual(result.entries.map((entry) => entry.serverName), ["b"]);
  assert.equal(result.diagnostics.length, 1);
  assert.match(result.diagnostics[0]!.message, /neither a remote url nor a local command/);
});

test("documents without a recognized container produce a diagnostic", () => {
  const result = parse('{"settings": {}}');
  assert.deepEqual(result.entries, []);
  assert.match(result.diagnostics[0]!.message, /container/);
});

test("non-object container and non-object entries are diagnosed, not thrown on", () => {
  const flat = parseDocument(null, "x.json");
  assert.equal(flat.entries.length, 0);
  const badContainer = parseLooseJson('{"mcpServers": 3}', "y.json");
  const r1 = parseDocument(badContainer.value, "y.json");
  assert.equal(r1.entries.length, 0);
  assert.match(r1.diagnostics[0]!.message, /not an object/);
});

test("formatForPath precedence resolves ambiguity deterministically", () => {
  assert.equal(formatForPath("/a/claude_desktop_config.json", false), "claude-desktop");
  assert.equal(formatForPath("/home/u/.cursor/mcp.json", false), "cursor");
  assert.equal(formatForPath("/proj/.vscode/mcp.json", true), "vscode");
  assert.equal(formatForPath("/proj/.mcp.json", false), "claude-code");
  assert.equal(formatForPath("/proj/mcp.json", false), "mcp-json");
  assert.equal(formatForPath("/proj/mcp.json", true), "vscode");
});

test("real process env resolution is wired by default", () => {
  const encoded = Buffer.from("u@corp.example:abc", "utf8").toString("base64");
  const result = parse(`{"mcpServers": {"a": {"url": "https://mcp.atlassian.com/v2/mcp", "headers": {"Authorization": "Basic ${encoded}"}}}}`, "mcp.json", resolveFromProcessEnv);
  assert.equal(result.entries[0]!.auth.kind, "api-token");
});

test("Windsurf and Devin share a filename and are told apart by install path", () => {
  assert.equal(formatForPath("/home/me/.codeium/windsurf/mcp_config.json", true), "windsurf");
  assert.equal(formatForPath("/home/me/.codeium/windsurf-next/mcp_config.json", true), "windsurf");
  assert.equal(formatForPath("/home/me/.config/devin/mcp_config.json", true), "devin");
});

test("windsurf vocabulary parses serverUrl remotes and honors the disabledTools list", () => {
  const result = parse('{"mcpServers": {"atlassian": {"serverUrl": "https://mcp.atlassian.com/v2/mcp", "disabledTools": ["delete_issue"]}}}', "/home/me/.codeium/windsurf/mcp_config.json");
  const entry = result.entries[0]!;
  assert.equal(entry.url, "https://mcp.atlassian.com/v2/mcp");
  assert.deepEqual(entry.disabledTools, ["delete_issue"]);
  assert.deepEqual(result.diagnostics, []);
});

test("malformed disabledTools is diagnosed, not silently armed", () => {
  const result = parse('{"mcpServers": {"a": {"url": "https://mcp.atlassian.com/v2/mcp", "disabledTools": "delete_*"}}}');
  const entry = result.entries[0]!;
  assert.equal(entry.disabledTools, null);
  assert.match(result.diagnostics[0]!.message, /disabledTools is not an array/);
});

test("zed context_servers entries keep their provenance distinct from every other format", () => {
  const result = parse(
    '{"context_servers": {"atlassian": {"source": "custom", "url": "https://mcp.atlassian.com/v2/mcp"}, "loader": {"source": "custom", "command": "npx"}}}',
    "/home/me/.zed/settings.json",
  );
  assert.equal(result.entries[0]!.client, "zed");
  assert.equal(result.entries[0]!.transport, "remote");
  assert.equal(result.entries[1]!.serverKey, "local:npx");
});

test("gemini cli resolves httpUrl before url and says so when both are set", () => {
  const result = parse(
    '{"mcpServers": {"atlassian": {"httpUrl": "https://mcp.atlassian.com/v2/mcp", "url": "https://mcp.atlassian.com/v1/sse"}}}',
    "/home/me/.gemini/settings.json",
  );
  const entry = result.entries[0]!;
  assert.equal(entry.client, "gemini-cli");
  assert.equal(entry.url, "https://mcp.atlassian.com/v2/mcp");
  assert.equal(entry.endpointClass, "atlassian-v2");
  assert.match(result.diagnostics[0]!.message, /"httpUrl" and "url"/);
});

test("documents without any recognized container keep a precise diagnostic", () => {
  const result = parse('{"agent": {}}');
  assert.match(result.diagnostics[0]!.message, /container/);
});
