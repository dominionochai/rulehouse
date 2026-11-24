import test from "node:test";
import assert from "node:assert/strict";
import { diffSnapshots, type DiffableSnapshot } from "../src/diff.js";
import type { InventoryEntry } from "../src/model.js";
import { fingerprintInlineSecret } from "../src/lib/secrets.js";

function entry(client: InventoryEntry["client"], serverName: string, overrides: Partial<InventoryEntry> = {}): InventoryEntry {
  return {
    client,
    serverName,
    transport: "remote",
    url: "https://mcp.atlassian.com/v2/mcp",
    serverKey: "atlassian:https://mcp.atlassian.com",
    endpointClass: "atlassian-v2",
    auth: { kind: "oauth" },
    toolsOverride: null,
    source: { file: `${client}/config.json`, pointer: `/mcpServers/${serverName}`, format: client },
    ...overrides,
  };
}

function snapshot(inventory: readonly InventoryEntry[], inputs: readonly { path: string; sha256: string }[] = []): DiffableSnapshot {
  return { capturedAt: "t", fingerprint: "sha256:x", inputs, inventory };
}

test("identical snapshots produce a zero diff and zero exit condition", () => {
  const state = snapshot([entry("cursor", "atlassian")]);
  const change = diffSnapshots(state, state);
  assert.equal(change.changeCount, 0);
  assert.equal(change.summary, "no changes detected");
});

test("added and removed registrations are reported per server", () => {
  const before = snapshot([entry("cursor", "atlassian")]);
  const after = snapshot([entry("cursor", "atlassian"), entry("claude-desktop", "atlassian"), entry("cursor", "extra", { serverKey: "remote:https://x/mcp", url: "https://x.example.com/mcp", endpointClass: "https-remote" })]);
  const change = diffSnapshots(before, after);
  const atlassian = change.servers.find((server) => server.serverKey === "atlassian:https://mcp.atlassian.com");
  assert.ok(atlassian !== undefined);
  assert.equal(atlassian.added.length, 1);
  assert.match(atlassian.added[0]!, /claude-desktop:atlassian/);
  const extra = change.servers.find((server) => server.serverKey === "remote:https://x/mcp");
  assert.ok(extra !== undefined && extra.added.length === 1);
});

test("auth, credential, endpoint, url, and tools changes are all detected", () => {
  const before = snapshot([entry("cursor", "atlassian"), entry("cursor", "runbook")]);
  const after = snapshot([
    entry("cursor", "atlassian", { auth: { kind: "api-token", scheme: "basic", username: "u@x", credential: fingerprintInlineSecret("a"), problem: null } }),
    entry("cursor", "runbook", { endpointClass: "atlassian-v1", url: "https://mcp.atlassian.com/v1/mcp", toolsOverride: ["all"] }),
  ]);
  const change = diffSnapshots(before, after);
  assert.equal(change.servers.length, 1);
  const changed = change.servers[0]!.changed;
  const atlassian = changed.find((c) => c.location.includes("atlassian"));
  assert.ok(atlassian !== undefined);
  assert.ok(atlassian.fields.some((f) => f.field === "auth" && f.from === "oauth"));
  const runbook = changed.find((c) => c.location.includes("runbook"));
  assert.ok(runbook !== undefined);
  assert.deepEqual(runbook.fields.map((f) => f.field).sort(), ["endpoint", "tools", "url"]);
});

test("username changes are part of the auth story, not dropped", () => {
  const before = snapshot([entry("cursor", "atlassian", { auth: { kind: "api-token", scheme: "basic", username: "old@x", credential: fingerprintInlineSecret("a"), problem: null } })]);
  const after = snapshot([entry("cursor", "atlassian", { auth: { kind: "api-token", scheme: "basic", username: "new@x", credential: fingerprintInlineSecret("a"), problem: null } })]);
  const change = diffSnapshots(before, after);
  const fields = change.servers.flatMap((server) => server.changed.flatMap((c) => c.fields));
  assert.ok(fields.some((f) => f.field === "username" && f.from === "old@x" && f.to === "new@x"));
});

test("modified input files are reported with before and after hashes", () => {
  const before = snapshot([], [{ path: "a.json", sha256: "1" }, { path: "b.json", sha256: "2" }, { path: "c.json", sha256: "3" }]);
  const after = snapshot([], [{ path: "a.json", sha256: "1" }, { path: "b.json", sha256: "9" }]);
  const change = diffSnapshots(before, after);
  assert.deepEqual(change.inputs.map((i) => [i.path, i.kind]), [["b.json", "modified"], ["c.json", "removed"]]);
  assert.equal(change.changeCount, 2);
});

test("the summary names added, removed, changed counts", () => {
  const before = snapshot([entry("cursor", "gone", { serverKey: "remote:https://g/mcp", url: "https://g.example.com/mcp", endpointClass: "https-remote" }), entry("cursor", "kept")]);
  const after = snapshot([entry("cursor", "kept", { toolsOverride: ["all"] }), entry("cursor", "new", { serverKey: "remote:https://n/mcp", url: "https://n.example.com/mcp", endpointClass: "https-remote" })]);
  const change = diffSnapshots(before, after);
  assert.equal(change.changeCount, 3);
  assert.match(change.summary, /1 registration\(s\) added/);
  assert.match(change.summary, /1 registration\(s\) removed/);
  assert.match(change.summary, /1 registration\(s\) changed/);
});
