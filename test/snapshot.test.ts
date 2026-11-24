import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fingerprintOf, readSnapshotFile, snapshotOf, snapshotToDocument, writeSnapshotFile, type ScanOutput } from "../src/snapshot.js";
import type { InventoryEntry } from "../src/model.js";

function fakeEntry(serverName: string): InventoryEntry {
  return {
    client: "cursor",
    serverName,
    transport: "remote",
    url: "https://mcp.atlassian.com/v2/mcp",
    serverKey: "atlassian:https://mcp.atlassian.com",
    endpointClass: "atlassian-v2",
    auth: { kind: "oauth" },
    toolsOverride: null,
    source: { file: "cursor/.cursor/mcp.json", pointer: `/mcpServers/${serverName}`, format: "cursor" },
  };
}

const scan: ScanOutput = {
  root: "/somewhere",
  inputs: [{ path: "cursor/.cursor/mcp.json", sha256: "a".repeat(64), bytes: 12 }],
  inventory: [fakeEntry("atlassian")],
  diagnostics: [],
};

test("capturedAt and root are excluded from the fingerprint", () => {
  const first = snapshotOf(scan, "2026-01-01T00:00:00Z");
  const second = snapshotOf(scan, "2026-06-01T00:00:00Z");
  assert.notEqual(first.capturedAt, second.capturedAt);
  assert.equal(first.fingerprint, second.fingerprint);
  const moved = snapshotOf({ ...scan, root: "/elsewhere" }, "2026-01-01T00:00:00Z");
  assert.equal(moved.fingerprint, first.fingerprint);
});

test("content changes move the fingerprint, including diagnostics", () => {
  const changed = snapshotOf({ ...scan, inventory: [fakeEntry("atlassian"), fakeEntry("extra")] }, "t");
  assert.notEqual(changed.fingerprint, snapshotOf(scan, "t").fingerprint);
  const diagnosed = snapshotOf({ ...scan, diagnostics: [{ source: "f", subject: "$", message: "unreadable" }] }, "t");
  assert.notEqual(diagnosed.fingerprint, snapshotOf(scan, "t").fingerprint);
});

test("input hash changes move the fingerprint", () => {
  const changed = snapshotOf({ ...scan, inputs: [{ path: "cursor/.cursor/mcp.json", sha256: "b".repeat(64), bytes: 13 }] }, "t");
  assert.notEqual(changed.fingerprint, snapshotOf(scan, "t").fingerprint);
});

test("snapshots round-trip through disk and recompute to the same fingerprint", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-test-"));
  try {
    const path = join(dir, "snapshot.json");
    const snapshot = snapshotOf(scan, "2026-01-01T00:00:00Z");
    await writeSnapshotFile(snapshot, path);
    const loaded = await readSnapshotFile(path);
    assert.ok(loaded.ok);
    if (loaded.ok) {
      assert.equal(loaded.snapshot.fingerprint, snapshot.fingerprint);
      assert.deepEqual(loaded.snapshot.inventory, snapshot.inventory);
      assert.deepEqual(loaded.snapshot.inputs, snapshot.inputs);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("tampering with a snapshot is detectable via recomputation", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rulehouse-test-"));
  try {
    const path = join(dir, "snapshot.json");
    await writeSnapshotFile(snapshotOf(scan, "t"), path);
    const { readFile, writeFile } = await import("node:fs/promises");
    const original = JSON.parse(await readFile(path, "utf8"));
    original.inventory[0].serverName = "atlassian-evil";
    await writeFile(path, JSON.stringify(original), "utf8");
    const loaded = await readSnapshotFile(path);
    assert.ok(loaded.ok);
    if (loaded.ok) {
      const { fingerprintOf } = await import("../src/snapshot.js");
      assert.notEqual(fingerprintOf(loaded.snapshot.inputs, loaded.snapshot.inventory, loaded.snapshot.diagnostics), loaded.snapshot.fingerprint);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("malformed snapshot documents fail with a precise error", async () => {
  const missing = await readSnapshotFile("/nonexistent/snapshot.json");
  assert.ok(!missing.ok);
  assert.match(missing.ok ? "" : missing.error, /cannot read/);
  const { snapshotFromDocument } = await import("../src/snapshot.js");
  const wrongFormat = snapshotFromDocument({ format: "other" });
  assert.ok(!wrongFormat.ok);
  const wrongVersion = snapshotFromDocument({ format: "rulehouse.snapshot", version: 9 });
  assert.ok(!wrongVersion.ok);
  assert.match(wrongVersion.ok ? "" : wrongVersion.error, /version/);
});

test("documents survive canonical serialization unchanged", () => {
  const snapshot = snapshotOf(scan, "t");
  const document = snapshotToDocument(snapshot);
  assert.deepEqual(JSON.parse(JSON.stringify(document)), document);
});
