import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  contentDigestOf,
  contentDigestOfText,
  readProvenanceRegistry,
  appendProvenanceRecord,
  type ProvenanceRecord,
} from "../src/provenance.js";

const CONTENT = "vendor advisory text used exactly once per digest";

test("content digests bind the exact mediated form", () => {
  assert.equal(contentDigestOf(CONTENT), `sha256:${createHash("sha256").update(CONTENT).digest("hex")}`);
  assert.notEqual(contentDigestOf(CONTENT), contentDigestOf(`${CONTENT}\n`), "an appended newline is different content");
});

test("structured content digests canonically: key order is not identity", () => {
  const one = contentDigestOf({ b: ["x", 2], a: { nested: true } });
  const two = contentDigestOf({ a: { nested: true }, b: ["x", 2] });
  assert.equal(one, two);
  assert.notEqual(one, contentDigestOf({ b: ["x", 2], a: { nested: false } }));
});

test("a registered file and the corresponding tool argument land on the same digest", () => {
  const registered = contentDigestOfText('{"operation":"delete","target":"SEC-1"}');
  const mediated = contentDigestOf({ operation: "delete", target: "SEC-1" });
  assert.equal(registered, mediated);
  const plain = contentDigestOfText("plain-text-instruction");
  assert.equal(plain, contentDigestOf("plain-text-instruction"));
});

function record(overrides: Partial<ProvenanceRecord> = {}): ProvenanceRecord {
  return {
    contentSha256: `sha256:${createHash("sha256").update(CONTENT).digest("hex")}`,
    origin: "external",
    trust: "untrusted",
    source: "webform:vendor-portal",
    labeledBy: "dso",
    labeledAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

async function withRegistry(): Promise<{ dir: string; path: string }> {
  const dir = await mkdtemp(join(tmpdir(), "rh-provenance-"));
  return { dir, path: join(dir, "provenance.jsonl") };
}

test("a registry is empty when the file is absent, not corrupt", async () => {
  const { dir } = await withRegistry();
  const registry = await readProvenanceRegistry(join(dir, "missing.jsonl"));
  assert.equal(registry.corrupt, null);
  assert.equal(registry.records.size, 0);
});

test("re-registering a digest supersedes the previous declaration and the chain keeps both", async () => {
  const { path } = await withRegistry();
  await appendProvenanceRecord(path, record({ trust: "untrusted" }), "2026-01-01T00:00:00.000Z");
  await appendProvenanceRecord(path, record({ trust: "trusted", source: "incident:SEC-1", labeledBy: "dso" }), "2026-01-01T00:00:01.000Z");

  const registry = await readProvenanceRegistry(path);
  assert.equal(registry.corrupt, null);
  assert.equal(registry.records.size, 1, "one digest, latest declaration wins");
  assert.equal(registry.records.get(record().contentSha256)?.trust, "trusted");

  const lines = (await readFile(path, "utf8")).split("\n").filter((line) => line.length > 0);
  assert.equal(lines.length, 2, "history is retained, not overwritten");
});

test("a corrupt registry is unavailable, which fails closed rather than degrading to unknown", async () => {
  const { path } = await withRegistry();
  await appendProvenanceRecord(path, record(), "2026-01-01T00:00:00.000Z");
  await writeFile(path, (await readFile(path, "utf8")).replace('"trust":"untrusted"', '"trust":"trusted"'), "utf8");

  const registry = await readProvenanceRegistry(path);
  assert.notEqual(registry.corrupt, null);
  assert.equal(registry.records.size, 0);
});
