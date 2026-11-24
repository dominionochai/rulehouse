import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { GENESIS_PREV, LedgerWriter, ledgerEntryHash, readLedger, verifyLedger } from "../src/gateway/ledger.js";
import type { LedgerRecord } from "../src/gateway/ledger.js";

function record(overrides: Partial<LedgerRecord> = {}): LedgerRecord {
  return {
    decisionId: "sha256:deadbeef",
    identity: "amara",
    method: "tools/call",
    tool: "get_issue",
    decision: { kind: "allowed", ruleId: "RH-GW-READ", reason: "read allowed" },
    enforcement: "forwarded-to-upstream",
    upstreamStatus: 200,
    ...overrides,
  };
}

test("an empty or absent ledger verifies trivially", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rh-ledger-"));
  const verification = await verifyLedger(join(dir, "missing.jsonl"));
  assert.equal(verification.ok, true);
  assert.equal(verification.entries, 0);
});

test("entries chain from genesis and the ledger verifies", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rh-ledger-"));
  const path = join(dir, "ledger.jsonl");
  const writer = await LedgerWriter.open(path);
  const first = await writer.append(record(), "2026-01-01T00:00:00.000Z");
  const second = await writer.append(record({ tool: "search_pages" }), "2026-01-01T00:00:01.000Z");

  assert.equal(first.prev, GENESIS_PREV);
  assert.equal(first.seq, 0);
  assert.equal(second.prev, first.hash);
  assert.equal(second.seq, 1);
  assert.equal(ledgerEntryHash(first, first.record), first.hash);

  const verification = await verifyLedger(path);
  assert.equal(verification.ok, true);
  assert.equal(verification.entries, 2);
});

test("reopening the writer continues the chain instead of forking it", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rh-ledger-"));
  const path = join(dir, "ledger.jsonl");
  const first = await LedgerWriter.open(path);
  await first.append(record(), "2026-01-01T00:00:00.000Z");

  const second = await LedgerWriter.open(path);
  const next = await second.append(record(), "2026-01-01T00:00:02.000Z");
  assert.equal(next.seq, 1);

  const verification = await verifyLedger(path);
  assert.equal(verification.ok, true);
});

async function tamperedLedger(mutate: (lines: string[]) => string[]): Promise<{ breakAt: number | null; problem: string | null }> {
  const dir = await mkdtemp(join(tmpdir(), "rh-ledger-"));
  const path = join(dir, "ledger.jsonl");
  const writer = await LedgerWriter.open(path);
  await writer.append(record(), "2026-01-01T00:00:00.000Z");
  await writer.append(record({ tool: "delete_issue" }), "2026-01-01T00:00:01.000Z");
  await writer.append(record(), "2026-01-01T00:00:02.000Z");
  const lines = (await readFile(path, "utf8")).split("\n").filter((line) => line.length > 0);
  await writeFile(path, mutate(lines).join("\n") + "\n", "utf8");
  const verification = await verifyLedger(path);
  return { breakAt: verification.breakAt, problem: verification.problem };
}

test("editing a recorded decision is audible through the chain", async () => {
  const changed = await tamperedLedger((lines) => lines.map((line, index) =>
    index === 1 ? line.replace("delete_issue", "get_issue") : line));
  assert.equal(changed.breakAt, 1);
  assert.ok(changed.problem?.includes("hash mismatch"));
});

test("deleting an entry breaks the linkage, not only one hash", async () => {
  const changed = await tamperedLedger((lines) => [lines[0]!, lines[2]!]);
  assert.equal(changed.breakAt, 1);
});

test("a truncated or corrupt append is reported as a structural problem", async () => {
  const changed = await tamperedLedger((lines) => [...lines, "{\"seq\":3,\"at\":\"non"]);
  assert.equal(changed.breakAt, 3);
  assert.ok(changed.problem?.includes("not valid JSON"));
});

test("readLedger returns parsed entries with their exact fields", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rh-ledger-"));
  const path = join(dir, "ledger.jsonl");
  const writer = await LedgerWriter.open(path);
  await writer.append(record({ identity: null, method: null, tool: null }), "2026-01-01T00:00:00.000Z");
  const read = await readLedger(path);
  assert.equal(read.problem, null);
  assert.equal(read.entries.length, 1);
  assert.equal(read.entries[0]!.record.identity, null);
  assert.equal(read.entries[0]!.record.method, null);
});
