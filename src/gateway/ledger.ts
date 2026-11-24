import { appendFile, readFile } from "node:fs/promises";
import { canonicalize, isJsonObject, sha256Hex, type Json } from "../lib/json.js";

/**
 * Why a tool call was mediated the way it was. The record explicitly
 * distinguishes the *decision* (policy, attribution, reason) from the
 * *enforcement result* (what actually happened to the request) — collapsing
 * the two is exactly how "we would have blocked it" drifts into "we blocked
 * it" in an audit trail.
 */
export interface LedgerRecord {
  readonly decisionId: string;
  readonly identity: string | null;
  readonly method: string | null;
  readonly tool: string | null;
  readonly decision: {
    readonly kind: "allowed" | "denied";
    readonly ruleId: string;
    readonly reason: string;
  };
  readonly enforcement: "blocked-at-gateway" | "forwarded-to-upstream" | "failed-forwarding";
  readonly upstreamStatus: number | null;
}

export const GENESIS_PREV = `sha256:${sha256Hex("rulehouse.ledger.genesis")}`;

interface EntryCore {
  readonly seq: number;
  readonly at: string;
  readonly prev: string;
}

function coreOf(record: LedgerRecord, core: EntryCore): Json {
  return {
    seq: core.seq,
    at: core.at,
    prev: core.prev,
    record: {
      decisionId: record.decisionId,
      identity: record.identity,
      method: record.method,
      tool: record.tool,
      decision: { kind: record.decision.kind, ruleId: record.decision.ruleId, reason: record.decision.reason },
      enforcement: record.enforcement,
      upstreamStatus: record.upstreamStatus,
    },
  };
}

export function ledgerEntryHash(core: EntryCore, record: LedgerRecord): string {
  return `sha256:${sha256Hex(canonicalize(coreOf(record, core)))}`;
}

export interface LedgerEntry {
  readonly seq: number;
  readonly at: string;
  readonly prev: string;
  readonly hash: string;
  readonly record: LedgerRecord;
}

export interface LedgerRead {
  readonly entries: readonly LedgerEntry[];
  /** Index of the first entry that fails verification, or null when intact. */
  readonly breakAt: number | null;
  readonly problem: string | null;
}

export async function readLedger(path: string): Promise<LedgerRead> {
  const text = await readFile(path, "utf8").catch(() => null);
  if (text === null) {
    return { entries: [], breakAt: null, problem: null };
  }

  const entries: LedgerEntry[] = [];
  const lines = text.split("\n").filter((line) => line.length > 0);
  for (const line of lines) {
    let document: Json;
    try {
      document = JSON.parse(line) as Json;
    } catch {
      return { entries, breakAt: entries.length, problem: `line ${entries.length + 1} is not valid JSON` };
    }
    const parsed = parseEntry(document);
    if (parsed === null) {
      return { entries, breakAt: entries.length, problem: `line ${entries.length + 1} is not a ledger entry` };
    }
    entries.push({ seq: parsed.seq, at: parsed.at, prev: parsed.prev, hash: parsed.hash, record: parsed.record });
  }
  return { entries, breakAt: null, problem: null };
}

export interface LedgerVerification {
  readonly ok: boolean;
  readonly entries: number;
  readonly breakAt: number | null;
  readonly problem: string | null;
}

/**
 * Recomputes every entry hash and the chain linkage from genesis. Any edit,
 * deletion, insertion, or reorder changes at least one hash, so tampering is
 * never silent — the same doctrine as snapshot fingerprints, applied to an
 * append-only stream.
 */
export async function verifyLedger(path: string): Promise<LedgerVerification> {
  const read = await readLedger(path);
  if (read.problem !== null) {
    return { ok: false, entries: read.entries.length, breakAt: read.breakAt, problem: read.problem };
  }
  let expectedPrev = GENESIS_PREV;
  for (const [index, entry] of read.entries.entries()) {
    if (entry.seq !== index) {
      return { ok: false, entries: read.entries.length, breakAt: index, problem: `entry ${index} has seq ${entry.seq}` };
    }
    if (entry.prev !== expectedPrev) {
      return { ok: false, entries: read.entries.length, breakAt: index, problem: `entry ${index} chains to ${entry.prev}, expected ${expectedPrev}` };
    }
    const recomputed = ledgerEntryHash(entry, entry.record);
    if (recomputed !== entry.hash) {
      return { ok: false, entries: read.entries.length, breakAt: index, problem: `entry ${index} hash mismatch: recorded ${entry.hash}, recomputed ${recomputed}` };
    }
    expectedPrev = entry.hash;
  }
  return { ok: true, entries: read.entries.length, breakAt: null, problem: null };
}

/**
 * Append-only ledger writer. The writer caches the chain head from creation
 * time, so a gateway instance pays one file read at startup and one append
 * per decision afterward. Single-process ownership is a stated limitation,
 * not an accident — it is what keeps the chain consistent without a lock.
 */
export class LedgerWriter {
  private nextSeq = 0;
  private prevHash = GENESIS_PREV;

  private constructor(readonly path: string) {}

  static async open(path: string): Promise<LedgerWriter> {
    const writer = new LedgerWriter(path);
    const read = await readLedger(path);
    const last = read.entries.at(-1);
    if (last !== undefined && read.problem === null) {
      writer.nextSeq = last.seq + 1;
      writer.prevHash = last.hash;
    }
    return writer;
  }

  async append(record: LedgerRecord, at: string): Promise<LedgerEntry> {
    const core: EntryCore = { seq: this.nextSeq, at, prev: this.prevHash };
    const hash = ledgerEntryHash(core, record);
    const entry: LedgerEntry = { ...core, hash, record };
    await appendFile(this.path, `${JSON.stringify({
      seq: entry.seq,
      at: entry.at,
      prev: entry.prev,
      hash: entry.hash,
      record: entry.record,
    })}\n`, "utf8");
    this.nextSeq = entry.seq + 1;
    this.prevHash = entry.hash;
    return entry;
  }
}

interface RawEntry {
  readonly seq: number;
  readonly at: string;
  readonly prev: string;
  readonly hash: string;
  readonly record: LedgerRecord;
}

function parseEntry(document: Json): RawEntry | null {
  if (!isJsonObject(document)) return null;
  const seq = document["seq"];
  const at = document["at"];
  const prev = document["prev"];
  const hash = document["hash"];
  const record = document["record"];
  if (typeof seq !== "number" || typeof at !== "string" || typeof prev !== "string" || typeof hash !== "string") return null;
  const parsedRecord = parseRecord(record);
  if (parsedRecord === null) return null;
  return { seq, at, prev, hash, record: parsedRecord };
}

function parseRecord(value: Json | undefined): LedgerRecord | null {
  if (!isJsonObject(value)) return null;
  const decisionId = value["decisionId"];
  if (typeof decisionId !== "string") return null;
  const method = nullableString(value["method"]);
  const tool = value["tool"];
  if (typeof tool !== "string" && tool !== null) return null;
  const identity = value["identity"];
  if (typeof identity !== "string" && identity !== null) return null;
  const decision = parseDecision(value["decision"]);
  if (decision === null) return null;
  const enforcement = value["enforcement"];
  if (enforcement !== "blocked-at-gateway" && enforcement !== "forwarded-to-upstream" && enforcement !== "failed-forwarding") return null;
  const upstreamStatus = value["upstreamStatus"];
  if (upstreamStatus !== null && (typeof upstreamStatus !== "number" || !Number.isInteger(upstreamStatus))) return null;
  return {
    decisionId,
    identity,
    method,
    tool,
    decision,
    enforcement,
    upstreamStatus,
  };
}

function parseDecision(value: Json | undefined): LedgerRecord["decision"] | null {
  if (!isJsonObject(value)) return null;
  const kind = value["kind"];
  const ruleId = value["ruleId"];
  const reason = value["reason"];
  if (kind !== "allowed" && kind !== "denied") return null;
  if (typeof ruleId !== "string" || typeof reason !== "string") return null;
  return { kind, ruleId, reason };
}

function nullableString(value: Json | undefined): string | null {
  return typeof value === "string" ? value : null;
}
