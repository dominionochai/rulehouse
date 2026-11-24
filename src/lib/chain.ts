import { appendFile, readFile } from "node:fs/promises";
import { canonicalize, isJsonObject, sha256Hex, type Json } from "./json.js";

/**
 * The append-only hash chain is Rulehouse's shared evidence primitive: every
 * entry binds its payload to the hash of the entry before it, back to a fixed
 * genesis. The decision ledger and the provenance registry are two floors of
 * the same building — each commits different records to the identical
 * linkage discipline, so one tamper-evidence argument covers every artifact
 * the control plane produces.
 */

export const GENESIS_PREV = `sha256:${sha256Hex("rulehouse.chain.genesis")}`;

export interface ChainEntry<TRecord> {
  readonly seq: number;
  readonly at: string;
  readonly prev: string;
  readonly hash: string;
  readonly record: TRecord;
}

export function chainHash(seq: number, at: string, prev: string, record: Json): string {
  return `sha256:${sha256Hex(canonicalize({ seq, at, prev, record }))}`;
}

export interface ChainRead<TRecord> {
  readonly entries: readonly ChainEntry<TRecord>[];
  /** Index of the first structurally invalid line, or null when none. */
  readonly breakAt: number | null;
  readonly problem: string | null;
}

/**
 * Reads a chain file line by line. `parseRecord` decides what payload the
 * caller understands; structural validity of the envelope is checked here.
 * A missing file reads as an empty chain — absence of evidence is not
 * breakage.
 */
export async function readChain<TRecord>(
  path: string,
  parseRecord: (value: Json | undefined) => TRecord | null,
): Promise<ChainRead<TRecord>> {
  const text = await readFile(path, "utf8").catch(() => null);
  if (text === null) {
    return { entries: [], breakAt: null, problem: null };
  }

  const entries: ChainEntry<TRecord>[] = [];
  const lines = text.split("\n").filter((line) => line.length > 0);
  for (const line of lines) {
    let document: Json;
    try {
      document = JSON.parse(line) as Json;
    } catch {
      return { entries, breakAt: entries.length, problem: `line ${entries.length + 1} is not valid JSON` };
    }
    if (!isJsonObject(document)) {
      return { entries, breakAt: entries.length, problem: `line ${entries.length + 1} is not a chain entry` };
    }
    const { seq, at, prev, hash, record } = document;
    if (typeof seq !== "number" || typeof at !== "string" || typeof prev !== "string" || typeof hash !== "string") {
      return { entries, breakAt: entries.length, problem: `line ${entries.length + 1} is not a chain entry` };
    }
    const parsedRecord = parseRecord(record);
    if (parsedRecord === null) {
      return { entries, breakAt: entries.length, problem: `line ${entries.length + 1} does not carry a parseable record` };
    }
    entries.push({ seq, at, prev, hash, record: parsedRecord });
  }
  return { entries, breakAt: null, problem: null };
}

function parseOpaqueRecord(value: Json | undefined): Json | null {
  return value !== undefined && isJsonObject(value) ? value : null;
}

export interface LinkCheck {
  readonly breakAt: number | null;
  readonly problem: string | null;
}

/**
 * Recomputes every entry hash and the linkage from genesis over an
 * in-memory chain. Any edit, deletion, insertion, or reorder changes at
 * least one hash, so tampering is never silent — the same doctrine as snapshot fingerprints, applied to
 * an append-only stream. Every consumer of a chain that is about to be
 * *trusted* must run this, not only a verify command: reading a chain back
 * is different from believing it.
 */
export function checkLinks(entries: readonly { seq: number; at: string; prev: string; hash: string; record: unknown }[]): LinkCheck {
  let expectedPrev = GENESIS_PREV;
  for (const [index, entry] of entries.entries()) {
    if (entry.seq !== index) {
      return { breakAt: index, problem: `entry ${index} has seq ${entry.seq}` };
    }
    if (entry.prev !== expectedPrev) {
      return { breakAt: index, problem: `entry ${index} chains to ${entry.prev}, expected ${expectedPrev}` };
    }
    const recomputed = chainHash(entry.seq, entry.at, entry.prev, entry.record as Json);
    if (recomputed !== entry.hash) {
      return { breakAt: index, problem: `entry ${index} hash mismatch: recorded ${entry.hash}, recomputed ${recomputed}` };
    }
    expectedPrev = entry.hash;
  }
  return { breakAt: null, problem: null };
}

export interface ChainVerification {
  readonly ok: boolean;
  readonly entries: number;
  readonly breakAt: number | null;
  readonly problem: string | null;
}

/**
 * Verifies a chain file end to end. Record schemas are the caller's concern:
 * chain integrity is argued from the hashes themselves.
 */
export async function verifyChain(path: string): Promise<ChainVerification> {
  const read = await readChain(path, parseOpaqueRecord);
  if (read.problem !== null) {
    return { ok: false, entries: read.entries.length, breakAt: read.breakAt, problem: read.problem };
  }
  const links = checkLinks(read.entries);
  return links.problem === null
    ? { ok: true, entries: read.entries.length, breakAt: null, problem: null }
    : { ok: false, entries: read.entries.length, breakAt: links.breakAt, problem: links.problem };
}

/**
 * Append-only writer. The writer caches the chain head from creation time, so
 * a process pays one file read at startup and one append per record after.
 * Single-process ownership is a stated limitation, not an accident — it
 * is what keeps the chain consistent without a lock.
 */
export class ChainWriter {
  private nextSeq = 0;
  private prevHash = GENESIS_PREV;

  private constructor(readonly path: string) {}

  static async open(path: string): Promise<ChainWriter> {
    const writer = new ChainWriter(path);
    const read = await readChain(path, parseOpaqueRecord);
    const last = read.entries.at(-1);
    if (last !== undefined && read.problem === null) {
      writer.nextSeq = last.seq + 1;
      writer.prevHash = last.hash;
    }
    return writer;
  }

  async append(record: Json, at: string): Promise<ChainEntry<Json>> {
    const seq = this.nextSeq;
    const prev = this.prevHash;
    const hash = chainHash(seq, at, prev, record);
    const entry: ChainEntry<Json> = { seq, at, prev, hash, record };
    await appendFile(this.path, `${JSON.stringify(entry)}\n`, "utf8");
    this.nextSeq = seq + 1;
    this.prevHash = hash;
    return entry;
  }
}
