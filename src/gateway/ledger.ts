import { ChainWriter, chainHash, readChain, verifyChain, GENESIS_PREV } from "../lib/chain.js";
import { isJsonObject, type Json, type JsonObject } from "../lib/json.js";
import { parseProvenanceFacts, type ProvenanceFact } from "../provenance.js";

export { GENESIS_PREV };

/**
 * Why a tool call was mediated the way it was. The record explicitly
 * distinguishes the *decision* (policy, attribution, reason) from the
 * *enforcement result* (what actually happened to the request) -- collapsing
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
  /**
   * Provenance facts consulted for the applied rule, or null when no
   * provenance check was involved. Older entries written before provenance
   * existed read back as null.
   */
  readonly provenance: readonly ProvenanceFact[] | null;
}

export interface LedgerEntry {
  readonly seq: number;
  readonly at: string;
  readonly prev: string;
  readonly hash: string;
  readonly record: LedgerRecord;
}

export function ledgerEntryHash(core: Pick<LedgerEntry, "seq" | "at" | "prev">, record: LedgerRecord): string {
  return chainHash(core.seq, core.at, core.prev, decisionRecordOf(record));
}

function decisionRecordOf(record: LedgerRecord): JsonObject {
  return {
    decisionId: record.decisionId,
    identity: record.identity,
    method: record.method,
    tool: record.tool,
    decision: { kind: record.decision.kind, ruleId: record.decision.ruleId, reason: record.decision.reason },
    enforcement: record.enforcement,
    upstreamStatus: record.upstreamStatus,
    provenance: record.provenance === null
      ? null
      : record.provenance.map((fact) => ({ argument: fact.argument, contentSha256: fact.contentSha256, trust: fact.trust })),
  };
}

export interface LedgerRead {
  readonly entries: readonly LedgerEntry[];
  /** Index of the first entry that fails verification, or null when intact. */
  readonly breakAt: number | null;
  readonly problem: string | null;
}

export async function readLedger(path: string): Promise<LedgerRead> {
  return await readChain(path, parseRecord);
}

export interface LedgerVerification {
  readonly ok: boolean;
  readonly entries: number;
  readonly breakAt: number | null;
  readonly problem: string | null;
}

/**
 * Verifies the append-only chain without committing to the record schema:
 * the hashes alone carry the tamper-evidence argument, and `ledger` is the
 * generic integrity command for any Rulehouse chain file. Structural
 * fidelity of decision records belongs to `readLedger`.
 */
export async function verifyLedger(path: string): Promise<LedgerVerification> {
  return await verifyChain(path);
}

/**
 * Typed front of the shared chain writer for decision records. `ChainWriter`
 * holds the single-process chain-head cache; this wrapper only narrows what
 * callers are allowed to commit.
 */
export class LedgerWriter {
  private constructor(private readonly chain: ChainWriter, readonly path: string) {}

  static async open(path: string): Promise<LedgerWriter> {
    return new LedgerWriter(await ChainWriter.open(path), path);
  }

  async append(record: LedgerRecord, at: string): Promise<LedgerEntry> {
    const entry = await this.chain.append(decisionRecordOf(record), at);
    return { ...entry, record };
  }
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
  const provenanceField = value["provenance"];
  let provenance: readonly ProvenanceFact[] | null = null;
  if (provenanceField !== undefined && provenanceField !== null) {
    provenance = parseProvenanceFacts(provenanceField);
    if (provenance === null) return null;
  }
  return {
    decisionId,
    identity,
    method,
    tool,
    decision,
    enforcement,
    upstreamStatus,
    provenance,
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
