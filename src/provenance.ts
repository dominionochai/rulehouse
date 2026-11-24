import { canonicalize, isJsonObject, sha256Hex, type Json } from "./lib/json.js";
import { ChainWriter, checkLinks, readChain, type ChainRead } from "./lib/chain.js";

/**
 * Provenance answers one question: where did this content come from, and is
 * it trusted to drive an action? Regulation here binds content by digest,
 * never by storing content -- the registry describes what was seen, the way
 * a customs ledger describes cargo without carrying it.
 */

export type ProvenanceTrust = "trusted" | "untrusted" | "unverified";
export type ProvenanceOrigin = "internal" | "external" | "derived";

/**
 * Trust as the gateway can observe it:
 * - a declared trust value from the registry;
 * - `unclassified`: the registry is healthy but this digest is not in it;
 * - `unavailable`: the registry is missing or corrupt, so no claim about any
 *   content can be made -- fail closed, and never collapse this into
 *   `unclassified`, because a broken evidence chain must not be read as a
 *   clean one.
 */
export type ObservedTrust = ProvenanceTrust | "unclassified" | "unavailable";

export interface ProvenanceRecord {
  /** `sha256:<64 hex>` over the content as mediated (see `contentDigestOf`). */
  readonly contentSha256: string;
  readonly origin: ProvenanceOrigin;
  readonly trust: ProvenanceTrust;
  /** Where the content came from, e.g. `jira:SEC-1042`, `webform:vendor-portal`. */
  readonly source: string;
  /** Who declared this classification -- attribution is mandatory. */
  readonly labeledBy: string;
  readonly labeledAt: string;
}

export const SHA256_HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ORIGINS: readonly ProvenanceOrigin[] = ["internal", "external", "derived"];
const TRUSTS: readonly ProvenanceTrust[] = ["trusted", "untrusted", "unverified"];

/**
 * A fact the decision ledger can quote: the digest that was inspected and the
 * trust the registry resolved for it at decision time.
 */
export interface ProvenanceFact {
  readonly argument: string;
  readonly contentSha256: string;
  readonly trust: ObservedTrust;
}

/**
 * Binds a digest to the exact mediated form of the content. A string is
 * digested over its raw UTF-8 bytes (what the upstream would receive); any
 * structured value is digested over canonical JSON, so key order has no
 * effect on identity. Consequence, stated deliberately: whitespace-wise
 * equivalent content re-serialized differently digests differently -- the
 * registry certifies bytes, not paraphrases.
 */
export function contentDigestOf(value: Json): string {
  if (typeof value === "string") return `sha256:${sha256Hex(value)}`;
  return `sha256:${sha256Hex(canonicalize(value))}`;
}

/**
 * Digests operator-supplied text (a CLI file or stdin stream) the same way
 * the gateway will digest the corresponding tool argument: unparseable text
 * is a string; parseable JSON is digested in its parsed, canonical form so a
 * registered file and a mediated argument land on the same digest.
 */
export function contentDigestOfText(text: string): string {
  try {
    return contentDigestOf(JSON.parse(text) as Json);
  } catch {
    return contentDigestOf(text);
  }
}

export function parseProvenanceRecord(value: Json | undefined): ProvenanceRecord | null {
  if (!isJsonObject(value)) return null;
  const contentSha256 = value["contentSha256"];
  const origin = value["origin"];
  const trust = value["trust"];
  const source = value["source"];
  const labeledBy = value["labeledBy"];
  const labeledAt = value["labeledAt"];
  if (typeof contentSha256 !== "string" || !SHA256_HASH_PATTERN.test(contentSha256)) return null;
  if (typeof origin !== "string" || !ORIGINS.includes(origin as ProvenanceOrigin)) return null;
  if (typeof trust !== "string" || !TRUSTS.includes(trust as ProvenanceTrust)) return null;
  if (typeof source !== "string" || source.length === 0) return null;
  if (typeof labeledBy !== "string" || labeledBy.length === 0) return null;
  if (typeof labeledAt !== "string") return null;
  return { contentSha256, origin: origin as ProvenanceOrigin, trust: trust as ProvenanceTrust, source, labeledBy, labeledAt };
}

/**
 * The registry is an append-only hash chain (the same one the decision
 * ledger uses). Re-registration is how trust changes: each line is a
 * declaration, and the most recent record for a digest wins. A damaged chain
 * poisons every answer it takes part in -- resolved as `unavailable`.
 */
export interface ProvenanceRegistry {
  readonly records: ReadonlyMap<string, ProvenanceRecord>;
  readonly corrupt: string | null;
}

export async function readProvenanceRegistry(path: string): Promise<ProvenanceRegistry> {
  const read: ChainRead<ProvenanceRecord> = await readChain(path, parseProvenanceRecord);
  const broken = read.problem ?? checkLinks(read.entries).problem;
  if (broken !== null) {
    return { records: new Map(), corrupt: broken };
  }
  const records = new Map<string, ProvenanceRecord>();
  for (const entry of read.entries) {
    records.set(entry.record.contentSha256, entry.record);
  }
  return { records, corrupt: null };
}

export function parseProvenanceFacts(value: Json | undefined): readonly ProvenanceFact[] | null {
  if (value === undefined) return null;
  if (!Array.isArray(value)) return null;
  const facts: ProvenanceFact[] = [];
  for (const element of value) {
    if (!isJsonObject(element)) return null;
    const argument = element["argument"];
    const contentSha256 = element["contentSha256"];
    const trust = element["trust"];
    if (typeof argument !== "string" || argument.length === 0) return null;
    if (typeof contentSha256 !== "string" || !SHA256_HASH_PATTERN.test(contentSha256)) return null;
    if (typeof trust !== "string" || !isObservedTrust(trust)) return null;
    facts.push({ argument, contentSha256, trust });
  }
  return facts;
}

function isObservedTrust(value: string): value is ObservedTrust {
  return value === "trusted" || value === "untrusted" || value === "unverified"
    || value === "unclassified" || value === "unavailable";
}

export async function appendProvenanceRecord(path: string, record: ProvenanceRecord, at: string): Promise<number> {
  const writer = await ChainWriter.open(path);
  const entry = await writer.append({
    contentSha256: record.contentSha256,
    origin: record.origin,
    trust: record.trust,
    source: record.source,
    labeledBy: record.labeledBy,
    labeledAt: record.labeledAt,
  }, at);
  return entry.seq;
}
