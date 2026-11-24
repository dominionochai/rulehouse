import { ChainWriter, checkLinks, readChain, type ChainRead } from "../lib/chain.js";
import { canonicalize, isJsonObject, sha256Hex, type Json, type JsonObject } from "../lib/json.js";
import { matchesAnyPattern } from "../gateway/match.js";
import { evaluateToolCall, type Decision } from "../gateway/authorize.js";
import type { GatewayPolicies } from "../gateway/config.js";
import type { ProvenanceFact, ProvenanceRegistry } from "../provenance.js";

/**
 * A2A delegation governance, expressed as exactly one new question and zero
 * new policy language. The registry answers only *who may act for whom*;
 * what a delegatee may then do is never restated -- it is recomputed, at
 * decision time, by running the existing gateway policies once per identity
 * on the delegation chain. That composition is the whole security argument:
 * a delegatee cannot exceed its delegator because the delegator's own rules
 * are evaluated against the same call, with the same arguments, by the same
 * evaluator that governs direct calls. There is no delegation policy file
 * whose drift away from the gateway policies would have to be audited,
 * because there is no delegation policy file.
 */

export interface DelegationGrant {
  /** Deterministic identity of the grant, derived from its full content. */
  readonly grantId: string;
  /** The principal whose authority is being handed on. */
  readonly delegator: string;
  /** The principal receiving it. */
  readonly delegatee: string;
  /** Tool-name patterns (same wildcard grammar as gateway rules) the grant covers. */
  readonly tools: readonly string[];
  /** Who authorized this delegation -- attribution is mandatory, as in provenance. */
  readonly grantedBy: string;
  readonly grantedAt: string;
  /** ISO timestamp after which the grant is inert; null never expires. */
  readonly expiresAt: string | null;
}

export interface DelegationRevocation {
  readonly grantId: string;
  readonly revokedBy: string;
}

export type DelegationRecord =
  | ({ readonly kind: "grant" } & DelegationGrant)
  | ({ readonly kind: "revocation" } & DelegationRevocation);

/**
 * The grant id is content-addressed: two issuances that differ in any field
 * -- scope, parties, attribution, even the instant of granting -- carry
 * different ids. A revocation therefore names one issuance, not a
 * delegator/delegatee pair, and re-granting the same scope produces a
 * genuinely new, independently attributable decision rather than resurrecting
 * a revoked one.
 */
export function grantIdOf(grant: Omit<DelegationGrant, "grantId">): string {
  const { delegator, delegatee, tools, grantedBy, grantedAt, expiresAt } = grant;
  return `delegation:${sha256Hex(canonicalize({ delegator, delegatee, tools, grantedBy, grantedAt, expiresAt }))}`;
}

const GRANT_ID_PATTERN = /^delegation:[0-9a-f]{64}$/;

function isIsoTimestamp(value: string): boolean {
  return Number.isFinite(Date.parse(value));
}

function grantFieldsOf(value: JsonObject): Omit<DelegationGrant, "grantId"> | null {
  const delegator = value["delegator"];
  const delegatee = value["delegatee"];
  const tools = value["tools"];
  const grantedBy = value["grantedBy"];
  const grantedAt = value["grantedAt"];
  const expiresAt = value["expiresAt"];
  if (typeof delegator !== "string" || delegator.length === 0) return null;
  if (typeof delegatee !== "string" || delegatee.length === 0) return null;
  if (!Array.isArray(tools) || tools.length === 0 || !tools.every((tool) => typeof tool === "string" && tool.length > 0)) return null;
  if (typeof grantedBy !== "string" || grantedBy.length === 0) return null;
  if (typeof grantedAt !== "string" || !isIsoTimestamp(grantedAt)) return null;
  if (expiresAt !== null && (typeof expiresAt !== "string" || !isIsoTimestamp(expiresAt))) return null;
  return { delegator, delegatee, tools: tools as readonly string[], grantedBy, grantedAt, expiresAt };
}

/**
 * Parses one record. The grant id on disk is checked, not trusted: it must
 * equal the id derived from the record's own content, so a grant can never
 * present itself under an id its content does not own.
 */
export function parseDelegationRecord(value: Json | undefined): DelegationRecord | null {
  if (!isJsonObject(value)) return null;
  const kind = value["kind"];
  if (kind === "grant") {
    const fields = grantFieldsOf(value);
    if (fields === null) return null;
    const grantId = value["grantId"];
    if (typeof grantId !== "string" || grantId !== grantIdOf(fields)) return null;
    return { kind: "grant", grantId, ...fields };
  }
  if (kind === "revocation") {
    const grantId = value["grantId"];
    const revokedBy = value["revokedBy"];
    if (typeof grantId !== "string" || !GRANT_ID_PATTERN.test(grantId)) return null;
    if (typeof revokedBy !== "string" || revokedBy.length === 0) return null;
    return { kind: "revocation", grantId, revokedBy };
  }
  return null;
}

export { GRANT_ID_PATTERN };

export interface GrantState {
  readonly grant: DelegationGrant;
  readonly revoked: boolean;
  readonly revokedBy: string | null;
}

/**
 * Resolved view of the delegation chain file: the latest record per grant id
 * wins, exactly like the provenance registry -- and, identically, every read
 * that anyone intends to *act on* re-derives the linkage. A chain that
 * cannot prove it is intact delegates nothing.
 */
export interface DelegationRegistry {
  readonly grants: ReadonlyMap<string, GrantState>;
  readonly corrupt: string | null;
  readonly entries: number;
}

export async function readDelegationRegistry(path: string): Promise<DelegationRegistry> {
  const read: ChainRead<DelegationRecord> = await readChain(path, parseDelegationRecord);
  const broken = read.problem ?? checkLinks(read.entries).problem;
  if (broken !== null) {
    return { grants: new Map(), corrupt: broken, entries: read.entries.length };
  }
  const grants = new Map<string, GrantState>();
  for (const entry of read.entries) {
    const record = entry.record;
    if (record.kind === "grant") {
      grants.set(record.grantId, { grant: record, revoked: false, revokedBy: null });
    } else {
      const existing = grants.get(record.grantId);
      if (existing !== undefined) {
        grants.set(record.grantId, { ...existing, revoked: true, revokedBy: record.revokedBy });
      }
    }
  }
  return { grants, corrupt: null, entries: read.entries.length };
}

export async function appendDelegationRecord(path: string, record: DelegationRecord, at: string): Promise<number> {
  const writer = await ChainWriter.open(path);
  const payload: Json = record.kind === "grant"
    ? {
        kind: record.kind,
        grantId: record.grantId,
        delegator: record.delegator,
        delegatee: record.delegatee,
        tools: [...record.tools],
        grantedBy: record.grantedBy,
        grantedAt: record.grantedAt,
        expiresAt: record.expiresAt,
      }
    : { kind: record.kind, grantId: record.grantId, revokedBy: record.revokedBy };
  const entry = await writer.append(payload, at);
  return entry.seq;
}

export interface DelegationLink {
  readonly grantId: string;
  readonly delegator: string;
  readonly delegatee: string;
}

export interface DelegationCeiling {
  readonly identity: string;
  readonly decision: Decision;
}

export interface DelegatedDecision {
  readonly allowed: boolean;
  readonly reason: string;
  /** The grants actually relied on, leaf first; empty when refused before evaluation. */
  readonly chain: readonly DelegationLink[];
  /** Policy decision per identity on the chain, leaf first; empty when refused before evaluation. */
  readonly ceilings: readonly DelegationCeiling[];
  /** True when every ceiling allows but at least one requires human approval -- escalation, never relaxation. */
  readonly approvalRequired: boolean;
  readonly provenance: readonly ProvenanceFact[];
}

function refused(reason: string): DelegatedDecision {
  return { allowed: false, reason, chain: [], ceilings: [], approvalRequired: false, provenance: [] };
}

export interface DelegatedCall {
  readonly policies: GatewayPolicies;
  readonly delegations: DelegationRegistry;
  /** Grant ids presented with the call, leaf (the acting agent) first, root (the final delegator) last. */
  readonly presented: readonly string[];
  /** The identity the caller presents; must be the leaf grant's delegatee. */
  readonly identity: string | null;
  readonly tool: string;
  readonly args: JsonObject | null;
  readonly registry: ProvenanceRegistry | null;
  /** ISO instant the evaluation is anchored to; expiry is measured against this. */
  readonly now: string;
}

/**
 * Evaluates a call made under delegation. Every rejection names the exact
 * defect -- unavailable registry, unknown or revoked grant, a chain that
 * does not connect, a cycle, expiry, an out-of-scope tool, or the ceiling
 * that denied -- because a governance layer that says only "denied" teaches
 * nobody why, and an audit that cannot explain itself cannot be defended.
 * Refusals happen in a fixed order, so the same call against the same state
 * always produces the same reason.
 */
export function evaluateDelegatedToolCall(call: DelegatedCall): DelegatedDecision {
  const { policies, delegations, presented, identity, tool, args, registry } = call;
  if (delegations.corrupt !== null) {
    return refused(`delegation registry is unavailable (${delegations.corrupt}); failing closed`);
  }
  if (presented.length === 0) {
    return refused(`no delegation presented: identity ${identity ?? "unauthenticated"} claims no grant`);
  }

  const links: { link: DelegationLink; grant: DelegationGrant }[] = [];
  for (const [index, grantId] of presented.entries()) {
    const state = delegations.grants.get(grantId);
    if (state === undefined) return refused(`grant ${grantId} (position ${index}) is not in the delegation registry`);
    if (state.revoked) {
      return refused(`grant ${grantId} (position ${index}) was revoked by ${state.revokedBy ?? "an unspecified revoker"}`);
    }
    links.push({ link: { grantId, delegator: state.grant.delegator, delegatee: state.grant.delegatee }, grant: state.grant });
  }

  const leaf = links[0]!;
  if (identity !== leaf.grant.delegatee) {
    return refused(`the leaf grant ${leaf.link.grantId} grants authority to ${leaf.grant.delegatee} but the call presents identity ${identity ?? "unauthenticated"}`);
  }
  for (const [hop, upper] of links.slice(1).entries()) {
    const below = links[hop]!;
    if (upper.grant.delegatee !== below.grant.delegator) {
      return refused(`grant ${upper.link.grantId} grants authority to ${upper.grant.delegatee} but the grant below it (${below.link.grantId}) acts for ${below.grant.delegator}; the chain does not connect`);
    }
  }

  const participants = [leaf.grant.delegatee, ...links.map((entry) => entry.grant.delegator)];
  const seen = new Set<string>();
  for (const participant of participants) {
    if (seen.has(participant)) {
      return refused(`delegation cycle: ${participant} appears more than once in the chain ${participants.join(" -> ")}`);
    }
    seen.add(participant);
  }

  for (const entry of links) {
    if (entry.grant.expiresAt !== null && Date.parse(entry.grant.expiresAt) <= Date.parse(call.now)) {
      return refused(`grant ${entry.link.grantId} (${entry.grant.delegator} -> ${entry.grant.delegatee}) expired at ${entry.grant.expiresAt}, evaluation anchored at ${call.now}`);
    }
  }

  for (const entry of links) {
    if (!matchesAnyPattern(entry.grant.tools, tool)) {
      return refused(`grant ${entry.link.grantId} (${entry.link.delegator} -> ${entry.link.delegatee}) does not cover tool "${tool}" (its scope is ${entry.grant.tools.join(", ")})`);
    }
  }

  const ceilings: DelegationCeiling[] = [];
  for (const participant of participants) {
    const decision = evaluateToolCall(policies, participant, tool, args, registry);
    ceilings.push({ identity: participant, decision });
    if (decision.kind === "denied") {
      return {
        allowed: false,
        reason: `delegated call to "${tool}" denied at ceiling ${participant}: [${decision.ruleId}] ${decision.reason}`,
        chain: links.map((entry) => entry.link),
        ceilings,
        approvalRequired: false,
        provenance: [],
      };
    }
  }

  const approvalRequired = ceilings.some((ceiling) => ceiling.decision.approvalRequired);
  const facts: ProvenanceFact[] = [];
  const seenFacts = new Set<string>();
  for (const ceiling of ceilings) {
    for (const fact of ceiling.decision.provenance) {
      const key = canonicalize({ argument: fact.argument, contentSha256: fact.contentSha256, trust: fact.trust });
      if (seenFacts.has(key)) continue;
      seenFacts.add(key);
      facts.push(fact);
    }
  }
  return {
    allowed: true,
    reason: `delegated call allowed: every identity on the chain (${participants.join(" -> ")}) is allowed by its own policies${approvalRequired ? "; approval is required by at least one ceiling" : ""}`,
    chain: links.map((entry) => entry.link),
    ceilings,
    approvalRequired,
    provenance: facts,
  };
}
