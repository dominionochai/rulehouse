import type { GatewayPolicies, GatewayRule } from "./config.js";
import type { GatewayEffect } from "./config.js";
import { matchesAnyPattern } from "./match.js";
import type { ProvenanceFact, ProvenanceRegistry, ProvenanceTrust } from "../provenance.js";
import { contentDigestOf } from "../provenance.js";
import { isJsonObject, type JsonObject } from "../lib/json.js";

export interface Decision {
  readonly kind: "allowed" | "denied";
  readonly ruleId: string;
  readonly reason: string;
  /**
   * A policy allowed the call but requires a recorded human approval before
   * execution. Only `allowed` decisions ever carry this.
   */
  readonly approvalRequired: boolean;
  /**
   * Provenance facts inspected for the applied rule, in check order; empty
   * when the applied rule consults no provenance.
   */
  readonly provenance: readonly ProvenanceFact[];
}

export const DEFAULT_RULE_ID = "RH-GW-DEFAULT";
export const METHOD_RULE_ID = "RH-GW-METHOD";

/**
 * Evaluates a tool call. First *satisfied* rule wins, in written order — an
 * explicit, auditable precedence, deliberately instead of a "most specific
 * wins" heuristic whose interactions are impossible to reason about under
 * review. A rule can be matched yet unsatisfied: if its provenance checks do
 * not resolve to accepted declared trust, the rule is skipped and evaluation
 * continues down the written list. No match falls back to the configured
 * default effect, and the reason then records why each earlier rule was
 * skipped, because an audit trail that cannot explain a skipped rule cannot
 * defend the denial it produces.
 */
export function evaluateToolCall(
  policies: GatewayPolicies,
  identity: string | null,
  tool: string,
  args: JsonObject | null = null,
  registry: ProvenanceRegistry | null = null,
): Decision {
  const subject = `identity ${identity ?? "unauthenticated"} calling tool "${tool}"`;
  const skipped: string[] = [];
  for (const rule of policies.rules) {
    if (!ruleMatches(rule, identity, tool)) continue;
    if (rule.provenanceChecks.length > 0) {
      const outcome = provenanceOutcome(rule, args, registry);
      if (outcome === null) {
        skipped.push(`rule ${rule.id} was skipped: ${provenanceSkipReason(rule, args, registry)}`);
        continue;
      }
      const base = ofEffect(rule.effect, rule.id, rule.approvalRequired, `rule ${rule.id} ${effectVerb(rule.effect)} ${subject}`);
      return { ...base, provenance: outcome };
    }
    return ofEffect(rule.effect, rule.id, rule.approvalRequired, `rule ${rule.id} ${effectVerb(rule.effect)} ${subject}`);
  }
  const fallback = `no rule matches ${subject}; the configured default effect is ${policies.defaultEffect}`;
  const reason = skipped.length === 0 ? fallback : `${fallback}; ${skipped.join("; ")}`;
  return ofEffect(policies.defaultEffect, DEFAULT_RULE_ID, false, reason);
}

function ruleMatches(rule: GatewayRule, identity: string | null, tool: string): boolean {
  if (rule.identities !== null && (identity === null || !rule.identities.includes(identity))) return false;
  return matchesAnyPattern(rule.tools, tool);
}

/**
 * Returns the evaluated facts when every check accepts its content, and null
 * when the rule should be skipped. A null `args` or a missing named argument
 * is never vacuously satisfied: a content check on absent content does not
 * pass.
 */
function provenanceOutcome(
  rule: GatewayRule,
  args: JsonObject | null,
  registry: ProvenanceRegistry | null,
): readonly ProvenanceFact[] | null {
  const facts: ProvenanceFact[] = [];
  for (const check of rule.provenanceChecks) {
    const fact = resolveCheckFact(check, args, registry);
    if (fact === null || !check.requireTrust.includes(fact.trust as ProvenanceTrust)) return null;
    facts.push(fact);
  }
  return facts;
}

function resolveCheckFact(
  check: GatewayRule["provenanceChecks"][number],
  args: JsonObject | null,
  registry: ProvenanceRegistry | null,
): ProvenanceFact | null {
  if (args === null || !isJsonObject(args)) return null;
  const value = args[check.argument];
  if (value === undefined || value === null) return null;
  const contentSha256 = contentDigestOf(value);
  const trust = registry === null ? "unavailable" : resolveTrust(registry, contentSha256);
  return { argument: check.argument, contentSha256, trust };
}

function resolveTrust(registry: ProvenanceRegistry, contentSha256: string): ProvenanceFact["trust"] {
  if (registry.corrupt !== null) return "unavailable";
  const record = registry.records.get(contentSha256);
  return record === undefined ? "unclassified" : record.trust;
}

function provenanceSkipReason(
  rule: GatewayRule,
  args: JsonObject | null,
  registry: ProvenanceRegistry | null,
): string {
  if (args === null) {
    return `its provenance checks reference argument(s) ${rule.provenanceChecks.map((check) => `"${check.argument}"`).join(", ")} of content but the call carries no arguments object`;
  }
  for (const check of rule.provenanceChecks) {
    const fact = resolveCheckFact(check, args, registry);
    if (fact === null) return `its provenance check found no content to inspect for argument "${check.argument}"`;
    if (!check.requireTrust.includes(fact.trust as ProvenanceTrust)) {
      return `its provenance check accepted ${check.requireTrust.join(" or ")} for argument "${check.argument}" but resolved ${fact.trust} (${fact.contentSha256})`;
    }
  }
  return "its provenance checks did not all resolve";
}

function effectVerb(effect: GatewayEffect): string {
  return effect === "deny" ? "denies" : "allows";
}

function ofEffect(effect: GatewayEffect, ruleId: string, approvalRequired: boolean, reason: string): Decision {
  return effect === "deny"
    ? { kind: "denied", ruleId, reason, approvalRequired: false, provenance: [] }
    : { kind: "allowed", ruleId, reason, approvalRequired, provenance: [] };
}
