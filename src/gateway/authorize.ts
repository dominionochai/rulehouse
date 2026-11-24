import type { GatewayPolicies, GatewayRule } from "./config.js";
import type { GatewayEffect } from "./config.js";
import { matchesAnyPattern } from "./match.js";

export interface Decision {
  readonly kind: "allowed" | "denied";
  readonly ruleId: string;
  readonly reason: string;
  /**
   * A policy allowed the call but requires a recorded human approval before
   * execution. Only `allowed` decisions ever carry this.
   */
  readonly approvalRequired: boolean;
}

export const DEFAULT_RULE_ID = "RH-GW-DEFAULT";
export const METHOD_RULE_ID = "RH-GW-METHOD";

/**
 * Evaluates a tool call. First matching rule wins, in written order — an
 * explicit, auditable precedence, deliberately instead of a "most specific
 * wins" heuristic whose interactions are impossible to reason about under
 * review. No match falls back to the configured default effect.
 */
export function evaluateToolCall(policies: GatewayPolicies, identity: string | null, tool: string): Decision {
  const subject = `identity ${identity ?? "unauthenticated"} calling tool "${tool}"`;
  for (const rule of policies.rules) {
    if (!ruleApplies(rule, identity, tool)) continue;
    return ofEffect(rule.effect, rule.id, rule.approvalRequired, `rule ${rule.id} ${effectVerb(rule.effect)} ${subject}`);
  }
  return ofEffect(policies.defaultEffect, DEFAULT_RULE_ID, false, `no rule matches ${subject}; the configured default effect is ${policies.defaultEffect}`);
}

function ruleApplies(rule: GatewayRule, identity: string | null, tool: string): boolean {
  if (rule.identities !== null && (identity === null || !rule.identities.includes(identity))) return false;
  return matchesAnyPattern(rule.tools, tool);
}

function effectVerb(effect: GatewayEffect): string {
  return effect === "deny" ? "denies" : "allows";
}

function ofEffect(effect: GatewayEffect, ruleId: string, approvalRequired: boolean, reason: string): Decision {
  return effect === "deny"
    ? { kind: "denied", ruleId, reason, approvalRequired: false }
    : { kind: "allowed", ruleId, reason, approvalRequired };
}
