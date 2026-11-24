const MATCH_CACHE_LIMIT = 512;

const matcherCache = new Map<string, RegExp>();

/**
 * Tool-match patterns use a single wildcard: `*`, standing for any character
 * sequence of any length, including empty. Everything else is literal. A
 * matcher is a compiled RegExp so a hot gateway request costs one `test()`
 * per candidate pattern, and a bounded cache keeps repeated identical
 * policy rules from recompiling on every decision.
 */
export function wildcardToRegExp(pattern: string): RegExp {
  const cached = matcherCache.get(pattern);
  if (cached !== undefined) return cached;
  let source = "";
  for (const ch of pattern) {
    source += ch === "*" ? "[\\s\\S]*" : escapeRegexp(ch);
  }
  const compiled = new RegExp(`^${source}$`);
  if (matcherCache.size >= MATCH_CACHE_LIMIT) matcherCache.clear();
  matcherCache.set(pattern, compiled);
  return compiled;
}

function escapeRegexp(ch: string): string {
  return ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function matchesPattern(pattern: string, value: string): boolean {
  return wildcardToRegExp(pattern).test(value);
}

export function matchesAnyPattern(patterns: readonly string[], value: string): boolean {
  return patterns.some((pattern) => matchesPattern(pattern, value));
}
