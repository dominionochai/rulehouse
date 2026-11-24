import { authKey, type EndpointClass, type InventoryEntry, type Severity } from "./model.js";

/**
 * A RuleVerdict is emitted for every (rule, in-scope element) pair, including
 * passes. Passes are first-class citizens here, not background noise: the
 * product claim is verifiable control effectiveness, so the report must be
 * able to say "rule X passed on element Y" — silence proves nothing.
 */
export interface RuleVerdict {
  readonly ruleId: string;
  readonly severity: Severity;
  readonly status: "finding" | "pass" | "not-applicable";
  /** Where the verdict attaches: a file and JSON pointer, or a server group key. */
  readonly subject: string;
  readonly message: string;
}

/**
 * A per-entry rule declares two total functions over one entry: whether the
 * security question it answers is in scope for that entry, and the answer.
 * Because scope and verdict share the entry type, adding a rule never touches
 * the evaluation loop, the report, or the CLI — the table below is the whole
 * policy surface.
 */
interface PerEntryRule {
  readonly id: string;
  readonly title: string;
  readonly severity: Severity;
  readonly rationale: string;
  readonly scope: (entry: InventoryEntry) => boolean;
  readonly verdict: (entry: InventoryEntry) => { readonly status: "finding" | "pass"; readonly message: string };
}

function credentialOf(entry: InventoryEntry): { readonly origin: string; readonly fingerprint: string; readonly envVar: string | null } | null {
  return entry.auth.kind === "api-token" || entry.auth.kind === "credential-header" ? entry.auth.credential : null;
}

function credentialMessage(origin: string, fingerprint: string, envVar: string | null): string {
  switch (origin) {
    case "inline":
      return `credential material is inlined in the configuration (fingerprint ${fingerprint})`;
    case "environment":
      return `credential referenced from environment variable ${envVar ?? "?"} (fingerprint ${fingerprint})`;
    case "unresolved":
      return `credential references environment variable ${envVar ?? "?"}, which is not set in this shell`;
    default:
      return "credential present";
  }
}

const CREDENTIAL_INLINE: PerEntryRule = {
  id: "RH-CRED-INLINE",
  title: "No credential material inlined in configuration files",
  severity: "high",
  rationale:
    "Secrets written into client configuration files are exposed to filesystem backup, sync tooling, and machine snapshots, and cannot be rotated centrally the way a secret-store reference can.",
  scope: (entry) => credentialOf(entry) !== null,
  verdict: (entry) => {
    const credential = credentialOf(entry);
    if (credential === null) return { status: "pass", message: "no credential material found" };
    const message = credentialMessage(credential.origin, credential.fingerprint, credential.envVar);
    return credential.origin === "inline" ? { status: "finding", message } : { status: "pass", message };
  },
};

const CREDENTIAL_UNRESOLVED: PerEntryRule = {
  id: "RH-CRED-UNRESOLVED",
  title: "Environment-referenced credentials resolve where clients run",
  severity: "low",
  rationale:
    "A ${VAR} reference the scanning shell cannot resolve may be supplied by a client keychain or secret store (fine), or may simply be unset — a connection that will fail. Both belong on the record.",
  scope: (entry) => credentialOf(entry) !== null,
  verdict: (entry) => {
    const problem = entry.auth.kind === "api-token" || entry.auth.kind === "credential-header" ? entry.auth.problem : null;
    return problem === null
      ? { status: "pass", message: "credential reference resolves in this scan environment" }
      : { status: "finding", message: problem };
  },
};

const remoteOnly = (entry: InventoryEntry): boolean => entry.transport === "remote";
const atlassianOnly = (entry: InventoryEntry): boolean =>
  entry.endpointClass === "atlassian-v2" || entry.endpointClass === "atlassian-v1" || entry.endpointClass === "atlassian-sse-legacy";

const ENDPOINT_SSE_LEGACY: PerEntryRule = {
  id: "RH-ENDPOINT-SSE-LEGACY",
  title: "No legacy Server-Sent-Events Atlassian endpoint",
  severity: "high",
  rationale:
    "Atlassian ended support for https://mcp.atlassian.com/v1/sse on 30 June 2026; a client left on it stops receiving updates and its traffic drops out of current enforcement surfaces.",
  scope: atlassianOnly,
  verdict: (entry) =>
    entry.endpointClass === "atlassian-sse-legacy"
      ? { status: "finding", message: `${entry.url} is the deprecated SSE endpoint; migrate to https://mcp.atlassian.com/v2/mcp` }
      : { status: "pass", message: `${entry.url} is a supported endpoint generation` },
};

const ENDPOINT_V1: PerEntryRule = {
  id: "RH-ENDPOINT-V1",
  title: "No legacy v1 Atlassian endpoint",
  severity: "medium",
  rationale:
    "v1 HTTP endpoints still work but present a second endpoint variant to keep aligned; standardizing on /v2/mcp removes an entire class of parity drift before it can occur.",
  scope: atlassianOnly,
  verdict: (entry) =>
    entry.endpointClass === "atlassian-v1"
      ? { status: "finding", message: `${entry.url} is a v1 endpoint; standardize on https://mcp.atlassian.com/v2/mcp` }
      : { status: "pass", message: `${entry.url} is a supported endpoint generation` },
};

const ENDPOINT_INSECURE: PerEntryRule = {
  id: "RH-ENDPOINT-INSECURE",
  title: "No plaintext-transport remote servers",
  severity: "critical",
  rationale:
    "A remote MCP server reached over cleartext HTTP exposes the credential, and every byte of organizational content, in transit.",
  scope: remoteOnly,
  verdict: (entry) =>
    entry.endpointClass === "insecure-remote"
      ? { status: "finding", message: `${entry.url} does not use HTTPS` }
      : { status: "pass", message: `${entry.url} is reached over HTTPS` },
};

const TOOLS_ALL_EXPOSURE: PerEntryRule = {
  id: "RH-TOOLS-ALL",
  title: "No tools=all toolset override",
  severity: "medium",
  rationale:
    "The ?tools=all override replaces Atlassian's curated primary-tool set with the complete flat tool list, so an agent can reach delete- and admin-class tools without the discovery step a reviewer would see first.",
  scope: remoteOnly,
  verdict: (entry) =>
    entry.toolsOverride !== null
      ? { status: "finding", message: `${entry.url} overrides default tool exposure with tools=${entry.toolsOverride.join(",")}` }
      : { status: "pass", message: `${entry.url} keeps Atlassian's default tool exposure` },
};

/**
 * The policy surface, in evaluation order. Each entry is complete: id, title,
 * severity, rationale for the report, scope, and verdict. Nothing about how
 * rules execute is encoded anywhere else.
 */
export const PER_ENTRY_RULES: readonly PerEntryRule[] = [
  CREDENTIAL_INLINE,
  CREDENTIAL_UNRESOLVED,
  ENDPOINT_SSE_LEGACY,
  ENDPOINT_V1,
  ENDPOINT_INSECURE,
  TOOLS_ALL_EXPOSURE,
];

export interface Allowlist {
  readonly urlPrefixes: readonly string[];
  readonly source: string | null;
}

function locationOf(entry: InventoryEntry): string {
  return `${entry.source.file}${entry.source.pointer}`;
}

export interface PolicyEvaluation {
  readonly verdicts: readonly RuleVerdict[];
  readonly findingCount: number;
}

function evaluatePerEntryRules(entries: readonly InventoryEntry[]): readonly RuleVerdict[] {
  const verdicts: RuleVerdict[] = [];
  for (const rule of PER_ENTRY_RULES) {
    const inScope = entries.filter(rule.scope);
    if (inScope.length === 0) {
      verdicts.push({ ruleId: rule.id, severity: rule.severity, status: "not-applicable", subject: "*", message: "no in-scope elements in this inventory" });
      continue;
    }
    for (const entry of inScope) {
      const result = rule.verdict(entry);
      verdicts.push({ ruleId: rule.id, severity: rule.severity, status: result.status, subject: locationOf(entry), message: result.message });
    }
  }
  return verdicts;
}

function evaluateAllowlist(entries: readonly InventoryEntry[], allowlist: Allowlist | null): readonly RuleVerdict[] {
  if (allowlist === null || allowlist.urlPrefixes.length === 0) {
    return [
      {
        ruleId: "RH-ALLOWLIST",
        severity: "high",
        status: "not-applicable",
        subject: "*",
        message: "no allowlist configured; run with --allowlist <file> to enforce the approved-server list",
      },
    ];
  }
  return entries
    .filter(remoteOnly)
    .map((entry): RuleVerdict => {
      const listed = allowlist.urlPrefixes.some((prefix) => (entry.url ?? "").startsWith(prefix));
      return listed
        ? { ruleId: "RH-ALLOWLIST", severity: "high", status: "pass", subject: locationOf(entry), message: `${entry.url} is on the approved server list` }
        : {
            ruleId: "RH-ALLOWLIST",
            severity: "high",
            status: "finding",
            subject: locationOf(entry),
            message: `${entry.url} is not on the approved server list (${allowlist.source ?? "inline allowlist"})`,
          };
    });
}

interface ServerGroup {
  readonly serverKey: string;
  readonly entries: readonly InventoryEntry[];
}

function groupByServerKey(entries: readonly InventoryEntry[]): readonly ServerGroup[] {
  const map = new Map<string, InventoryEntry[]>();
  for (const entry of entries) {
    const bucket = map.get(entry.serverKey);
    if (bucket === undefined) map.set(entry.serverKey, [entry]);
    else bucket.push(entry);
  }
  return [...map.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([serverKey, bucket]) => ({ serverKey, entries: bucket }));
}

/**
 * Cross-client parity: for each logical server that more than one client
 * registers, the authentication scheme, endpoint generation, and tool
 * exposure must all agree. Divergence is the Phase-1 wedge — a restriction
 * configured for one authentication path offers no evidence about another,
 * and divergent endpoint generations are where those gaps hide. Note that
 * Atlassian's v1/v2/SSE paths collapse into one serverKey, so a v1-in-one-
 * client / v2-in-another split is caught here rather than being mistaken for
 * two unrelated servers.
 */
export function parityVerdicts(entries: readonly InventoryEntry[]): readonly RuleVerdict[] {
  const verdicts: RuleVerdict[] = [];
  for (const group of groupByServerKey(entries)) {
    if (group.entries.length < 2) {
      verdicts.push({
        ruleId: "RH-PARITY",
        severity: "high",
        status: "not-applicable",
        subject: group.serverKey,
        message: "registered in a single client; cross-client parity requires at least two registrations",
      });
      continue;
    }
    verdicts.push(...authParity(group));
    verdicts.push(...endpointParityGroup(group));
    verdicts.push(...toolsParity(group));
  }
  return verdicts;
}

function describeAuth(key: string): string {
  if (key === "oauth") return "OAuth 2.1";
  if (key === "token:unspecified") return "API token (scheme unspecified)";
  if (key.startsWith("token:")) return `API token (${key.slice("token:".length)})`;
  if (key.startsWith("header:")) return `credential header ${key.slice("header:".length)}`;
  return `unclassified (${key.slice("unknown:".length)})`;
}

/**
 * Buckets a group by a derived facet while recording exactly which
 * registrations landed in each bucket — the report needs both the divergence
 * (the values) and the evidence (which client:server pairs, where).
 */
function facetBuckets<T>(
  items: readonly T[],
  key: (item: T) => string,
  label: (item: T) => string,
): readonly { readonly value: string; readonly labels: readonly string[] }[] {
  const buckets = new Map<string, string[]>();
  for (const item of items) {
    const k = key(item);
    const bucket = buckets.get(k);
    if (bucket === undefined) buckets.set(k, [label(item)]);
    else bucket.push(label(item));
  }
  return [...buckets.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
    .map(([value, labels]) => ({ value, labels }));
}

function divergenceOrPass(
  ruleId: string,
  severity: Severity,
  subject: string,
  buckets: readonly { readonly value: string; readonly labels: readonly string[] }[],
  uniformMessage: string,
  divergenceMessage: (values: string) => string,
): RuleVerdict {
  if (buckets.length <= 1) {
    return { ruleId, severity, status: "pass", subject, message: uniformMessage };
  }
  return {
    ruleId,
    severity,
    status: "finding",
    subject,
    message: divergenceMessage(buckets.map((b) => `${b.value} [${b.labels.join("; ")}]`).join("  vs  ")),
  };
}

function authParity(group: ServerGroup): readonly RuleVerdict[] {
  const first = group.entries[0];
  const rawBuckets = facetBuckets(group.entries, (entry) => authKey(entry.auth), locationOf);
  const buckets = rawBuckets.map((bucket) => ({ value: describeAuth(bucket.value), labels: bucket.labels }));
  return [
    divergenceOrPass(
      "RH-PARITY",
      "high",
      group.serverKey,
      buckets,
      `authentication is ${first !== undefined ? describeAuth(authKey(first.auth)) : "uniformly unclassified"} in all ${group.entries.length} registrations`,
      (values) => `authentication differs across registrations: ${values}`,
    ),
  ];
}

function firstEndpointOf(group: ServerGroup): EndpointClass {
  const first = group.entries[0];
  return first === undefined ? "unparseable-url" : first.endpointClass;
}

function endpointParityGroup(group: ServerGroup): readonly RuleVerdict[] {
  const buckets = facetBuckets(group.entries, (entry) => entry.endpointClass, locationOf);
  return [
    divergenceOrPass(
      "RH-PARITY",
      "medium",
      group.serverKey,
      buckets,
      `endpoint generation is uniform (${firstEndpointOf(group)}) in all ${group.entries.length} registrations`,
      (values) => `endpoint generation differs across registrations: ${values}`,
    ),
  ];
}

function toolSignature(entry: InventoryEntry): string {
  return entry.toolsOverride === null ? "default exposure" : `tools=${entry.toolsOverride.join(",")}`;
}

function firstToolSignatureOf(group: ServerGroup): string {
  const first = group.entries[0];
  return first === undefined ? "default exposure" : toolSignature(first);
}

function toolsParity(group: ServerGroup): readonly RuleVerdict[] {
  const buckets = facetBuckets(group.entries, toolSignature, locationOf);
  return [
    divergenceOrPass(
      "RH-PARITY",
      "medium",
      group.serverKey,
      buckets,
      `tool exposure is uniform (${firstToolSignatureOf(group)}) in all ${group.entries.length} registrations`,
      (values) => `tool exposure differs across registrations: ${values}`,
    ),
  ];
}

export function evaluatePolicy(entries: readonly InventoryEntry[], allowlist: Allowlist | null): PolicyEvaluation {
  const verdicts: RuleVerdict[] = [
    ...evaluatePerEntryRules(entries),
    ...evaluateAllowlist(entries, allowlist),
    ...parityVerdicts(entries),
  ];
  return { verdicts, findingCount: verdicts.filter((v) => v.status === "finding").length };
}

const CATALOG_ENTRIES: readonly (readonly [string, { readonly title: string; readonly rationale: string }])[] = [
  ...PER_ENTRY_RULES.map((rule): readonly [string, { readonly title: string; readonly rationale: string }] => [rule.id, { title: rule.title, rationale: rule.rationale }]),
  [
    "RH-PARITY",
    {
      title: "Cross-client registration parity",
      rationale:
        "A restriction configured for one authentication path or endpoint generation offers no evidence about another; the same logical server must present the same auth scheme, endpoint generation, and tool exposure in every client that registers it.",
    },
  ],
  [
    "RH-ALLOWLIST",
    {
      title: "Approved-server allowlist",
      rationale:
        "Every remote registration must appear on the operator-maintained approved list, so unapproved servers are a finding the moment they appear rather than a discovery during the next audit.",
    },
  ],
];

export const RULE_CATALOG: ReadonlyMap<string, { readonly title: string; readonly rationale: string }> = new Map(CATALOG_ENTRIES);
