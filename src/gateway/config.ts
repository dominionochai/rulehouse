import type { ScanDiagnostic } from "../model.js";
import { isJsonObject, parseLooseJson, type Json } from "../lib/json.js";
import type { JsonObject } from "../lib/json.js";
import { decomposeAuthorizationHeader } from "../lib/secrets.js";
import type { ProvenanceTrust } from "../provenance.js";

export type { ProvenanceTrust };
const TRUSTS: readonly ProvenanceTrust[] = ["trusted", "untrusted", "unverified"];

export type IdentityKind = "user" | "service-account" | "agent";
const IDENTITY_KINDS: readonly IdentityKind[] = ["user", "service-account", "agent"];

export interface GatewayIdentity {
  readonly name: string;
  readonly kind: IdentityKind;
  /**
   * Full SHA-256 digest of the client key, `sha256:<64 hex>`. Only the digest
   * is configured; the key itself is presented per-request by the client and
   * verified with a constant-time comparison.
   */
  readonly keyHash: string;
}

export type GatewayEffect = "allow" | "deny";

export interface ProvenanceCheck {
  /** Name of the tool-call argument whose content must resolve in the registry. */
  readonly argument: string;
  /**
   * Declared trust values that satisfy the check. Content with no registry
   * record (`unclassified`) satisfies nothing: a rule can only ever trust
   * content that someone explicitly declared.
   */
  readonly requireTrust: readonly ProvenanceTrust[];
}

export interface GatewayRule {
  readonly id: string;
  /** Names this rule applies to; `null` matches every identity. */
  readonly identities: readonly string[] | null;
  readonly tools: readonly string[];
  readonly effect: GatewayEffect;
  /** Only meaningful with `effect: "allow"`. */
  readonly approvalRequired: boolean;
  /**
   * Provenance conditions on the rule. A matched rule applies only if every
   * check resolves to an accepted declared trust; otherwise evaluation falls
   * through to later rules. Untrusted content therefore cannot ride on an
   * allow rule written for trusted work.
   */
  readonly provenanceChecks: readonly ProvenanceCheck[];
}

export interface GatewayPolicies {
  readonly defaultEffect: GatewayEffect;
  readonly rules: readonly GatewayRule[];
}

export interface GatewayUpstream {
  readonly url: string;
  /**
   * Environment variable holding the upstream credential the gateway presents
   * to the upstream MCP server. With `credentialScheme` set ("basic",
   * "bearer") the header is `<Scheme> <value>`; otherwise the variable's
   * whole value is expected to be a scheme-prefixed header value verbatim
   * (e.g. Atlassian's `Basic base64(email:api_token)`).
   */
  readonly credentialEnv: string;
  readonly credentialScheme: string | null;
}

export interface GatewayListen {
  readonly host: string;
  readonly port: number;
  readonly path: string;
}

const DEFAULT_LISTEN: GatewayListen = { host: "127.0.0.1", port: 8080, path: "/mcp" };
const KEY_HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;

/**
 * Opt-in acknowledgement that requests reach the gateway through a trusted
 * authenticating proxy: the named header carries the identity name an
 * already-authenticated party acts as. Because the gateway is loopback-only
 * and cannot verify who set the header, enabling this widens the trust
 * boundary to every process that can reach the listener; configuration and
 * startup output say so, and the decision ledger records the basis per
 * request (`forwarded-header`, versus `bearer-key`). Clients that present a
 * bearer key are never affected, a bearer key that fails to authenticate is
 * never downgraded to a forwarded identity, and an asserted value must name
 * a configured identity exactly.
 */
export interface GatewayForwardedIdentity {
  /** Lower-case header name the trusted proxy sets. */
  readonly header: string;
}

export interface GatewayConfig {
  readonly source: string;
  readonly listen: GatewayListen;
  readonly upstream: GatewayUpstream;
  readonly identities: readonly GatewayIdentity[];
  readonly policies: GatewayPolicies;
  readonly ledgerPath: string;
  /**
   * When set, the path of a provenance registry (an append-only chain of
   * `ProvenanceRecord`s). Re-read per request like approvals, so a
   * re-classification takes effect immediately.
   */
  readonly provenancePath: string | null;
  /**
   * When set, `approval-required` denials become allows once the decision id
   * appears in this newline-delimited file. Approvals are re-checked per
   * request, never cached, so revoking an approval takes effect immediately.
   */
  readonly approvalsPath: string | null;
  /** Proxy-asserted identity trust, or null (the default) when disabled. */
  readonly trustForwardedIdentity: GatewayForwardedIdentity | null;
}

/**
 * Loads a gateway policy document, applying the same scanner doctrine as the
 * inventory side: no throw, every problem is a diagnostic naming the exact
 * field, and `config` is null unless the document was good enough to enforce.
 */
export function readGatewayConfig(
  text: string,
  source: string,
  resolveEnv: (name: string) => string | undefined,
): { readonly config: GatewayConfig | null; readonly diagnostics: readonly ScanDiagnostic[] } {
  const diagnostics: ScanDiagnostic[] = [];
  const fail = (subject: string, message: string): void => {
    diagnostics.push({ source, subject: `/gateway${subject}`, message });
  };

  const parsed = parseLooseJson(text, source);
  if (parsed.value === null) {
    for (const d of parsed.diagnostics) diagnostics.push({ source, subject: "/gateway", message: d.message });
    return { config: null, diagnostics };
  }

  const root = asObject(parsed.value);
  if (root === null) {
    fail("", "top-level value must be an object");
    return { config: null, diagnostics };
  }

  const upstream = readUpstream(root["upstream"], resolveEnv, fail);
  const identities = readIdentities(root["identities"], fail);
  const provenancePath = readProvenancePath(root["provenance"], fail);
  const policies = readPolicies(root["policies"], identities, provenancePath !== null, fail);
  const listen = readListen(root["listen"], fail);
  const ledgerPath = readLedgerPath(root["ledger"], fail);
  const approvalsPath = readOptionalString(root["approvals"]);
  const trustForwardedIdentity = readForwardedIdentity(root["trustForwardedIdentity"], fail);

  const viable = upstream !== null && identities !== null && policies !== null && listen !== null;
  const config: GatewayConfig | null = viable && listen !== null
    ? {
        source,
        listen,
        upstream,
        identities,
        policies,
        ledgerPath,
        provenancePath,
        approvalsPath,
        trustForwardedIdentity,
      }
    : null;
  return { config, diagnostics };
}

const DEFAULT_LEDGER_PATH = "rulehouse-gateway-ledger.jsonl";

function readUpstream(
  value: Json | undefined,
  resolveEnv: (name: string) => string | undefined,
  fail: (subject: string, message: string) => void,
): GatewayUpstream | null {
  const obj = asObject(value);
  if (obj === null) {
    fail("/upstream", "is required and must be an object");
    return null;
  }
  const urlValue = asString(obj["url"]);
  if (urlValue === null) {
    fail("/upstream/url", "is required and must be a string");
    return null;
  }
  let url: URL;
  try {
    url = new URL(urlValue);
  } catch {
    fail("/upstream/url", `is not a valid URL: ${urlValue}`);
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    fail("/upstream/url", `must be an http(s) URL, got ${url.protocol}`);
    return null;
  }

  const credentialEnv = asString(obj["credentialEnv"]);
  if (credentialEnv === null) {
    fail("/upstream/credentialEnv", "is required: the gateway must know which env var carries its upstream credential");
    return null;
  }
  const scheme = asString(obj["credentialScheme"])?.toLowerCase() ?? null;
  if (scheme !== null && scheme !== "basic" && scheme !== "bearer") {
    fail("/upstream/credentialScheme", `must be "basic", "bearer", or omitted, got "${scheme}"`);
    return null;
  }

  const resolved = resolveEnv(credentialEnv);
  if (resolved !== undefined) {
    const headerValue = scheme === null ? resolved : `${scheme} ${resolved}`;
    const parts = decomposeAuthorizationHeader(headerValue, () => undefined);
    if (parts.malformed !== null || parts.scheme === null) {
      fail("/upstream/credentialEnv", `resolves to a credential the gateway cannot classify (${parts.malformed ?? "no recognizable scheme"})`);
      return null;
    }
  }

  return { url: urlValue, credentialEnv, credentialScheme: scheme };
}

function readIdentities(
  value: Json | undefined,
  fail: (subject: string, message: string) => void,
): readonly GatewayIdentity[] | null {
  if (!Array.isArray(value)) {
    fail("/identities", "is required and must be an array");
    return null;
  }
  const identities: GatewayIdentity[] = [];
  const seen = new Set<string>();
  let ok = true;
  for (const [index, element] of value.entries()) {
    const obj = asObject(element);
    if (obj === null) {
      fail(`/identities/${index}`, "must be an object");
      ok = false;
      continue;
    }
    const name = asString(obj["name"]);
    const kind = asString(obj["kind"]) ?? "service-account";
    const keyHash = asString(obj["keyHash"]);
    if (name === null || name.length === 0) {
      fail(`/identities/${index}/name`, "is required and must be a non-empty string");
      ok = false;
      continue;
    }
    if (seen.has(name)) {
      fail(`/identities/${index}/name`, `duplicates identity name "${name}"`);
      ok = false;
      continue;
    }
    if (!IDENTITY_KINDS.includes(kind as IdentityKind)) {
      fail(`/identities/${index}/kind`, `must be one of ${IDENTITY_KINDS.join(", ")}, got "${kind}"`);
      ok = false;
      continue;
    }
    if (keyHash === null || !KEY_HASH_PATTERN.test(keyHash)) {
      fail(`/identities/${index}/keyHash`, `must be "sha256:" followed by 64 lowercase hex characters (sha256 of the client key)`);
      ok = false;
      continue;
    }
    seen.add(name);
    identities.push({ name, kind: kind as IdentityKind, keyHash });
  }
  return ok ? identities : null;
}

function readProvenancePath(
  value: Json | undefined,
  fail: (subject: string, message: string) => void,
): string | null {
  if (value === undefined) return null;
  const obj = asObject(value);
  if (obj === null) {
    fail("/provenance", "must be an object with a \"path\" field");
    return null;
  }
  const path = asString(obj["path"]);
  if (path === null || path.length === 0) {
    fail("/provenance/path", "must be a non-empty file path");
    return null;
  }
  return path;
}

function readPolicies(
  value: Json | undefined,
  identities: readonly GatewayIdentity[] | null,
  provenanceConfigured: boolean,
  fail: (subject: string, message: string) => void,
): GatewayPolicies | null {
  const obj = asObject(value);
  if (obj === null) {
    fail("/policies", "is required and must be an object");
    return null;
  }
  const defaultEffect = asString(obj["defaultEffect"]) ?? "deny";
  if (defaultEffect !== "allow" && defaultEffect !== "deny") {
    fail("/policies/defaultEffect", `must be "allow" or "deny" (defaults to "deny"), got "${defaultEffect}"`);
    return null;
  }
  if (!Array.isArray(obj["rules"])) {
    fail("/policies/rules", "is required and must be an array");
    return null;
  }

  const knownNames = new Set((identities ?? []).map((identity) => identity.name));
  const rules: GatewayRule[] = [];
  const seenIds = new Set<string>();
  let ok = true;
  for (const [index, element] of obj["rules"].entries()) {
    const ruleObj = asObject(element);
    if (ruleObj === null) {
      fail(`/policies/rules/${index}`, "must be an object");
      ok = false;
      continue;
    }
    const id = asString(ruleObj["id"]);
    const tools = asStringArray(ruleObj["tools"]);
    const identitiesField = ruleObj["identities"];
    const ruleIdentities = identitiesField === undefined ? null : asStringArray(identitiesField);
    const effect = asString(ruleObj["effect"]);
    const approvalRequired = ruleObj["approval"] === "required";
    const checks = readProvenanceChecks(ruleObj["provenanceChecks"], index, fail);

    if (id === null || id.length === 0) {
      fail(`/policies/rules/${index}/id`, "is required and must be a non-empty string");
      ok = false;
      continue;
    }
    if (seenIds.has(id)) {
      fail(`/policies/rules/${index}/id`, `duplicates rule id "${id}"`);
      ok = false;
      continue;
    }
    if (tools === null || tools.length === 0 || tools.some((tool) => tool.length === 0)) {
      fail(`/policies/rules/${index}/tools`, "is required and must be a non-empty array of non-empty tool-name patterns");
      ok = false;
      continue;
    }
    if (effect !== "allow" && effect !== "deny") {
      fail(`/policies/rules/${index}/effect`, `must be "allow" or "deny", got "${effect ?? "non-string"}"`);
      ok = false;
      continue;
    }
    if (ruleIdentities !== null && identities !== null && ruleIdentities.some((name) => !knownNames.has(name))) {
      const unknown = ruleIdentities.filter((name) => !knownNames.has(name));
      fail(`/policies/rules/${index}/identities`, `references unknown identity name(s): ${unknown.join(", ")}`);
      ok = false;
      continue;
    }
    if (effect === "deny" && approvalRequired) {
      fail(`/policies/rules/${index}/approval`, "approval cannot be required on a deny rule; the request is blocked regardless");
      ok = false;
      continue;
    }
    if (checks === null) {
      ok = false;
      continue;
    }
    if (checks.length > 0 && !provenanceConfigured) {
      fail(`/policies/rules/${index}/provenanceChecks`, `rule "${id}" consults provenance but no top-level "provenance" path is configured; every check would resolve as unavailable`);
      ok = false;
      continue;
    }
    seenIds.add(id);
    rules.push({ id, identities: ruleIdentities, tools, effect, approvalRequired, provenanceChecks: checks });
  }
  return ok ? { defaultEffect, rules } : null;
}

function readProvenanceChecks(
  value: Json | undefined,
  ruleIndex: number,
  fail: (subject: string, message: string) => void,
): readonly ProvenanceCheck[] | null {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    fail(`/policies/rules/${ruleIndex}/provenanceChecks`, "must be an array of { argument, requireTrust } objects");
    return null;
  }
  const checks: ProvenanceCheck[] = [];
  let ok = true;
  for (const [index, element] of value.entries()) {
    const obj = asObject(element);
    if (obj === null) {
      fail(`/policies/rules/${ruleIndex}/provenanceChecks/${index}`, "must be an object");
      ok = false;
      continue;
    }
    const argument = asString(obj["argument"]);
    if (argument === null || argument.length === 0) {
      fail(`/policies/rules/${ruleIndex}/provenanceChecks/${index}/argument`, "is required and must be a non-empty argument name");
      ok = false;
      continue;
    }
    const requireTrust = asStringArray(obj["requireTrust"]);
    if (requireTrust === null || requireTrust.length === 0) {
      fail(`/policies/rules/${ruleIndex}/provenanceChecks/${index}/requireTrust`, `must be a non-empty array drawn from ${TRUSTS.join(", ")}`);
      ok = false;
      continue;
    }
    const invalid = requireTrust.filter((trust) => !TRUSTS.includes(trust as ProvenanceTrust));
    if (invalid.length > 0) {
      fail(`/policies/rules/${ruleIndex}/provenanceChecks/${index}/requireTrust`, `unknown trust value(s): ${invalid.join(", ")}; content with no registry record satisfies nothing`);
      ok = false;
      continue;
    }
    checks.push({ argument, requireTrust: requireTrust as readonly ProvenanceTrust[] });
  }
  return ok ? checks : null;
}

function readListen(
  value: Json | undefined,
  fail: (subject: string, message: string) => void,
): GatewayListen | null {
  if (value === undefined) return { ...DEFAULT_LISTEN };
  const obj = asObject(value);
  if (obj === null) {
    fail("/listen", "must be an object");
    return null;
  }
  const host = asString(obj["host"]) ?? DEFAULT_LISTEN.host;
  let ok = true;
  if (host !== "127.0.0.1" && host !== "localhost") {
    fail("/listen/host", `must be "127.0.0.1" or "localhost"; binds are restricted to loopback (run the gateway behind a TLS-terminating proxy for remote access)`);
    ok = false;
  }
  const requestedPort = obj["port"] ?? DEFAULT_LISTEN.port;
  const port = typeof requestedPort === "number" && Number.isInteger(requestedPort) && requestedPort >= 0 && requestedPort <= 65535
    ? requestedPort
    : null;
  if (port === null) {
    fail("/listen/port", "must be an integer between 0 and 65535");
    ok = false;
  }
  const path = asString(obj["path"]) ?? DEFAULT_LISTEN.path;
  if (!path.startsWith("/")) {
    fail("/listen/path", `must start with "/", got "${path}"`);
    ok = false;
  }
  return ok && port !== null ? { host, port, path } : null;
}

function readLedgerPath(
  value: Json | undefined,
  fail: (subject: string, message: string) => void,
): string {
  if (value === undefined) return DEFAULT_LEDGER_PATH;
  const obj = asObject(value);
  if (obj === null) {
    fail("/ledger", "must be an object with a \"path\" field");
    return DEFAULT_LEDGER_PATH;
  }
  const path = asString(obj["path"]);
  if (path === null || path.length === 0) {
    fail("/ledger/path", "must be a non-empty file path");
    return DEFAULT_LEDGER_PATH;
  }
  return path;
}

/**
 * Header names that already carry credentials or transport state on the
 * mediated path. Selecting one of them as the identity header would either
 * recycle a credential as an identity or collide with routing state the
 * gateway itself forwards, so the configuration is refused outright.
 */
const USURPED_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "mcp-session-id",
  "mcp-protocol-version",
  "traceparent",
]);

function readForwardedIdentity(
  value: Json | undefined,
  fail: (subject: string, message: string) => void,
): GatewayForwardedIdentity | null {
  if (value === undefined) return null;
  const obj = asObject(value);
  if (obj === null) {
    fail("/trustForwardedIdentity", 'must be an object with a "header" field');
    return null;
  }
  const header = asString(obj["header"]);
  if (header === null || header.length === 0) {
    fail("/trustForwardedIdentity/header", "is required when trustForwardedIdentity is configured: the header whose value names a configured identity");
    return null;
  }
  const normalized = header.toLowerCase();
  if (!/^[a-z0-9][a-z0-9-]*$/.test(normalized)) {
    fail("/trustForwardedIdentity/header", `"${header}" is not a valid header name`);
    return null;
  }
  if (USURPED_HEADERS.has(normalized)) {
    fail("/trustForwardedIdentity/header", `"${header}" already carries credentials or transport state on the mediated path and cannot carry a proxy-asserted identity`);
    return null;
  }
  return { header: normalized };
}

function readOptionalString(value: Json | undefined): string | null {
  const obj = asObject(value);
  if (obj === null) return null;
  return asString(obj["path"]);
}

function asObject(value: Json | undefined): JsonObject | null {
  return value === undefined ? null : isJsonObject(value) ? value : null;
}

function asString(value: Json | undefined): string | null {
  return typeof value === "string" ? value : null;
}

function asStringArray(value: Json | undefined): readonly string[] | null {
  return Array.isArray(value) && value.every((entry) => typeof entry === "string")
    ? (value as readonly string[])
    : null;
}
