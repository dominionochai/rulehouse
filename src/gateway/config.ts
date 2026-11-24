import type { ScanDiagnostic } from "../model.js";
import { isJsonObject, parseLooseJson, type Json } from "../lib/json.js";
import type { JsonObject } from "../lib/json.js";
import { decomposeAuthorizationHeader } from "../lib/secrets.js";

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

export interface GatewayRule {
  readonly id: string;
  /** Names this rule applies to; `null` matches every identity. */
  readonly identities: readonly string[] | null;
  readonly tools: readonly string[];
  readonly effect: GatewayEffect;
  /** Only meaningful with `effect: "allow"`. */
  readonly approvalRequired: boolean;
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

export interface GatewayConfig {
  readonly source: string;
  readonly listen: GatewayListen;
  readonly upstream: GatewayUpstream;
  readonly identities: readonly GatewayIdentity[];
  readonly policies: GatewayPolicies;
  readonly ledgerPath: string;
  /**
   * When set, `approval-required` denials become allows once the decision id
   * appears in this newline-delimited file. Approvals are re-checked per
   * request, never cached, so revoking an approval takes effect immediately.
   */
  readonly approvalsPath: string | null;
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
  const policies = readPolicies(root["policies"], identities, fail);
  const listen = readListen(root["listen"], fail);
  const ledgerPath = readLedgerPath(root["ledger"], fail);
  const approvalsPath = readOptionalString(root["approvals"]);

  const viable = upstream !== null && identities !== null && policies !== null && listen !== null;
  const config: GatewayConfig | null = viable && listen !== null
    ? {
        source,
        listen,
        upstream,
        identities,
        policies,
        ledgerPath,
        approvalsPath,
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

function readPolicies(
  value: Json | undefined,
  identities: readonly GatewayIdentity[] | null,
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
    seenIds.add(id);
    rules.push({ id, identities: ruleIdentities, tools, effect, approvalRequired });
  }
  return ok ? { defaultEffect, rules } : null;
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
