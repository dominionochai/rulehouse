import { basename } from "node:path";
import type { Json } from "./lib/json.js";
import {
  decomposeAuthorizationHeader,
  envReference,
  type SecretFingerprint,
  fingerprintEnvSecret,
  fingerprintInlineSecret,
  unresolvedSecret,
} from "./lib/secrets.js";
import {
  endpointClassForUrl,
  serverKeyForUrl,
  type ClientFormat,
  type InventoryEntry,
  type AuthView,
  type ScanDiagnostic,
  type SourceLocation,
  type Transport,
} from "./model.js";

export interface ParseResult {
  readonly entries: readonly InventoryEntry[];
  readonly diagnostics: readonly ScanDiagnostic[];
}

export type ResolveEnv = (name: string) => string | undefined;

export const resolveFromProcessEnv: ResolveEnv = (name) => process.env[name];

/**
 * Header names that carry credentials when they appear in an MCP server
 * entry — a curated allowlist rather than a pattern, because a loose pattern
 * like "contains 'key'" would flood reports with false findings (e.g.
 * `X-Monotoken`) or, worse, train users to ignore findings.
 */
const CREDENTIALISH_HEADERS = new Set([
  "authorization",
  "x-api-key",
  "api-key",
  "apikey",
  "x-auth-token",
  "auth-token",
  "x-auth",
  "x-token",
  "x-access-token",
  "access-token",
  "private-token",
  "x-private-token",
]);

/**
 * Assigns each recognized filename pattern its provenance. Provenance matters
 * for the parity rule (Claude Code and Cursor files share one vocabulary but
 * belong to different agents) and for the report's evidence trail.
 */
export function formatForPath(path: string, documentHasKeyServers: boolean): ClientFormat {
  const name = basename(path);
  if (name === "claude_desktop_config.json") return "claude-desktop";
  if (path.includes("/.cursor/")) return "cursor";
  if (path.includes("/.vscode/")) return "vscode";
  if (name === ".mcp.json") return "claude-code";
  return documentHasKeyServers ? "vscode" : "mcp-json";
}

export function parseDocument(
  document: Json,
  file: string,
  resolveEnv: ResolveEnv = resolveFromProcessEnv,
): ParseResult {
  if (typeof document !== "object" || document === null || Array.isArray(document)) {
    return { entries: [], diagnostics: [diag(file, "$", "top-level document is not a JSON object")] };
  }
  const doc = document as { readonly [key: string]: Json };

  const keys = Object.keys(doc);
  const containerKey = keys.includes("mcpServers") ? "mcpServers" : keys.includes("servers") ? "servers" : null;
  if (containerKey === null) {
    return { entries: [], diagnostics: [diag(file, "$", 'no "mcpServers" or "servers" container found')] };
  }

  const container = doc[containerKey];
  if (typeof container !== "object" || container === null || Array.isArray(container)) {
    return { entries: [], diagnostics: [diag(file, `/${containerKey}`, `"${containerKey}" is not an object`)] };
  }

  const format = formatForPath(file, containerKey === "servers");
  const entries: InventoryEntry[] = [];
  const diagnostics: ScanDiagnostic[] = [];

  const containerRecord = container as { readonly [key: string]: Json };
  for (const [serverName, rawEntry] of Object.entries(containerRecord)) {
    if (typeof rawEntry !== "object" || rawEntry === null || Array.isArray(rawEntry)) {
      diagnostics.push(diag(file, `/${containerKey}/${serverName}`, "server entry is not an object"));
      continue;
    }
    const built = buildEntry(rawEntry as { readonly [key: string]: Json }, serverName, `/${containerKey}/${serverName}`, file, format, resolveEnv);
    entries.push(...built.entries);
    diagnostics.push(...built.diagnostics);
  }

  return { entries, diagnostics };
}

function diag(file: string, subject: string, message: string): ScanDiagnostic {
  return { source: file, subject, message };
}

function buildEntry(
  entry: { readonly [key: string]: Json },
  serverName: string,
  pointer: string,
  file: string,
  format: ClientFormat,
  resolveEnv: ResolveEnv,
): ParseResult {
  const source: SourceLocation = { file, pointer, format };

  const transport = transportOf(entry);
  if (transport === null) {
    return { entries: [], diagnostics: [diag(file, pointer, "entry has neither a remote url nor a local command")] };
  }

  const { credentialPairs, pairDiagnostics } = readCredentialPairs(entry, file, pointer);
  const { auth } = extractAuth(credentialPairs, resolveEnv);
  const diagnostics = [...pairDiagnostics];

  if (transport === "local") {
    const command = entry["command"];
    if (typeof command !== "string") {
      return { entries: [], diagnostics: [diag(file, pointer, "local command is not a string")] };
    }
    const argumentList = arrayOfStrings(entry["args"]);
    if (entry["args"] !== undefined && entry["args"] !== null && (!Array.isArray(entry["args"]) || argumentList.length !== (entry["args"] as readonly unknown[]).length)) {
      diagnostics.push(diag(file, `${pointer}/args`, "args is not an array of strings; non-string items were skipped in the command line"));
    }
    return {
      entries: [
        {
          client: format,
          serverName,
          transport,
          url: null,
          serverKey: `local:${[command, ...argumentList].join(" ")}`,
          endpointClass: "local",
          auth,
          toolsOverride: null,
          source,
        },
      ],
      diagnostics,
    };
  }

  const urlText = entry["url"];
  if (typeof urlText !== "string") {
    return { entries: [], diagnostics: [diag(file, pointer, "remote entry url is not a string")] };
  }

  return {
    entries: [
      {
        client: format,
        serverName,
        transport: "remote",
        url: urlText,
        serverKey: serverKeyForUrl(urlText),
        endpointClass: endpointClassForUrl(urlText),
        auth,
        toolsOverride: toolsOverrideOf(urlText),
        source,
      },
    ],
    diagnostics,
  };
}

function transportOf(entry: { readonly [key: string]: Json }): Transport | null {
  if (typeof entry["url"] === "string" && entry["url"].length > 0) return "remote";
  if (typeof entry["command"] === "string" && entry["command"].length > 0) return "local";
  return null;
}

function toolsOverrideOf(urlText: string): readonly string[] | null {
  try {
    const values = new URL(urlText).searchParams.getAll("tools");
    return values.length > 0 ? values : null;
  } catch {
    return null;
  }
}

function arrayOfStrings(value: unknown): readonly string[] {
  if (typeof value !== "object" || value === null || !Array.isArray(value)) return [];
  return value.filter((element): element is string => typeof element === "string");
}

/**
 * Credential-carrying values flow through one map whether declared under
 * `headers` (remote entries) or `env` (stdio entries): the security question
 * is identical — did someone inline a secret into a file, and does the
 * environment actually hold the referenced value. Only the first
 * credential-bearing pair becomes the entry's auth view; additional ones can
 * legitimately exist but are not folded into a single view, which is why
 * `readCredentialPairs` reports them through diagnostics rather than
 * discarding them.
 */
function readCredentialPairs(
  entry: { readonly [key: string]: Json },
  file: string,
  pointer: string,
): {
  readonly credentialPairs: readonly (readonly [string, string])[];
  readonly pairDiagnostics: readonly ScanDiagnostic[];
} {
  const credentialPairs: (readonly [string, string])[] = [];
  const pairDiagnostics: ScanDiagnostic[] = [];
  for (const blockKey of ["headers", "env"] as const) {
    const block = entry[blockKey];
    if (block === undefined) continue;
    if (typeof block !== "object" || block === null || Array.isArray(block)) {
      pairDiagnostics.push(diag(file, `${pointer}/${blockKey}`, `${blockKey} is not an object; credential values in it were not evaluated`));
      continue;
    }
    for (const [name, value] of Object.entries(block)) {
      if (typeof value === "string") credentialPairs.push([name, value] as const);
      else pairDiagnostics.push(diag(file, `${pointer}/${blockKey}/${name}`, `${blockKey} value is not a string; not evaluated`));
    }
  }
  return { credentialPairs, pairDiagnostics };
}

function extractAuth(
  credentialPairs: readonly (readonly [string, string])[],
  resolveEnv: ResolveEnv,
): { readonly auth: AuthView } {
  const authorization = credentialPairs.find(([name]) => name.toLowerCase() === "authorization");
  if (authorization !== undefined) {
    const parts = decomposeAuthorizationHeader(authorization[1], resolveEnv);
    if (parts.malformed !== null) {
      return { auth: { kind: "unknown", reason: `malformed Authorization header: ${parts.malformed}` } };
    }
    if (parts.scheme === null || parts.secret === null) {
      return { auth: { kind: "unknown", reason: `unsupported Authorization scheme "${parts.scheme ?? "none"}"` } };
    }
    return {
      auth: {
        kind: "api-token",
        scheme: parts.scheme === "env" ? "unspecified" : parts.scheme,
        username: parts.username,
        credential: parts.secret,
        problem: parts.secret.origin === "unresolved" ? `environment variable ${parts.secret.envVar ?? "?"} is not set in this shell` : null,
      },
    };
  }

  const credentialish = (name: string): boolean => CREDENTIALISH_HEADERS.has(name.toLowerCase().replace(/_/g, "-"));
  for (const [name, value] of credentialPairs) {
    if (!credentialish(name)) continue;
    const env = envReference(value);
    const resolved = env === null ? undefined : resolveEnv(env.name);
    const credential: SecretFingerprint = env === null
      ? fingerprintInlineSecret(value)
      : resolved !== undefined && resolved.length > 0
        ? fingerprintEnvSecret(resolved, env.name)
        : unresolvedSecret(env.name);
    return {
      auth: {
        kind: "credential-header",
        header: name,
        credential,
        problem: credential.origin === "unresolved" ? `environment variable ${env?.name ?? "?"} is not set in this shell` : null,
      },
    };
  }

  return { auth: { kind: "oauth" } };
}
