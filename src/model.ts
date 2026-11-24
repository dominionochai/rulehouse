import type { CredentialOrigin, SecretFingerprint } from "./lib/secrets.js";

/**
 * Why a configuration entry could not be turned into an inventory item.
 * Diagnostics ride alongside results everywhere: reluctance to fail loudly is
 * deliberate, because a single malformed client file must never cost the
 * security team visibility into the rest of the fleet.
 */
export interface ScanDiagnostic {
  readonly source: string;
  readonly subject: string;
  readonly message: string;
}

export type ClientFormat = "claude-desktop" | "claude-code" | "cursor" | "mcp-json" | "vscode";

export interface SourceLocation {
  readonly file: string;
  /**
   * JSON pointer to the server entry within the parsed document, e.g.
   * `/mcpServers/atlassian` — enough for an engineer to jump straight to the
   * evidence without re-running anything.
   */
  readonly pointer: string;
  readonly format: ClientFormat;
}

/** Endpoint shape classes that carry distinct security consequences. */
export type EndpointClass =
  | "atlassian-v2"
  | "atlassian-v1"
  | "atlassian-sse-legacy"
  | "https-remote"
  | "insecure-remote"
  | "local"
  | "unparseable-url";

export type Transport = "remote" | "local";

export type Severity = "critical" | "high" | "medium" | "low";

interface AuthCommon {
  readonly credential: SecretFingerprint | null;
  readonly problem: string | null;
}

export type AuthView =
  | { readonly kind: "oauth" }
  | ({ readonly kind: "api-token"; readonly scheme: "basic" | "bearer" | "unspecified"; readonly username: string | null } & AuthCommon)
  | ({ readonly kind: "credential-header"; readonly header: string } & AuthCommon)
  | { readonly kind: "unknown"; readonly reason: string };

/**
 * One configured server as seen from one client configuration file. The same
 * server legitimately appears once per client — that repetition is what makes
 * cross-client policy parity checkable, so entries are never deduplicated
 * away, only grouped by `serverKey` when the analysis calls for it.
 */
export interface InventoryEntry {
  readonly client: ClientFormat;
  readonly serverName: string;
  readonly transport: Transport;
  /** Full URL including query parameters (`?tools=…` matters). */
  readonly url: string | null;
  readonly serverKey: string;
  readonly endpointClass: EndpointClass;
  readonly auth: AuthView;
  /** Raw `tools=` query parameter values when present, else null. */
  readonly toolsOverride: readonly string[] | null;
  readonly source: SourceLocation;
}

/**
 * Canonical identity of an MCP server behind possibly-divergent registrations.
 * Atlassian's endpoint generations (`/v1/mcp`, `/v1/mcp/authv2`, `/v2/mcp`,
 * `/v1/sse`) all target the same logical server, so they collapse to a shared
 * key — that is what lets the parity rule catch a v1-in-one-client,
 * v2-in-another drift that a raw-URL grouping would silently split in two.
 */
export function serverKeyForUrl(urlText: string): string {
  let parsed: URL;
  try {
    parsed = new URL(urlText);
  } catch {
    return `unparseable:${urlText}`;
  }
  const host = parsed.host.toLowerCase();
  if (parsed.host === "") {
    return `unparseable:${urlText}`;
  }
  const path = parsed.pathname.replace(/\/+$/, "") || "/";
  if (host === "mcp.atlassian.com") {
    return "atlassian:https://mcp.atlassian.com";
  }
  return `remote:${parsed.protocol}//${host}${path}`;
}

export function endpointClassForUrl(urlText: string): EndpointClass {
  let parsed: URL;
  try {
    parsed = new URL(urlText);
  } catch {
    return "unparseable-url";
  }
  if (parsed.host === "") return "unparseable-url";
  const isHttps = parsed.protocol === "https:";
  if (parsed.host.toLowerCase() === "mcp.atlassian.com") {
    if (!isHttps) return "insecure-remote";
    if (parsed.pathname === "/v2/mcp") return "atlassian-v2";
    if (parsed.pathname === "/v1/mcp" || parsed.pathname === "/v1/mcp/authv2") return "atlassian-v1";
    if (parsed.pathname === "/v1/sse") return "atlassian-sse-legacy";
    return isHttps ? "atlassian-v2" : "insecure-remote";
  }
  return isHttps ? "https-remote" : "insecure-remote";
}

export interface FingerprintedInput {
  /** Path as given on the command line, stable across a scan. */
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
}

export type { CredentialOrigin, SecretFingerprint };

/** Comparison key the parity rule uses: OAuth vs each token scheme vs opaque credential headers. */
export function authKey(auth: AuthView): string {
  switch (auth.kind) {
    case "oauth":
      return "oauth";
    case "api-token":
      return `token:${auth.scheme}`;
    case "credential-header":
      return `header:${auth.header.toLowerCase()}`;
    case "unknown":
      return `unknown:${auth.reason}`;
  }
}
