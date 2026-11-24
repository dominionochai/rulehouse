import { readFile, writeFile } from "node:fs/promises";
import type { AuthView, ClientFormat, EndpointClass, FingerprintedInput, InventoryEntry, ScanDiagnostic, SourceLocation } from "./model.js";
import type { CredentialOrigin, SecretFingerprint } from "./lib/secrets.js";
import { canonicalize, sha256Hex, type Json } from "./lib/json.js";

/**
 * The snapshot is the audit artifact: it captures exactly what was seen, in a
 * form whose semantic content hashes to a single fingerprint. Everything
 * environment-dependent (the wall-clock timestamp, the scan root path) sits
 * outside the hash so that two engineers scanning identical bytes always
 * produce the same fingerprint — the property cross-review relies on.
 */
export interface Snapshot {
  readonly format: "rulehouse.snapshot";
  readonly version: 1;
  readonly capturedAt: string;
  readonly root: string;
  readonly fingerprint: string;
  readonly inputs: readonly FingerprintedInput[];
  readonly inventory: readonly InventoryEntry[];
  readonly diagnostics: readonly ScanDiagnostic[];
}

export const SNAPSHOT_FORMAT = "rulehouse.snapshot" as const;

/**
 * Hashes the semantic content of a scan: which files were read (with their
 * content hashes), what inventory was derived, and what the parser had to
 * say. Two scans of the same bytes produce the same value regardless of
 * machine, ordering, or capture time.
 */
export function fingerprintOf(inputs: readonly FingerprintedInput[], inventory: readonly InventoryEntry[], diagnostics: readonly ScanDiagnostic[]): string {
  return `sha256:${sha256Hex(canonicalize(asJson({ inputs, inventory: inventory.map(entryToJson), diagnostics })))}`;
}

export function snapshotOf(scan: ScanOutput, capturedAt: string): Snapshot {
  return {
    format: SNAPSHOT_FORMAT,
    version: 1,
    capturedAt,
    root: scan.root,
    fingerprint: fingerprintOf(scan.inputs, scan.inventory, scan.diagnostics),
    inputs: scan.inputs,
    inventory: scan.inventory,
    diagnostics: scan.diagnostics,
  };
}

export interface ScanOutput {
  readonly root: string;
  readonly inputs: readonly FingerprintedInput[];
  readonly inventory: readonly InventoryEntry[];
  readonly diagnostics: readonly ScanDiagnostic[];
}

/* --------------------------------------------------------------- */
/* Serialization                                                    */
/* --------------------------------------------------------------- */

function asJson(value: unknown): Json {
  return value as Json;
}

export function snapshotToDocument(snapshot: Snapshot): Json {
  return asJson({
    format: snapshot.format,
    version: snapshot.version,
    capturedAt: snapshot.capturedAt,
    root: snapshot.root,
    fingerprint: snapshot.fingerprint,
    inputs: snapshot.inputs,
    inventory: snapshot.inventory.map(entryToJson),
    diagnostics: snapshot.diagnostics,
  });
}

function entryToJson(entry: InventoryEntry): Json {
  return asJson({
    client: entry.client,
    serverName: entry.serverName,
    transport: entry.transport,
    url: entry.url,
    serverKey: entry.serverKey,
    endpointClass: entry.endpointClass,
    auth: authToJson(entry.auth),
    toolsOverride: entry.toolsOverride,
    source: entry.source,
  });
}

function authToJson(auth: AuthView): Json {
  switch (auth.kind) {
    case "oauth":
      return asJson({ kind: "oauth", scheme: null, username: null, header: null, credential: null, problem: null, reason: null });
    case "api-token":
      return asJson({ kind: auth.kind, scheme: auth.scheme, username: auth.username, header: null, credential: auth.credential, problem: auth.problem, reason: null });
    case "credential-header":
      return asJson({ kind: auth.kind, scheme: null, username: null, header: auth.header, credential: auth.credential, problem: auth.problem, reason: null });
    case "unknown":
      return asJson({ kind: auth.kind, scheme: null, username: null, header: null, credential: null, problem: null, reason: auth.reason });
  }
}

/* --------------------------------------------------------------- */
/* Deserialization                                                  */
/* --------------------------------------------------------------- */

export type ReadResult =
  | { readonly ok: true; readonly snapshot: Snapshot }
  | { readonly ok: false; readonly error: string };

/**
 * Parses and validates a snapshot document, then re-derives its fingerprint
 * so tampered or hand-edited files are detected rather than trusted.
 */
export async function readSnapshotFile(path: string): Promise<ReadResult> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    return { ok: false, error: `cannot read ${path}: ${(error as Error).message}` };
  }
  let document: Json;
  try {
    document = JSON.parse(text) as Json;
  } catch (error) {
    return { ok: false, error: `${path} is not valid JSON: ${(error as Error).message}` };
  }
  return snapshotFromDocument(document);
}

export function snapshotFromDocument(document: Json): ReadResult {
  const record = asRecord(document);
  if (record === null) return { ok: false, error: "snapshot document is not a JSON object" };
  if (record["format"] !== SNAPSHOT_FORMAT) return { ok: false, error: `not a ${SNAPSHOT_FORMAT} document` };
  if (record["version"] !== 1) return { ok: false, error: `unsupported snapshot version ${JSON.stringify(record["version"])}` };

  const capturedAt = asString(record["capturedAt"]);
  const root = asString(record["root"]);
  const storedFingerprint = asString(record["fingerprint"]);
  if (capturedAt === null || root === null || storedFingerprint === null) {
    return { ok: false, error: "snapshot is missing capturedAt, root, or fingerprint" };
  }

  const inputsJson = arrayOrEmpty(record["inputs"]);
  const inputs = inputsJson.flatMap((raw) => collect(inputFromJson(asRecord(raw))));
  if (inputs.length !== inputsJson.length) {
    return { ok: false, error: "snapshot contains a malformed inputs entry" };
  }
  const inventoryJson = arrayOrEmpty(record["inventory"]);
  const inventory: InventoryEntry[] = inventoryJson.flatMap((raw) => collect(entryFromJson(asRecord(raw))));
  if (inventory.length !== inventoryJson.length) {
    return { ok: false, error: "snapshot contains a malformed inventory entry" };
  }
  const diagnosticsJson = arrayOrEmpty(record["diagnostics"]);
  const diagnostics = diagnosticsJson.flatMap((raw) => collect(diagnosticFromJson(asRecord(raw))));
  if (diagnostics.length !== diagnosticsJson.length) {
    return { ok: false, error: "snapshot contains a malformed diagnostics entry" };
  }

  return {
    ok: true,
    snapshot: {
      format: SNAPSHOT_FORMAT,
      version: 1,
      capturedAt,
      root,
      fingerprint: storedFingerprint,
      inputs,
      inventory,
      diagnostics,
    },
  };
}

function collect<T>(value: T | null): readonly T[] {
  return value === null ? [] : [value];
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function arrayOrEmpty(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

function inputFromJson(record: Record<string, unknown> | null): FingerprintedInput | null {
  if (record === null) return null;
  const path = asString(record["path"]);
  const sha256 = asString(record["sha256"]);
  const bytes = record["bytes"];
  if (path === null || sha256 === null || typeof bytes !== "number" || !Number.isInteger(bytes) || bytes < 0) return null;
  return { path, sha256, bytes };
}

function diagnosticFromJson(record: Record<string, unknown> | null): ScanDiagnostic | null {
  if (record === null) return null;
  const source = asString(record["source"]);
  const subject = asString(record["subject"]);
  const message = asString(record["message"]);
  if (source === null || subject === null || message === null) return null;
  return { source, subject, message };
}

function entryFromJson(record: Record<string, unknown> | null): InventoryEntry | null {
  if (record === null) return null;
  const client = asString(record["client"]);
  const serverName = asString(record["serverName"]);
  const transport = record["transport"];
  const serverKey = asString(record["serverKey"]);
  const endpointClass = asString(record["endpointClass"]);
  const url = record["url"] === null ? null : asString(record["url"]);
  const rawTools = record["toolsOverride"];
  const toolsOverride = rawTools === null || rawTools === undefined ? null : arrayOrEmpty(rawTools).map((t) => asString(t));
  const source = sourceFromJson(asRecord(record["source"]));
  const auth = authFromJson(asRecord(record["auth"]));

  if (
    client === null || serverName === null || serverKey === null || endpointClass === null || auth === null ||
    (transport !== "remote" && transport !== "local") || url === null && transport === "remote" ||
    (toolsOverride !== null && toolsOverride.includes(null))
  ) {
    return null;
  }

  return {
    client: client as ClientFormat,
    serverName,
    transport,
    url,
    serverKey,
    endpointClass: endpointClass as EndpointClass,
    auth,
    toolsOverride: toolsOverride === null ? null : toolsOverride.map((t) => t ?? ""),
    source,
  };
}

function authFromJson(record: Record<string, unknown> | null): AuthView | null {
  if (record === null) return null;
  const credential = secretFromJson(record["credential"]);
  const problem = record["problem"] === null ? null : asString(record["problem"]);
  const username = record["username"] === null ? null : asString(record["username"]);
  switch (record["kind"]) {
    case "oauth":
      return { kind: "oauth" };
    case "api-token": {
      const scheme = record["scheme"];
      if (scheme !== "basic" && scheme !== "bearer" && scheme !== "unspecified") return null;
      if (problem === null && record["problem"] !== null) return null;
      if (username === null && record["username"] !== null) return null;
      return { kind: "api-token", scheme, username, credential, problem };
    }
    case "credential-header": {
      const header = asString(record["header"]);
      if (header === null) return null;
      if (problem === null && record["problem"] !== null) return null;
      return { kind: "credential-header", header, credential, problem };
    }
    case "unknown": {
      const reason = asString(record["reason"]);
      return reason === null ? null : { kind: "unknown", reason };
    }
    default:
      return null;
  }
}

function secretFromJson(value: unknown): SecretFingerprint | null {
  if (value === null) return null;
  const record = asRecord(value);
  if (record === null) return null;
  const origin = record["origin"];
  const fingerprint = asString(record["fingerprint"]);
  const probe = asString(record["probe"]);
  const length = record["length"];
  const envVar = record["envVar"] === null ? null : asString(record["envVar"]);
  if (origin !== "inline" && origin !== "environment" && origin !== "unresolved") return null;
  if (fingerprint === null || probe === null || typeof length !== "number") return null;
  return { origin: origin as CredentialOrigin, fingerprint, probe, length, envVar };
}

function sourceFromJson(record: Record<string, unknown> | null): SourceLocation {
  if (record === null) return { file: "", pointer: "", format: "mcp-json" };
  return {
    file: asString(record["file"]) ?? "",
    pointer: asString(record["pointer"]) ?? "",
    format: (asString(record["format"]) ?? "mcp-json") as ClientFormat,
  };
}

export async function writeSnapshotFile(snapshot: Snapshot, path: string): Promise<void> {
  await writeFile(path, `${JSON.stringify(snapshotToDocument(snapshot), null, 2)}\n`, "utf8");
}
