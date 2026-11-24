import { authKey, type InventoryEntry } from "./model.js";

/**
 * Change detection between two snapshots. The design question — "what counts
 * as a meaningful change?" — is answered by the facet set below: a
 * registration changed if and only if one of these facets changed. Adding a
 * facet later automatically extends change detection, the exit code, and the
 * report, because nothing else knows the facet list.
 */
const FACETS = ["endpoint", "url", "tools", "auth", "credential", "username"] as const;
export type FacetName = (typeof FACETS)[number];

export interface FieldChange {
  readonly field: FacetName;
  readonly from: string;
  readonly to: string;
}

export interface ServerChange {
  readonly serverKey: string;
  /** Registrations (client: serverName) present now but absent before. */
  readonly added: readonly string[];
  /** Registrations present before but absent now. */
  readonly removed: readonly string[];
  readonly changed: readonly { readonly location: string; readonly fields: readonly FieldChange[] }[];
}

export interface InputChange {
  readonly path: string;
  readonly from: string | null;
  readonly to: string | null;
  readonly kind: "added" | "removed" | "modified";
}

export interface SnapshotDiff {
  readonly baseline: { readonly capturedAt: string; readonly fingerprint: string };
  readonly current: { readonly capturedAt: string; readonly fingerprint: string };
  readonly inputs: readonly InputChange[];
  readonly servers: readonly ServerChange[];
  readonly changeCount: number;
  readonly summary: string;
}

function locationOf(entry: InventoryEntry): string {
  return `${entry.client}:${entry.serverName} (${entry.source.file}${entry.source.pointer})`;
}

interface FacetState {
  readonly endpoint: string;
  readonly url: string;
  readonly tools: string;
  readonly auth: string;
  readonly credential: string;
  readonly username: string;
}

function facetsOf(entry: InventoryEntry): FacetState {
  return {
    endpoint: entry.endpointClass,
    url: entry.url ?? "<none>",
    tools: entry.toolsOverride === null ? "default" : `tools=${entry.toolsOverride.join(",")}`,
    auth: authKey(entry.auth),
    credential: credentialFacet(entry),
    username: entry.auth.kind === "api-token" && entry.auth.username !== null ? entry.auth.username : "<none>",
  };
}

function credentialFacet(entry: InventoryEntry): string {
  const credential = entry.auth.kind === "api-token" || entry.auth.kind === "credential-header" ? entry.auth.credential : null;
  if (credential === null) return "<none>";
  return `${credential.origin}:${credential.fingerprint || "unresolved"}`;
}

/**
 * Compares two snapshots into a structural diff. Registration identity inside
 * a server group is (client, serverName): the same client re-registering a
 * server under a new name is reported as remove+add, which is the honest
 * description of what happened on disk.
 */
export function diffSnapshots(baseline: DiffableSnapshot, current: DiffableSnapshot): SnapshotDiff {
  const inputs = diffInputs(baseline.inputs, current.inputs);

  const baselineGroups = groupBy(baseline.inventory, (entry) => entry.serverKey);
  const currentGroups = groupBy(current.inventory, (entry) => entry.serverKey);

  const servers: ServerChange[] = [];
  for (const serverKey of union(baselineGroups.keys(), currentGroups.keys())) {
    const before = baselineGroups.get(serverKey);
    const after = currentGroups.get(serverKey);
    if (before === undefined && after !== undefined) {
      servers.push({ serverKey, added: after.map(locationOf), removed: [], changed: [] });
      continue;
    }
    if (before !== undefined && after === undefined) {
      servers.push({ serverKey, added: [], removed: before.map(locationOf), changed: [] });
      continue;
    }
    const change = diffGroup(serverKey, before!, after!);
    if (change !== null) servers.push(change);
  }

  const serverChangeCount = servers.reduce(
    (total, server) => total + server.added.length + server.removed.length + server.changed.length,
    0,
  );
  const changeCount = inputs.length + serverChangeCount;

  return {
    baseline: { capturedAt: baseline.capturedAt, fingerprint: baseline.fingerprint },
    current: { capturedAt: current.capturedAt, fingerprint: current.fingerprint },
    inputs,
    servers,
    changeCount,
    summary: summarize(inputs, servers, changeCount),
  };
}

/**
 * The snapshot fields the differ consumes. A full Snapshot satisfies this
 * structurally: byte counts and diagnostics are deliberately outside the
 * diff's vocabulary, so they can never masquerade as a content change.
 */
export interface DiffableSnapshot {
  readonly capturedAt: string;
  readonly fingerprint: string;
  readonly inputs: readonly { readonly path: string; readonly sha256: string }[];
  readonly inventory: readonly InventoryEntry[];
}

function diffInputs(
  before: readonly { readonly path: string; readonly sha256: string }[],
  after: readonly { readonly path: string; readonly sha256: string }[],
): readonly InputChange[] {
  const changes: InputChange[] = [];
  const beforeByPath = new Map(before.map((input) => [input.path, input.sha256] as const));
  const afterByPath = new Map(after.map((input) => [input.path, input.sha256] as const));
  for (const path of union(beforeByPath.keys(), afterByPath.keys())) {
    const from = beforeByPath.get(path) ?? null;
    const to = afterByPath.get(path) ?? null;
    if (from === to) continue;
    changes.push({
      path,
      from,
      to,
      kind: from === null ? "added" : to === null ? "removed" : "modified",
    });
  }
  return changes.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
}

function diffGroup(serverKey: string, before: readonly InventoryEntry[], after: readonly InventoryEntry[]): ServerChange | null {
  const byRegistration = (entries: readonly InventoryEntry[]) =>
    new Map(entries.map((entry) => [`${entry.client}::${entry.serverName}`, entry] as const));

  const beforeByRegistration = byRegistration(before);
  const afterByRegistration = byRegistration(after);

  const added: string[] = [];
  const removed: string[] = [];
  const changed: { readonly location: string; readonly fields: readonly FieldChange[] }[] = [];

  for (const [registration, entry] of afterByRegistration) {
    const prior = beforeByRegistration.get(registration);
    if (prior === undefined) {
      added.push(locationOf(entry));
      continue;
    }
    const fields = changedFacets(prior, entry);
    if (fields.length > 0) {
      changed.push({ location: locationOf(entry), fields });
    }
  }
  for (const [registration, entry] of beforeByRegistration) {
    if (!afterByRegistration.has(registration)) {
      removed.push(locationOf(entry));
    }
  }

  const isSilent = added.length === 0 && removed.length === 0 && changed.length === 0;
  return isSilent ? null : { serverKey, added, removed, changed };
}

function changedFacets(before: InventoryEntry, after: InventoryEntry): readonly FieldChange[] {
  const beforeFacets = facetsOf(before);
  const afterFacets = facetsOf(after);
  const changes: FieldChange[] = [];
  for (const facet of FACETS) {
    const from = beforeFacets[facet];
    const to = afterFacets[facet];
    if (from !== to) {
      changes.push({ field: facet, from, to });
    }
  }
  return changes;
}

function groupBy<T>(items: readonly T[], key: (item: T) => string): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    const bucket = groups.get(k);
    if (bucket === undefined) groups.set(k, [item]);
    else bucket.push(item);
  }
  return groups;
}

function union(a: Iterable<string>, b: Iterable<string>): readonly string[] {
  return [...new Set([...a, ...b])].sort((x, y) => (x < y ? -1 : x > y ? 1 : 0));
}

function summarize(inputs: readonly InputChange[], servers: readonly ServerChange[], changeCount: number): string {
  if (changeCount === 0) return "no changes detected";
  const parts: string[] = [];
  const addedServers = servers.reduce((total, s) => total + s.added.length, 0);
  const removedServers = servers.reduce((total, s) => total + s.removed.length, 0);
  const modifiedServers = servers.reduce((total, s) => total + s.changed.length, 0);
  const modifiedInputs = inputs.filter((input) => input.kind === "modified").length;
  if (addedServers > 0) parts.push(`${addedServers} registration(s) added`);
  if (removedServers > 0) parts.push(`${removedServers} registration(s) removed`);
  if (modifiedServers > 0) parts.push(`${modifiedServers} registration(s) changed`);
  if (modifiedInputs > 0) parts.push(`${modifiedInputs} configuration file(s) modified`);
  return `${changeCount} change(s): ${parts.join(", ")}`;
}
