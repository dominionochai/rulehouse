import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { parseLooseJson, sha256Hex } from "./lib/json.js";
import { parseDocument, type ResolveEnv } from "./parse.js";
import type { FingerprintedInput, InventoryEntry, ScanDiagnostic } from "./model.js";

export interface ScanOutput {
  readonly root: string;
  readonly inputs: readonly FingerprintedInput[];
  readonly inventory: readonly InventoryEntry[];
  readonly diagnostics: readonly ScanDiagnostic[];
}

/**
 * Directory names whose contents are never MCP configuration and whose
 * traversal would both slow scans and — for caches, build output, and VCS
 * internals — create misleading duplicate findings.
 */
const SKIPPED_DIRECTORIES = new Set([
  ".git",
  "node_modules",
  "dist",
  "dist-test",
  "coverage",
  "build",
  "out",
  ".venv",
  "venv",
]);

const CONFIG_BASENAMES = new Set(["claude_desktop_config.json", ".mcp.json", "mcp.json"]);

/**
 * Walks the scan root, hashes every recognized configuration file, and parses
 * each into inventory entries. Inputs are sorted by path so that the snapshot
 * fingerprint is independent of directory-listing order — a prerequisite for
 * "same bytes, same hash" reproducibility on any machine.
 */
export async function scanRoot(root: string, resolveEnv: ResolveEnv): Promise<ScanOutput> {
  const files = (await listCandidateFiles(root)).sort();

  const inputs: FingerprintedInput[] = [];
  const inventory: InventoryEntry[] = [];
  const diagnostics: ScanDiagnostic[] = [];

  for (const relativePath of files) {
    const path = join(root, relativePath);
    let bytes: Buffer;
    try {
      bytes = await readFile(path);
    } catch (error) {
      diagnostics.push({ source: relativePath, subject: "$", message: `unreadable: ${(error as Error).message}` });
      continue;
    }
    inputs.push({ path: relativePath, sha256: sha256Hex(bytes), bytes: bytes.length });
    const parsed = parseLooseJson(bytes.toString("utf8"), relativePath);
    diagnostics.push(...parsed.diagnostics.map((d) => ({ source: d.source, subject: "$", message: d.message })));
    const result = parseDocument(parsed.value, relativePath, resolveEnv);
    inventory.push(...result.entries);
    diagnostics.push(...result.diagnostics);
  }

  return { root, inputs, inventory, diagnostics };
}

async function listCandidateFiles(dir: string, prefix: string = ""): Promise<string[]> {
  let dirEntries;
  try {
    dirEntries = await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  const found: string[] = [];
  for (const entry of dirEntries) {
    const relativePath = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRECTORIES.has(entry.name)) {
        found.push(...(await listCandidateFiles(join(dir, entry.name), relativePath)));
      }
      continue;
    }
    if (entry.isFile() && CONFIG_BASENAMES.has(entry.name)) {
      found.push(relativePath);
    }
  }
  return found;
}
