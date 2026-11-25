import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { scanRoot } from "../src/discover.js";
import { parseDocument, formatForPath } from "../src/parse.js";

const NO_ENV = () => undefined;

async function withFleet(build: (dir: string) => Promise<void>): Promise<{ readonly files: readonly string[]; readonly clients: readonly string[] }> {
  const dir = await mkdtemp(join(tmpdir(), "rh-discover-"));
  try {
    await build(dir);
    const scan = await scanRoot(dir, NO_ENV);
    return {
      files: scan.inputs.map((input) => input.path).sort(),
      clients: scan.inventory.map((entry) => entry.client),
    };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("generic names are only candidates inside the client's own dot-directory", async () => {
  const result = await withFleet(async (dir) => {
    await writeFile(join(dir, "settings.json"), "{}", "utf8");
    await writeFile(join(dir, "config.toml"), "", "utf8");
    await mkdir(join(dir, "agents"));
    await writeFile(join(dir, "agents", "config.toml"), "", "utf8");
    await mkdir(join(dir, ".zed"));
    await writeFile(join(dir, ".zed", "settings.json"), "{}", "utf8");
    await mkdir(join(dir, ".gemini"));
    await writeFile(join(dir, ".gemini", "settings.json"), "{}", "utf8");
    await mkdir(join(dir, ".codex"));
    await writeFile(join(dir, ".codex", "config.toml"), "", "utf8");
  });
  assert.deepEqual(result.files, [".codex/config.toml", ".gemini/settings.json", ".zed/settings.json"]);
});

test("mcp_config.json is a candidate anywhere, in either vendor's layout", async () => {
  const result = await withFleet(async (dir) => {
    await mkdir(join(dir, ".codeium", "windsurf"), { recursive: true });
    await writeFile(join(dir, ".codeium", "windsurf", "mcp_config.json"), "{}", "utf8");
    await mkdir(join(dir, ".config", "devin"), { recursive: true });
    await writeFile(join(dir, ".config", "devin", "mcp_config.json"), "{}", "utf8");
    await mkdir(join(dir, "somewhere"));
    await writeFile(join(dir, "somewhere", "mcp_config.json"), "{}", "utf8");
  });
  assert.deepEqual(result.files, [
    ".codeium/windsurf/mcp_config.json",
    ".config/devin/mcp_config.json",
    "somewhere/mcp_config.json",
  ]);
});

test("an empty or container-less recognized file is still fingerprinted, not silently dropped", async () => {
  const result = await withFleet(async (dir) => {
    await writeFile(join(dir, ".mcp.json"), "{}", "utf8");
  });
  assert.deepEqual(result.files, [".mcp.json"]);
  assert.deepEqual(result.clients, []);
});

test("Codex TOML files route through the TOML subset and carry codex provenance", async () => {
  const dir = await mkdtemp(join(tmpdir(), "rh-discover-"));
  try {
    await mkdir(join(dir, ".codex"));
    await writeFile(join(dir, ".codex", "config.toml"), '[mcp_servers.atlassian]\nurl = "https://mcp.atlassian.com/v2/mcp"\n', "utf8");
    const scan = await scanRoot(dir, NO_ENV);
    assert.equal(scan.diagnostics.length, 0);
    assert.equal(scan.inventory.length, 1);
    assert.equal(scan.inventory[0]!.client, "codex");
    assert.equal(scan.inventory[0]!.endpointClass, "atlassian-v2");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("formatForPath keeps the mcpjson fallback for path-evidence-less servers containers", () => {
  assert.equal(formatForPath("loose.json", true), "vscode");
  assert.equal(formatForPath("loose.json", false), "mcp-json");
});
