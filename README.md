# Rulehouse — Continuous Assurance

Rulehouse is an enterprise security control plane for governing how
AI-connected systems access organizational information. This repository
currently contains the **Phase-1 Continuous Assurance prototype**: a
zero-dependency scanner that inventories Atlassian MCP client
configurations, evaluates a defined policy set against them, detects
configuration drift, and produces evidence another engineer can
independently verify.

**Scope honesty, up front.** Continuous Assurance discovers and verifies
configuration. It does not intercept, mediate, or enforce anything: a
finding here describes what the configuration says, not what the Atlassian
platform did. Every remediation claim is detection-level until the Phase-2
gateway exists.

## Engineering rules of record

Two rules govern every contribution; they live in
[AGENTS.md](AGENTS.md) and are treated as acceptance criteria, not
guidelines:

1. **Code quality must be admirable, not acceptable.** One precise
   mechanism over three approximate ones; declarative policy tables over
   scattered scan loops; names that carry the reasoning.
2. **Bug-free is a product requirement.** A security product with a bug
   produces either false alarms or false assurance. The latter is worse
   than no control at all.

## Install and run

Requires Node 20+. There are **zero runtime dependencies** — deliberate,
for a security tool: `npm ci` installs only TypeScript and `@types/node`.

```sh
npm ci
npm run build
node dist/index.js scan examples/fleet          # inventory + policy report
node dist/index.js scan examples/fleet --strict # exit 1 if any finding
```

To exercise the drift story end to end:

```sh
node dist/index.js scan examples/fleet --out /tmp/rh-baseline
node dist/index.js scan examples/fleet-drift-after --out /tmp/rh-current
node dist/index.js diff /tmp/rh-baseline/snapshot.json /tmp/rh-current/snapshot.json
node dist/index.js verify /tmp/rh-baseline/snapshot.json --root examples/fleet
```

## Commands and exit codes

| Command | Purpose | Exit codes |
| --- | --- | --- |
| `scan <root> [--allowlist f] [--out d] [--strict]` | Walk a tree of MCP client configs, inventory registrations, evaluate the policy set, write `snapshot.json`, `report.json`, `report.md` into the out dir (default `./rulehouse-out`). | `0` normal; `1` `--strict` with findings; `2` usage error |
| `diff <baseline.json> <current.json>` | Compare two snapshots facet by facet (endpoint, url, tools, auth, credential, username) per server, plus input-file hash changes. | `0` identical; `1` changed; `2` error |
| `verify <snapshot.json> --root <root>` | Re-derive the SHA-256 of every recorded input and re-compute the snapshot fingerprint. | `0` all evidence matches; `1` drift, missing inputs, or fingerprint mismatch; `2` error |

Usage errors and tampering are distinct exits (`2` vs `1`) so CI can
separate "the tool was misused" from "the evidence disagrees".

## What scan actually checks

Policies are declarative tables in `src/policy.ts`. Per registration:

| Rule | Severity | Finding |
| --- | --- | --- |
| `RH-CRED-INLINE` | high | Credential material inlined in a configuration file |
| `RH-CRED-UNRESOLVED` | low | Credential references an environment variable not resolvable in the scanning shell |
| `RH-ENDPOINT-SSE-LEGACY` | high | Registered against the deprecated `/v1/sse` endpoint |
| `RH-ENDPOINT-V1` | medium | Registered against the v1 endpoint rather than v2 |
| `RH-ENDPOINT-INSECURE` | critical | Non-HTTPS remote endpoint |
| `RH-TOOLS-ALL` | medium | `?tools=all` overrides default tool exposure |

Across registrations of the same server:

- `RH-PARITY` — auth path, endpoint generation, or tool exposure differs
  between clients that register the same Atlassian server. This is the
  detection-level answer to policy-parity: a restriction configured for
  the OAuth path does not automatically bind the API-token path, and the
  inventory makes the divergence visible.
- `RH-ALLOWLIST` — a registered URL that is not covered by the optional
  allowlist (`urlPrefixes`).

Passes and `not-applicable` verdicts are recorded alongside findings.
Silence proves nothing; the report shows the checks that ran and passed.

## Secrets policy

Credentials found in configurations are **fingerprinted at parse time**
into a `SecretFingerprint` (`sha256:<16-hex prefix>` plus structural
metadata: probe characters, length, origin). No output type in the codebase
can carry raw credential material, and a test asserts synthetic tokens
never appear in any serialized output. Attribution usernames (which are
Atlassian account emails, i.e. evidence, not secrets) and SHA-256 input
hashes are retained.

## Evidence chain

Every scan hashes each input file (SHA-256 of the exact bytes, comments
and all) and computes a canonical fingerprint over
`{inputs, inventory, diagnostics}`. The snapshot carries both. So:

- `report.md` embeds per-input hashes and a `sha256sum` command, letting a
  third party confirm the findings correspond to bytes they hold, without
  running Rulehouse.
- `verify` re-derives everything against the live tree.
- `diff` changes are grounded in before/after input hashes.
- Tampering with a snapshot is audible: the recomputed fingerprint no
  longer matches the stored one.

## Supported configuration formats

- `claude_desktop_config.json` (Claude Desktop, `mcpServers`)
- `.mcp.json` (Claude Code, `mcpServers`)
- `.cursor/mcp.json` (Cursor)
- `.vscode/mcp.json` (VS Code, `servers`)
- generic `mcp.json` (`mcpServers`)

JSONC relaxations (comments, trailing commas) are accepted through a
single-pass normalizer; anything unparseable yields a diagnostic, never a
crash — one malformed file can never cost fleet visibility.

## Development

```sh
npm run check        # typecheck + full test suite
npm test             # tests run via node:test against compiled output
```

## Non-goals of this prototype

- No enforcement or mediation (Phase 2 gateway).
- No native Rovo interception claims — none exists without an
  Atlassian-supported control point.
- No universal shadow-MCP discovery — only explicitly registered
  client configurations on disk are inventoried.
- No A2A governance — deferred until its enforcement architecture is
  validated.
