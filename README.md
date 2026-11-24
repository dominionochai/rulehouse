# Rulehouse — Continuous Assurance

Rulehouse is an enterprise security control plane for governing how
AI-connected systems access organizational information. The repository
contains four working phases:

- **Phase 1 — Continuous Assurance**: a zero-dependency scanner that
  inventories Atlassian MCP client configurations, evaluates a defined
  policy set, detects configuration drift, and produces evidence another
  engineer can independently verify.
- **Phase 2 — MCP gateway (prototype)**: a policy-enforcing proxy that
  sits between MCP clients and an upstream server, authenticates each
  client to an identity, evaluates tool policy, blocks disallowed tool
  calls **before execution**, and records every decision in a
  tamper-evident hash-chained ledger.
- **Phase 3 — Provenance-aware enforcement (prototype)**: a
  content-trust registry and policy conditions that stop content of
  declared untrusted provenance from independently driving privileged
  tool calls on mediated paths.
- **Phase 4 — A2A delegation governance (engineering primitives)**:
  validation of A2A agent cards against the frozen v1.0 spec facts, and a
  delegation registry whose decisions are computed by the same policy
  engine as direct calls — a delegatee can never exceed its delegator
  because there is no separate delegation policy to drift.

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

## The MCP gateway (Phase 2)

The gateway is the Phase-2 enforcement point from the product brief: it
mediates MCP traffic between clients and an upstream server (e.g.
`https://mcp.atlassian.com/v2/mcp`) at the HTTP boundary.

What it establishes, each anchored to a test:

- **Identity handling** — clients authenticate to the gateway with a
  bearer key; only the key's SHA-256 digest is configured, and the
  gateway forwards *its own* upstream credential upstream, never the
  client's key.
- **Attribution** — every mediated request produces a ledger record
  carrying the authenticated identity, the method, the tool, the
  decision, the rule that produced it, and the enforcement result.
- **Policy evaluation** — declarative first-match-wins rules
  (`get_*`, `delete_*`, …) per identity with a configurable default
  effect (default: deny).
- **Pre-execution enforcement** — a denied tool call never reaches the
  upstream; the mock-upstream tests assert request counts to prove the
  block actually happened at the boundary.
- **Approval requirements** — a rule can mark calls as
  `approval: "required"`; they deny until their derived decision id is
  listed in the approvals file. Decision ids are deterministic (hash of
  identity + method + tool + arguments), so an operator's grant matches
  a client retry byte-for-byte, and revoking the line re-blocks
  immediately — the file is re-read per request.
- **Decision ledger** — an append-only JSONL file where each entry
  hashes its content and links to the previous entry's hash;
  `rulehouse ledger <file>` verifies the chain, and any edit, deletion,
  or reordering is reported at the first broken entry.

Run it (example config in `examples/gateway/`; binds loopback only):

```sh
node dist/index.js serve --config examples/gateway/rulehouse-gateway.jsonc
node dist/index.js ledger rulehouse-gateway-ledger.jsonl
```

**Attribution honesty.** The ledger records the identity the gateway
authenticated, i.e. decision-grade attribution for requests it mediates.
It does not claim to change or repair Atlassian's native audit records.

**Prototype limits, stated as limits.** Requests are forwarded
byte-for-byte over stateless HTTP POST (JSON mode); SSE-streamed MCP
sessions and body rewriting are not implemented. There is no TLS — the
config loader refuses any non-loopback bind and remote deployments must
sit behind a TLS-terminating proxy. An unreachable upstream fails
closed: the operation is not executed and the failure is recorded as
`failed-forwarding`, which the ledger keeps distinct from both
`blocked-at-gateway` and `forwarded-to-upstream`.

## Provenance on mediated paths (Phase 3)

The brief's distinction — **content an AI system can read is not
automatically an instruction it is authorized to follow** — enforced as
policy, at the only boundary where it can actually be enforced.

- **The provenance registry** — an append-only file built on the same
  hash chain as the decision ledger. Each record binds a content digest
  (`contentSha256`) to an origin (`internal`/`external`/`derived`), a
  trust declaration (`trusted`/`untrusted`/`unverified`), a source label,
  and a mandatory classifier attribution (`labeledBy`). Content is never
  stored; the registry describes what was seen, by digest. Re-registering
  a digest supersedes the previous declaration and the chain keeps the
  full history.
- **Digesting rule** — a string argument digests over its exact UTF-8
  bytes; any structured argument digests over canonical JSON (key order
  does not change identity). A registered file and the mediated argument
  therefore land on the same digest; paraphrased or re-serialized content
  deliberately does not, because the registry certifies bytes, not
  paraphrases.
- **Provenance conditions on policy rules** — a rule can carry
  `provenanceChecks` naming tool arguments and the declared trust values
  they must resolve to. A matched rule whose checks do not resolve is
  *skipped*, and evaluation continues down the written list — so
  untrusted content cannot ride on an allow rule written for trusted
  work, and a deny rule can be written to trigger exactly on declared
  untrusted content. Content with no registry record satisfies nothing
  (`unclassified`); a corrupt registry resolves as `unavailable` and
  fails closed. Both the registry and the approvals file are re-read per
  request, so re-classification takes effect on the next call.
- **The decision ledger quotes its evidence** — entries for rules with
  provenance checks carry the inspected digests and the trust the
  registry resolved for them at decision time, and denials explain which
  rule was skipped and what trust its check actually resolved.

Register and inspect content (`-` reads stdin):

```sh
node dist/index.js provenance register examples/gateway/provenance.jsonl \
  examples/gateway/contents/vendor-advisory.txt \
  --origin external --trust untrusted \
  --source webform:vendor-portal --labeled-by security-team
node dist/index.js provenance inspect examples/gateway/provenance.jsonl examples/gateway/contents/runbook.md
node dist/index.js ledger examples/gateway/provenance.jsonl   # the registry is a verifiable chain too
```

**Rovo honesty.** Phase 3 enforces provenance only on paths the gateway
actually mediates. Native Rovo operations (server-side retrieval, URL
fetching) never cross the gateway and remain outside every claim here.
Published 2026 research (Varonis' RovoBlast; PromptArmor's URL-retrieval
exfiltration) demonstrated exactly that gap: a feature toggle does not
close an egress path that an adjacent capability still reaches. The
correct posture — narrow product claim, detection and reporting only
where telemetry permits — is retained rather than marketed over.

## A2A delegation governance (Phase 4)

Phase 4 answers the brief's deferred capability -- agent-to-agent
delegation, trust, permission inheritance, revocation, and audit trails --
as validated engineering primitives, and it is deliberate about what it
does not claim: **Rulehouse evaluates delegation decisions; it does not
intercept A2A traffic.** Mediating agent-to-agent calls requires a
validated control point (a gateway, a broker, or a platform-supported
hook), and none is proven yet. What ships here is the decision core that
such a control point would one day call, exercised end to end by the CLI.

### Agent card validation

Every A2A server publishes an agent card -- the discovery document that
says who an agent is, where it is reachable, and what it can do. `a2a
validate` checks a card (file or stdin) against the published v1.0 conformance
facts: required identity fields (`name`, `description`, the agent release
`version`, and `protocolVersion`); the v1.0 `supportedInterfaces` array
with its binding names, while tolerating the legacy v0.x single `url`
shape (Atlassian's Rovo card still serves that, at
`https://a2a.atlassian.com/.well-known/agent.json`); boolean
`capabilities`; the required `id`/`name`/`description`/`tags` skill
fields; security-scheme references that actually resolve; and signature
coverage. Defects are reported one by one as findings instead of discarding
the whole card, and a broken entry never poisons its siblings:

```sh
node dist/index.js a2a validate examples/a2a/agent-card.json
node dist/index.js a2a validate examples/a2a/rovo-agent-card.json
```

Note what validation does *not* claim: signature *verification* (JWS over
the RFC 8785 canonical card) needs key discovery that no validated
integration point provides yet, so cards are reported signed/unsigned and
structurally sound or not -- never "authentic".

### Delegation without a second policy language

The delegation registry records two record kinds -- `grant` and
`revocation` -- on the same append-only hash chain as the decision ledger
and the provenance registry. Grant ids are content-addressed: re-derived
from the grant's own fields and checked against the file on every read,
so a grant cannot present itself under an id its content does not own,
and re-granting after revocation is a visibly new issuance, not a
resurrection.

The security core is what the registry does *not* contain: no delegation
policy file. When a delegated call is evaluated, the existing gateway
policies are executed once per identity on the grant chain -- the acting
agent, then each delegator up to the root -- against the same tool and
the same arguments:

- a delegatee can never exceed its delegator, because the delegator's own
  rules deny the call directly;
- approval requirements escalate: if any ceiling requires human approval,
  the delegated call requires human approval, even where the agent's own
  rule does not;
- provenance conditions compose: an untrusted argument is still denied at
  the ceiling, not waved through by delegation;
- revocation cascades for free: a chain is only as valid as every grant
  on it, so revoking one upstream grant kills every downstream
  presentation without any cascading logic;
- cycles (A acts for B while B acts for A) are refused by construction;
- expiry is anchored to an explicit evaluation instant; and
- every refusal names its exact defect -- unknown grant, revoked,
  disconnected chain, cycle, expiry, out-of-scope tool, or the ceiling
  that denied -- because an audit that cannot explain itself cannot be
  defended.

Govern the chain from the CLI:

```sh
node dist/index.js a2a delegate examples/a2a/delegations.jsonl \
  --from amara --to runbook-agent --tools "search_*,get_*,list_*" \
  --granted-by secops
node dist/index.js a2a inspect examples/a2a/delegations.jsonl
node dist/index.js a2a revoke examples/a2a/delegations.jsonl <grantId> --revoked-by secops
```

And evaluate a delegated call offline against the same gateway
configuration the live gateway enforces (`a2a simulate`). The example
registry contains a standing grant of read authority from `amara` to
`runbook-agent`; the simulate output is a full decision artifact -- chain,
per-ceiling rule decisions, provenance facts -- ready to be quoted as
evidence:

```sh
node dist/index.js a2a simulate examples/a2a/delegations.jsonl \
  --config examples/gateway/rulehouse-gateway.jsonc \
  --identity runbook-agent --tool get_issue \
  --via delegation:716eebecf9c03483db98c784ce78a48836e287b4601fdcf83270b9deac308955
```

### Phase-4 honesty

- Interception of A2A traffic itself remains an explicit non-claim until a
  control point is demonstrated; the primitives here are the evaluated
  decision core, not a mediator.
- Agent-card signature verification is structural only; JWS verification
  awaits a validated key-distribution path.
- The `now` used for expiry is pinned per invocation (`--now`), which
  makes decisions reproducible -- and means callers must pass a real
  clock in production integrations.

## Phase-1 scanner

The Continuous Assurance side of the tool: point `scan` at a directory
tree of MCP client configurations and it produces verifiable inventory,
policy and drift evidence without ever running anything against the
upstream servers.

### Commands and exit codes

| Command | Purpose | Exit codes |
| --- | --- | --- |
| `scan <root> [--allowlist f] [--out d] [--strict]` | Walk a tree of MCP client configs, inventory registrations, evaluate the policy set, write `snapshot.json`, `report.json`, `report.md` into the out dir (default `./rulehouse-out`). | `0` normal; `1` `--strict` with findings; `2` usage error |
| `diff <baseline.json> <current.json>` | Compare two snapshots facet by facet (endpoint, url, tools, auth, credential, username) per server, plus input-file hash changes. | `0` identical; `1` changed; `2` error |
| `verify <snapshot.json> --root <root>` | Re-derive the SHA-256 of every recorded input and re-compute the snapshot fingerprint. | `0` all evidence matches; `1` drift, missing inputs, or fingerprint mismatch; `2` error |

Usage errors and tampering are distinct exits (`2` vs `1`) so CI can
separate "the tool was misused" from "the evidence disagrees".

### What scan actually checks

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

### Secrets policy

Credentials found in configurations are **fingerprinted at parse time**
into a `SecretFingerprint` (`sha256:<16-hex prefix>` plus structural
metadata: probe characters, length, origin). No output type in the codebase
can carry raw credential material, and a test asserts synthetic tokens
never appear in any serialized output. Attribution usernames (which are
Atlassian account emails, i.e. evidence, not secrets) and SHA-256 input
hashes are retained.

### Evidence chain

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

### Supported configuration formats

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

## Non-goals

- No native Rovo interception claims — none exists without an
  Atlassian-supported control point.
- No universal shadow-MCP discovery — only explicitly registered
  client configurations on disk are inventoried.
- No A2A traffic interception — delegation governance ships as
  evaluated primitives (Phase 4); mediating A2A calls waits for a
  demonstrated control point.
- No chat interface, no model training, no replacement for Atlassian's
  identity or permission system.
