# Rulehouse - Agent Brief: Remaining Work

Read AGENTS.md first. Its two rules are acceptance criteria for everything below.
Current state: Phases 1-5 are built on branch vibe/mcp-gateway-1bf408 (v0.5.0). This brief covers only what is NOT done.

## Ground rules (non-negotiable)

- Node 20+, TypeScript strict with noUncheckedIndexedAccess. No `any`, no non-null `!` outside test fixtures.
- Zero runtime dependencies. Do not add one without an explicit written justification in the PR.
- Parsers never throw on malformed input: return values plus diagnostics.
- Never store, log or echo secrets. Fingerprint prefix plus source location only.
- Every rule or classifier ships with fixture-driven positive, negative and malformed tests.
- Claims track mediation reality. Never label anything "enforced" on traffic the gateway cannot intercept. Unverified is reported as unverified.
- Each task ends with `npm run check` green on Node 20 and 22 (CI).
- Update README scope statements in the same change as any capability change. No claim ahead of code.

## Task 0 - Housekeeping (do first)

1. Merge vibe/mcp-gateway-1bf408 into main (it is a strict superset of vibe/continuous-assurance-1bf408; that branch can then be deleted).
2. Retitle README from "Rulehouse - Continuous Assurance" to "Rulehouse". Keep the scope-honesty section.
3. Confirm CI runs on main.

Done when: main contains Phases 1-5, CI green, README title correct.

## Task 1 - Streaming MCP support in the gateway (highest priority)

Problem: the gateway forwards stateless HTTP POST in JSON mode only. SSE-streamed MCP sessions and body rewriting are not implemented. The real upstream (e.g. https://mcp.atlassian.com/v2/mcp) is likely to use streaming, so the gateway cannot yet front it.

Scope:
- Handle the MCP streamable-HTTP transport: POST responses that arrive as text/event-stream, and session identification headers.
- Policy evaluation and ledger recording must still happen before any tool call is forwarded.
- Decide and document how responses are handled: pass-through stream versus buffered. Record the enforcement result for streamed calls.
- Fail closed on any parse failure of a request that could be a tool call.

Acceptance:
- Mock upstream tests that stream SSE; assert upstream request counts to prove denied calls never reach it.
- Ledger entries for streamed calls remain distinct: blocked-at-gateway, forwarded-to-upstream, failed-forwarding.
- A documented list of MCP transport behaviors NOT handled, in the README.

## Task 2 - TLS and deployment story

Problem: no TLS. The config loader refuses any non-loopback bind, so remote use needs a TLS-terminating proxy.

Scope (choose the narrowest option that is honest):
- Either document and test a reference deployment behind a TLS-terminating reverse proxy (including the Phase 5 proxy-asserted identity path), or add native TLS using node:tls/https with no new dependency.
- Keep the loopback-only default. Any non-loopback bind must require explicit configuration.

Acceptance:
- Config-loader tests covering refused and allowed binds.
- README deployment section stating exactly what the gateway does and does not protect.

## Task 3 - Outbound protection

Problem: the product brief lists outbound protection (controlling sensitive information leaving through supported integration paths). Nothing in the repo implements it.

Scope:
- Add declarative outbound rules on mediated paths: destination-based and content-class-based conditions on tool-call arguments (for example, sensitive-labelled content, by digest or by label from the provenance registry, flowing into a tool that sends data externally).
- Reuse the existing policy engine and decision ledger. No second policy system.
- Define what "sensitive" means mechanically (declared labels, not guessed content classification) and say so.

Acceptance:
- Fixture-driven tests: allowed, denied, malformed, and not-mediated cases.
- README states that outbound protection applies only to traffic the gateway mediates.

## Task 4 - Rovo security path

Problem: the brief's Phase 3 is Rovo security. The repo's Phase 3 is generic provenance. There is no Rovo-specific work.

Scope:
- Investigate which Rovo-involving paths can actually be mediated (for example Rovo agents calling tools via MCP). Produce a written finding first (docs/rovo-mediation.md): per path, mediable or not, and why.
- Implement provenance-aware restrictions and outbound controls only on paths found mediable.
- For paths that cannot be mediated, add scanner-level detection (configuration discovery) and label them detection-only.

Acceptance:
- The finding document exists and is evidence-based; unknowns are listed as unknowns.
- No README claim of Rovo protection beyond what the document supports.

## Task 5 - Demonstrate differentiation

Problem: the brief says differentiation must be shown technically against existing security platforms, not assumed.

Scope:
- Build a reproducible scenario suite (examples/scenarios/) where untrusted content tries to drive a privileged tool call, and show Rulehouse's decision, ledger entry, and the failure mode of a permissions-only control on the same scenario.
- State the comparison method and its limits. Do not name or characterize a competitor's product beyond what is documented.

Acceptance:
- One command runs the suite and emits a verifiable report with hashes.
- Each scenario states what Rulehouse does and does not stop.

## Task 6 - Live Atlassian MCP validation

Problem: all gateway tests use a mock upstream. Nothing is verified against a real Atlassian MCP server.

Scope:
- Add an opt-in integration test (skipped by default, enabled by env vars) that runs the gateway in front of a real Atlassian MCP endpoint with a test site.
- Never commit credentials. Never log them. Fingerprints only.
- Record differences between mock and live behavior and fix the mock to match.

Acceptance:
- Documented procedure to run the live test.
- A short results note listing what was observed (identity, tool listing, a denied call, an approved call).

## Task 7 - Multi-process ledger safety

Problem: the hash-chained ledger and provenance registry assume single-process ownership (stated limitation in src/lib/chain.ts).

Scope:
- Add a safe append mechanism (file lock or single-writer design) so two gateway processes cannot fork the chain, or enforce and test a hard single-writer guard that fails closed.

Acceptance:
- A concurrency test that attempts concurrent appends and proves the chain stays valid or the second writer is refused.

## Suggested order

0, 1, 6, 2, 3, 4, 7, 5. Task 6 follows Task 1 because live validation needs streaming. Task 5 goes last so it demonstrates the finished capabilities.

## Definition of done for the whole brief

- main holds all work, CI green on Node 20 and 22.
- README claims match code and tests exactly.
- Every capability is reproducible by another engineer from the README alone.
