# Live Atlassian MCP validation

All gateway unit and integration tests run against a mock upstream. This
document is the procedure and the results note for the **opt-in** live
test that runs the gateway in front of a real Atlassian MCP endpoint.

Status: **not yet run against a live endpoint.** The test exists, is
skipped by default, and records observations; the results section below
is filled in from actual runs only. Mock assumptions that the run
disproves get fixed in the mock in the same change.

## Scope of the live test

The probe walks one mediated session against the configured upstream:

1. `initialize` — asserts HTTP 200, captures the relayed
   `mcp-session-id`, and records whether the upstream answered buffered
   JSON or `text/event-stream`.
2. `tools/list` — asserts 200 and records the published tool names
   (tool publication data is not secret).
3. One allowed `tools/call` — the first listable read-shaped tool
   (`list*`/`search*`/`get*`/`read*`, else the first published tool);
   asserts the gateway forwards and the upstream answers.
4. One denied `tools/call` — `rulehouse_forbidden_probe`, blocked by
   policy **before** any upstream traffic; asserts 403 and the
   `blocked-at-gateway` ledger entry.
5. One unauthenticated request — asserts 401 with no upstream traffic
   beyond the refusal.

It then verifies the hash chain and asserts the ledger shows, in order:
`forwarded-to-upstream` ×3, `blocked-at-gateway` ×2.

## Procedure

Prerequisites: a test Atlassian site and an OAuth token with the scopes
the MCP endpoint requires (verify the current scope set against
Atlassian's documentation — treat any scope claim here as unverified
until the live run). Nothing in this repository contains a credential.

```sh
RULEHOUSE_LIVE_UPSTREAM_URL=https://mcp.atlassian.com/v2/mcp \
RULEHOUSE_LIVE_UPSTREAM_CREDENTIAL=$ATLASSIAN_TEST_TOKEN \
npm test
```

`RULEHOUSE_LIVE_UPSTREAM_CREDENTIAL` is read from the environment and
forwarded only inside the gateway's Authorization header. It is never
logged, echoed, or written to the ledger. The client-side key is
generated per run and only its SHA-256 digest exists. If the upstream
rejects the credential, the probe fails with an explicit message and
the credential value is still not printed.

Without both environment variables the test skips itself; CI always
runs in the skipped state.

## What the probe records

One JSON observation block per run (status codes, content types,
relayed session id, tool count and a name preview, ledger enforcement
sequence). Differences from the mock's assumptions feed mock fixes.

## Known unknowns (as of this writing)

- Whether the production endpoint answers `initialize` with a session
  id header, and whether sessions are required on subsequent calls.
- Whether `tools/list` or `tools/call` responses arrive as
  `text/event-stream` and whether event frames use single or multiple
  `data:` lines.
- The exact required scopes and token lifetime for a service-account
  style deployment (the gateway's own upstream credential model —
  `credentialScheme` + one environment variable — is shared with this
  probe, so configuration drift shows up as probe failures).
- Whether the upstream rejects JSON-RPC batches, notifications, or
  requests lacking a `mcp-protocol-version` header differently from the
  mock's assumed tolerance.

## Results

Not yet run — no live observations exist. Do not cite this document as
evidence until the results section below contains real run output.

| Date | Endpoint | Observations | Follow-ups |
| --- | --- | --- | --- |
| — | — | — | — |
