# Engineering Rules of Record

These two rules govern every contribution to Rulehouse. They are not
guidelines; treat them as acceptance criteria enforced in review and in CI.

## Rule 1 — Code quality: admirable, not acceptable

The standard is *clever and original*, not merely functional. Code that reads
like it was produced quickly, defensively copied from a template, or papered
over with abstraction is rejected.

In practice this means:

- Prefer one precise mechanism over three approximate ones. If two rules share
  shape, unify them rather than duplicate them.
- Finding rules in `src/policy.ts` are declarative tables, each a single
  deterministic predicate over the inventory — no imperative scan loops
  scattered across the codebase.
- Naming carries the reasoning. If a name needs a comment paragraph above it to
  be understood, the design is wrong.
- No dead code, no speculative options, no config knobs nobody sets. A security
  product's surface area is its attack surface.

## Rule 2 — Code quality: bug-free is a product requirement, not an aspiration

Rulehouse ships security verdicts. A bug in a finding, a classifier, or the
snapshot differ means either a false alarm (erodes trust) or a silent miss
(creates false assurance, which is worse than no control at all).

Non-negotiable mechanics:

- `strict: true` TypeScript with `noUncheckedIndexedAccess`; no `any`, no
  non-null assertions (`!`) except in test fixtures.
- Parsers never throw on malformed input: they return values plus diagnostics.
  A scanner that crashes on a user's config is a defect, not an edge case.
- Secrets found in configurations are never stored, logged, or echoed — only a
  SHA-256 fingerprint prefix and their source location. This is enforced by the
  type system (`credential/source` carries fingerprints, never raw material)
  and tested.
- Every classification and policy rule has a fixture-driven test covering the
  positive, negative, and malformed cases. A rule without a test is a defect
  per review.
- Machine-verifiable output: every scan records the SHA-256 of each input file
  and its own canonical hash, so another engineer can independently re-verify
  that a finding corresponds to the exact bytes analyzed.
- Claims track mediation reality: the tool never labels anything "enforced"
  that it did not actually observe. Unverified is reported as unverified.

If a change cannot be clearly justified in both dimensions above, narrow the
claim or don't ship the change.
