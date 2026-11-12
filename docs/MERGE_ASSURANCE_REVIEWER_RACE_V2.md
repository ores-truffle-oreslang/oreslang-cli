# Public reviewer and merge-race formal reference v2

This is a **new public, source-free** model stacked on CLI PR #151.
It is NOT the private conformance specification, and it contains no private
AttoLang compiler/SSR source.

The strict safety invariant requires ALL of:
1. Current-head approval by an independent reviewer, never the PR author.
2. Positive executed CI steps bound to the same current source head.
3. Enforced protected-main admission.
The merge event records whether these conditions held at the moment of merge.
No cached qualification or past approval is accepted by the strict gate.

## Model-checker matrix

| TLC config | Expected |
| --- | --- |
| safe | Exhaustive exploration without an invariant violation |
| self-review | Counterexample: author pretends to independently approve |
| stale-snapshot | Counterexample: previously valid preflight reused after head or policy change |
| revoked-review | Counterexample: approval reused after dismissal or changes requested |

The three mutants intentionally introduce an unsafe branch into CandidateGate.
The NoUnsafeMerge invariant is never weakened, so the CI job must identify the
specific invariant violation—not a parser error—for every mutant.

The GitHub Actions workflow pins SHA-256 of the public TLC release JAR
ab323b79802aedc3203b3f9af37c6aca3ed43f4e0225b36f2aa77b26de46c05f
(release tla2tools-2026.08.11.125311), checks the original immutable PR HEAD,
prints the source tree and file hashes, and stores the model-checker logs.

IMPORTANT LIMITS: A passing bounded model is not authenticated GitHub review
evidence, repository branch enforcement, merge-service race immunity, private
CI recovery, or AttoLang guest/compiler parity. It cannot authorize a merge.
