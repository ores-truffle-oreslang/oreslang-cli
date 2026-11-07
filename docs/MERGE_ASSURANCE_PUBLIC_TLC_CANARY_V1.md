# Source-free public TLC assurance canary (v1)

This is a **new independently authored public governance model**. It contains
no source copied from private AttoLang compiler, SSR, or conformance repos.

The model represents an immutable PR head, current-head review approval,
executed exact-head CI with positive step count, protected main with bypass
disabled, and merge eligibility. It explores sequences of new commits, approval,
dismissal, change requests, CI completion, forged zero-step success, and policy
enable/disable. The accepted configuration must satisfy NoUnsafeMerge.

Three intentionally weakened models (stale-review, zero-step, bypass) must each
produce a real TLC invariant counterexample, not a parser error.

CI downloads immutable [TLC build 2026.08.11.125311](https://github.com/zactionsz/tla-tools/releases/tag/tla2tools-2026.08.11.125311).
GitHub release metadata lists jar SHA256:
ab323b79802aedc3203b3f9af37c6aca3ed43f4e0225b36f2aa77b26de46c05f.
Exact original PR head/tree and per-file hashes are printed before toolchain
retrieval; TLC output logs are attached.

BOUNDARY: This source-free canary is NOT real compiler-backed AttoLang
execution, private source CI, authentic GitHub review evidence, live
branch-protection enforcement, or a check of the separate private
conformance #496 TLA+ model. It must never authorize a merge by itself.
