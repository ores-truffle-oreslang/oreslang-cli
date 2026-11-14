# Advisory merge-wave preflight v1

## Purpose

Source-free adversarial checks for user-requested batches of **at least five PRs across at least three distinct repositories**. This is a **regression model**, not a live GitHub auditor, reviewer, merge button, deployment receipt, or evidence of compiler-backed AttoLang execution. It never grants merge or release authorization. The positive result is deliberately `READY_FOR_LIVE_RECHECK`, `merge_authorized:false`, `max_merge_attempts_authorized:0`.

## Required live checks before any real merge

An independent reviewer must submit a qualifying approval for the exact current head. A requested review, self-review, stale approval, or a review followed by new changes cannot count. An administrator must enable and independently demonstrate effective protected `main`, non-bypassable code-owner review and required checks, stale-review dismissal, and any ruleset requirements. A verified workflow must test **the immutable original source head and tree**, show a positive runner ID and successful executed test steps; `steps=[]`, null, synthetic merged-ref execution, and source-free evidence must not be described as compiler-backed guest parity.

Each candidate must be conflict-free and agent coordination claims must be checked. Fresh head SHA, base SHA, approvals, required checks, and lease status must be independently re-read **immediately before every single merge**; a preceding merge to the same base invalidates a cached preflight. Use a GitHub expected-head SHA lock on each merge action. If any read or permission check is denied, fail closed; never claim a successful snapshot proves administrative enforcement.

## Running the tests

`node --test tests/merge-wave-preflight-v1.test.mjs`

The dedicated PR workflow checks out the original PR head, validates commit identity and checkout state, records Git source hashes, and runs the Node adversarial matrix. Fixtures are invented synthetic data and do not query GitHub or require credentials. Cases cover five-in-three quorum, duplicate entries, draft/conflicts, active leases, head/base drift, missing or revoked independent reviews, outstanding changes requested, non-Gregorian/future/stale snapshots, unprotected branches and bypass, and zero-step, synthetic-head, wrong-tree, or incomplete CI. The suite also asserts that all positive inputs remain non-authorizing.

## Limitations

The `source_integrity_verified`, `verified_independent`, `rulesets_verified`, and coordination booleans are assertions inside an **untrusted hypothetical snapshot**. Their value cannot substitute for actual authenticated GitHub API responses. Do not wire the advisory result directly to a merge action or use this source-free matrix as evidence of actor/runtime/backend parity. Actual post-merge evidence belongs in separately reviewed checks of the landed `main` tree and workflow run/attempt.
