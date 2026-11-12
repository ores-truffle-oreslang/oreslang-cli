# AttoLang CLI main — administrator ruleset proposal

**Current state (2026-11-12): NOT ENFORCED.** `GET /repos/ores-truffle-oreslang/oreslang-cli/rulesets` returned `[]`. Committing `CODEOWNERS` or the accompanying JSON template does **not** install the rule. The connected GitHub integration cannot use the branch-protection administration endpoint (403).

An authorized repository administrator must open **Settings → Rules → Rulesets** and create an **active branch ruleset** targeting only `refs/heads/main` using the reviewed `.github/policies/main-ruleset.proposed.json` payload. Independently read the effective GitHub policy back before declaring enforcement.

This proposal requires one non-self CODEOWNER approval from `@ORESoftware` or `@the1mills`, approval after the last push, stale-review dismissal, resolved conversations, no bypasses, and protection against direct pushes, force pushes and deletions. The required exact source check is the observed GitHub Actions `rust` job, App ID `15368`. Its `cargo test --workspace --locked` and source-free archive negative controls must actually execute; an empty or zero-step job does not satisfy evidence.

The `rust` check is **not** five-backend compiler guest parity, a release attestation, authorization for private source transfer, or proof that the ruleset was applied. Before merging any PR also verify the exact source head/tree and check its changed-file scope. No authored PR may be self-approved.

## Verification after applying the real rule

Use GitHub's effective ruleset readback and an innocuous test PR to confirm: direct pushes and merges without approval are rejected; self approval, stale approvals and unresolved threads are rejected; missing or failing `rust` checks block merges. Do not try destructive tests on `main`. A successful unit test of this JSON is not active policy.
