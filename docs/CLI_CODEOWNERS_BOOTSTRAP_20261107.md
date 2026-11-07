# AttoLang CLI CODEOWNERS bootstrap — 2026-11-07

## Scope, facts and nonclaims

This change establishes explicit ownership of all existing CLI roots and future files through a catch-all `* @ORESoftware`, plus dedicated clauses for release-critical locations. It contains **no private compiler source** and does **not** modify permissions, release artifacts, the CLI compiler/runtime, or any existing agent-owned paths.

Verified by GitHub: `@ORESoftware` has `admin` permission on `ores-truffle-oreslang/oreslang-cli`. That confirms the account can be named as a code owner; it does not constitute submitted independent review.

At inspection, `main` was `7eaa52e4f52d95df670d516d34d4907872be1730`, `protected=false`, and the applicable ruleset listing was empty. Branch-protection details are not available to the connected GitHub App (403). **The owner file alone cannot enforce any reviews.**

The previous five merges were completed without submitted independent PR approvals. New reviews cannot retroactively satisfy those missing pre-merge conditions.

## Phase A — administrator enables enforceable baseline (BEFORE THIS PR IS MERGED)

An authorized administrator must navigate to **Repository Settings → Rules → Rulesets**, create or update an **active branch ruleset targeting `main`**, and verify its effective settings:

- Require a pull request before merging (no direct pushes, no force pushes and no deletions of `main`).
- Require at least **one independent approving review**, dismiss stale reviews after new commits, and require approval of the most recent reviewable push by someone other than its author.
- Require successful source-owned, executed CI on the **immutable original PR head**. Initially the existing `CI / rust` job is available; verify its *actual GitHub check name* rather than copying this text blindly.
- Prohibit bypass (including administrators, apps, and automation identities) unless explicitly authorized by a separate security decision. Do not configure a permanent self-bypass exception.

Read back `main.protected=true`, effective active rules and required check issuers. A UI click or the mere presence of `.github/CODEOWNERS` is not evidence of enforcement. The current GitHub connector cannot set or read detailed branch protection and must not claim success.

## Phase B — independent owner reviews this bootstrap

1. Inspect the exact final head of this PR and changes in `.github/CODEOWNERS`, tests, workflow and documentation.
2. Wait for source-owned `CLI CODEOWNERS policy (source-free, non-promoting) / codeowners-policy` and existing `CI / rust` checks to **complete successfully with real executed test steps on the final head**. The ownership tests are static validation, not a substitute for real GitHub branch-policy checks.
3. Obtain substantive **submitted `APPROVED` review** from `@ORESoftware` (or a different independently authorized security reviewer). Reviewer request or comment is not an approval. The PR author cannot self-approve.
4. Land through GitHub's protected PR merge path and verify the merge SHA and new `main` CI. Never force-push or write directly to `main`.

## Phase C — activate code-owner enforcement after the file reaches main

- Enable **Require review from Code Owners** and maintain at least one independent approval on the effective branch ruleset, with stale dismissal and no bypass.
- Require the stable job identities for both `CI / rust` and `CLI CODEOWNERS policy / codeowners-policy`, using the exact names shown in GitHub's job picker. The code-ownership workflow deliberately runs on **every `pull_request`**, not only path-filtered PRs; a required job must not be skipped for unrelated changes.
- Exercise a dedicated **test PR**: a non-owner change to `tools/`, `crates/` or `.github/workflows/` must be unable to merge without independent code-owner approval. Likewise, verify a new push invalidates previous approval and an actual failing or absent required job blocks merge.
- Re-read active rulesets and `main.protected` after applying rules. Use an independent administrator/reviewer to verify no bypass rights. Retain source SHA, CI attempt/job/step IDs, reviewer GitHub identity, protection snapshot and merged SHA in the audit ledger.

## Historical batch and release status

Highlighter #269/#267, CLI #151, Sublime #144 and VS Code #217 all have source-owned successful post-merge test runs but **lacked pre-merge independent approvals** and were merged while unprotected. Refer to [CLI audit PR #156](https://github.com/ores-truffle-oreslang/oreslang-cli/pull/156), [CLI governance PR #155](https://github.com/ores-truffle-oreslang/oreslang-cli/pull/155), and [CLI preflight PR #157](https://github.com/ores-truffle-oreslang/oreslang-cli/pull/157). They are independent, non-authorizing workstreams. Keep release qualification **BLOCKED** until independent post-merge diff audit and explicit release-owner recertification.

The other three repositories already have CODEOWNERS on `main` but remain unprotected: `html-js-css-syntax-highlighter`, `sublime-text-plugins`, `vscode-plugins`. They require administrator-enforced rules independently. VS Code original-head CI remediation is tracked in draft [#211](https://github.com/ores-truffle-oreslang/vscode-plugins/pull/211); do not duplicate edits to its agent-owned branch.
