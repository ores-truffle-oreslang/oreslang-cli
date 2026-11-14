# Public AttoLang merge protection: administrator-only plan v1

This isolated public, source-free tool creates deterministic GitHub classic branch-protection PUT request bodies for five AttoLang public Website/tool/editor repositories. It CANNOT configure GitHub. It CANNOT attest reviewer independence, actual server enforcement, the absence of other org rules, trusted runner execution or release fitness.

## Current gate

On 2026-11-07 UTC, CLI, Highlighter, Sublime and VS Code reported main.protected=false and no repository rulesets. On 2026-11-11 UTC the Website joined this census: Website, CLI and Sublime had main.protected=false and no rulesets; the Website had no CODEOWNERS on main. The connected GitHub App received 403 from GET branch protection and has NO administration write action. CI green is not branch enforcement. Never merge these security PRs until an administrator confirms effective protections and an actual independent human approves the exact head.

## Administration sequence

1. Assign a real reviewer who is independent of the PR author, last pusher, agents and alternate accounts. In particular, the GitHub bootstrap issue in oreslang-platform-conformance#69 explicitly treats @ORESoftware and @the1mills as operator-controlled for private-source security gates; choosing @ORESoftware as CODEOWNER alone must not be confused with independent review. For these public repos, have an independent security owner validate the identity policy and update CODEOWNERS as needed.
2. Confirm that each proposed context is emitted by an actual GitHub Actions job on ALL relevant PR heads and verify the issuer's GitHub App ID (15368). Do not require jobs conditional on only particular PRs. CLI stable base job is rust. Website's exact-head Actions run #42386935307 verified the job context 'AttoLang Site Validation' from GitHub Actions app 15368 with real executed steps. Other jobs are copied from the respective security blocker issues (#11 Highlighter, #139 Sublime, #218 VS Code). Revalidate names before activating.
3. For CLI and Website, **before** reviewed CODEOWNERS policies land, use their respective bootstrap phase. Both still require a real PR, independent approval, last-pusher-independent approval, stale dismissal, issuer-bound required CI ('rust' for CLI; 'AttoLang Site Validation' for Website), resolved discussions, admin enforcement, and no bypass; neither can require code-owner approval from a missing main-branch file. Do not mark CLI draft #158 or any Website ownership PR ready merely because a policy file exists.
**Bootstrap downgrade guard:** The administrator must independently inspect all GitHub CODEOWNERS locations on the current main revision (root, `.github/`, `docs/`) and record an explicit `codeowners_present_on_main=false` only when absence is actually verified. The readback model rejects `true`, `null`, omitted, or any other unknown value during `bootstrap`. Recheck immediately before and after applying changes; if CODEOWNERS appears, STOP using bootstrap and transition to `steady` only after validating independent ownership. Source-owned tests of this rule do not authenticate the observation or substitute for actual GitHub enforcement.

4. After independently reviewed ownership policies land for CLI **and Website**, inspect CODEOWNERS on each main branch, verify that the human/team owner is genuinely independent, then apply that repository's steady phase requiring code-owner review. Include CLI's always-on codeowners-policy check only after verifying that check is emitted by main and every relevant PR; the template deliberately does not pre-require a not-yet-main job.
5. For the other three repositories with existing main CODEOWNERS (Highlighter, Sublime and VS Code), use steady phase immediately after confirming owner independence. Record exact HEAD and the admin REST readback.
6. Check no PR-bypass allowlists, no force pushes/deletions, admin enforcement, strict status checks from the GitHub Actions app, stale dismissals, last-pusher approval, resolved review threads. Verify rulesets, including effective org rules, and check a safe negative no-review/stale-review test. Do not perform any direct push to main as an experiment.
7. Require independent approvals and source-owned, nonzero-step exact-head CI for CLI #155–#158 and VS Code #211 after reconciling its divergent base. Keep the five-PR / three-repo quorum independent of these controls.
8. Only AFTER a protected reviewed merge, generate externally controlled attestation and record reviewed HEAD SHA, root tree, exact executed jobs and runner IDs, policy snapshot, reviewer IDs, landed commit and post-merge tree. The signer/trust root cannot be owned by the PR author. This source-free plan never signs or authorizes one.

## Deterministic payload generation

From the reviewed CLI repository checkout:

  node tools/public-main-protection-v1.mjs --plan ores-truffle-oreslang/oreslang-cli bootstrap > /tmp/atto-cli-bootstrap.json
  node tools/public-main-protection-v1.mjs --plan ores-truffle-oreslang/oreslang-cli steady > /tmp/atto-cli-steady.json
  node tools/public-main-protection-v1.mjs --plan ores-truffle-oreslang/ores-truffle-oreslang.github.io bootstrap > /tmp/atto-website-bootstrap.json
  node tools/public-main-protection-v1.mjs --plan ores-truffle-oreslang/ores-truffle-oreslang.github.io steady > /tmp/atto-website-steady.json
  node tools/public-main-protection-v1.mjs --plan ores-truffle-oreslang/html-js-css-syntax-highlighter steady > /tmp/atto-highlighter.json
  node tools/public-main-protection-v1.mjs --plan ores-truffle-oreslang/sublime-text-plugins steady > /tmp/atto-sublime.json
  node tools/public-main-protection-v1.mjs --plan ores-truffle-oreslang/vscode-plugins steady > /tmp/atto-vscode.json

These JSON files are templates, NOT a live-sourced proof of valid required check contexts. The administrator must independently inspect existing protections before replacement, because PUT replaces the whole branch-protection configuration. After review, an administrator with repository Administration WRITE permission may use GitHub Settings or, from THEIR authenticated admin session, GitHub CLI:

  gh api --method PUT repos/ores-truffle-oreslang/oreslang-cli/branches/main/protection --input /tmp/atto-cli-bootstrap.json

Apply the Website bootstrap file to the Website repository only, with an authorized, separately controlled administrator. Never run any protection PUT through a PR workflow or this GitHub connector. Never store admin tokens in repository secrets or logs merely for bootstrapping. Confirm response and independently re-fetch the branch and effective policies. Repeat per repository with the correct reviewed payload and current status contexts.

For a read-only model audit, assemble a JSON input with branch GET response, admin-only protection GET response, full ruleset readback, before/after main head, and separately verified codeowners_present_on_main boolean. Then run:

  node tools/public-main-protection-v1.mjs --audit ores-truffle-oreslang/oreslang-cli bootstrap /tmp/admin-observation.json

Audit ALWAYS exits 3, with merge_authorized=false, release_authorized=false and private_source_export_authorized=false even when its modeled input is consistent. Caller-provided JSON can be forged. The tool is not an authorization source and does not itself establish an independent signer. An active org rule not included in the snapshot, or a missing bypass field, must be treated as UNKNOWN, not success.

## Limits and coordination

- Do not edit or force-update existing agents' CLI #155–#159, VS Code #211 or compiler source; follow conformance issue #359 leases.
- Source-owned workflow checks the original PR SHA, not a synthetic merge ref, and runs only public Node tests; it never requests admin credentials.
- The CI tests are adversarial data-model checks, NOT executed guest/compiler parity.
- The Website/CLI bootstrap phase never waives independent reviewer approval, and must not be confused with owner-review steady state. This plan does not verify actual independent human control.
- Do not classify the previous five public merges as release-qualified retroactively.
- GitHub REST branch protection reference: https://docs.github.com/en/rest/branches/branch-protection

## Adversarial model hardening

The model now requires an exact authenticated repository numeric ID + full name from a separate repository GET alongside the branch readback; unknown/duplicated ruleset IDs or enforcement states, unbound or unexpected status check names, legacy contexts not covered by issuer-bound checks, extra bypass keys, and review-dismissal allowlists fail closed. Reported consistency is still caller-provided input consistency, NEVER an independently authenticated permission decision. Ruleset list and details, including organization-level inherited rules, require separate authenticated administrative inspection. Main-SHA checks and repository ID matching do not create tamper-proof provenance.

The CLI rejects symlinked and larger-than-1-MiB audit input files to avoid accidentally consuming an unbounded or surprising input. This is a guardrail, not proof that the file is trustworthy; obtain the data from a trusted read-only administrator session and keep it out of untrusted PR workflows.

### Hostile CLI input controls

For `--audit` the tool opens the evidence file with `O_NOFOLLOW`, checks a real regular-file descriptor and bounded size (maximum 1 MiB), verifies a stable read size, decodes strict UTF-8 and refuses malformed JSON. Adversarial Node tests spawn the executable and verify that symlinks, oversized files, invalid UTF-8 and broken JSON return failure without authorizing any action. The audit's exit status is **3 even when all supplied data appears consistent**; a parser/error failure exits **2**. No CLI exit status authorizes a merge, promotion, release or source export.
