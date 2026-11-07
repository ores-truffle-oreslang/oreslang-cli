# AttoLang branch governance audit v1 (read-only advisory)

This is a **fail-closed** operator tool to inventory classic GitHub branch protection on
sixteen repositories: Java, LLVM, Wasm, Forge, .NET, six platform members,
platform-conformance, three editors and the CLI.

## Administrator execution

From a **trusted, private administrator workstation**, after obtaining a
fine-grained, expiring, appropriately scoped GitHub credential with access to
the private source repositories and **administration read** capability:

    GH_TOKEN=<admin-read-token> node tools/branch-governance-audit-v1/verify.mjs

Or restrict scope:

    GH_TOKEN=<admin-read-token> node tools/branch-governance-audit-v1/verify.mjs --repo ores-truffle-oreslang/oreslang-source.java

Do **not** commit the token, paste it into issues/chats, upload output containing
private source content, run an untrusted PR's script with it, or place it in
public Actions secrets. The tool reads only branch metadata and classic
branch-protection policy from GitHub; it never checks out, exports or copies
private source. Hosted CI exercises **synthetic in-memory fixtures only**, with
no live protected-repository API calls or admin credential.

Each repository is queried in order as:

1. GET /repos/{owner}/{repo}/branches/main
2. GET /repos/{owner}/{repo}/branches/main/protection (capture canonical policy snapshot)
3. GET /repos/{owner}/{repo}/branches/main/protection (repeat, fail closed on a difference)
4. GET /repos/{owner}/{repo}/branches/main (again to detect a moving HEAD)

Every request is bounded, read-only, directed to api.github.com, and emits
only **reason codes** and main SHAs, not raw GitHub metadata or credential.
403/404/unknown metadata/moving HEAD **or changed branch-protection policy** all block. This double-read is a limited observation window, **not an atomic GitHub transaction**; a policy that changes and reverts between reads may still evade detection. A ruleset-only configuration
is intentionally **not accepted as proof** of equivalent classic protection:
an independent authorized ruleset verifier is required for that mode.

## Required controls

The v1 checker requires all of:

- protected main, stable forty-hex source commit before and after;
- PR review with at least one approval, CODEOWNER review, dismissal of stale reviews, and approval of the **most recent push by someone other than its pusher**;
- absence of user/team/app PR-bypass allowances;
- administrators subject to policy;
- force pushes and branch deletion explicitly disabled;
- conversation resolution required;
- strict required status checks with distinct, positively issuer-bound app IDs,
  **not** legacy unbound contexts; the REST `contexts` inventory must be present
  and every context must correspond to an issuer-bound item in `checks`; a bound
  check cannot conceal an additional legacy unbound context;
- for each of the five compiler repositories, a required check named
  private-ci-policy bound to GitHub Actions App ID 15368.

If the GitHub REST response omits a control, v1 reports BLOCKED rather than
assuming a secure default. In particular, omitted `bypass_pull_request_allowances`,
`require_last_push_approval`, `required_status_checks.contexts`, and unbound app
IDs cannot be treated as proof of a safe policy. This is conservative and may require GitHub
administrator review of effective rulesets, plan/entitlement and API response
shape. It does not infer or change settings.

## Output and exit contract

Machine-readable JSON includes per-repo policy_state, sanitized blockers
and observed_main_sha plus non-authorizing flags.

- Exit 1: one or more repositories blocked/unknown.
- Exit 2: invalid arguments/missing admin credential/unavailable audit.
- Exit 3: all *classic branch policy metadata* requirements observed. This is
  an **advisory positive**, not process success or permission to release.
- Exit **0 never occurs** in the audited CLI path.

All outputs always contain merge_authorized=false,
release_authorized=false and private_source_export_authorized=false.
This checker cannot establish **independent actual PR approvals**, reviewer
identity independence, **presence/coverage of effective CODEOWNERS files**,
real executed CI, signed artifacts, authorized
private-source carriers, or AttoLang guest parity. Those remain separate gates.

## P0 remediation sequence

1. Have a designated org administrator diagnose Actions runner admission in
   [conformance #315](https://github.com/ores-truffle-oreslang/oreslang-platform-conformance/issues/315).
   A zero-step failed job is NOT_EXECUTED; it does not prove depleted billing
   minutes. First demonstrate a stepful source-org **source-free** job.
2. Configure all source repository main branches using
   [security bootstrap #69](https://github.com/ores-truffle-oreslang/oreslang-platform-conformance/issues/69)
   and platform controls [#170](https://github.com/ores-truffle-oreslang/oreslang-platform-conformance/issues/170).
   Verify with the local read-only audit and separate effective policy readback.
3. Require genuine independent human reviews and complete exact-head
   stepful CI; reviewer *requests*, bot approvals and source-free policy tests
   cannot substitute for this.
4. Preserve independent privacy-incident holds [#22](https://github.com/ores-truffle-oreslang/oreslang-platform-conformance/issues/22),
   [#77](https://github.com/ores-truffle-oreslang/oreslang-platform-conformance/issues/77),
   and [#127](https://github.com/ores-truffle-oreslang/oreslang-platform-conformance/issues/127).
   No cross-org private-source transfers pending explicit security resolution.
5. Only then integrate the reviewed premerge and postmerge evidence proposals,
   and execute pinned Java/LLVM/Wasm/Forge/.NET compiler and guest fixtures.
   Never treat an advisory status as authorization.

This is a non-authorizing governance evidence artifact, not an administration
API implementation, bypass, attestation signing key or release workflow.
