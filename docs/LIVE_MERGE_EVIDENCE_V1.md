# AttoLang live merge evidence v1: independent authority integration prototype

## Scope and status

This PUBLIC CLI PR demonstrates authenticated, read-only GitHub REST evidence collection, deterministic analysis, and detached external Ed25519/DSSE signature validation over a SHA-256 digest. It intentionally has no private key, no GitHub write capability, no merge action, no release action and no authorizing result.

DO NOT run this project's PR-authored verifier as a trusted deployment. A PR author can change any code in an unprotected repository. The independent authority must pin and review its own binary/source and workflow in a separate protected security domain. The status returned here is only evidence consistency, never merge eligibility or certification.

Related work is independently scoped: CLI #153–#154 signed offline receipt experiments, CLI #159–#162 checkpoint/transactional-ledger experiments, CLI #155–#158/#160 advisory review, postflight, ownership and administrator plans, and .github #30–#33 offline evidence. This PR adds LIVE GitHub API capture and pinned workflow-definition verification, not another release ledger or signer. Track P0 governance in organization .github issue #34.

## Verified source policies (2026-11-07 UTC)

Four allowlisted PUBLIC repositories have immutable numeric IDs, mainline GitHub Actions CI workflow IDs and file blob SHA pins in verify.mjs. Before deploying, an independent maintainer must review these facts and promote the immutable verifier separately.

| Repository | GitHub repo ID | Workflow ID | Required job names |
| --- | ---: | ---: | --- |
| oreslang-cli | 1402495995 | 373591906 | rust |
| html-js-css-syntax-highlighter | 1409308342 | 377788496 | test, browser-dom, release-package |
| sublime-text-plugins | 1402482919 | 373587523 | package, sublime-syntax-engine, release-package |
| vscode-plugins | 1402488145 | 373588125 | test, vscode-restricted-mode, release-vsix, Native VS Code extension-host smoke (not compiler guest), Windows archive extraction (not IDE GUI) |

Every expected job binds GitHub Actions issuer app_id 15368, run ID and attempt, job/check-run ID, runner ID, successful source-identity guard, and executed meaningful test step. A same-app green check emitted from a modified PR workflow is not considered pinned. The workflow blob pins refer to PRE-EXISTING main; e.g. VS Code #211's updated CI workflow cannot qualify until an independent review and trusted pin revision.

## Trusted external deployment sequence (not automated in this PR)

1. Administrator enables protected main for all four repos, requires current independent PR approval, review by independent CODEOWNERS, stale-review dismissal, last-pusher approval, conversation resolution, admin enforcement, no bypass, no force push/deletion, and strict issuer-bound successful CI. CLI has a two-phase CODEOWNERS bootstrap (draft #158 and #160).
2. An independent security operator deploys a separately reviewed and pinned verifier and its allowed API routes on a protected host or separately controlled GitHub App; provision read-only GitHub metadata and administrative branch-protection/ruleset GET access. NEVER grant a token to an untrusted PR workflow. The current GitHub App connection cannot read /branches/main/protection (HTTP 403).
3. Authenticated collector GETs repo identity, main before/after, exact PR before/after, head commit/tree, CODEOWNERS on main, workflow file at exact PR head, branch protection, inherited ruleset detail and effective branch rules, complete review history, check-run issuer IDs and matching Actions run IDs/attempts/runner jobs. It rejects 403, 404, pagination, duplicate IDs, changed head/base. There is no source-owned fallback.
4. Verify approval freshness and independence. No author, operator-controlled alternate identities (the1mills, ORESoftware), dismissed/superseded reviews; COMMENTED does not clear CHANGES_REQUESTED. The model does not prove the reviewer is human or Code Owner independently; trusted admin policy still required.
5. Independently inspect workflow definitions and all transitive executable dependencies. This reference pins the CI workflow YAML blob and source-guard step, but cannot prove every script/action/tool was independently reviewed. Unknown effective rules and modified workflow definitions fail closed. App ID 15368 alone does not establish workflow provenance.
6. Re-fetch current PR head, main/base and effective policy IMMEDIATELY before a privileged merge, then atomically compare a merge intent against SHA-bound evidence. This model does NOT implement a privileged atomic action. Any code, base, approval, CI, workflow, runner attempt or settings drift must reject.
7. After independent authority approval, an external protected signer MAY sign exact candidate digest via Ed25519 DSSE, holding private keys OUTSIDE this repository and PR. The attest.mjs module takes only an externally pinned Ed25519 SPKI public key and SHA-256 key ID and verifies canonical payload/signature. This verifies signature, NOT merge/release permission. The key presented by a PR or envelope is NEVER a trusted root.
8. A separately protected multi-host durable ledger must atomically record monotonic sequence/CAS, request nonce, replay and revocation before privileged action. CLI #161/#162 are EXPERIMENTAL non-authorizing references, not automatically trusted services. No signer is included here; no authority without a separately controlled deployment.

## Administrator-only read-only usage

From a separately reviewed executable on a trusted host (not a PR workflow):

    GH_TOKEN='<admin-read-only-token>' node tools/live-merge-evidence-v1/collect.mjs --repo ores-truffle-oreslang/oreslang-cli --pr 158 --out /secure/evidence.json

Output file must not exist; capture uses exclusive create (0600), no symlink follow and refuses >1 MiB JSON. Run on a secure private filesystem; token is never printed. A 403 or incomplete readback is terminal. The PR-owned workflow NEVER calls the live collector and NEVER receives an administrator token.

verifySnapshot(snapshot) is read-only. A consistent snapshot yields evidence_consistent:true and candidate_sha256, but merge_authorized:false, release_authorized:false and private_source_export_authorized:false. A forged snapshot can imitate the entire JSON structure: consistency is NOT independent proof of origin. The digest is unsigned, NOT a release manifest.

verifyExternalSignature(candidate_sha256, dsse_envelope, externally_pinned_anchor) verifies Ed25519 DSSE payload type application/vnd.attolang.live-merge-evidence-sha256.v1 with canonical UTF-8 payload: 64 lowercase hexadecimal SHA-256 bytes plus one newline. This proves only a cryptographic signature relative to the SEPARATELY supplied trust root. Freshness and anti-replay require independent service and ledger.

## Test coverage and nonclaims

Source-owned Node 22 tests cover four-repo policy identity, hostile fork/PR/base/head/tree/ruleset/review/check-run/workflow/runner failures, denied administrative protection reads, pagination and replay ambiguities, and real ephemeral Ed25519 sign/verify negative controls. PR CI checks out original exact HEAD, validates physical blob IDs and executes public tests. These are source-free HOST tests only.

This DOES NOT establish a trustworthy deployment, authoritative timestamps, human reviewer independence, transitive dependency audit, actual atomic GitHub merge, real protected branches, private compiler guest parity or release authority. No private code may be mirrored into public GitHub CI.
