# Five-merge security postflight — November 7, 2026

Public, metadata-only audit: **not** a merge permission, release certification, signature verification, or compiler-backed AttoLang execution proof.

## Confirmed landed evidence

| PR | Merge SHA | Host CI run |
| --- | --- | --- |
| html-js-css-syntax-highlighter #269 | 30dc3935c71207118149809d713f8d1d8d66154d | 42317820906 |
| oreslang-cli #151 | 7eaa52e4f52d95df670d516d34d4907872be1730 | 42317841429 |
| sublime-text-plugins #144 | 2f6530a587f69ac5efb68ddfa1321e521bac2422 | 42317848407 |
| vscode-plugins #217 | 73b4ae187c68878631649e7936051002605238ff | 42317855556 |
| html-js-css-syntax-highlighter #267 | e53e657a5404fdd465ffbdd2a403b0d67a965c55 | 42317954805 |

All five post-merge push runs succeeded with meaningful executed test steps. **All five merged PRs lack submitted independent review.** As inspected, all four default branches report protected=false, no rulesets and no separately readable enforced protection details (403 to the current integration). Host checks are not compiler guest validation.

The current VS Code workflow lacks an explicitly named exact-original-HEAD verification step. Existing draft VS Code #211 addresses that gap; coordinate with its owner rather than overwriting its files.

## How to execute

Run deterministic adversarial host-only tests:

    node --test tests/five-merge-postflight-20261107.test.mjs

Run read-only live metadata check (token optional for public endpoints):

    GITHUB_TOKEN=READ_ONLY_TOKEN node tools/five-merge-postflight-20261107.mjs --live

The live command emits JSON and **exits nonzero**. It checks public PR head and merge identities, ancestry to main, original-head review timestamps, current policy, exact-landed SHA push run, and completed test steps. HTTP 403, partial pagination, missing source identity or zero runner steps cannot promote the batch. The source-free workflow intentionally runs unit tests only, never a synthetic self-certification.

## P0 administrator remediation

1. Enable required pull requests on main for all four repositories, at least one **independent code-owner approval**, stale approval dismissal, required status checks backed by meaningful exact-head CI, administrator and automation bypass restrictions, and effective CODEOWNERS policy. Re-read effective protection settings after configuration.
2. Independently audit the **already landed** five diffs and mark the historical review exception. A review performed now is NOT a pre-merge approval.
3. Finish exact-head checkout-hardening for VS Code through existing owner-scoped PR #211, with test evidence, independent review and protected merging.
4. Require signed release evidence and exact-main postflight tests, and obtain explicit independent release-owner recertification before release. Do not rewrite main history, export private source, or treat CODEOWNERS alone as enforcement.

Historical branch enforcement and pre-merge approvals cannot be reconstructed from present-day settings. The incident audit **always returns BLOCKED** even when current policy is subsequently strengthened. Track coordination at oreslang-platform-conformance issue #359.
