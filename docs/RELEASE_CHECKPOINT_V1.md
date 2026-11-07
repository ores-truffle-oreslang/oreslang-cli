# AttoLang role-separated release checkpoint v1 (NON-AUTHORIZING)

This public, source-free additive prototype is stacked on [CLI #154](https://github.com/ores-truffle-oreslang/oreslang-cli/pull/154), itself stacked on [#153](https://github.com/ores-truffle-oreslang/oreslang-cli/pull/153). It does **not** modify either parent. Parent-first integration and independent review remain required.

## Security model and actual limitation

The parent validates a canonical Ed25519 DSSE candidate against an independent root-signed trust registry, immutable source head/tree and real artifact bytes. This child adds two **additional** DSSE-signed payloads with different delegated key roles:

1. **Checkpoint**, signed by a separately delegated governance-review key: the ledger ID, most recently consumed sequence, predecessor intent hash and nonce, registry byte hash, policy identity/generation and short observed_at / expires_at window.
2. **Release intent**, signed by a separate release-approval key: exact repository/head/tree/artifact/candidate-envelope, registry hash, policy identity/generation, ledger ID, next sequence, predecessor hash, unique nonce and short issue/expiry window.

Both signing keys must belong to the **same root-signed registry** authenticated by the parent and must not equal the delegated candidate-signing key or each other. Repository-scoped role, validity, current revocation and signature checks remain mandatory.

An **independently trusted caller** must additionally pin the complete checkpoint and intent envelope SHA-256 hashes, ledger ID, next expected sequence and last intent hash. The verifier checks exact byte equality to those pins, nonzero nonce, no immediate nonce reuse, sequence last + 1, predecessor link, policy/registry identity, and a five-minute maximum issuance/freshness/lifetime window.

**Crucial:** signed checkpoints, even when fresh, do not prove that the asserted high-water mark is the latest committed state. The current library does not have an authenticated monotonic storage backend, compare-and-swap or atomic consumption. A stale but valid signed snapshot plus stale externally supplied pins can still be replayed. This is an intentionally **advisory local candidate** and not an authorization or secure replay database. Verify policy/revocation/time at the instant of any future privileged action, not only at preparatory verification.

## Hardened lifetime intersection

The checkpoint's exclusive `expires_at` must be **no later than** the governance-review key's delegated expiry, its scheduled revocation (if any), or the root-signed registry expiry. The release intent's exclusive expiry must be **no later than** the checkpoint expiry, the release-approval key's expiry/revocation, the candidate-signing key's expiry/revocation, or the registry expiry. An exact equality at an exclusive boundary is allowed; even a one-second overrun is denied. A key valid at the current clock instant is insufficient for a later-expiring signed claim. Candidate envelopes have no independently authenticated signing timestamp, so a delegation covering the asserted intent interval is a conservative admission constraint, **not** proof when the candidate was signed.

These restrictions only prevent locally contradictory validity windows. They cannot establish that `now` is an independently authenticated time, that root revocations were fetched live, or that the checkpoint came from the latest durable atomic high-water store. The "two concurrent intents, one sequence" problem remains blocked by absence of CAS: no successful local result can spend a sequence or authorize release.

## Canonical payloads

- DSSE payload type application/vnd.atto.release-checkpoint.v1+json; strict keys: schema, repository, policy_id, policy_sequence, registry_sha256, ledger_id, last_sequence, last_intent_sha256, last_nonce, observed_at, expires_at.
- DSSE payload type application/vnd.atto.release-intent.v1+json; strict keys: schema, repository, head_sha, tree_sha, artifact_sha256, candidate_envelope_sha256, policy_id, policy_sequence, registry_sha256, ledger_id, sequence, previous_intent_sha256, nonce, issued_at, expires_at.
- External pin JSON schema atto.release-link-pin.v1 with checkpoint_sha256, intent_sha256, ledger_id, next_sequence, and previous_intent_sha256; all fields required and no extras.

All hashes are lowercase SHA-256. First-ever genesis checkpoint requires last_sequence=0, all-zero predecessor hash and all-zero last nonce. Its next sequence is 1. For established ledgers, the high-water state must come from authoritative append-only/transactional storage, not a workspace JSON file.

## CLI

    node tools/release-checkpoint-v1/verify.mjs \
      --registry ./root-signed-registry.dsse \
      --root-key ./pinned-root.pem \
      --candidate ./candidate.dsse \
      --artifact ./release.tar \
      --expected ./independently-pinned-release.json \
      --checkpoint ./governance-checkpoint.dsse \
      --intent ./release-intent.dsse \
      --pin ./independently-pinned-ledger-state.json

Exit code **3** = SEQUENCE_LINKED_LOCAL_CANDIDATE (not release-authorized). Exit **1** = denied. Exit **2** = invalid usage or unsafe file admission. There is **no exit code 0**. Every result has release_authorized=false, authenticated_github=false, compiler_guest_parity_proven=false, ledger_cas_committed=false. The CLI relies on its unauthenticated host clock, so production clock assurance is not provided.

The expected record and pin file names are not security credentials; a tampered caller can supply matching files. They **must originate out-of-band from a genuinely trusted governance and ledger authority**. Never automatically derive them from untrusted candidate or mutable repository data.

## CI and unfulfilled P0 release gates

The source-owned workflow checks out the *original immutable PR head*, verifies the exact Git commit/tree and each source blob, executes base + registry + new adversarial Node tests using pinned Node 22 and read-only GitHub token permissions. All signing identities in tests are ephemeral synthetic keys. No production signer keys, private compiler sources, runner mirroring, releases, branch protections, or approval bypass are touched.

Before any privileged release can be considered, separately implement and **prove** an atomic compare-and-swap on the authoritative ledger, secure trusted time and revocation freshness, independently authenticated GitHub head/tree/review/policy/job/run-attempt/step evidence, all five real compiler-backed guest receipts, protected main, independent current-head code-owner approval and a final race-safe readback. Until then no merge or publish is authorized merely by these local cryptographic checks.
