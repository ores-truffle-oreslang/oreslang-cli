# AttoLang public release trust registry v1 — NON-AUTHORIZING

This reviewable source-free prototype stacks on CLI [#153](https://github.com/ores-truffle-oreslang/oreslang-cli/pull/153). It composes the existing local DSSE artifact verifier with a second, independently signed trust registry.

**Neither DSSE signature proves GitHub review/CI/backend execution. A root-signed local policy is not a privileged release decision.**

## Keys, roles and origin

Supply a separately approved Ed25519 **root SPKI PEM** and pin its DER SHA-256 fingerprint independently in the expected-policy record. The registry envelope is canonical compact UTF-8 JSON with exactly `payloadType`, `payload` and one `signatures` entry. The type is `application/vnd.atto.trust-registry.v1+json`; Ed25519 signs DSSE pre-authentication encoding (PAE) over that exact type and the byte-identical payload.

The root-signed payload has exactly:

- `schema`: `atto.trust-registry.v1`
- `policy_id`: a stable, externally approved name
- `sequence`: monotonic positive policy generation
- `not_before` and `not_after`: strict whole-second UTC bounds
- `keys`: up to 32 unambiguous Ed25519 SPKI public keys, each with a computed `keyid`, `role`, `repository`, bounded validity interval and optional `revoked_at` timestamp (null when not revoked).

The defined roles are **candidate-signing**, **build-provenance**, **release-approval**, and **governance-review**. Only `candidate-signing` can validate the signed release candidate. A build signer or reviewer cannot impersonate that role. The offline root key itself cannot be delegated as a release-candidate signer. No production private keys are added or used.

## Externally pinned expected identity

Supply a separately trusted, canonical JSON expected record containing exactly:

`policy_id`, `minimum_sequence`, `root_keyid`, `repository`,
`head_sha`, `tree_sha`, `artifact_sha256`, and `envelope_sha256`.

This binds accepted local evidence to an externally specified immutable source head/tree, artifact digest, particular DSSE envelope bytes, explicit trusted root fingerprint and minimum policy generation. Signed old registries with generations less than `minimum_sequence` cannot be replayed as current. A signer whose key is expired, not yet valid or revoked at the supplied `now` is denied.

**Caveat:** a local file is not automatically independently trusted. In production, this record and monotonically increasing minimum sequence must be supplied by a separately authenticated authority; copying the expected values from the candidate or mutable working tree defeats the threat model. The current library takes caller-supplied `now`, and the CLI uses the local system clock. Neither is independently authenticated by this implementation. Clock rollback and stale external state remain blockers to production authorization. Registry sequence plus pinned envelope digest reduce substitution risk but are not a global replay database or unique-release nonce.

## CLI

```bash
node tools/release-trust-registry-v1/verify.mjs \
  --registry ./offline-root-signed-registry.dsse \
  --root-key ./independently-trusted-root-spki.pem \
  --candidate ./release-manifest.dsse \
  --artifact ./atto-release.tar.gz \
  --expected ./independently-pinned-release-identity.json
```

- Exit `3`: `TRUST_POLICY_BOUND_LOCAL_CANDIDATE`, still `release_authorized=false`, `authenticated_github=false`, `compiler_guest_parity_proven=false`.
- Exit `1`: `DENIED` (signature, expiry, revocation, role, scope, or pinned identity mismatch).
- Exit `2`: malformed usage or unsafe file admission (bounded no-follow single-linked regular files).

**No path returns an authorized exit code 0.** The expected record and root-key path should be outside the untrusted build workspace. Even for a matching cryptographic candidate, independent authenticated GitHub job/review/policy evidence, five source-backed compiler guest receipts, independent release approval, secure clock, live revocation, and a final race-safe readback are needed before release.

## Adversarial and provenance tests

`.github/workflows/release-trust-registry-v1.yml` runs Node 22.20.0, pinned Actions checkout/setup-node, immutable original PR SHA checkout and raw Git-blob identity verification before invoking both the existing base release-assurance tests and new trust-policy tests. Tests use ephemeral synthetic root/signing keys only, and exercise key swaps, root substitution, key-role confusion, duplicates, expiry, current/future revocation, policy rollback, stale-envelope pins, changed source identity, tampered artifact, incorrect clock, canonical JSON/DSSE errors, and CLI nonzero exit behavior. This workflow does not access private compiler source or require privileged tokens.

The existing conformance [#516](https://github.com/ores-truffle-oreslang/oreslang-platform-conformance/pull/516) release-certificate reporter and authenticated collector/merge bridge are independently owned and are **not** modified here. Their live source/CI evidence remains necessary. Branch protection and an independent code-owner approval remain separate administrative requirements.
