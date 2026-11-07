# AttoLang signed PostgreSQL claim admission and bounded TLC verification v2

**Public, non-authorizing security child of CLI #162.** This is a reviewable
loopback diagnostic service, not a production publisher or release approval.

## Trust boundary

The service operator, not the HMAC client, pins the Ed25519 root public key,
the exact source/candidate/artifact expectations and the checkpoint and intent
envelope hashes. Configuration is deep-copied and frozen before admission.
Operator-supplied pins and clock are not themselves independently attested.

v2 HTTP uses a separate HMAC-SHA256 domain (ATTO-SIGNED-LEDGER-v2) over
method, route, canonical request-body SHA256, client identity, timestamp
and nonce. v1 credentials cannot be replayed into v2. POST v2 signed-claim
and receipt are the only stateful HTTP routes, limited to loopback and
32KiB request bodies. Only exact fields with canonical base64 are accepted.

Existing #159 verifySequenceLinkedCandidate checks the root-signed policy,
Ed25519 role separation, delegated signer validity/revocations and lifetimes,
signed checkpoint and intent sequence/freshness and externally pinned digests,
synthetic candidate receipts and artifact bytes before any DB operation.
The adapter only derives PostgreSQL claim fields from **already verified**
signed intent payloads. PostgreSQL current high-water snapshot is compared
to the signed checkpoint (repository, seq, previous SHA and previous nonce).
This check is raceable: the parent #162 PostgreSQL transaction (row lock,
unique events, sequence + predecessor CAS, durable request replay journal)
decides the actual winner.

Every outcome has release_authorized=false, authenticated_github=false and
compiler_guest_parity_proven=false, even if locally committed. The inherited
v1 HMAC-only route remains a lower-trust non-publishing diagnostic and cannot
be used as a privileged release admission.

Test signing keys are freshly generated synthetic Ed25519 identities and
never production signers. The service contains no real release keys.

## Executable bounded formal model

formal/release-ledger-service-v2/ReleaseLedgerChecked.tla models six requests,
two sequence slots, policy floor, competing commits, nonce uniqueness,
repository scoping, rejection, cancellation, lost COMMIT acknowledgements,
receipt reconciliation and publication permanently disabled. The CFG
checks: TypeOK, MonotonicSequence, NoDuplicateSequence, NoDuplicateNonce,
NoPolicyRollback, RepositoryFenced, NoFalseDenial, AckOnlyForCommitted and
NoReleaseAuthorization.

Two separate deliberately broken executable mutant specs remove the policy
floor and force publication after commit. The source-owned CI script requires
real TLC to report NO invariant failure for healthy spec AND detect each
mutant's named invariant violation. If the jar cannot be downloaded or the
runner has zero steps, TLC is NOT_EXECUTED, never a pass.

TLC build 2026.08.11.125311 uses a versioned mirror release rather than a
mutable upstream tag, with exact SHA256
ab323b79802aedc3203b3f9af37c6aca3ed43f4e0225b36f2aa77b26de46c05f.
The finite model checks are bounded, not a proof of PostgreSQL, network,
multi-host durability, real clocks or operating-system security.

## CI and remaining release holds

GitHub Actions checks the immutable PR head and each on-disk Git blob,
executes Node22 adversarial tests with a real ephemeral PostgreSQL 16.8
service, and independently runs TLC and detects negative mutations.
It must check actual executed steps, nonzero test counts, no skipped tests.

The synthetic signed guest/review receipts in test fixtures are **not**
independent GitHub approvals or compiler guest executions. Missing:
independently authenticated rollback-resistant distributed high-water witness,
live GitHub PR/head/required check/run-step and review provenance, true
independent reviewer identity, protected main, fresh trusted clock and
revocation, five compiler-backed executed guest outputs, production credential
custody, mTLS and pinned transitive package/deployment provenance. No actual
release approval, merge or publication is permitted.

Parent-first review: CLI #153 → #154 → #159 → #161 → #162 → v2 child.

On a disposable PostgreSQL instance only:

    node --test tests/release-ledger-service-v2.test.mjs tests/release-ledger-service-v2-pg.test.mjs
    bash formal/release-ledger-service-v2/run-tlc.sh

Use ATTO_LEDGER_TEST_PG_URL for the isolated PostgreSQL database. Never
execute this test schema installer against production data.
