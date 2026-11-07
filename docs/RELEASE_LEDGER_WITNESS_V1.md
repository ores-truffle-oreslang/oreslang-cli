# AttoLang monotonic-witness reference v1 — NON-AUTHORIZING

This is an isolated security DRAFT child of CLI #165. It implements a
reference to a separately administered witness, NOT a deployed independent
witness and NOT a production release authorization service.

## Explicit independence limit

CI creates TWO PostgreSQL databases in ONE disposable PostgreSQL 16.8
cluster with the SAME test role. This genuinely exercises two separate
transaction state stores, but NOT distinct administrative trust principals,
failure domains, consensus/quorum, external rollback proof, secure clock,
separate signing-key custody, Byzantine behavior, production transport or
safe multi-region failover. Production needs an entirely separately operated
witness service, authenticated transport, independent database roles, signed
checkpoint provenance and durable quorum.

## Three-phase fail-closed protocol

1. RESERVE: after #165 locally validates the operator-pinned Ed25519 DSSE
   intent chain, the coordinator compares independently read primary/witness
   current high-water state with the signed checkpoint. Witness reserve uses
   a transaction and row lock to create exactly ONE persistent pending
   reservation, generation and token, bound to repository, intent digest,
   policy generation, client request ID, predecessor digest and nonce.
   Conflicting reservations are rejected and existing reservations fence all
   subsequent sequence requests.

2. PRIMARY COMMIT: only an already reserved intent is submitted to existing
   #162 PostgreSQL compare-and-swap. A lost commit ACK or timeout is not proof
   of noncommit. Pending reservations NEVER automatically expire or abort.
   No release publisher exists.

3. WITNESS FINALIZE: a witness-controlled readonly primary DB identity must
   independently read the exact committed event AND current primary high-water
   digest, nonce, head, artifact, policy, request ID and repository. The
   witness atomically appends its own event, advances generation and deletes
   its pending reservation. A distinct Ed25519 witness signing key produces
   a bounded canonical receipt from persisted witness events. Clients must
   independently pin the witness public key; no client claim or boolean can
   satisfy proof.

MANUAL RECONCILIATION: if primary acknowledged its durable commit but the
client missed the ACK, the witness can finalize only after independent
primary readback. If the witness finalize ACK was missed, an operator can
read the persisted finalized event, verify token and digest and reconstruct
the signed receipt. There is NO automatic unreserve on timers, no permission
to skip a sequence and no publication after a pending/unknown state.

The synthetic test signing private key is generated in the disposable CI
process only. It is not real independence. The separate operator API is
injected in tests, not deployed with production authorization.

## Adversarial tests

Hosted Node22 tests with the two disposable PostgreSQL databases cover:
100 competing witness reservations; 100 concurrently signed witness/primary
claims; 100 repeated requests; 20 independent ledgers; precommit crash;
lost primary and witness ACK; witness/primary partitions; replayed nonce;
wrong reservation token; stale generation; cross-repository pivot; policy
rollback; fake witness signing identity; malicious primary snapshot restore;
malicious witness snapshot restore; no auto-unreserve; 100 Ed25519 signature
tamper tests; 40 signed-payload tamper tests; and 220 primary/witness
high-water mutation tests.

These tests require original-HEAD Git checkout, exact tree and blob
verification, and actual nonzero executed CI steps. A same-cluster simulation
does not prove multi-region consensus or independence.

## Bounded actual TLC checks

formal/release-ledger-witness-v1/WitnessProtocol.tla models the ordered
reserve/primary-commit/witness-finalize protocol, concurrent writers,
client cancellation before reserve, lost acknowledgements and crash/partition
stuttering. It checks witness never ahead of primary, primary never more than
one reservation ahead, no unreserved primary commits, nondecreasing policy,
single generation, nonreplayed nonce and publication permanently disabled.

Two deliberately unsafe mutant models (primary commit with no witness
reservation and witness finalization before primary) must be REJECTED by
actual TLC for their named invariant violations. TLC JAR pinned SHA256:
ab323b79802aedc3203b3f9af37c6aca3ed43f4e0225b36f2aa77b26de46c05f.

TLC is bounded with a single linearizable witness assumption. It does not
prove source code, DB power-loss behavior, real consensus or clock security.

## Production admission HOLD

All results remain release_authorized=false, authenticated_github=false,
compiler_guest_parity_proven=false. No deployment, production credentials,
actual publisher, release merge or independent authority are created.
External GitHub reviews/head/required checks, five actual compiler-backed
guest receipts, protected main, trusted time/revocation, independent
CODEOWNER reviewers, quorum-backed witness and separate credentials
remain unsatisfied. Parent first #153 → #154 → #159 → #161 → #162 → #165
→ this witness child, all subject to review and current CI.

For disposable PG only, configure ATTO_LEDGER_TEST_PG_URL and
ATTO_WITNESS_TEST_PG_URL to DIFFERENT databases and run:

    node --test tests/release-ledger-witness-v1.test.mjs tests/release-ledger-witness-v1-pg.test.mjs
    bash formal/release-ledger-witness-v1/run-tlc.sh

Never install these schemas in production through the test harness.
