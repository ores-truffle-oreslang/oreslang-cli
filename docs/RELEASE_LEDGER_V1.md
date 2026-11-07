# AttoLang transactional release-intent ledger v1 — LOCAL ONLY

This additive, PUBLIC, source-free reference implementation is stacked only on existing unmodified CLI [#159](https://github.com/ores-truffle-oreslang/oreslang-cli/pull/159), which depends on #154 and #153. The intent is to close the two-concurrent-intents/one-checkpoint race for a **single SQLite database on one host** while preserving strict non-authorization.

## Implemented and boundaries

- Node 22 built-in node:sqlite DatabaseSync; private owner directory mode 0700 and a single-linked regular SQLite file mode 0600; reject symlinks, hardlinks, path aliases and unexpected file replacement.
- SQLite **WAL**, verified **synchronous=FULL**, busy timeout, foreign keys, schema version and exact schema checks; BEGIN IMMEDIATE around a verified ledger snapshot, atomic event insert plus compare-and-swap update, then COMMIT. Unique ledger/sequence, intent digest and nonce prevent reuse. A bounded 4096-event chain is validated on every read using predecessor hashes.
- Explicit one-time genesis bootstrap (sequence 0, zero predecessor/nonce) refuses an existing file. Never silently reinitialize an existing damaged database.
- Signed integration entrypoint consumeSignedIntent first calls existing #159 verifySequenceLinkedCandidate, derives checkpoint and intent fields from **previously DSSE-verified canonical envelope bytes**, and performs local ledger CAS. Raw consumeLocalAdvisoryClaim is separately named and exported only as a non-authorizing local reference primitive (not a release verifier).
- A local successful transaction reports LOCAL_LEDGER_CAS_COMMITTED and ledger_cas_committed=true; all results retain release_authorized=false, authenticated_github=false and compiler_guest_parity_proven=false. It never publishes. Test probe CLI exits 3 for local-only success, 1 for denial, 2 for malformed usage; never exit zero for authorization.
- Native Node adversarial coverage includes parallel subprocesses competing for one sequence; missing/invalid pins, corrupt state/schema, symlink/hardlink/permission attacks, restart/recovery, process exit before insert, after insert, before COMMIT and after COMMIT. A post-commit client crash leaves the sequence consumed; retry denied.

## Fail-closed scope, policy and commit-outcome rules

Each ledger ID represents **one repository scope**, established by its first event and held constant across later events. Committed `policy_sequence` may remain equal or increase, but never decrease. Both the transactional admission and full event-chain read reject a cross-repository transition or lower policy generation. Corrupted historical scope or policy monotonicity blocks all future reads and claims; an authorized migration requires a new reviewed protocol, not a silent reset.

Transaction outcomes distinguish **pre-commit rejection** from **post-commit uncertainty**. A clean denial means the transaction did not produce a committed CAS (or the signed input was rejected before reaching it). If SQLite COMMIT returned successfully but a subsequent file-integrity readback fails, the result is `LOCAL_LEDGER_COMMIT_UNVERIFIED` with `ledger_cas_committed:null` and `requires_manual_reconciliation:true`, never a misleading clean `DENIED`. This is **not authorization** and does not promise the database is intact; an independent operator must reconcile the durable event before retrying. A synthetic post-commit test observer throwing after COMMIT cannot undo the transaction; successful CAS is reported with `postcommit_observer_failed:true`. Caller-supplied callbacks remain test-only and must not enter any privileged publisher.

These checks do **not** defend against an adversary who can rewrite the entire database with the same UID, restore an older valid snapshot, compromise SQLite WAL sidecar files, or roll back external evidence. A trusted distributed high-water service is still necessary.

## Important limitations — NOT production authorization

This is **not an independent distributed ledger**. SQLite WAL coordinates writers only on the same host with a correct local filesystem. It must never be placed on NFS/SMB, ephemeral runners, or shared network mounts. Same-UID compromise can alter/replace the database or filesystem; a stale database image may be rolled back. A caller-supplied signed checkpoint or expectation is not an independently authenticated monotonic high-water read. A separate trusted governance service must own the ledger, authoritative pin, revocation and secure clock before publication authority is considered.

SQLite FULL-sync is intended to support local durable commits on a correct filesystem, but CI process-exit tests do **not** simulate power loss, damaged disks, Byzantine storage, replicated consensus or trusted time. The 4096-event cap fails closed until a reviewable schema migration and archival strategy exist.

All tests use synthetic keys and bytes; simulated compiler-guest receipts are NOT compiler-backed five-backend verification. Even locally committed signed intent does **not** prove live GitHub checks, independently submitted approvals, protected main, current revocation, toolchain identity or native code generation. Release remains blocked. Parent-first integration #153 -> #154 -> #159 -> child, with independent CODEOWNER/security review.

## Reproducibility

    node --test tests/release-assurance-v1.test.mjs tests/release-trust-registry-v1.test.mjs tests/release-checkpoint-v1.test.mjs tests/release-ledger-v1.test.mjs

Source-owned GitHub Actions pins Node 22.20.0 and checkout to reviewed hashes, disables persisted GitHub credentials, verifies the original PR SHA/tree and every dependent Git blob, executes real tests and validates TAP totals. Zero-step and skipped tests cannot count as success.

For the single-host restriction see SQLite WAL https://sqlite.org/wal.html and synchronous=FULL https://sqlite.org/pragma.html#pragma_synchronous. A production release authority needs separately administered transactional/consensus service with authenticated monotonic quorum state and immutable audit.
