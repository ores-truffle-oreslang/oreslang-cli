# AttoLang PostgreSQL ledger service v1 — NON-AUTHORIZING

This new public source-free child of CLI DRAFT #161 implements an **authenticated,
loopback-only PostgreSQL CAS service** as a bridge from the existing local SQLite
prototype. It does not enable a release publisher, authorize production releases,
perform independent GitHub API evidence collection, or prove five-backend guest
execution. It is a *transactional diagnostic service*, not a production authority.

## Protocol and operational boundaries

- Only POST /v1/claim, POST /v1/receipt and GET /healthz exist. Every result
  includes release_authorized=false, authenticated_github=false and
  compiler_guest_parity_proven=false. /healthz says alive, **not ready to publish**.
- Client requests require a 32-byte HMAC secret passed out of band, a canonical
  exact-key JSON body, a strict client identity, signed method/path/body digest,
  explicit timestamp with +/-30s local clock window, and a distinct 32-byte
  request nonce. Duplicate/extra auth headers, unknown routes, malformed JSON,
  noncanonical bytes, unexpected authority flags, oversized bodies, and bad MACs
  are denied before database access. Request bodies are capped at 32 KiB.
- A dedicated PostgreSQL role must own a **preinstalled** schema. There is no
  HTTP bootstrap or schema mutation endpoint. An operator-only bootstrap helper
  confirms a fixed repository scope without ever resetting an existing ledger.
- POST /v1/claim uses a real PostgreSQL BEGIN transaction, row lock
  SELECT ... FOR UPDATE, a persistent unique (client,auth_nonce) and
  (client,client_request_id) replay journal, an exact high-water compare-and-swap
  and a uniqueness-enforced event append. Failed/stale requests consume an
  authenticated request ID and nonce if the rejection transaction commits.
  Policy generations cannot decrease and a ledger cannot pivot repositories.
  Retried request IDs are rejected rather than committed a second time.
- On any loss of COMMIT acknowledgement the service reports
  LOCAL_PG_COMMIT_UNVERIFIED / ledger_cas_committed=null and
  requires_manual_reconciliation=true. An authenticated /v1/receipt lookup
  returns the server's durable committed/rejected receipt. A receipt never
  authorizes publication. Uncommitted pre-COMMIT errors cause ROLLBACK.
- The HTTP process binds **127.0.0.1 only**. HMAC alone is *not transport
  confidentiality* or separate human review; never expose it to the network
  without a separately administered mutually authenticated TLS or identity
  proxy, strictly isolated secrets, allowlists, least-privilege DB roles and
  independent source-verification service.

## Tests and formal work

The source-owned original-PR-head GitHub Actions test uses an ephemeral
PostgreSQL 16.8 service plus native Node 22.20.0. Real concurrency tests include
100 simultaneously competing clients with exactly one committed sequence,
100 same-request retries, policy-generation rotations, multi-ledger parallel
claims, persistent denial nonces, authenticated HTTP requests and lost-COMMIT
acknowledgement reconciliation. Unit cases cover canonical JSON, malformed
HMAC/timestamps/route binding, poison fields, UTF-8, replay identities and
boundary input classes. Actual Git blob SHA/tree and positive executed-step
CI evidence are separate from TLA+ model authoring.

The TLA+ specification at formal/release-ledger-service-v1/ReleaseLedger.tla
is an **authored abstract state machine only**. TLC/Apalache has **not** checked
it, and no proof of real PostgreSQL linearizability or power-loss durability is
claimed. PostgreSQL integration tests do not establish consensus or resistance
to operator rollback, compromised DB roles, nonmonotonic trusted time,
network partitions, or Byzantine actors. All test credentials are synthetic.

## Important release holds

1. The service does not yet verify actual DSSE candidate/intent envelopes:
   an HMAC-authenticated client may request a *diagnostic* local CAS. No
   request or resulting receipt is allowed to authorize release. Production
   verification must independently pin the root key, live GitHub approval
   and required CI, fresh revocations, guest toolchain receipts and trusted
   now, rather than trusting source-free caller claims.
2. A PostgreSQL primary with row locks is not independently authenticated
   durable consensus state. Protection against rollback requires a separately
   administered monotonic witness or quorum log, HA failover tests and
   precisely specified commit acknowledgements.
3. This reference installation uses an exact major/minor PostgreSQL test
   image and an exact direct pg dependency, but lacks reviewed transitive
   package-lock integrity and signed deployment provenance. It must not be
   promoted or deployed as a privileged production controller.
4. Parent stack integration and governance remain blocked: CLI PRs
   #153 -> #154 -> #159 -> #161 -> this child, independent reviewer identity,
   protected main and original-head fully executed CI. A requested approval
   from an operator-linked account is not independent.

## Run on a disposable local PostgreSQL instance

Install the exact package version under tools/release-ledger-service-v1,
create a disposable PostgreSQL database and set ATTO_LEDGER_TEST_PG_URL to
the disposable database URL. Then run Node 22:

    node --test tests/release-ledger-service-v1.test.mjs tests/release-ledger-service-v1-pg.test.mjs

For the non-public diagnostic HTTP process, use ATTO_LEDGER_PG_URL,
ATTO_LEDGER_HMAC_KEY_HEX (exactly 64 lowercase hexadecimal characters),
ATTO_LEDGER_TEST_CLIENT and ATTO_LEDGER_PORT, then run server.mjs.
Schema installation is an **out-of-band operator action** and never happens
when the HTTP server starts.

PostgreSQL transaction reference: https://www.postgresql.org/docs/current/explicit-locking.html
PostgreSQL unique constraints: https://www.postgresql.org/docs/current/ddl-constraints.html
