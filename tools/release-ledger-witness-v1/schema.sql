-- AttoLang NON-AUTHORIZING separately administered monotonic witness schema.
-- In CI this is a SECOND DATABASE IN THE SAME EPHEMERAL CLUSTER, not a real
-- independent trust/failure domain. Operator must use a separate cluster/role.
CREATE TABLE witness_state (
  ledger_id text PRIMARY KEY CHECK (ledger_id ~ '^[a-z][a-z0-9._-]{2,63}$'),
  repository text NOT NULL CHECK (repository ~ '^ores-truffle-oreslang/[a-z0-9][a-z0-9._-]{0,119}$'),
  sequence bigint NOT NULL DEFAULT 0 CHECK (sequence BETWEEN 0 AND 1000000),
  policy_sequence bigint NOT NULL DEFAULT 0 CHECK (policy_sequence BETWEEN 0 AND 1000000),
  last_intent_sha256 text NOT NULL DEFAULT repeat('0',64) CHECK(last_intent_sha256 ~ '^[a-f0-9]{64}$'),
  last_nonce text NOT NULL DEFAULT repeat('0',64) CHECK(last_nonce ~ '^[a-f0-9]{64}$'),
  generation bigint NOT NULL DEFAULT 0 CHECK(generation BETWEEN 0 AND 1000000),
  CHECK(generation=sequence)
);
CREATE TABLE witness_pending (
  ledger_id text PRIMARY KEY REFERENCES witness_state(ledger_id),
  repository text NOT NULL,
  sequence bigint NOT NULL CHECK(sequence BETWEEN 1 AND 1000000),
  policy_sequence bigint NOT NULL CHECK(policy_sequence BETWEEN 1 AND 1000000),
  previous_intent_sha256 text NOT NULL CHECK(previous_intent_sha256 ~ '^[a-f0-9]{64}$'),
  intent_sha256 text NOT NULL CHECK(intent_sha256 ~ '^[a-f0-9]{64}$'),
  nonce text NOT NULL CHECK(nonce ~ '^[a-f0-9]{64}$'),
  client_request_id text NOT NULL CHECK(client_request_id ~ '^[a-f0-9]{64}$'),
  reservation_id text NOT NULL UNIQUE CHECK(reservation_id ~ '^[a-f0-9]{64}$'),
  generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 1000000),
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp()
);
CREATE TABLE witness_event (
  ledger_id text NOT NULL REFERENCES witness_state(ledger_id),
  sequence bigint NOT NULL CHECK(sequence BETWEEN 1 AND 1000000),
  generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 1000000),
  repository text NOT NULL,
  policy_sequence bigint NOT NULL,
  previous_intent_sha256 text NOT NULL CHECK(previous_intent_sha256 ~ '^[a-f0-9]{64}$'),
  intent_sha256 text NOT NULL CHECK(intent_sha256 ~ '^[a-f0-9]{64}$'),
  nonce text NOT NULL CHECK(nonce ~ '^[a-f0-9]{64}$'),
  client_request_id text NOT NULL CHECK(client_request_id ~ '^[a-f0-9]{64}$'),
  reservation_id text NOT NULL UNIQUE CHECK(reservation_id ~ '^[a-f0-9]{64}$'),
  finalized_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (ledger_id,sequence),
  UNIQUE (ledger_id,intent_sha256),
  UNIQUE (ledger_id,nonce),
  UNIQUE (ledger_id,generation)
);
