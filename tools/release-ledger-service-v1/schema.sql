-- Only an operator-owned migration may execute this schema. Never auto-create on a claim.
-- This is a NON-AUTHORIZING transactional witness; release publishing is blocked.
CREATE TABLE ledger_service_state (
  ledger_id text PRIMARY KEY CHECK (ledger_id ~ '^[a-z][a-z0-9._-]{2,63}$'),
  repository text NOT NULL CHECK (repository ~ '^ores-truffle-oreslang/[a-z0-9][a-z0-9._-]{0,119}$'),
  sequence bigint NOT NULL DEFAULT 0 CHECK (sequence BETWEEN 0 AND 1000000),
  policy_sequence bigint NOT NULL DEFAULT 0 CHECK (policy_sequence BETWEEN 0 AND 1000000),
  last_intent_sha256 text NOT NULL DEFAULT repeat('0',64) CHECK (last_intent_sha256 ~ '^[a-f0-9]{64}$'),
  last_nonce text NOT NULL DEFAULT repeat('0',64) CHECK (last_nonce ~ '^[a-f0-9]{64}$'),
  CHECK ((sequence = 0 AND last_intent_sha256 = repeat('0',64) AND last_nonce = repeat('0',64)) OR
         (sequence > 0 AND last_intent_sha256 <> repeat('0',64) AND last_nonce <> repeat('0',64)))
);
CREATE TABLE ledger_service_request (
  client text NOT NULL,
  auth_nonce text NOT NULL CHECK (auth_nonce ~ '^[a-f0-9]{64}$'),
  client_request_id text NOT NULL CHECK (client_request_id ~ '^[a-f0-9]{64}$'),
  ledger_id text NOT NULL,
  body_sha256 text NOT NULL CHECK (body_sha256 ~ '^[a-f0-9]{64}$'),
  outcome text NOT NULL CHECK (outcome IN ('PENDING','COMMITTED','DENIED')),
  reason text NOT NULL,
  committed_sequence bigint,
  committed_intent_sha256 text,
  committed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (client, auth_nonce),
  UNIQUE (client, client_request_id),
  CHECK ((outcome = 'COMMITTED' AND committed_sequence IS NOT NULL AND committed_intent_sha256 IS NOT NULL) OR
         (outcome <> 'COMMITTED' AND committed_sequence IS NULL AND committed_intent_sha256 IS NULL))
);
CREATE TABLE ledger_service_event (
  ledger_id text NOT NULL REFERENCES ledger_service_state(ledger_id),
  sequence bigint NOT NULL CHECK (sequence BETWEEN 1 AND 1000000),
  previous_intent_sha256 text NOT NULL CHECK (previous_intent_sha256 ~ '^[a-f0-9]{64}$'),
  intent_sha256 text NOT NULL CHECK (intent_sha256 ~ '^[a-f0-9]{64}$' AND intent_sha256 <> repeat('0',64)),
  nonce text NOT NULL CHECK (nonce ~ '^[a-f0-9]{64}$' AND nonce <> repeat('0',64)),
  repository text NOT NULL,
  head_sha text NOT NULL CHECK (head_sha ~ '^[a-f0-9]{40}$'),
  artifact_sha256 text NOT NULL CHECK (artifact_sha256 ~ '^[a-f0-9]{64}$'),
  policy_sequence bigint NOT NULL,
  client text NOT NULL,
  client_request_id text NOT NULL,
  committed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY (ledger_id, sequence),
  UNIQUE (ledger_id, intent_sha256),
  UNIQUE (ledger_id, nonce),
  UNIQUE (client, client_request_id)
);
CREATE INDEX ledger_service_event_recent ON ledger_service_event (ledger_id,sequence DESC);
