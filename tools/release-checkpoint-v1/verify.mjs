#!/usr/bin/env node
// Source-free, NON-AUTHORIZING ledger-link verifier. No local input is a
// substitute for an independently authenticated, atomic high-water store.
import { createHash, verify as verifyEd25519 } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { trustKeyId, readBoundedRegularFile } from '../release-assurance-v1/verify.mjs';
import { verifyPolicyBoundCandidate } from '../release-trust-registry-v1/verify.mjs';

export const CHECKPOINT_TYPE = 'application/vnd.atto.release-checkpoint.v1+json';
export const INTENT_TYPE = 'application/vnd.atto.release-intent.v1+json';
const HASH = /^[a-f0-9]{64}$/;
const HEAD = /^[a-f0-9]{40}$/;
const LEDGER = /^[a-z][a-z0-9._-]{2,63}$/;
const ZERO = '0'.repeat(64);
const MAX_DOCUMENT = 256 * 1024;
const MAX_AGE_MS = 5 * 60 * 1000;
const obj = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const keys = (v, expected) => obj(v) && Object.keys(v).length === expected.length &&
  expected.every(k => Object.hasOwn(v, k));
const hex = v => typeof v === 'string' && HASH.test(v);
const positive = v => Number.isSafeInteger(v) && v > 0;
const nonnegative = v => Number.isSafeInteger(v) && v >= 0;
const hash = v => createHash('sha256').update(v).digest('hex');
const denied = reason => ({ classification: 'DENIED', reason,
  release_authorized: false, authenticated_github: false,
  compiler_guest_parity_proven: false, ledger_cas_committed: false });
const validBase64 = s => typeof s === 'string' && /^[A-Za-z0-9+/]+={0,2}$/.test(s) &&
  s.length > 0 && Buffer.from(s, 'base64').toString('base64') === s;

function millis(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(s))
    return null;
  const d = new Date(s);
  if (!Number.isFinite(d.getTime()) || d.getUTCFullYear() < 1970 ||
      d.toISOString() !== s.replace('Z', '.000Z')) return null;
  return d.getTime();
}
function canonical(bytes, limit=MAX_DOCUMENT) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > limit)
    throw Error('non-buffer or over-limit input');
  const source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const value = JSON.parse(source);
  if (JSON.stringify(value) !== source) throw Error('noncanonical JSON');
  return value;
}
function pae(type, payload) {
  const t = Buffer.from(type);
  return Buffer.concat([Buffer.from('DSSEv1 ' + t.length + ' '), t,
    Buffer.from(' ' + payload.length + ' '), payload]);
}
function signed(envelopeBytes, type) {
  const env = canonical(envelopeBytes);
  if (!keys(env, ['payloadType', 'payload', 'signatures']) ||
      env.payloadType !== type || !validBase64(env.payload) ||
      !Array.isArray(env.signatures) || env.signatures.length !== 1 ||
      !keys(env.signatures[0], ['keyid', 'sig']) ||
      !hex(env.signatures[0].keyid) || !validBase64(env.signatures[0].sig))
    throw Error('invalid signed envelope');
  const payload = Buffer.from(env.payload, 'base64');
  const parsed = canonical(payload);
  const signature = Buffer.from(env.signatures[0].sig, 'base64');
  if (signature.length !== 64) throw Error('invalid signature length');
  return { payload: parsed, raw: payload, signature,
    keyid: env.signatures[0].keyid, digest: hash(envelopeBytes), type };
}
function authorizeRole(e, policy, role, repository, now, signedAt, disallow) {
  const matching = policy.keys.filter(k => k.keyid === e.keyid);
  if (matching.length !== 1 || e.keyid === disallow ||
      matching[0].role !== role || matching[0].repository !== repository)
    throw Error('untrusted or overlapping delegated signing role');
  const record = matching[0];
  if (now < millis(record.not_before) || now >= millis(record.not_after) ||
      signedAt < millis(record.not_before) || signedAt >= millis(record.not_after) ||
      (record.revoked_at !== null && now >= millis(record.revoked_at)))
    throw Error('delegation expired, future-effective, or revoked');
  const { key, keyid } = trustKeyId(record.spki_pem);
  if (keyid !== e.keyid || !verifyEd25519(null, pae(e.type, e.raw), key, e.signature))
    throw Error('invalid delegated signature');
  return keyid;
}
function validateLink(state, intent, pin, base, registryHash, sequence, nowMs) {
  if (!keys(pin, ['schema', 'checkpoint_sha256', 'intent_sha256', 'ledger_id',
      'next_sequence', 'previous_intent_sha256']) ||
      pin.schema !== 'atto.release-link-pin.v1' || !hex(pin.checkpoint_sha256) ||
      !hex(pin.intent_sha256) || !LEDGER.test(pin.ledger_id) ||
      !positive(pin.next_sequence) || !hex(pin.previous_intent_sha256))
    throw Error('invalid externally supplied ledger pin');
  if (!keys(state, ['schema', 'repository', 'policy_id', 'policy_sequence',
      'registry_sha256', 'ledger_id', 'last_sequence', 'last_intent_sha256',
      'last_nonce', 'observed_at', 'expires_at']) ||
      state.schema !== 'atto.release-checkpoint.v1' ||
      state.repository !== base.repository || state.policy_id !== base.policy_id ||
      state.policy_sequence !== sequence || state.registry_sha256 !== registryHash ||
      state.ledger_id !== pin.ledger_id || !nonnegative(state.last_sequence) ||
      !hex(state.last_intent_sha256) || !hex(state.last_nonce) ||
      millis(state.observed_at) === null || millis(state.expires_at) === null)
    throw Error('checkpoint identity or state invalid');
  const observed = millis(state.observed_at), stateUntil = millis(state.expires_at);
  if (observed > nowMs || nowMs - observed > MAX_AGE_MS ||
      stateUntil <= nowMs || stateUntil <= observed ||
      stateUntil - observed > MAX_AGE_MS)
    throw Error('checkpoint expired, stale, future, or too long-lived');
  if (state.last_sequence === 0 &&
      (state.last_intent_sha256 !== ZERO || state.last_nonce !== ZERO))
    throw Error('invalid genesis checkpoint');
  if (state.last_sequence === Number.MAX_SAFE_INTEGER ||
      pin.next_sequence !== state.last_sequence + 1 ||
      pin.previous_intent_sha256 !== state.last_intent_sha256)
    throw Error('ledger sequence rollback, gap, or predecessor mismatch');
  if (!keys(intent, ['schema', 'repository', 'head_sha', 'tree_sha',
      'artifact_sha256', 'candidate_envelope_sha256', 'policy_id',
      'policy_sequence', 'registry_sha256', 'ledger_id', 'sequence',
      'previous_intent_sha256', 'nonce', 'issued_at', 'expires_at']) ||
      intent.schema !== 'atto.release-intent.v1' ||
      intent.repository !== base.repository || intent.head_sha !== base.head_sha ||
      intent.tree_sha !== base.tree_sha || intent.artifact_sha256 !== base.artifact_sha256 ||
      intent.candidate_envelope_sha256 !== base.envelope_sha256 ||
      intent.policy_id !== base.policy_id || intent.policy_sequence !== sequence ||
      intent.registry_sha256 !== registryHash || intent.ledger_id !== pin.ledger_id ||
      intent.sequence !== pin.next_sequence ||
      intent.previous_intent_sha256 !== pin.previous_intent_sha256 ||
      !hex(intent.nonce) || intent.nonce === ZERO || intent.nonce === state.last_nonce ||
      millis(intent.issued_at) === null || millis(intent.expires_at) === null)
    throw Error('intent not bound to current release or unique ledger step');
  const issued = millis(intent.issued_at), until = millis(intent.expires_at);
  if (issued < observed || issued > nowMs || nowMs >= until ||
      until <= issued || until - issued > MAX_AGE_MS)
    throw Error('release intent stale, not yet effective, or expired');
  return { observed, issued };
}

// Caller pins MUST come independently from an authenticated governance/ledger
// service. This function cannot enforce an atomic compare-and-swap itself.
export function verifySequenceLinkedCandidate({ registryEnvelopeBytes,
  trustedRootPem, candidateEnvelopeBytes, artifactBytes, expected, now,
  checkpointEnvelopeBytes, intentEnvelopeBytes, ledgerPin }) {
  try {
    const local = verifyPolicyBoundCandidate({ registryEnvelopeBytes,
      trustedRootPem, candidateEnvelopeBytes, artifactBytes, expected, now });
    if (local.classification !== 'TRUST_POLICY_BOUND_LOCAL_CANDIDATE')
      return denied('BASE_POLICY_DENIED: ' + local.reason);
    const nowMs = millis(now);
    if (nowMs === null) return denied('INVALID_CLOCK');
    const registry = canonical(registryEnvelopeBytes);
    const policy = canonical(Buffer.from(registry.payload, 'base64'));
    const state = signed(checkpointEnvelopeBytes, CHECKPOINT_TYPE);
    const intent = signed(intentEnvelopeBytes, INTENT_TYPE);
    if (!obj(ledgerPin) || state.digest !== ledgerPin.checkpoint_sha256 ||
        intent.digest !== ledgerPin.intent_sha256)
      return denied('CHECKPOINT_OR_INTENT_NOT_EXTERNALLY_PINNED');
    const registryHash = hash(registryEnvelopeBytes);
    const timing = validateLink(state.payload, intent.payload, ledgerPin,
      expected, registryHash, local.policy_sequence, nowMs);
    const governanceKeyId = authorizeRole(state, policy, 'governance-review',
      expected.repository, nowMs, timing.observed, local.signer_keyid);
    const approvalKeyId = authorizeRole(intent, policy, 'release-approval',
      expected.repository, nowMs, timing.issued, local.signer_keyid);
    if (governanceKeyId === approvalKeyId)
      return denied('SEPARATE_APPROVAL_AND_CHECKPOINT_KEYS_REQUIRED');
    return { classification: 'SEQUENCE_LINKED_LOCAL_CANDIDATE',
      release_authorized: false, authenticated_github: false,
      compiler_guest_parity_proven: false, ledger_cas_committed: false,
      repository: expected.repository, head_sha: expected.head_sha,
      policy_sequence: local.policy_sequence, ledger_id: ledgerPin.ledger_id,
      sequence: ledgerPin.next_sequence, checkpoint_sha256: state.digest,
      intent_sha256: intent.digest, candidate_signer_keyid: local.signer_keyid,
      checkpoint_signer_keyid: governanceKeyId, intent_signer_keyid: approvalKeyId,
      reason: 'Synthetic signed role-separated chain verified locally; external ledger freshness, atomic CAS, live GitHub evidence and compiler-backed execution remain unverified' };
  } catch (e) { return denied('INVALID_CHAIN_OR_INPUT: ' + e.message); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const names = ['--registry', '--root-key', '--candidate', '--artifact',
      '--expected', '--checkpoint', '--intent', '--pin'];
    if (process.argv.length !== 18 ||
        !names.every((name, i) => process.argv[2 + i * 2] === name))
      throw Error('usage: --registry FILE --root-key FILE --candidate FILE --artifact FILE --expected FILE --checkpoint FILE --intent FILE --pin FILE');
    const read = (index, limit=MAX_DOCUMENT) =>
      readBoundedRegularFile(process.argv[index], limit);
    const result = verifySequenceLinkedCandidate({
      registryEnvelopeBytes: read(3), trustedRootPem: read(5, 16384),
      candidateEnvelopeBytes: read(7), artifactBytes: read(9, 64*1024*1024),
      expected: canonical(read(11, 16384), 16384),
      checkpointEnvelopeBytes: read(13), intentEnvelopeBytes: read(15),
      ledgerPin: canonical(read(17, 16384), 16384),
      now: new Date().toISOString().slice(0,19) + 'Z'
    });
    process.stdout.write(JSON.stringify(result) + '\n');
    process.exitCode = result.classification === 'SEQUENCE_LINKED_LOCAL_CANDIDATE' ? 3 : 1;
  } catch (e) {
    process.stderr.write(JSON.stringify(denied('INPUT_ADMISSION_ERROR: ' + e.message)) + '\n');
    process.exitCode = 2;
  }
}
