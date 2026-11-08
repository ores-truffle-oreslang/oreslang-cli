#!/usr/bin/env node
// Public source-free verifier. A root-signed key registry is not GitHub evidence
// and MUST NEVER be interpreted as merge or release authorization.
import { createHash, verify as verifyEd25519 } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import {
  PAYLOAD_TYPE, dssePAE, trustKeyId, verifySignedCandidate,
  readBoundedRegularFile
} from '../release-assurance-v1/verify.mjs';

export const REGISTRY_TYPE = 'application/vnd.atto.trust-registry.v1+json';
const HEX40 = /^[0-9a-f]{40}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const REPO = /^ores-truffle-oreslang\/[a-z0-9][a-z0-9._-]{0,119}$/;
const POLICY_ID = /^[a-z][a-z0-9._-]{2,63}$/;
const ALLOWED_ROLES = new Set([
  'candidate-signing', 'build-provenance', 'release-approval', 'governance-review'
]);
const isObject = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const exactKeys = (x, keys) => isObject(x) &&
  Object.keys(x).length === keys.length && keys.every(k => Object.hasOwn(x, k));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const deny = reason => ({
  classification: 'DENIED', release_authorized: false,
  compiler_guest_parity_proven: false, authenticated_github: false, reason
});
const b64 = value => typeof value === 'string' && value.length > 0 &&
  /^[A-Za-z0-9+/]+={0,2}$/.test(value) &&
  Buffer.from(value, 'base64').toString('base64') === value;
const positive = x => Number.isSafeInteger(x) && x >= 1;

function strictTime(s) {
  if (typeof s !== 'string' ||
      !/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/.test(s)) return null;
  const d = new Date(s);
  return Number.isFinite(d.getTime()) && d.getUTCFullYear() >= 1970 &&
    d.toISOString() === s.replace('Z', '.000Z') ? d.getTime() : null;
}

function json(bytes, limit) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > limit)
    throw Error('invalid or oversized byte input');
  const s = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const parsed = JSON.parse(s);
  if (JSON.stringify(parsed) !== s) throw Error('noncanonical JSON');
  return parsed;
}

export function registryPAE(payload) {
  if (!Buffer.isBuffer(payload)) throw Error('invalid registry payload');
  const type = Buffer.from(REGISTRY_TYPE);
  return Buffer.concat([
    Buffer.from('DSSEv1 ' + type.length + ' '), type,
    Buffer.from(' ' + payload.length + ' '), payload
  ]);
}

function unwrapRootPolicy(registryEnvelopeBytes, rootPem) {
  const env = json(registryEnvelopeBytes, 256 * 1024);
  if (!exactKeys(env, ['payloadType', 'payload', 'signatures']) ||
      env.payloadType !== REGISTRY_TYPE || !b64(env.payload) ||
      !Array.isArray(env.signatures) || env.signatures.length !== 1 ||
      !exactKeys(env.signatures[0], ['keyid', 'sig']) ||
      !HEX64.test(env.signatures[0].keyid) || !b64(env.signatures[0].sig))
    throw Error('invalid root DSSE envelope');
  const { key: root, keyid: rootId } = trustKeyId(rootPem);
  if (env.signatures[0].keyid !== rootId) throw Error('untrusted policy root');
  const payload = Buffer.from(env.payload, 'base64');
  if (payload.length < 1 || payload.length > 256 * 1024) throw Error('oversized policy');
  const signature = Buffer.from(env.signatures[0].sig, 'base64');
  if (signature.length !== 64 ||
      !verifyEd25519(null, registryPAE(payload), root, signature))
    throw Error('invalid root signature');
  return { policy: json(payload, 256 * 1024), rootId };
}

function validatePolicy(policy, expected, now, rootId) {
  if (!exactKeys(policy, ['schema', 'policy_id', 'sequence',
      'not_before', 'not_after', 'keys']) ||
      policy.schema !== 'atto.trust-registry.v1' ||
      !POLICY_ID.test(policy.policy_id) || !positive(policy.sequence) ||
      !Array.isArray(policy.keys) || policy.keys.length < 1 ||
      policy.keys.length > 32 ||
      strictTime(policy.not_before) === null ||
      strictTime(policy.not_after) === null ||
      policy.not_before >= policy.not_after ||
      policy.policy_id !== expected.policy_id ||
      policy.sequence < expected.minimum_sequence)
    return 'TRUST_POLICY_INVALID_OR_ROLLED_BACK';
  if (now < policy.not_before || now >= policy.not_after)
    return 'TRUST_POLICY_NOT_CURRENT';

  const seen = new Set();
  for (const item of policy.keys) {
    if (!exactKeys(item, ['keyid', 'spki_pem', 'role', 'repository',
        'not_before', 'not_after', 'revoked_at']) ||
        !HEX64.test(item.keyid) ||
        typeof item.spki_pem !== 'string' ||
        item.spki_pem.length < 40 || item.spki_pem.length > 4096 ||
        !ALLOWED_ROLES.has(item.role) || !REPO.test(item.repository) ||
        strictTime(item.not_before) === null ||
        strictTime(item.not_after) === null ||
        item.not_before >= item.not_after ||
        item.not_before < policy.not_before || item.not_after > policy.not_after ||
        (item.revoked_at !== null && strictTime(item.revoked_at) === null))
      return 'TRUST_KEY_RECORD_INVALID';
    let id;
    try { id = trustKeyId(item.spki_pem).keyid; }
    catch { return 'TRUST_KEY_NOT_ED25519'; }
    if (id !== item.keyid || id === rootId || seen.has(id))
      return 'DUPLICATE_OR_UNTRUSTED_KEY_IDENTITY';
    seen.add(id);
  }
  return null;
}

function validateExpected(expected) {
  return exactKeys(expected, ['policy_id', 'minimum_sequence', 'root_keyid',
    'repository', 'head_sha', 'tree_sha', 'artifact_sha256', 'envelope_sha256']) &&
    POLICY_ID.test(expected.policy_id) && positive(expected.minimum_sequence) &&
    HEX64.test(expected.root_keyid) && REPO.test(expected.repository) &&
    HEX40.test(expected.head_sha) && HEX40.test(expected.tree_sha) &&
    HEX64.test(expected.artifact_sha256) && HEX64.test(expected.envelope_sha256);
}

// Always returns a NON-AUTHORIZING local candidate. now and expected MUST come
// from a caller independently trusted by the release governance service.
export function verifyPolicyBoundCandidate(input) {
  try {
    if (!isObject(input))
      return deny('INVALID_TRUST_POLICY_OR_INPUT');
    const { registryEnvelopeBytes, trustedRootPem, candidateEnvelopeBytes,
      artifactBytes, expected, now } = input;
    if (!validateExpected(expected)) return deny('INVALID_EXTERNALLY_PINNED_EXPECTATIONS');
    if (strictTime(now) === null) return deny('INVALID_TRUSTED_CLOCK');
    if (!Buffer.isBuffer(candidateEnvelopeBytes) ||
        sha256(candidateEnvelopeBytes) !== expected.envelope_sha256)
      return deny('ENVELOPE_NOT_PINNED_TO_EXPECTATION');
    const { policy, rootId } = unwrapRootPolicy(registryEnvelopeBytes, trustedRootPem);
    if (rootId !== expected.root_keyid) return deny('ROOT_FINGERPRINT_NOT_PINNED');
    const policyProblem = validatePolicy(policy, expected, now, rootId);
    if (policyProblem) return deny(policyProblem);
    const env = json(candidateEnvelopeBytes, 256 * 1024);
    if (!exactKeys(env, ['payloadType', 'payload', 'signatures']) ||
        env.payloadType !== PAYLOAD_TYPE || !Array.isArray(env.signatures) ||
        env.signatures.length !== 1 ||
        !exactKeys(env.signatures[0], ['keyid', 'sig']) ||
        !HEX64.test(env.signatures[0].keyid))
      return deny('INVALID_CANDIDATE_SIGNING_IDENTITY');
    const matches = policy.keys.filter(k => k.keyid === env.signatures[0].keyid);
    if (matches.length !== 1) return deny('CANDIDATE_SIGNER_NOT_IN_ROOT_POLICY');
    const signer = matches[0];
    if (signer.role !== 'candidate-signing') return deny('SIGNER_ROLE_NOT_AUTHORIZED');
    if (signer.repository !== expected.repository) return deny('SIGNER_REPOSITORY_NOT_AUTHORIZED');
    if (now < signer.not_before || now >= signer.not_after)
      return deny('SIGNER_EXPIRED_OR_NOT_YET_VALID');
    if (signer.revoked_at !== null && now >= signer.revoked_at)
      return deny('SIGNER_KEY_REVOKED');
    const result = verifySignedCandidate({
      envelopeBytes: candidateEnvelopeBytes, trustedKeyPem: signer.spki_pem, artifactBytes
    });
    if (result.classification !== 'LOCAL_CRYPTOGRAPHIC_CANDIDATE')
      return deny('CANDIDATE_DENIED: ' + result.reason);
    if (result.repository !== expected.repository ||
        result.head_sha !== expected.head_sha ||
        result.tree_sha !== expected.tree_sha ||
        result.artifact_sha256 !== expected.artifact_sha256)
      return deny('CANDIDATE_NOT_PINNED_TO_EXPECTATIONS');
    return {
      classification: 'TRUST_POLICY_BOUND_LOCAL_CANDIDATE',
      release_authorized: false, compiler_guest_parity_proven: false,
      authenticated_github: false, root_keyid: rootId, signer_keyid: signer.keyid,
      policy_id: policy.policy_id, policy_sequence: policy.sequence,
      repository: result.repository, head_sha: result.head_sha,
      artifact_sha256: result.artifact_sha256,
      reason: 'Root signature, candidate signature, local artifact bytes and external pins match; live GitHub, key-clock integrity and guest execution NOT authenticated'
    };
  } catch { return deny('INVALID_TRUST_POLICY_OR_INPUT'); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const args = process.argv;
    if (args.length !== 12 || args[2] !== '--registry' ||
        args[4] !== '--root-key' || args[6] !== '--candidate' ||
        args[8] !== '--artifact' || args[10] !== '--expected')
      throw Error('usage: node verify.mjs --registry policy.dsse --root-key root.pem --candidate release.dsse --artifact artifact.tar --expected independently-pinned.json');
    const read = (i, max) => readBoundedRegularFile(args[i], max);
    const expected = json(read(11, 16384), 16384);
    const result = verifyPolicyBoundCandidate({
      registryEnvelopeBytes: read(3, 256 * 1024),
      trustedRootPem: read(5, 16384),
      candidateEnvelopeBytes: read(7, 256 * 1024),
      artifactBytes: read(9, 64 * 1024 * 1024),
      expected, now: new Date().toISOString().slice(0, 19) + 'Z'
    });
    process.stdout.write(JSON.stringify(result) + '\n');
    process.exitCode = result.classification === 'TRUST_POLICY_BOUND_LOCAL_CANDIDATE' ? 3 : 1;
  } catch (e) {
    process.stderr.write(JSON.stringify(deny('INPUT_ADMISSION_ERROR: ' + e.message)) + '\n');
    process.exitCode = 2;
  }
}
