#!/usr/bin/env node
// Public, source-free, LOCAL cryptographic candidate verifier.
// Neither a signature nor a JSON receipt authenticates GitHub/guest execution.
import { createHash, createPublicKey, verify as verifySignature } from 'node:crypto';
import { openSync, fstatSync, readSync, closeSync, constants as fsConstants } from 'node:fs';
import { pathToFileURL } from 'node:url';

export const PAYLOAD_TYPE = 'application/vnd.atto.release-assurance.v1+json';
const SHA1 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const REPO = /^ores-truffle-oreslang\/[A-Za-z0-9][A-Za-z0-9._-]*$/;
const NAME = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,119}$/;
const BACKENDS = ['java', 'llvm', 'net', 'wasm', 'forge'];
const MAX_DOCUMENT = 256 * 1024;
const MAX_ARTIFACT = 64 * 1024 * 1024;
const isObj = value => !!value && typeof value === 'object' && !Array.isArray(value);
const pos = value => Number.isSafeInteger(value) && value > 0;
const sha1 = value => typeof value === 'string' && SHA1.test(value);
const sha256 = value => typeof value === 'string' && SHA256.test(value);
const string = value => typeof value === 'string' && value.length > 0 && value === value.trim();
const eqKeys = (value, keys) => isObj(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const unique = (items) => new Set(items).size === items.length;
const deny = reason => ({ classification: 'DENIED', release_authorized: false,
  compiler_guest_parity_proven: false, reason });
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const exactBase64 = input => typeof input === 'string' && input.length > 0 &&
  /^[A-Za-z0-9+/]+={0,2}$/.test(input) &&
  Buffer.from(input, 'base64').toString('base64') === input;

function strictUtc(s) {
  if (typeof s !== 'string') return false;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/.exec(s);
  if (!match) return false;
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
  if (year < 1970 || month < 1 || month > 12 || day < 1 || day > 31 ||
      hour > 23 || minute > 59 || second > 59) return false;
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  return date.getUTCFullYear() === year && date.getUTCMonth() + 1 === month &&
    date.getUTCDate() === day && date.getUTCHours() === hour &&
    date.getUTCMinutes() === minute && date.getUTCSeconds() === second;
}

function decodeCanonicalJson(bytes) {
  const data = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const parsed = JSON.parse(data);
  // Byte-canonical JSON excludes duplicate keys, unsupported whitespace,
  // alternate number escapes/representations, and invalid Unicode encodings.
  if (JSON.stringify(parsed) !== data) throw Error('noncanonical JSON document');
  return parsed;
}

export function dssePAE(payloadType, payload) {
  if (payloadType !== PAYLOAD_TYPE || !Buffer.isBuffer(payload)) throw Error('invalid DSSE input');
  const type = Buffer.from(payloadType, 'utf8');
  return Buffer.concat([Buffer.from(`DSSEv1 ${type.length} `), type,
    Buffer.from(` ${payload.length} `), payload]);
}

export function trustKeyId(publicPem) {
  const key = createPublicKey(publicPem);
  if (key.asymmetricKeyType !== 'ed25519' || key.type !== 'public')
    throw Error('trusted public key must be Ed25519 SPKI');
  return { key, keyid: digest(key.export({ type: 'spki', format: 'der' })) };
}

function validateReceipt(m) {
  if (!eqKeys(m, ['schema', 'subject', 'governance', 'reviews', 'workflow', 'backends']) ||
      m.schema !== 'atto.release-assurance.v1') return 'INVALID_RELEASE_SCHEMA';
  const s = m.subject;
  if (!eqKeys(s, ['repository', 'head_sha', 'tree_sha', 'artifact']) ||
      !REPO.test(s.repository) || !sha1(s.head_sha) || !sha1(s.tree_sha) ||
      !eqKeys(s.artifact, ['filename', 'sha256', 'size']) ||
      !NAME.test(s.artifact.filename) || !sha256(s.artifact.sha256) || !pos(s.artifact.size))
    return 'INVALID_RELEASE_IDENTITY';
  const g = m.governance;
  if (!eqKeys(g, ['protected_main', 'no_bypass', 'require_codeowner_review',
      'dismiss_stale_reviews', 'author', 'codeowners', 'required_contexts']) ||
      g.protected_main !== true || g.no_bypass !== true ||
      g.require_codeowner_review !== true || g.dismiss_stale_reviews !== true ||
      !string(g.author) || !Array.isArray(g.codeowners) || g.codeowners.length === 0 ||
      !g.codeowners.every(string) || !unique(g.codeowners.map(v => v.toLowerCase())) ||
      !Array.isArray(g.required_contexts) || g.required_contexts.length === 0 ||
      !g.required_contexts.every(string) || !unique(g.required_contexts))
    return 'GOVERNANCE_NOT_ASSERTED';
  if (!Array.isArray(m.reviews) || m.reviews.length === 0) return 'MISSING_REVIEWS';
  const byUser = new Map();
  const seenReviewTimes = new Set();
  for (const review of m.reviews) {
    if (!eqKeys(review, ['reviewer', 'state', 'commit_id', 'submitted_at']) ||
        !string(review.reviewer) || !['APPROVED', 'CHANGES_REQUESTED', 'DISMISSED', 'COMMENTED'].includes(review.state) ||
        !sha1(review.commit_id) || !strictUtc(review.submitted_at)) return 'INVALID_REVIEW';
    const user = review.reviewer.toLowerCase();
    const eventKey = `${user}|${review.submitted_at}`;
    if (seenReviewTimes.has(eventKey)) return 'AMBIGUOUS_REVIEW_HISTORY';
    seenReviewTimes.add(eventKey);
    // GitHub COMMENTED does not dismiss a preceding CHANGES_REQUESTED review.
    // Only an explicit new APPROVED or DISMISSED decision supersedes it.
    if (review.state === 'COMMENTED') continue;
    const previous = byUser.get(user);
    if (!previous || previous.submitted_at < review.submitted_at) byUser.set(user, review);
  }
  const latest = [...byUser.values()];
  if (latest.some(r => r.state === 'CHANGES_REQUESTED')) return 'OUTSTANDING_CHANGES_REQUESTED';
  const approved = latest.some(r => r.state === 'APPROVED' &&
    r.commit_id === s.head_sha && r.reviewer.toLowerCase() !== g.author.toLowerCase() &&
    g.codeowners.some(owner => owner.toLowerCase() === r.reviewer.toLowerCase()));
  if (!approved) return 'INDEPENDENT_CURRENT_HEAD_CODEOWNER_APPROVAL_MISSING';
  const w = m.workflow;
  if (!eqKeys(w, ['run_id', 'run_attempt', 'job_id', 'runner_id', 'job_name',
      'head_sha', 'tree_sha', 'status', 'conclusion', 'steps',
      'checkout_step_number', 'test_step_number']) ||
      ![w.run_id,w.run_attempt,w.job_id,w.runner_id,w.checkout_step_number,w.test_step_number].every(pos) ||
      !string(w.job_name) || !g.required_contexts.includes(w.job_name) ||
      w.head_sha !== s.head_sha || w.tree_sha !== s.tree_sha ||
      w.status !== 'completed' || w.conclusion !== 'success' ||
      !Array.isArray(w.steps) || w.steps.length < 2 ||
      !unique(w.steps.map(step => step?.number))) return 'WORKFLOW_NOT_BOUND_OR_UNEXECUTED';
  if (!w.steps.every(step => eqKeys(step, ['number', 'name', 'status', 'conclusion']) &&
      pos(step.number) && string(step.name) && step.status === 'completed' &&
      step.conclusion === 'success') ||
      !w.steps.some(step => step.number === w.checkout_step_number && step.name === 'Verify immutable source') ||
      !w.steps.some(step => step.number === w.test_step_number && step.name === 'Execute source tests') ||
      w.checkout_step_number === w.test_step_number)
    return 'REQUIRED_EXECUTED_STEP_MISSING';
  if (!Array.isArray(m.backends) || m.backends.length !== BACKENDS.length ||
      !unique(m.backends.map(b => b?.backend)) ||
      !BACKENDS.every(name => m.backends.some(b => b?.backend === name)))
    return 'FIVE_BACKEND_RECEIPTS_MISSING';
  const tuples = [];
  let canonicalFixture, canonicalOutput;
  for (const b of m.backends) {
    if (!eqKeys(b, ['backend', 'repository', 'head_sha', 'tree_sha', 'classification',
        'run_id', 'run_attempt', 'job_id', 'runner_id', 'executed_steps',
        'toolchain_sha256', 'fixture_sha256', 'output_sha256']) ||
        !BACKENDS.includes(b.backend) || !REPO.test(b.repository) ||
        !sha1(b.head_sha) || !sha1(b.tree_sha) ||
        b.classification !== 'EXECUTED_COMPILER_GUEST' ||
        ![b.run_id,b.run_attempt,b.job_id,b.runner_id,b.executed_steps].every(pos) ||
        !sha256(b.toolchain_sha256) || !sha256(b.fixture_sha256) ||
        !sha256(b.output_sha256)) return 'BACKEND_GUEST_RECEIPT_UNVERIFIED';
    if (canonicalFixture === undefined) canonicalFixture = b.fixture_sha256;
    if (canonicalOutput === undefined) canonicalOutput = b.output_sha256;
    if (b.fixture_sha256 !== canonicalFixture || b.output_sha256 !== canonicalOutput)
      return 'BACKEND_CANONICAL_OUTPUT_MISMATCH';
    tuples.push(`${b.repository}:${b.run_id}:${b.run_attempt}:${b.job_id}`);
  }
  if (!unique(tuples)) return 'DUPLICATE_BACKEND_JOB_RECEIPT';
  return null;
}

// Successful result is ONLY a signed local candidate, never a verified release.
export function verifySignedCandidate(input) {
  try {
    if (!isObj(input)) return deny('INVALID_BINARY_INPUT');
    const { envelopeBytes, trustedKeyPem, artifactBytes } = input;
    if (!Buffer.isBuffer(envelopeBytes) || !Buffer.isBuffer(artifactBytes))
      return deny('INVALID_BINARY_INPUT');
    if (envelopeBytes.length < 1 || envelopeBytes.length > MAX_DOCUMENT)
      return deny('ENVELOPE_SIZE_INVALID');
    if (artifactBytes.length < 1 || artifactBytes.length > MAX_ARTIFACT)
      return deny('ARTIFACT_SIZE_INVALID');
    const env = decodeCanonicalJson(envelopeBytes);
    if (!eqKeys(env, ['payloadType', 'payload', 'signatures']) ||
        env.payloadType !== PAYLOAD_TYPE || !exactBase64(env.payload) ||
        !Array.isArray(env.signatures) || env.signatures.length !== 1 ||
        !eqKeys(env.signatures[0], ['keyid', 'sig']) ||
        !sha256(env.signatures[0].keyid) || !exactBase64(env.signatures[0].sig))
      return deny('INVALID_DSSE_ENVELOPE');
    const payload = Buffer.from(env.payload, 'base64');
    if (payload.length < 1 || payload.length > MAX_DOCUMENT) return deny('INVALID_PAYLOAD_SIZE');
    const manifest = decodeCanonicalJson(payload);
    const { key, keyid } = trustKeyId(trustedKeyPem);
    if (env.signatures[0].keyid !== keyid) return deny('UNTRUSTED_SIGNING_KEY');
    const signature = Buffer.from(env.signatures[0].sig, 'base64');
    if (signature.length !== 64 || !verifySignature(null, dssePAE(PAYLOAD_TYPE, payload), key, signature))
      return deny('INVALID_DSSE_SIGNATURE');
    const reason = validateReceipt(manifest);
    if (reason) return deny(reason);
    if (artifactBytes.length !== manifest.subject.artifact.size ||
        digest(artifactBytes) !== manifest.subject.artifact.sha256)
      return deny('ARTIFACT_BYTES_MISMATCH');
    return { classification: 'LOCAL_CRYPTOGRAPHIC_CANDIDATE',
      release_authorized: false, compiler_guest_parity_proven: false,
      reason: 'DSSE signature, synthetic receipt shape, and local artifact digest verified; authenticate GitHub and execution separately',
      repository: manifest.subject.repository, head_sha: manifest.subject.head_sha,
      tree_sha: manifest.subject.tree_sha, artifact_sha256: manifest.subject.artifact.sha256,
      keyid, receipt_count: manifest.backends.length };
  } catch { return deny('INVALID_INPUT_OR_CRYPTO'); }
}

// File descriptor is pinned before reading; block FIFOs, sockets, symlinks,
// hardlinks, oversized objects, and mutations during read.
export function readBoundedRegularFile(path, limit) {
  if (typeof path !== 'string' || !path || !Number.isSafeInteger(limit) || limit < 1 ||
      !Number.isInteger(fsConstants.O_NOFOLLOW) || !Number.isInteger(fsConstants.O_NONBLOCK))
    throw Error('unsafe file path/flags');
  const fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  try {
    const before = fstatSync(fd, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(limit))
      throw Error('input is not a single-linked bounded regular file');
    const parts = [];
    let count = 0;
    const temp = Buffer.alloc(65536);
    while (count <= limit) {
      const n = readSync(fd, temp, 0, Math.min(temp.length, limit + 1 - count), null);
      if (!n) break;
      parts.push(Buffer.from(temp.subarray(0, n)));
      count += n;
    }
    const after = fstatSync(fd, { bigint: true });
    if (!count || count > limit || before.ino !== after.ino || before.dev !== after.dev ||
        before.size !== after.size || BigInt(count) !== after.size ||
        before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs)
      throw Error('input mutated or exceeded bounded size');
    return Buffer.concat(parts, count);
  } finally { closeSync(fd); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if (process.argv.length !== 8 || process.argv[2] !== '--envelope' ||
        process.argv[4] !== '--trusted-key' || process.argv[6] !== '--artifact')
      throw Error('usage: node verify.mjs --envelope envelope.json --trusted-key trusted-ed25519.pem --artifact artifact.bin');
    const envelopeBytes = readBoundedRegularFile(process.argv[3], MAX_DOCUMENT);
    const trustedKeyPem = readBoundedRegularFile(process.argv[5], 16384);
    const artifactBytes = readBoundedRegularFile(process.argv[7], MAX_ARTIFACT);
    const result = verifySignedCandidate({ envelopeBytes, trustedKeyPem, artifactBytes });
    process.stdout.write(JSON.stringify(result) + '\n');
    // Nonzero by design: this tool MUST NOT grant release/merge authorization.
    process.exitCode = result.classification === 'LOCAL_CRYPTOGRAPHIC_CANDIDATE' ? 3 : 1;
  } catch (err) {
    process.stderr.write(JSON.stringify(deny('INPUT_ADMISSION_ERROR: ' + err.message)) + '\n');
    process.exitCode = 2;
  }
}
