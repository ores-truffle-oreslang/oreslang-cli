import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync, symlinkSync, linkSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { verifySignedCandidate, trustKeyId, dssePAE, PAYLOAD_TYPE,
  readBoundedRegularFile } from '../tools/release-assurance-v1/verify.mjs';

const pair = generateKeyPairSync('ed25519');
const spki = pair.publicKey.export({ format: 'pem', type: 'spki' });
const sha = x => createHash('sha256').update(x).digest('hex');
const keyid = trustKeyId(spki).keyid;
const bytes = Buffer.from('atto-release-fixture-NEVER-A-REAL-RELEASE\n');
const head = 'a'.repeat(40), tree = 'b'.repeat(40);
const backendNames = ['java', 'llvm', 'net', 'wasm', 'forge'];
function fixture() {
  return {
    schema: 'atto.release-assurance.v1',
    subject: {
      repository: 'ores-truffle-oreslang/oreslang-cli', head_sha: head, tree_sha: tree,
      artifact: { filename: 'atto-demo.tar.gz', sha256: sha(bytes), size: bytes.length }
    },
    governance: {
      protected_main: true, no_bypass: true, require_codeowner_review: true,
      dismiss_stale_reviews: true, author: 'BuildAuthor',
      codeowners: ['IndependentOwner'], required_contexts: ['release-assurance']
    },
    reviews: [{ reviewer: 'IndependentOwner', state: 'APPROVED',
      commit_id: head, submitted_at: '2026-11-06T20:40:00Z' }],
    workflow: {
      run_id: 123, run_attempt: 2, job_id: 345, runner_id: 456,
      job_name: 'release-assurance', head_sha: head, tree_sha: tree,
      status: 'completed', conclusion: 'success',
      steps: [
        { number: 1, name: 'Verify immutable source', status: 'completed', conclusion: 'success' },
        { number: 2, name: 'Execute source tests', status: 'completed', conclusion: 'success' }
      ], checkout_step_number: 1, test_step_number: 2
    },
    backends: backendNames.map((backend,i) => ({
      backend,
      repository: 'ores-truffle-oreslang/oreslang-source.' + backend,
      head_sha: String(i + 1).repeat(40), tree_sha: String(i + 5).repeat(40),
      classification: 'EXECUTED_COMPILER_GUEST',
      run_id: 1000 + i, run_attempt: 1, job_id: 2000 + i, runner_id: 3000 + i,
      executed_steps: 3, toolchain_sha256: 'e'.repeat(64),
      fixture_sha256: 'f'.repeat(64), output_sha256: 'd'.repeat(64)
    }))
  };
}
function signed(m = fixture(), options = {}) {
  const payload = options.rawPayload ?? Buffer.from(JSON.stringify(m));
  const signature = sign(null, dssePAE(PAYLOAD_TYPE, payload), options.signer || pair.privateKey);
  const envelope = {
    payloadType: PAYLOAD_TYPE, payload: payload.toString('base64'),
    signatures: [{ keyid: options.keyid ?? keyid, sig: signature.toString('base64') }]
  };
  return Buffer.from(JSON.stringify(envelope));
}
function check(m = fixture(), options={}) {
  return verifySignedCandidate({ envelopeBytes: signed(m, options),
    trustedKeyPem: options.trustedKeyPem ?? spki, artifactBytes: options.artifactBytes ?? bytes });
}

// No positive test represents a real GitHub run; all fixture fields are synthetic.
test('synthetic signed candidate cryptographically binds local bytes but never authorizes release', () => {
  const output = check();
  assert.equal(output.classification, 'LOCAL_CRYPTOGRAPHIC_CANDIDATE');
  assert.equal(output.release_authorized, false);
  assert.equal(output.compiler_guest_parity_proven, false);
  assert.equal(output.receipt_count, 5);
});
test('all 40 individually specified adversarial evidence mutations fail closed', () => {
  const mutate = [
    x => { x.schema = 'fake'; },
    x => { x.subject.head_sha = 'A'.repeat(40); },
    x => { x.subject.tree_sha = 'bad'; },
    x => { x.subject.artifact.size = 0; },
    x => { x.subject.artifact.filename = '../escape'; },
    x => { x.subject.artifact.sha256 = '0'.repeat(64); },
    x => { x.subject.extra = true; },
    x => { x.governance.protected_main = false; },
    x => { x.governance.no_bypass = false; },
    x => { x.governance.require_codeowner_review = false; },
    x => { x.governance.dismiss_stale_reviews = false; },
    x => { x.governance.codeowners = []; },
    x => { x.governance.codeowners = ['IndependentOwner','independentowner']; },
    x => { x.governance.required_contexts = ['other-check']; },
    x => { x.governance.author = 'independentowner'; },
    x => { x.reviews = []; },
    x => { x.reviews[0].state = 'CHANGES_REQUESTED'; },
    x => { x.reviews[0].commit_id = '0'.repeat(40); },
    x => { x.reviews[0].submitted_at = '2026-02-30T20:40:00Z'; },
    x => { x.reviews.push({ ...x.reviews[0], state: 'DISMISSED', submitted_at:'2026-11-06T20:41:00Z' }); },
    x => { x.reviews.push({ ...x.reviews[0], state: 'CHANGES_REQUESTED', submitted_at:'2026-11-06T20:41:00Z' }); },
    x => {
      x.governance.codeowners.push('OtherOwner');
      x.reviews.push({ ...x.reviews[0], state: 'CHANGES_REQUESTED', submitted_at:'2026-11-06T20:41:00Z' });
      x.reviews.push({ ...x.reviews[0], state: 'COMMENTED', submitted_at:'2026-11-06T20:42:00Z' });
      x.reviews.push({ ...x.reviews[0], reviewer:'OtherOwner', submitted_at:'2026-11-06T20:40:30Z' });
    },
    x => { x.reviews.push({ ...x.reviews[0] }); },
    x => { x.workflow.run_attempt = 0; },
    x => { x.workflow.runner_id = 0; },
    x => { x.workflow.head_sha = '0'.repeat(40); },
    x => { x.workflow.tree_sha = '0'.repeat(40); },
    x => { x.workflow.conclusion = 'failure'; },
    x => { x.workflow.steps = []; },
    x => { x.workflow.steps = null; },
    x => { x.workflow.steps[1].conclusion = 'failure'; },
    x => { x.workflow.steps[0].number = 2; },
    x => { x.workflow.checkout_step_number = 3; },
    x => { x.backends = x.backends.slice(0,4); },
    x => { x.backends[0].classification = 'HOST_ONLY'; },
    x => { x.backends[0].executed_steps = 0; },
    x => { x.backends[0].output_sha256 = '0'.repeat(64); },
    x => { x.backends[0].fixture_sha256 = '0'.repeat(64); },
    x => { x.backends[1] = { ...x.backends[0], backend: 'llvm' }; },
    x => { x.backends.push({ ...x.backends[0] }); }
  ];
  assert.equal(mutate.length, 40);
  for (const [index, apply] of mutate.entries()) {
    const x = fixture(); apply(x);
    const result = check(x);
    assert.equal(result.classification, 'DENIED', 'mutation index ' + index);
    assert.equal(result.release_authorized, false, 'mutation index ' + index);
  }
});
test('all 1,024 combinations of 10 independent unsafe controls are denied', () => {
  const flags = [
    x => { x.governance.protected_main = false; },
    x => { x.governance.no_bypass = false; },
    x => { x.governance.require_codeowner_review = false; },
    x => { x.governance.dismiss_stale_reviews = false; },
    x => { x.governance.author = 'independentowner'; },
    x => { x.reviews[0].commit_id = '0'.repeat(40); },
    x => { x.workflow.runner_id = 0; },
    x => { x.workflow.steps = []; },
    x => { x.backends[0].classification = 'HOST_ONLY'; },
    x => { x.backends[0].output_sha256 = '0'.repeat(64); }
  ];
  for (let mask = 0; mask < 1024; ++mask) {
    const x = fixture();
    flags.forEach((f,i) => { if (mask & (1<<i)) f(x); });
    assert.equal(check(x).classification, mask === 0 ? 'LOCAL_CRYPTOGRAPHIC_CANDIDATE' : 'DENIED', 'mask ' + mask);
  }
});
test('changed artifact, untrusted signer, forged keyid, or bitflip fail', () => {
  const wrong = generateKeyPairSync('ed25519');
  assert.equal(check(fixture(), { artifactBytes: Buffer.from('other') }).classification, 'DENIED');
  assert.equal(check(fixture(), { signer: wrong.privateKey }).classification, 'DENIED');
  assert.equal(check(fixture(), { keyid: '0'.repeat(64) }).classification, 'DENIED');
  assert.equal(check(fixture(), { trustedKeyPem: wrong.publicKey.export({format:'pem',type:'spki'}) }).classification, 'DENIED');
  const e = JSON.parse(signed().toString());
  e.signatures[0].sig = Buffer.alloc(64).toString('base64');
  assert.equal(verifySignedCandidate({ envelopeBytes: Buffer.from(JSON.stringify(e)), trustedKeyPem: spki, artifactBytes: bytes }).classification, 'DENIED');
});
test('canonical JSON prevents duplicate keys, unknown envelope fields and invalid UTF-8', () => {
  const env = JSON.parse(signed().toString());
  const withDuplicate = Buffer.from(JSON.stringify(env).replace('{"payloadType":', '{"payloadType":"duplicate","payloadType":'));
  const extra = Buffer.from(JSON.stringify({ ...env, publicKey: spki }));
  const invalidUnicode = Buffer.concat([signed(), Buffer.from([0xff])]);
  const payloadWithDuplicate = Buffer.from(JSON.stringify(fixture()).replace('{"schema":','{"schema":"fake","schema":'));
  const wrongPayload = signed(fixture(), { rawPayload: payloadWithDuplicate });
  for (const envelopeBytes of [withDuplicate, extra, invalidUnicode, wrongPayload]) {
    assert.equal(verifySignedCandidate({ envelopeBytes, trustedKeyPem: spki, artifactBytes: bytes }).classification, 'DENIED');
  }
});
test('DSSE rejects noncanonical base64 and signature replay into a different type', () => {
  const env = JSON.parse(signed().toString());
  env.payload += '\n';
  assert.equal(verifySignedCandidate({envelopeBytes:Buffer.from(JSON.stringify(env)),trustedKeyPem:spki,artifactBytes:bytes}).classification,'DENIED');
  env.payload = JSON.parse(signed().toString()).payload;
  env.payloadType = 'application/vnd.fake+json';
  assert.equal(verifySignedCandidate({envelopeBytes:Buffer.from(JSON.stringify(env)),trustedKeyPem:spki,artifactBytes:bytes}).classification,'DENIED');
});
test('filesystem admission rejects symlink, hardlink, directory, empty and oversized', (t) => {
  const d = mkdtempSync(join(tmpdir(), 'atto-assurance-'));
  const normal = join(d,'normal'); writeFileSync(normal,'signed');
  assert.equal(readBoundedRegularFile(normal,100).toString(),'signed');
  const link = join(d,'symlink'); symlinkSync(normal,link);
  assert.throws(()=>readBoundedRegularFile(link,100));
  const hardlink = join(d,'hardlink');linkSync(normal,hardlink);
  assert.throws(()=>readBoundedRegularFile(normal,100));
  assert.throws(()=>readBoundedRegularFile(hardlink,100));
  const directory = join(d,'directory');mkdirSync(directory);
  assert.throws(()=>readBoundedRegularFile(directory,100));
  const empty = join(d,'empty');writeFileSync(empty,'');
  assert.throws(()=>readBoundedRegularFile(empty,100));
  const large = join(d,'large');writeFileSync(large,Buffer.alloc(101));
  assert.throws(()=>readBoundedRegularFile(large,100));
});
test('standalone CLI exits 3 for local candidate, 1 on rejected claim, 2 for invalid file', () => {
  const d = mkdtempSync(join(tmpdir(), 'atto-verify-cli-'));
  const envPath=join(d,'envelope.json'),keyPath=join(d,'pub.pem'),artifactPath=join(d,'artifact.bin');
  writeFileSync(envPath,signed());writeFileSync(keyPath,spki);writeFileSync(artifactPath,bytes);
  const cli=resolve(import.meta.dirname,'../tools/release-assurance-v1/verify.mjs');
  const args=['--envelope',envPath,'--trusted-key',keyPath,'--artifact',artifactPath];
  const run=(params)=>spawnSync(process.execPath,[cli,...params],{encoding:'utf8'});
  const ok=run(args);
  assert.equal(ok.status,3,ok.stderr);
  assert.equal(JSON.parse(ok.stdout).release_authorized,false);
  writeFileSync(artifactPath,'MUTATED');
  const invalid=run(args);
  assert.equal(invalid.status,1,invalid.stderr);
  assert.equal(JSON.parse(invalid.stdout).classification,'DENIED');
  const missing=run([...args.slice(0,5),'--artifact','/no/such/file']);
  assert.equal(missing.status,2,missing.stderr);
});

test('review chronology fails closed on comments, dismissal, and stale approval; fresh approval restores only local candidate', () => {
  const approval = { ...fixture().reviews[0] };
  const decision = (state, when, overrides = {}) => ({
    ...approval, state, submitted_at: when, ...overrides
  });
  const change = decision('CHANGES_REQUESTED', '2026-11-06T20:41:00Z');
  const comment = decision('COMMENTED', '2026-11-06T20:42:00Z');
  const reapprove = decision('APPROVED', '2026-11-06T20:43:00Z');
  const ignored = fixture();
  ignored.reviews = [approval, change, comment];
  assert.equal(check(ignored).reason, 'OUTSTANDING_CHANGES_REQUESTED');

  const recovered = fixture();
  recovered.reviews = [approval, change, comment, reapprove];
  const local = check(recovered);
  assert.equal(local.classification, 'LOCAL_CRYPTOGRAPHIC_CANDIDATE');
  assert.equal(local.release_authorized, false);
  assert.equal(local.compiler_guest_parity_proven, false);

  const dismissed = fixture();
  dismissed.reviews = [approval, decision('DISMISSED', '2026-11-06T20:41:00Z')];
  assert.equal(check(dismissed).reason, 'INDEPENDENT_CURRENT_HEAD_CODEOWNER_APPROVAL_MISSING');

  const stale = fixture();
  stale.reviews = [decision('APPROVED', '2026-11-06T20:40:00Z',
    { commit_id: '0'.repeat(40) })];
  assert.equal(check(stale).reason, 'INDEPENDENT_CURRENT_HEAD_CODEOWNER_APPROVAL_MISSING');
});

test('duplicate and mixed-case reviewer identities cannot forge a second independent reviewer', () => {
  const sameAuthor = fixture();
  sameAuthor.reviews[0].reviewer = 'buildauthor';
  assert.equal(check(sameAuthor).reason, 'INDEPENDENT_CURRENT_HEAD_CODEOWNER_APPROVAL_MISSING');

  const sameTimestamp = fixture();
  sameTimestamp.reviews.push({
    ...sameTimestamp.reviews[0], reviewer: 'independentowner', state: 'COMMENTED'
  });
  assert.equal(check(sameTimestamp).reason, 'AMBIGUOUS_REVIEW_HISTORY');

  const unrelated = fixture();
  unrelated.reviews[0].reviewer = 'NotACodeowner';
  assert.equal(check(unrelated).reason, 'INDEPENDENT_CURRENT_HEAD_CODEOWNER_APPROVAL_MISSING');
});

test('unexecuted, aliased, or fabricated workflow steps cannot promote synthetic evidence', () => {
  const mutations = [
    m => { m.workflow.steps[0].status = 'queued'; },
    m => { m.workflow.steps[1].status = 'in_progress'; },
    m => { m.workflow.steps[1].conclusion = null; },
    m => { m.workflow.steps[0].name = 'Check out repository'; },
    m => { m.workflow.steps[1].name = 'Skipped'; },
    m => { m.workflow.checkout_step_number = 2; m.workflow.test_step_number = 2; },
    m => { m.workflow.steps[0].number = 0; },
    m => { m.workflow.steps[1].number = 1; },
    m => { m.workflow.steps[1].extra = 'verified'; },
    m => { m.workflow.run_id = Number.MAX_SAFE_INTEGER + 1; },
    m => { m.workflow.job_name = 'unregistered-check'; },
    m => { m.workflow.steps = [m.workflow.steps[0]]; },
  ];
  for (const [i, mutate] of mutations.entries()) {
    const m = fixture(); mutate(m);
    const result = check(m);
    assert.equal(result.classification, 'DENIED', 'workflow mutation ' + i);
    assert.equal(result.release_authorized, false);
  }
});

test('backend job replay, classification downgrade, and incomplete receipts fail closed', () => {
  const cases = [
    m => {
      Object.assign(m.backends[1], {
        repository: m.backends[0].repository,
        run_id: m.backends[0].run_id,
        run_attempt: m.backends[0].run_attempt,
        job_id: m.backends[0].job_id
      });
    },
    m => { m.backends[0].classification = 'PARSER_ONLY'; },
    m => { m.backends[0].classification = 'NOT_EXECUTED'; },
    m => { m.backends[0].classification = 'NOT_CERTIFIED'; },
    m => { m.backends[0].run_id = 0; },
    m => { m.backends[0].executed_steps = null; },
    m => { m.backends[0].fixture_sha256 = '0'.repeat(64); },
    m => { m.backends[0].output_sha256 = '0'.repeat(64); },
    m => { delete m.backends[0].toolchain_sha256; },
    m => { m.backends[0].unknown_verified = true; },
  ];
  for (const [i, mutate] of cases.entries()) {
    const m = fixture(); mutate(m);
    assert.equal(check(m).classification, 'DENIED', 'backend mutation ' + i);
  }
});

test('file admission enforces exact sizes and rejects unsafe bounds; CLI cannot treat malformed inputs as success', () => {
  const d = mkdtempSync(join(tmpdir(), 'atto-assurance-edge-'));
  const regular = join(d, 'regular');
  writeFileSync(regular, bytes);
  assert.deepEqual(readBoundedRegularFile(regular, bytes.length), bytes);
  for (const bound of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1, bytes.length - 1]) {
    assert.throws(() => readBoundedRegularFile(regular, bound), 'bound ' + bound);
  }
  assert.throws(() => readBoundedRegularFile('', bytes.length));
  assert.throws(() => readBoundedRegularFile(null, bytes.length));

  const env = JSON.parse(signed().toString('utf8'));
  for (const mutations of [
    e => { e.signatures = []; },
    e => { e.signatures.push(e.signatures[0]); },
    e => { e.signatures[0].sig = Buffer.alloc(63).toString('base64'); },
    e => { e.signatures[0].keyid = 'A'.repeat(64); },
    e => { e.signatures[0].unexpectedKey = spki; },
    e => { e.payload += '='; },
  ]) {
    const altered = structuredClone(env);
    mutations(altered);
    const result = verifySignedCandidate({
      envelopeBytes: Buffer.from(JSON.stringify(altered)), trustedKeyPem: spki, artifactBytes: bytes
    });
    assert.equal(result.classification, 'DENIED');
    assert.equal(result.release_authorized, false);
  }
});


test('five backend receipt repositories must match their named compiler backends, not just a GitHub-shaped slug', () => {
  assert.equal(check().classification, 'LOCAL_CRYPTOGRAPHIC_CANDIDATE');
  const substitutions = [
    { backend: 'java', repository: 'ores-truffle-oreslang/oreslang-source.llvm' },
    { backend: 'net', repository: 'ores-truffle-oreslang/oreslang-source.net-fake' },
    { backend: 'wasm', repository: 'ores-truffle-oreslang/oreslang-cli' },
    { backend: 'forge', repository: 'ores-truffle-oreslang/oreslang-source.java' }
  ];
  for (const [i, substitution] of substitutions.entries()) {
    const manifest = fixture();
    const entry = manifest.backends.find(item => item.backend === substitution.backend);
    entry.repository = substitution.repository;
    // Preserve all signature, digest, distinct-job and five-backend-shape fields:
    // ONLY the source attribution is invalid.
    const result = check(manifest);
    assert.equal(result.classification, 'DENIED', 'repository substitution ' + i);
    assert.equal(result.reason, 'BACKEND_REPOSITORY_MISMATCH', 'reason ' + i);
    assert.equal(result.release_authorized, false);
    assert.equal(result.compiler_guest_parity_proven, false);
  }
});

test('bounded release evidence rejects symlinked ancestor paths and lexical dot-dot segments', () => {
  const parent = mkdtempSync(join(tmpdir(), 'atto-input-ancestor-'));
  const privateDir = join(parent, 'private');
  mkdirSync(privateDir);
  const candidate = join(privateDir, 'release-evidence.json');
  writeFileSync(candidate, bytes);
  assert.deepEqual(readBoundedRegularFile(candidate, bytes.length), bytes);

  const alias = join(parent, 'redirect');
  symlinkSync(privateDir, alias, 'dir');
  assert.throws(() => readBoundedRegularFile(join(alias, 'release-evidence.json'), bytes.length),
    /symlinked or non-directory input parent/);
  const aliasViaSecondLevel = join(parent, 'more-redirect');
  symlinkSync(alias, aliasViaSecondLevel, 'dir');
  assert.throws(() => readBoundedRegularFile(join(aliasViaSecondLevel, 'release-evidence.json'), bytes.length),
    /symlinked or non-directory input parent/);

  // Construct lexical traversal without join(), which would erase ../.
  const traversal = privateDir + '/inner/../release-evidence.json';
  assert.throws(() => readBoundedRegularFile(traversal, bytes.length),
    /noncanonical input path parent/);
  assert.deepEqual(readBoundedRegularFile(candidate, bytes.length), bytes);
});

test('CLI refuses cryptographic candidate through a symlinked parent even with valid key and artifact', () => {
  const parent = mkdtempSync(join(tmpdir(), 'atto-assurance-redirect-'));
  const real = join(parent, 'real');
  mkdirSync(real);
  const envelope = join(real, 'envelope.json');
  const publicKey = join(real, 'trusted.pem');
  const artifact = join(real, 'artifact.bin');
  writeFileSync(envelope, signed());
  writeFileSync(publicKey, spki);
  writeFileSync(artifact, bytes);
  const redirect = join(parent, 'redirect');
  symlinkSync(real, redirect, 'dir');
  const cli = resolve(import.meta.dirname, '../tools/release-assurance-v1/verify.mjs');
  const result = spawnSync(process.execPath, [cli, '--envelope', join(redirect, 'envelope.json'),
    '--trusted-key', publicKey, '--artifact', artifact], { encoding: 'utf8' });
  assert.equal(result.status, 2, result.stderr);
  const denial = JSON.parse(result.stderr.trim());
  assert.equal(denial.classification, 'DENIED');
  assert.equal(denial.release_authorized, false);
  assert.equal(result.stdout, '');
});


test('trust-anchor admission rejects private signing secrets and multiple PEM blocks', () => {
  const privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  const alternate = generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  const malformedKeys = [
    privatePem,
    Buffer.from(privatePem),
    spki + privatePem,
    privatePem + spki,
    spki + alternate,
    spki + '\nINJECTED DATA\n',
    'UNTRUSTED PREFIX\n' + spki,
    spki.replace('BEGIN PUBLIC KEY', 'BEGIN PRIVATE KEY'),
    Buffer.from([0xff, 0xfe, 0xfd]),
  ];
  for (const [index, invalid] of malformedKeys.entries()) {
    assert.throws(() => trustKeyId(invalid), 'invalid trust anchor ' + index);
    const result = check(fixture(), { trustedKeyPem: invalid });
    assert.equal(result.classification, 'DENIED', 'candidate ' + index);
    assert.equal(result.release_authorized, false);
  }
  // A public PEM input with conventional CRLF line endings is still a
  // single public trust anchor; never derive trust from the signed payload.
  const crlf = spki.replace(/\n/g, '\r\n');
  assert.equal(trustKeyId(Buffer.from(spki)).keyid, keyid);
  assert.equal(trustKeyId(crlf).keyid, keyid);
});

test('standalone CLI cannot import a signing private key as its trusted public anchor', () => {
  const d = mkdtempSync(join(tmpdir(), 'atto-assurance-private-trust-'));
  const envPath = join(d, 'envelope.json');
  const keyPath = join(d, 'secret.pkcs8.pem');
  const artifactPath = join(d, 'artifact.bin');
  writeFileSync(envPath, signed());
  writeFileSync(keyPath, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }));
  writeFileSync(artifactPath, bytes);
  const cli = resolve(import.meta.dirname, '../tools/release-assurance-v1/verify.mjs');
  const run = spawnSync(process.execPath, [cli, '--envelope', envPath,
    '--trusted-key', keyPath, '--artifact', artifactPath], { encoding: 'utf8' });
  assert.equal(run.status, 1, run.stderr);
  const result = JSON.parse(run.stdout);
  assert.equal(result.classification, 'DENIED');
  assert.equal(result.release_authorized, false);
  assert.match(result.reason, /trusted key must be a single public SPKI PEM block/);
});
