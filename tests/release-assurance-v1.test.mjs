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


test('five synthetic backend receipts cannot impersonate another compiler repository', () => {
  for (let index = 0; index < backendNames.length; ++index) {
    const m = fixture();
    const expected = backendNames[index];
    const other = backendNames[(index + 1) % backendNames.length];
    m.backends[index].repository = 'ores-truffle-oreslang/oreslang-source.' + other;
    const result = check(m);
    assert.equal(result.classification, 'DENIED', expected + ' relabeled as ' + other);
    assert.equal(result.reason, 'BACKEND_GUEST_RECEIPT_UNVERIFIED');
    assert.equal(result.release_authorized, false);
    assert.equal(result.compiler_guest_parity_proven, false);
  }
});

test('lookalike, forked and spelling-variant compiler repos never count as guests', () => {
  for (const replacement of [
    'ores-truffle-oreslang/oreslang-source.java-shadow',
    'ores-truffle-oreslang/oreslang-source.java.backup',
    'ores-truffle-oreslang/oreslang-source.Java',
    'other-organization/oreslang-source.java',
    'ores-truffle-oreslang/oreslang-source.fake',
  ]) {
    const m = fixture();
    m.backends[0].repository = replacement;
    const result = check(m);
    assert.equal(result.classification, 'DENIED', replacement);
    assert.equal(result.release_authorized, false);
  }
});

test('canonical five-repo identity remains a non-authorizing synthetic candidate', () => {
  const m = fixture();
  for (const b of m.backends) {
    assert.equal(b.repository, 'ores-truffle-oreslang/oreslang-source.' + b.backend);
  }
  const result = check(m);
  assert.equal(result.classification, 'LOCAL_CRYPTOGRAPHIC_CANDIDATE');
  assert.equal(result.receipt_count, 5);
  assert.equal(result.release_authorized, false);
  assert.equal(result.compiler_guest_parity_proven, false);
});


test('signed backend receipts cannot reuse workflow run or job identities across repos', () => {
  for (const [kind, mutate] of [
    ['same job ID in distinct runs', m => { m.backends[4].job_id = m.backends[0].job_id; }],
    ['same workflow run ID across canonical repositories', m => {
      m.backends[4].run_id = m.backends[0].run_id;
    }],
    ['same run and job IDs despite distinct repo names', m => {
      m.backends[4].run_id = m.backends[0].run_id;
      m.backends[4].job_id = m.backends[0].job_id;
    }],
  ]) {
    const m = fixture();
    mutate(m);
    const result = check(m);
    assert.equal(result.classification, 'DENIED', kind);
    assert.equal(result.reason, 'DUPLICATE_BACKEND_JOB_RECEIPT', kind);
    assert.equal(result.release_authorized, false);
    assert.equal(result.compiler_guest_parity_proven, false);
  }
});

test('distinct source-owned run and job IDs preserve synthetic nonauthorization', () => {
  const m = fixture();
  assert.equal(new Set(m.backends.map(b => b.run_id)).size, backendNames.length);
  assert.equal(new Set(m.backends.map(b => b.job_id)).size, backendNames.length);
  const result = check(m);
  assert.equal(result.classification, 'LOCAL_CRYPTOGRAPHIC_CANDIDATE');
  assert.equal(result.release_authorized, false);
  assert.equal(result.compiler_guest_parity_proven, false);
});


test('one asserted successful workflow cannot falsely cover two required contexts', () => {
  for (const required_contexts of [
    ['release-assurance', 'compiler-negative'],
    ['compiler-negative', 'release-assurance'],
    ['release-assurance', 'release-signature', 'backend-conformance'],
  ]) {
    const m = fixture();
    m.governance.required_contexts = required_contexts;
    const result = check(m);
    assert.equal(result.classification, 'DENIED', required_contexts.join(','));
    assert.equal(result.reason, 'GOVERNANCE_NOT_ASSERTED');
    assert.equal(result.release_authorized, false);
  }
  assert.equal(check(fixture()).classification, 'LOCAL_CRYPTOGRAPHIC_CANDIDATE');
});

test('untrusted test execution before immutable checkout and reordered receipts fail closed', () => {
  for (const [description, mutate] of [
    ['checkout after tests', m => {
      const [checkout, execution] = m.workflow.steps;
      m.workflow.steps = [
        { ...execution, number: 1 },
        { ...checkout, number: 2 },
      ];
      m.workflow.checkout_step_number = 2;
      m.workflow.test_step_number = 1;
    }],
    ['unordered executed step list', m => {
      m.workflow.steps.reverse();
    }],
    ['nonmonotonic step numbers', m => {
      m.workflow.steps[0].number = 5;
      m.workflow.checkout_step_number = 5;
    }],
  ]) {
    const m = fixture();
    mutate(m);
    const result = check(m);
    assert.equal(result.classification, 'DENIED', description);
    assert.equal(result.reason, 'REQUIRED_EXECUTED_STEP_MISSING', description);
    assert.equal(result.release_authorized, false);
    assert.equal(result.compiler_guest_parity_proven, false);
  }
  const valid = check(fixture());
  assert.equal(valid.classification, 'LOCAL_CRYPTOGRAPHIC_CANDIDATE');
  assert.equal(valid.release_authorized, false);
});
