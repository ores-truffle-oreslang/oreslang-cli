import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync, symlinkSync, linkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { dssePAE, PAYLOAD_TYPE, trustKeyId } from '../tools/release-assurance-v1/verify.mjs';
import {
  REGISTRY_TYPE, registryPAE, verifyPolicyBoundCandidate
} from '../tools/release-trust-registry-v1/verify.mjs';

const root = generateKeyPairSync('ed25519');
const signer = generateKeyPairSync('ed25519');
const builder = generateKeyPairSync('ed25519');
const anotherRoot = generateKeyPairSync('ed25519');
const pem = p => p.publicKey.export({ format: 'pem', type: 'spki' });
const hash = b => createHash('sha256').update(b).digest('hex');
const now = '2026-11-07T00:01:00Z';
const repo = 'ores-truffle-oreslang/oreslang-cli';
const head = 'a'.repeat(40), tree = 'b'.repeat(40);
const artifact = Buffer.from('SYNTHETIC-ATTO-BYTES--NOT-A-RELEASE\n');
const keyId = p => trustKeyId(pem(p)).keyid;
const key = (p, role='candidate-signing') => ({
  keyid: keyId(p), spki_pem: pem(p), role, repository: repo,
  not_before: '2026-01-01T00:00:00Z', not_after: '2028-01-01T00:00:00Z',
  revoked_at: null
});
const manifest = () => ({
  schema: 'atto.release-assurance.v1',
  subject: { repository: repo, head_sha: head, tree_sha: tree,
    artifact: { filename: 'release.tgz', size: artifact.length, sha256: hash(artifact) } },
  governance: { protected_main: true, no_bypass: true,
    require_codeowner_review: true, dismiss_stale_reviews: true,
    author: 'BuildAuthor', codeowners: ['IndependentOwner'],
    required_contexts: ['release-assurance'] },
  reviews: [{ reviewer: 'IndependentOwner', state: 'APPROVED',
    commit_id: head, submitted_at: '2026-11-06T20:40:00Z' }],
  workflow: { run_id: 12, run_attempt: 2, job_id: 15, runner_id: 16,
    job_name: 'release-assurance', head_sha: head, tree_sha: tree,
    status: 'completed', conclusion: 'success',
    steps: [
      { number: 1, name: 'Verify immutable source', status: 'completed', conclusion: 'success' },
      { number: 2, name: 'Execute source tests', status: 'completed', conclusion: 'success' }
    ], checkout_step_number: 1, test_step_number: 2 },
  backends: ['java', 'llvm', 'net', 'wasm', 'forge'].map((backend, i) => ({
    backend, repository: 'ores-truffle-oreslang/oreslang-source.' + backend,
    head_sha: String(i + 1).repeat(40), tree_sha: String(i + 5).repeat(40),
    classification: 'EXECUTED_COMPILER_GUEST', run_id: 100 + i,
    run_attempt: 1, job_id: 200 + i, runner_id: 300 + i,
    executed_steps: 3, toolchain_sha256: 'e'.repeat(64),
    fixture_sha256: 'f'.repeat(64), output_sha256: 'd'.repeat(64)
  }))
});
const policy = () => ({
  schema: 'atto.trust-registry.v1',
  policy_id: 'atto-release-policy', sequence: 8,
  not_before: '2026-01-01T00:00:00Z', not_after: '2029-01-01T00:00:00Z',
  keys: [key(signer)]
});
const candidateEnvelope = (m=manifest(), p=signer) => {
  const b = Buffer.from(JSON.stringify(m));
  return Buffer.from(JSON.stringify({
    payloadType: PAYLOAD_TYPE, payload: b.toString('base64'),
    signatures: [{ keyid: keyId(p),
      sig: sign(null, dssePAE(PAYLOAD_TYPE,b), p.privateKey).toString('base64') }]
  }));
};
const policyEnvelope = (p=policy(), signingRoot=root) => {
  const b = Buffer.from(JSON.stringify(p));
  return Buffer.from(JSON.stringify({
    payloadType: REGISTRY_TYPE, payload: b.toString('base64'),
    signatures: [{ keyid: keyId(signingRoot),
      sig: sign(null, registryPAE(b), signingRoot.privateKey).toString('base64') }]
  }));
};
const expectations = e => ({
  policy_id: 'atto-release-policy', minimum_sequence: 8,
  root_keyid: keyId(root), repository: repo, head_sha: head, tree_sha: tree,
  artifact_sha256: hash(artifact), envelope_sha256: hash(e)
});
function make(p=policy(),m=manifest(), releaseSigner=signer) {
  const candidateEnvelopeBytes = candidateEnvelope(m,releaseSigner);
  return {
    registryEnvelopeBytes: policyEnvelope(p),
    trustedRootPem: pem(root),
    candidateEnvelopeBytes, artifactBytes: artifact,
    expected: expectations(candidateEnvelopeBytes), now
  };
}
const verdict = args => verifyPolicyBoundCandidate(args).classification;
const denied = args => assert.equal(verdict(args), 'DENIED');
const modify = f => { const p=policy(); f(p); return make(p); };

test('root-signed registry selects separate candidate signer and never authorizes release', () => {
  const v = verifyPolicyBoundCandidate(make());
  assert.equal(v.classification, 'TRUST_POLICY_BOUND_LOCAL_CANDIDATE');
  assert.equal(v.release_authorized, false);
  assert.equal(v.compiler_guest_parity_proven, false);
  assert.equal(v.authenticated_github, false);
  assert.equal(v.policy_sequence, 8);
  assert.equal(v.signer_keyid, keyId(signer));
  assert.notEqual(v.root_keyid, v.signer_keyid);
});

test('wrong root, changed signature, and substituting root plus policy are denied', () => {
  const a = make(); a.trustedRootPem=pem(anotherRoot); denied(a);
  const b = make(); b.registryEnvelopeBytes=policyEnvelope(policy(),anotherRoot); denied(b);
  const c = make(); c.registryEnvelopeBytes=policyEnvelope(policy(),anotherRoot);
  c.trustedRootPem=pem(anotherRoot); denied(c); // external root pin still original
  const d = make(); const e=JSON.parse(d.registryEnvelopeBytes);
  e.signatures[0].sig=Buffer.alloc(64).toString('base64');
  d.registryEnvelopeBytes=Buffer.from(JSON.stringify(e)); denied(d);
  const f = make(); const z=JSON.parse(f.registryEnvelopeBytes);
  z.payloadType='application/vnd.atto.fake+json';
  f.registryEnvelopeBytes=Buffer.from(JSON.stringify(z)); denied(f);
});

test('externally pinned sequence rejects signed policy rollback', () => {
  denied(modify(p=>{p.sequence=7}));
  denied(modify(p=>{p.sequence=0}));
  const good=make(); good.expected.minimum_sequence=9; denied(good);
  const newer=modify(p=>{p.sequence=9});
  assert.equal(verdict(newer),'TRUST_POLICY_BOUND_LOCAL_CANDIDATE');
});

test('external head/tree/artifact/envelope digests prevent substitution and stale replay', () => {
  for(const f of [
    x=>{x.expected.head_sha='c'.repeat(40)},
    x=>{x.expected.tree_sha='c'.repeat(40)},
    x=>{x.expected.artifact_sha256='0'.repeat(64)},
    x=>{x.expected.envelope_sha256='0'.repeat(64)},
    x=>{x.expected.repository='ores-truffle-oreslang/other'},
    x=>{x.expected.policy_id='old-policy'},
    x=>{x.expected.root_keyid='0'.repeat(64)}
  ]){const a=make();f(a);denied(a);}
  const stale=make();
  const m=manifest();m.subject.head_sha='c'.repeat(40);
  m.reviews[0].commit_id=m.subject.head_sha;
  m.workflow.head_sha=m.subject.head_sha;
  stale.candidateEnvelopeBytes=candidateEnvelope(m);
  denied(stale); // old externally fetched envelope hash invalidates re-signing
  const changed=make();changed.artifactBytes=Buffer.from('ATTACKER-BYTES');denied(changed);
});

test('different signer duties cannot impersonate candidate-signing authority', () => {
  for(const role of ['release-approval','build-provenance','governance-review']) {
    denied(modify(p=>{p.keys[0].role=role}));
  }
  denied(modify(p=>{p.keys[0].role='owner'}));
  denied(modify(p=>{p.keys[0].repository='ores-truffle-oreslang/other'}));
  const wrong=make();
  wrong.candidateEnvelopeBytes=candidateEnvelope(manifest(),builder);
  wrong.expected.envelope_sha256=hash(wrong.candidateEnvelopeBytes);
  denied(wrong);
  const badRoot=make(policy(),manifest(),root);
  badRoot.expected.envelope_sha256=hash(badRoot.candidateEnvelopeBytes);
  denied(badRoot);
});

test('key rotation, revocation and live time-window admission fail closed', () => {
  denied(modify(p=>{p.keys[0].revoked_at='2026-11-07T00:00:00Z'}));
  denied(modify(p=>{p.keys[0].revoked_at=now}));
  const future=modify(p=>{p.keys[0].revoked_at='2027-01-01T00:00:00Z'});
  assert.equal(verdict(future),'TRUST_POLICY_BOUND_LOCAL_CANDIDATE');
  denied(modify(p=>{p.keys[0].not_before='2027-01-01T00:00:00Z'}));
  denied(modify(p=>{p.keys[0].not_after='2026-11-07T00:00:00Z'}));
  denied(modify(p=>{p.not_before='2027-01-01T00:00:00Z'}));
  denied(modify(p=>{p.not_after='2026-11-07T00:00:00Z'}));
  const clock=make();clock.now='2026-02-30T00:01:00Z';denied(clock);
  const clock2=make();clock2.now='bad';denied(clock2);
});

test('reject duplicate, misleading, nonsensical and unauthorized registry entries', () => {
  const mutations=[
    p=>{p.keys.push({...p.keys[0]})},
    p=>{p.keys.push(key(builder,'build-provenance'));p.keys.push({...p.keys[1]})},
    p=>{p.keys[0].keyid='0'.repeat(64)},
    p=>{p.keys[0].spki_pem=pem(builder)},
    p=>{p.keys[0].spki_pem='not an ed25519 public key'},
    p=>{p.keys[0].revoked_at='2026-02-30T00:00:00Z'},
    p=>{p.keys[0].not_after='2030-01-01T00:00:00Z'},
    p=>{p.keys[0].extra=true},
    p=>{p.keys=[]},
    p=>{p.keys=Array.from({length:33},()=>key(signer))},
    p=>{p.keys[0].repository='HTTPS://github.com/ores-truffle-oreslang/oreslang-cli'},
    p=>{p.keys[0].not_before=p.keys[0].not_after},
    p=>{p.schema='untrusted'},
    p=>{p.policy_id='INVALID POLICY'},
    p=>{p.anotherField=true}
  ];
  for(const [i,f] of mutations.entries()){
    const p=policy();f(p); assert.equal(verdict(make(p)),'DENIED','mutation '+i);
  }
  const p=policy();p.keys=[key(root)]; // same root cannot also be delegated signer
  const r=make(p,manifest(),root);r.expected.envelope_sha256=hash(r.candidateEnvelopeBytes);
  denied(r);
});

test('reject noncanonical and malformed trust envelopes', () => {
  const a=make();
  const base=JSON.parse(a.registryEnvelopeBytes);
  const bad=[
    Buffer.concat([a.registryEnvelopeBytes, Buffer.from([0xff])]),
    Buffer.from(JSON.stringify({...base, publicKey:pem(root)})),
    Buffer.from(JSON.stringify(base).replace('{"payloadType":','{"payloadType":"dup","payloadType":')),
    Buffer.from(JSON.stringify({...base,payload:base.payload+'\n'})),
    Buffer.from(JSON.stringify({...base,signatures:[]})),
    Buffer.from(JSON.stringify({...base,signatures:[base.signatures[0],base.signatures[0]]})),
    Buffer.from(JSON.stringify({...base,signatures:[{...base.signatures[0],keyid:'0'.repeat(64)}]}))
  ];
  for(const [i,x] of bad.entries()){const t=make();t.registryEnvelopeBytes=x;assert.equal(verdict(t),'DENIED','bad envelope '+i);}
});

test('base candidate verifier independently rejects unexecuted or host-only guest receipts', () => {
  const noSteps=manifest();noSteps.workflow.steps=[];
  const a=make(policy(),noSteps);denied(a);
  const hostOnly=manifest();hostOnly.backends[1].classification='HOST_ONLY';
  denied(make(policy(),hostOnly));
  const stale=manifest();stale.reviews[0].commit_id='0'.repeat(40);
  denied(make(policy(),stale));
});

test('independent expected policy data rejects ambiguity and bogus clock values', () => {
  const badExpect=[
    x=>{x.minimum_sequence=0},x=>{x.minimum_sequence=-1},
    x=>{x.policy_id=''},x=>{x.root_keyid='A'.repeat(64)},
    x=>{x.repository='attacker/repo'},x=>{x.extra='trusted'},
    x=>{delete x.envelope_sha256}
  ];
  for(const [i,mut] of badExpect.entries()){
    const a=make();mut(a.expected);assert.equal(verdict(a),'DENIED','bad expectation '+i);
  }
});

test('CLI is non-authorizing exit 3, denies tampering exit 1, blocks symlink/hardlink exit 2',()=>{
  const d=mkdtempSync(join(tmpdir(),'atto-root-policy-'));
  const paths={registry:join(d,'registry.dsse'),root:join(d,'root.pem'),
    candidate:join(d,'release.dsse'),artifact:join(d,'release.tgz'),expected:join(d,'expected.json')};
  const a=make();
  writeFileSync(paths.registry,a.registryEnvelopeBytes);writeFileSync(paths.root,a.trustedRootPem);
  writeFileSync(paths.candidate,a.candidateEnvelopeBytes);
  writeFileSync(paths.artifact,a.artifactBytes);
  writeFileSync(paths.expected,JSON.stringify(a.expected));
  const command=resolve(import.meta.dirname,'../tools/release-trust-registry-v1/verify.mjs');
  const cli=()=>spawnSync(process.execPath,[command,'--registry',paths.registry,
    '--root-key',paths.root,'--candidate',paths.candidate,
    '--artifact',paths.artifact,'--expected',paths.expected],{encoding:'utf8'});
  const ok=cli();assert.equal(ok.status,3,ok.stderr);
  assert.equal(JSON.parse(ok.stdout).release_authorized,false);
  writeFileSync(paths.artifact,'tampered');
  const tampered=cli();assert.equal(tampered.status,1,tampered.stderr);
  writeFileSync(paths.artifact,artifact);
  const external=join(d,'external');writeFileSync(external,JSON.stringify(a.expected));
  const link=join(d,'symlink');symlinkSync(external,link);
  const original=paths.expected;paths.expected=link;
  assert.equal(cli().status,2);
  paths.expected=original;
  const hard=join(d,'hardlink');linkSync(original,hard);
  assert.equal(cli().status,2);
  const error=spawnSync(process.execPath,[command,'--help'],{encoding:'utf8'});
  assert.equal(error.status,2);
});


// boundary policy tests: executable negative controls for stacked release assurance.
test('trust-policy validity is start-inclusive, end-exclusive and revocation is immediate', () => {
  const atStart=make();
  atStart.now='2026-01-01T00:00:00Z';
  assert.equal(verdict(atStart),'TRUST_POLICY_BOUND_LOCAL_CANDIDATE');
  const before=make();
  before.now='2025-12-31T23:59:59Z';
  denied(before);
  const last=make();
  last.now='2027-12-31T23:59:59Z';
  assert.equal(verdict(last),'TRUST_POLICY_BOUND_LOCAL_CANDIDATE');
  const signerExpires=make();
  signerExpires.now='2028-01-01T00:00:00Z';
  denied(signerExpires);
  const policyExpires=make();
  policyExpires.now='2029-01-01T00:00:00Z';
  denied(policyExpires);
  const revoked=policy();
  revoked.keys[0].revoked_at='2026-11-07T00:01:01Z';
  const justBefore=make(revoked);
  assert.equal(verdict(justBefore),'TRUST_POLICY_BOUND_LOCAL_CANDIDATE');
  const atRevocation=make(revoked);
  atRevocation.now='2026-11-07T00:01:01Z';
  denied(atRevocation);
});

test('review history fails closed on author approval, stale code owner and COMMENTED after veto', () => {
  const mutations=[
    m => {m.governance.author='IndependentOwner'},
    m => {m.reviews[0].reviewer='BuildAuthor'},
    m => {m.reviews[0].reviewer='UnlistedReviewer'},
    m => {m.reviews[0].commit_id='0'.repeat(40)},
    m => {m.reviews[0].state='COMMENTED'},
    m => {m.reviews.push({...m.reviews[0], state:'CHANGES_REQUESTED',
      submitted_at:'2026-11-06T20:41:00Z'})},
    m => {m.reviews.push({...m.reviews[0], state:'CHANGES_REQUESTED',
      submitted_at:'2026-11-06T20:41:00Z'});
      m.reviews.push({...m.reviews[0], state:'COMMENTED',
        submitted_at:'2026-11-06T20:42:00Z'})},
    m => {m.reviews.push({...m.reviews[0], state:'DISMISSED',
      submitted_at:'2026-11-06T20:41:00Z'})},
    m => {m.reviews.push({...m.reviews[0], state:'APPROVED',
      submitted_at:'2026-11-06T20:40:00Z'})}
  ];
  for (const [i, mutate] of mutations.entries()) {
    const m=manifest();
    mutate(m);
    const result=verifyPolicyBoundCandidate(make(policy(),m));
    assert.equal(result.classification,'DENIED','review mutation '+i);
    assert.equal(result.release_authorized,false);
    assert.equal(result.authenticated_github,false);
  }
  const recovered=manifest();
  recovered.reviews.push({...recovered.reviews[0],state:'CHANGES_REQUESTED',
    submitted_at:'2026-11-06T20:41:00Z'});
  recovered.reviews.push({...recovered.reviews[0],state:'APPROVED',
    submitted_at:'2026-11-06T20:42:00Z'});
  assert.equal(verdict(make(policy(),recovered)),'TRUST_POLICY_BOUND_LOCAL_CANDIDATE');
});

test('all five backend receipts reject host-only labels, zero-step runners and source mixups', () => {
  const names=['java','llvm','net','wasm','forge'];
  let checked=0;
  for(let i=0;i<names.length;i++){
    const other=names[(i+1)%names.length];
    const mutations=[
      b => {b.classification='HOST_ONLY'},
      b => {b.classification='NOT_EXECUTED'},
      b => {b.executed_steps=0},
      b => {b.run_id=0},
      b => {b.run_attempt=0},
      b => {b.job_id=0},
      b => {b.runner_id=0},
      b => {b.fixture_sha256='1'.repeat(64)},
      b => {b.output_sha256='2'.repeat(64)},
      b => {b.repository='ores-truffle-oreslang/oreslang-source.'+other},
      b => {b.repository='ores-truffle-oreslang/unrelated'}
    ];
    for(const [j, mutate] of mutations.entries()){
      const m=manifest();
      mutate(m.backends[i]);
      const result=verifyPolicyBoundCandidate(make(policy(),m));
      assert.equal(result.classification,'DENIED',names[i]+' backend mutation '+j);
      assert.equal(result.release_authorized,false);
      checked++;
    }
  }
  assert.equal(checked,55);
});

test('unassigned or fictional workflow test steps never become a signed candidate', () => {
  const mutations=[
    w=>{w.steps=[]},
    w=>{w.steps=null},
    w=>{w.runner_id=null},
    w=>{w.runner_id=0},
    w=>{w.run_attempt=0},
    w=>{w.steps[0].number=w.steps[1].number},
    w=>{w.steps[0].name='Generic setup'},
    w=>{w.steps[1].name='Publish release'},
    w=>{w.steps[1].conclusion='skipped'},
    w=>{w.steps[1].status='queued'},
    w=>{w.checkout_step_number=w.test_step_number},
    w=>{w.job_name='untrusted-ci'},
    w=>{w.head_sha='f'.repeat(40)},
    w=>{w.tree_sha='f'.repeat(40)}
  ];
  for(const [i,mutate] of mutations.entries()){
    const m=manifest();
    mutate(m.workflow);
    const result=verifyPolicyBoundCandidate(make(policy(),m));
    assert.equal(result.classification,'DENIED','workflow mutation '+i);
    assert.equal(result.release_authorized,false);
    assert.equal(result.compiler_guest_parity_proven,false);
  }
});



// Wave 2: independent, signed input mutations. These must never promote a
// local cryptographic candidate to live GitHub/guest/release authorization.
test('clock parser denies offset, fractional, lowercase and malformed UTC instants', () => {
  for (const clock of [
    '2026-11-07T00:01:00+00:00','2026-11-07T00:01:00.000Z',
    '2026-11-07T00:01:00z','2026-11-07 00:01:00Z',
    '2026-11-07T00:01:60Z','1969-12-31T23:59:59Z',
    '2026-02-29T00:01:00Z','2026-13-01T00:01:00Z'
  ]) { const x=make();x.now=clock;denied(x); }
});
test('not-before instant is inclusive but expiry instant is exclusive', () => {
  const before=make();before.now='2026-01-01T00:00:00Z';
  assert.equal(verdict(before),'TRUST_POLICY_BOUND_LOCAL_CANDIDATE');
  const expires=make();expires.now='2028-01-01T00:00:00Z';denied(expires);
  const policyExpires=make();policyExpires.now='2029-01-01T00:00:00Z';
  denied(policyExpires);
});
test('signed candidate signer is invalid exactly at revocation instant', () => {
  const exactly=modify(p=>{p.keys[0].revoked_at=now}); denied(exactly);
  const prior=modify(p=>{p.keys[0].revoked_at='2026-11-06T23:59:59Z'}); denied(prior);
  const later=modify(p=>{p.keys[0].revoked_at='2026-11-07T00:01:01Z'});
  assert.equal(verdict(later),'TRUST_POLICY_BOUND_LOCAL_CANDIDATE');
});
test('policy sequence is an actual bounded integer, not a float/string', () => {
  for (const value of [8.5, '8', null, -1, 0, 9007199254740992]) {
    denied(modify(p=>{p.sequence=value}));
  }
});
test('externally supplied minimum sequence is bounded and typed', () => {
  for (const value of [8.2,'8',null,-1,0,9007199254740992]) {
    const x=make();x.expected.minimum_sequence=value;denied(x);
  }
});
test('independent root signature cannot rehabilitate semantically malformed policy', () => {
  for (const mutate of [
    p=>{p.policy_id='CAPITAL_POLICY'},
    p=>{p.not_before='2026-02-30T00:00:00Z'},
    p=>{p.not_after=p.not_before},
    p=>{p.keys[0].not_before='2025-12-31T23:59:59Z'},
    p=>{p.keys[0].not_after='2030-01-01T00:00:00Z'}
  ]) {const p=policy();mutate(p);denied(make(p));}
});
test('additional independent signer roles do not grant candidate-signing privilege', () => {
  const p=policy();
  p.keys.push(key(builder,'governance-review'));
  const x=make(p);
  const result=verifyPolicyBoundCandidate(x);
  assert.equal(result.classification,'TRUST_POLICY_BOUND_LOCAL_CANDIDATE');
  assert.equal(result.release_authorized,false);
  assert.equal(result.authenticated_github,false);
  const forged=make(p,manifest(),builder);
  forged.expected.envelope_sha256=hash(forged.candidateEnvelopeBytes);
  denied(forged);
});
test('signed duplicate-key JSON root policy is denied despite valid Ed25519 signature', () => {
  const raw=Buffer.from(JSON.stringify(policy()).replace(
    '"schema":','"schema":"other","schema":'));
  const x=make();
  x.registryEnvelopeBytes=Buffer.from(JSON.stringify({
    payloadType:REGISTRY_TYPE,payload:raw.toString('base64'),
    signatures:[{keyid:keyId(root),sig:sign(null,registryPAE(raw),
      root.privateKey).toString('base64')}]
  }));
  denied(x);
});
test('signed whitespace-altered root policy is not canonical JSON', () => {
  const raw=Buffer.from(JSON.stringify(policy()).replace(',"policy_id":',', "policy_id":'));
  const x=make();
  x.registryEnvelopeBytes=Buffer.from(JSON.stringify({
    payloadType:REGISTRY_TYPE,payload:raw.toString('base64'),
    signatures:[{keyid:keyId(root),sig:sign(null,registryPAE(raw),
      root.privateKey).toString('base64')}]
  }));
  denied(x);
});
test('signed invalid UTF-8 policy is not accepted as valid identity', () => {
  const raw=Buffer.from([0xff,0xfe,0x7b,0x7d]);
  const x=make();
  x.registryEnvelopeBytes=Buffer.from(JSON.stringify({
    payloadType:REGISTRY_TYPE,payload:raw.toString('base64'),
    signatures:[{keyid:keyId(root),sig:sign(null,registryPAE(raw),
      root.privateKey).toString('base64')}]
  }));
  denied(x);
});
test('correctly re-pinned envelope cannot authorize duplicate DSSE signatures', () => {
  const x=make(),env=JSON.parse(x.candidateEnvelopeBytes);
  env.signatures.push({...env.signatures[0]});
  x.candidateEnvelopeBytes=Buffer.from(JSON.stringify(env));
  x.expected.envelope_sha256=hash(x.candidateEnvelopeBytes);
  denied(x);
});
test('all valid local trust results explicitly deny merge and release authority', () => {
  for(const args of [
    make(),
    modify(p=>{p.sequence=10}),
    modify(p=>{p.keys.push(key(builder,'release-approval'))})
  ]){
    const x=verifyPolicyBoundCandidate(args);
    assert.equal(x.classification,'TRUST_POLICY_BOUND_LOCAL_CANDIDATE');
    assert.equal(x.release_authorized,false);
    assert.equal(x.authenticated_github,false);
    assert.equal(x.compiler_guest_parity_proven,false);
    assert.ok(!Object.hasOwn(x,'merge_authorized') || x.merge_authorized===false);
  }
});
