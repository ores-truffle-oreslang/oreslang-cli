import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { mkdtempSync, writeFileSync, symlinkSync, linkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { PAYLOAD_TYPE, dssePAE, trustKeyId } from '../tools/release-assurance-v1/verify.mjs';
import { REGISTRY_TYPE, registryPAE } from '../tools/release-trust-registry-v1/verify.mjs';
import { CHECKPOINT_TYPE, INTENT_TYPE, verifySequenceLinkedCandidate } from '../tools/release-checkpoint-v1/verify.mjs';

const kp = () => generateKeyPairSync('ed25519');
const root=kp(), candidate=kp(), governance=kp(), approval=kp(), outsider=kp();
const pem = k => k.publicKey.export({format:'pem',type:'spki'});
const id = k => trustKeyId(pem(k)).keyid;
const sha = b => createHash('sha256').update(b).digest('hex');
const repo='ores-truffle-oreslang/oreslang-cli';
const HEAD='a'.repeat(40), TREE='b'.repeat(40), ZERO='0'.repeat(64);
const artifact=Buffer.from('SYNTHETIC PUBLIC TEST ARTIFACT — NOT A RELEASE\n');
const now='2026-11-07T00:01:30Z';
const checkpointTime='2026-11-07T00:00:00Z';
const timeTo='2026-11-07T00:04:00Z';
const key = (who,role) => ({keyid:id(who),spki_pem:pem(who),role,
  repository:repo,not_before:'2026-01-01T00:00:00Z',
  not_after:'2028-01-01T00:00:00Z',revoked_at:null});
const policy=()=>({schema:'atto.trust-registry.v1',policy_id:'atto-release-policy',
  sequence:8,not_before:'2026-01-01T00:00:00Z',
  not_after:'2029-01-01T00:00:00Z',
  keys:[key(candidate,'candidate-signing'),
    key(governance,'governance-review'),key(approval,'release-approval')]});
const receipt=()=>({schema:'atto.release-assurance.v1',
  subject:{repository:repo,head_sha:HEAD,tree_sha:TREE,
    artifact:{filename:'release.tgz',sha256:sha(artifact),size:artifact.length}},
  governance:{protected_main:true,no_bypass:true,require_codeowner_review:true,
    dismiss_stale_reviews:true,author:'BuildAuthor',codeowners:['IndependentOwner'],
    required_contexts:['release-assurance']},
  reviews:[{reviewer:'IndependentOwner',state:'APPROVED',commit_id:HEAD,
    submitted_at:'2026-11-06T20:40:00Z'}],
  workflow:{run_id:12,run_attempt:2,job_id:15,runner_id:16,
    job_name:'release-assurance',head_sha:HEAD,tree_sha:TREE,
    status:'completed',conclusion:'success',
    steps:[{number:1,name:'Verify immutable source',status:'completed',conclusion:'success'},
      {number:2,name:'Execute source tests',status:'completed',conclusion:'success'}],
    checkout_step_number:1,test_step_number:2},
  backends:['java','llvm','net','wasm','forge'].map((name,i)=>({
    backend:name,repository:'ores-truffle-oreslang/oreslang-source.'+name,
    head_sha:String(i+1).repeat(40),tree_sha:String(i+5).repeat(40),
    classification:'EXECUTED_COMPILER_GUEST',run_id:100+i,run_attempt:1,
    job_id:200+i,runner_id:300+i,executed_steps:3,
    toolchain_sha256:'e'.repeat(64),fixture_sha256:'f'.repeat(64),
    output_sha256:'d'.repeat(64)}))});
const envelope=(type,payload,who) => {
  const raw=Buffer.from(JSON.stringify(payload));
  const p = type===PAYLOAD_TYPE ? dssePAE(type,raw) :
    type===REGISTRY_TYPE ? registryPAE(raw) : (()=> {
      const t=Buffer.from(type);
      return Buffer.concat([Buffer.from('DSSEv1 '+t.length+' '),t,
        Buffer.from(' '+raw.length+' '),raw]);
    })();
  return Buffer.from(JSON.stringify({payloadType:type,payload:raw.toString('base64'),
    signatures:[{keyid:id(who),sig:sign(null,p,who.privateKey).toString('base64')}]}));
};
function make(o={}) {
  const p=policy();o.policyEdit?.(p);
  const manifest=receipt();o.receiptEdit?.(manifest);
  const candidateEnvelopeBytes=envelope(PAYLOAD_TYPE,manifest,o.candidateSigner||candidate);
  const registryEnvelopeBytes=envelope(REGISTRY_TYPE,p,o.rootSigner||root);
  const expected={policy_id:'atto-release-policy',minimum_sequence:8,
    root_keyid:id(root),repository:repo,head_sha:HEAD,tree_sha:TREE,
    artifact_sha256:sha(artifact),envelope_sha256:sha(candidateEnvelopeBytes)};
  o.expectedEdit?.(expected);
  const cp={schema:'atto.release-checkpoint.v1',repository:repo,
    policy_id:'atto-release-policy',policy_sequence:8,
    registry_sha256:sha(registryEnvelopeBytes),ledger_id:'atto-ledger',
    last_sequence:11,last_intent_sha256:'1'.repeat(64),last_nonce:'2'.repeat(64),
    observed_at:checkpointTime,expires_at:'2026-11-07T00:05:00Z'};
  o.checkpointEdit?.(cp);
  const intent={schema:'atto.release-intent.v1',repository:repo,head_sha:HEAD,
    tree_sha:TREE,artifact_sha256:sha(artifact),
    candidate_envelope_sha256:sha(candidateEnvelopeBytes),
    policy_id:'atto-release-policy',policy_sequence:8,
    registry_sha256:sha(registryEnvelopeBytes),ledger_id:'atto-ledger',
    sequence:12,previous_intent_sha256:'1'.repeat(64),nonce:'3'.repeat(64),
    issued_at:'2026-11-07T00:01:00Z',expires_at:timeTo};
  o.intentEdit?.(intent);
  const checkpointEnvelopeBytes=envelope(CHECKPOINT_TYPE,cp,o.checkpointSigner||governance);
  const intentEnvelopeBytes=envelope(INTENT_TYPE,intent,o.intentSigner||approval);
  const ledgerPin={schema:'atto.release-link-pin.v1',
    checkpoint_sha256:sha(checkpointEnvelopeBytes),intent_sha256:sha(intentEnvelopeBytes),
    ledger_id:'atto-ledger',next_sequence:12,previous_intent_sha256:'1'.repeat(64)};
  o.pinEdit?.(ledgerPin);
  return {registryEnvelopeBytes,trustedRootPem:pem(o.trustedRoot||root),
    candidateEnvelopeBytes,artifactBytes:artifact,expected,
    checkpointEnvelopeBytes,intentEnvelopeBytes,ledgerPin,now:o.now||now};
}
const run = o => verifySequenceLinkedCandidate(make(o));
const denied = o => {
  const v=run(o);
  assert.equal(v.classification,'DENIED',JSON.stringify(v));
  assert.equal(v.release_authorized,false);
  assert.equal(v.ledger_cas_committed,false);
  assert.equal(v.authenticated_github,false);
};
test('correctly linked three distinct delegated signatures give NON-AUTHORIZING local candidate',()=>{
  const v=run();
  assert.equal(v.classification,'SEQUENCE_LINKED_LOCAL_CANDIDATE');
  assert.equal(v.sequence,12);
  assert.equal(v.release_authorized,false);
  assert.equal(v.compiler_guest_parity_proven,false);
  assert.equal(v.authenticated_github,false);
  assert.equal(v.ledger_cas_committed,false);
  assert.notEqual(v.candidate_signer_keyid,v.checkpoint_signer_keyid);
  assert.notEqual(v.checkpoint_signer_keyid,v.intent_signer_keyid);
});
const cases = [
 ['wrong root', {trustedRoot:outsider}],
 ['swapped root signing key', {rootSigner:outsider}],
 ['candidate signer outside delegation', {candidateSigner:outsider}],
 ['checkpoint signer outside delegation', {checkpointSigner:outsider}],
 ['intent signer outside delegation', {intentSigner:outsider}],
 ['reused candidate signer for checkpoint', {checkpointSigner:candidate}],
 ['reused candidate signer for intent', {intentSigner:candidate}],
 ['checkpoint role confusion', {policyEdit:p=>p.keys[1].role='build-provenance'}],
 ['approval role confusion', {policyEdit:p=>p.keys[2].role='build-provenance'}],
 ['governance signer revoked now', {policyEdit:p=>p.keys[1].revoked_at='2026-11-07T00:01:00Z'}],
 ['approval signer revoked now', {policyEdit:p=>p.keys[2].revoked_at='2026-11-07T00:01:00Z'}],
 ['candidate signer revoked now', {policyEdit:p=>p.keys[0].revoked_at='2026-11-07T00:01:00Z'}],
 ['approval signer future-valid', {policyEdit:p=>p.keys[2].not_before='2027-01-01T00:00:00Z'}],
 ['policy rollback against floor', {policyEdit:p=>p.sequence=7}],
 ['checkpoint wrong policy generation', {checkpointEdit:c=>c.policy_sequence=7}],
 ['intent wrong policy generation', {intentEdit:i=>i.policy_sequence=7}],
 ['checkpoint policy id changed', {checkpointEdit:c=>c.policy_id='other-policy'}],
 ['checkpoint wrong registry bytes', {checkpointEdit:c=>c.registry_sha256='a'.repeat(64)}],
 ['intent wrong registry bytes', {intentEdit:i=>i.registry_sha256='a'.repeat(64)}],
 ['checkpoint wrong repository', {checkpointEdit:c=>c.repository='ores-truffle-oreslang/other'}],
 ['intent wrong repository', {intentEdit:i=>i.repository='ores-truffle-oreslang/other'}],
 ['different original head', {intentEdit:i=>i.head_sha='f'.repeat(40)}],
 ['different Git tree', {intentEdit:i=>i.tree_sha='f'.repeat(40)}],
 ['different artifact digest', {intentEdit:i=>i.artifact_sha256='f'.repeat(64)}],
 ['different candidate envelope bytes', {intentEdit:i=>i.candidate_envelope_sha256='f'.repeat(64)}],
 ['checkpoint too old', {checkpointEdit:c=>{c.observed_at='2026-11-06T23:40:00Z';c.expires_at='2026-11-07T00:09:00Z';}}],
 ['checkpoint expired', {checkpointEdit:c=>c.expires_at='2026-11-07T00:01:00Z'}],
 ['checkpoint from future', {checkpointEdit:c=>c.observed_at='2026-11-07T00:02:00Z'}],
 ['checkpoint excessive future TTL', {checkpointEdit:c=>c.expires_at='2026-11-07T00:10:00Z'}],
 ['checkpoint invalid calendar date', {checkpointEdit:c=>c.observed_at='2026-02-30T00:00:00Z'}],
 ['intent expired', {intentEdit:i=>i.expires_at='2026-11-07T00:01:20Z'}],
 ['intent not yet issued', {intentEdit:i=>i.issued_at='2026-11-07T00:02:00Z'}],
 ['intent excessive lifetime', {intentEdit:i=>i.expires_at='2026-11-07T00:10:00Z'}],
 ['intent timestamp before checkpoint', {intentEdit:i=>i.issued_at='2026-11-06T23:59:59Z'}],
 ['intent clock invalid calendar date', {intentEdit:i=>i.expires_at='2026-02-30T01:00:00Z'}],
 ['intent repeated checkpoint nonce', {intentEdit:i=>i.nonce='2'.repeat(64)}],
 ['intent zero nonce', {intentEdit:i=>i.nonce=ZERO}],
 ['intent predecessor mismatch', {intentEdit:i=>i.previous_intent_sha256='f'.repeat(64)}],
 ['checkpoint predecessor mismatch', {checkpointEdit:c=>c.last_intent_sha256='f'.repeat(64)}],
 ['next sequence replayed', {intentEdit:i=>i.sequence=11}],
 ['next sequence skipped', {intentEdit:i=>i.sequence=13}],
 ['pinned sequence stale', {pinEdit:p=>p.next_sequence=11}],
 ['pinned digest stale', {pinEdit:p=>p.intent_sha256='f'.repeat(64)}],
 ['pinned checkpoint replaced', {pinEdit:p=>p.checkpoint_sha256='f'.repeat(64)}],
 ['wrong ledger pin', {pinEdit:p=>p.ledger_id='other-ledger'}],
 ['wrong predecessor pin', {pinEdit:p=>p.previous_intent_sha256='f'.repeat(64)}],
 ['malformed ledger pin', {pinEdit:p=>{p.extra=true;}}],
 ['genesis nonzero predecessor', {checkpointEdit:c=>c.last_sequence=0}],
 ['checkpoint unsafe max integer counter', {checkpointEdit:c=>c.last_sequence=Number.MAX_SAFE_INTEGER}],
 ['invalid externally pinned source', {expectedEdit:e=>e.head_sha='f'.repeat(40)}],
 ['invalid clock', {now:'2026-02-30T00:00:00Z'}],
];
for(const [name,options] of cases)test('deny: '+name,()=>denied(options));
test('established signed checkpoint cannot reset predecessor to genesis zero',()=>{
  denied({checkpointEdit:c=>c.last_intent_sha256=ZERO,
    intentEdit:i=>i.previous_intent_sha256=ZERO,
    pinEdit:p=>p.previous_intent_sha256=ZERO});
});
test('established signed checkpoint cannot reset last nonce to genesis zero',()=>{
  denied({checkpointEdit:c=>c.last_nonce=ZERO});
});
test('genesis zero predecessor with seq 1 is valid only as a local candidate',()=>{
  const v=run({checkpointEdit:c=>{c.last_sequence=0;c.last_intent_sha256=ZERO;c.last_nonce=ZERO;},
    intentEdit:i=>{i.sequence=1;i.previous_intent_sha256=ZERO;},
    pinEdit:p=>{p.next_sequence=1;p.previous_intent_sha256=ZERO;}});
  assert.equal(v.classification,'SEQUENCE_LINKED_LOCAL_CANDIDATE');
  assert.equal(v.release_authorized,false);
});
test('checkpoint parser rejects malformed, noncanonical, and oversized bytes',()=>{
  const x=make();
  for(const corrupted of [Buffer.from('not-json'),Buffer.from(' { }'),
    Buffer.alloc(256*1024+1),Buffer.from('')]){
    assert.equal(verifySequenceLinkedCandidate({...x,checkpointEnvelopeBytes:corrupted})
      .classification,'DENIED');
  }
});
test('intent parser rejects mismatching signed body and pinned digest',()=>{
  const x=make();
  const v=JSON.parse(x.intentEnvelopeBytes);
  v.payload=Buffer.from('{}').toString('base64');
  x.intentEnvelopeBytes=Buffer.from(JSON.stringify(v));
  assert.equal(verifySequenceLinkedCandidate(x).classification,'DENIED');
});
test('missing secure ledger pin never promotes a signed candidate',()=>{
  const x=make();
  x.ledgerPin=undefined;
  assert.equal(verifySequenceLinkedCandidate(x).classification,'DENIED');
});
test('standalone CLI uses 3 for local, 1 for rejected chain, 2 for unsafe file',()=>{
  // Build a source-free fixture with validity centered on the actual host clock.
  const t=new Date();
  const whole= d=>new Date(Math.floor(d/1000)*1000).toISOString().replace('.000Z','Z');
  const at=whole(t.getTime()), plus=whole(t.getTime()+120000), earlier=whole(t.getTime()-30000);
  const x=make({now:at,checkpointEdit:c=>{c.observed_at=earlier;c.expires_at=plus;},
    intentEdit:i=>{i.issued_at=earlier;i.expires_at=plus;},
    policyEdit:p=>{p.not_after='2029-01-01T00:00:00Z';}});
  const d=mkdtempSync(join(tmpdir(),'atto-checkpoint-test-'));
  const files=[['--registry','policy.dsse',x.registryEnvelopeBytes],
    ['--root-key','root.pem',x.trustedRootPem],
    ['--candidate','candidate.dsse',x.candidateEnvelopeBytes],
    ['--artifact','artifact.bin',x.artifactBytes],
    ['--expected','expected.json',Buffer.from(JSON.stringify(x.expected))],
    ['--checkpoint','checkpoint.dsse',x.checkpointEnvelopeBytes],
    ['--intent','intent.dsse',x.intentEnvelopeBytes],
    ['--pin','pin.json',Buffer.from(JSON.stringify(x.ledgerPin))]];
  for(const [,name,body] of files)writeFileSync(join(d,name),body);
  const args=files.flatMap(([flag,name])=>[flag,join(d,name)]);
  const script=resolve(import.meta.dirname,'../tools/release-checkpoint-v1/verify.mjs');
  const runCli=ar=>spawnSync(process.execPath,[script,...ar],{encoding:'utf8'});
  const local=runCli(args);
  assert.equal(local.status,3,local.stderr+' '+local.stdout);
  assert.equal(JSON.parse(local.stdout).release_authorized,false);
  writeFileSync(join(d,'pin.json'),JSON.stringify({...x.ledgerPin,next_sequence:13}));
  const rejected=runCli(args);
  assert.equal(rejected.status,1,rejected.stderr);
  assert.equal(JSON.parse(rejected.stdout).ledger_cas_committed,false);
  const link=join(d,'linked');symlinkSync(join(d,'policy.dsse'),link);
  const unsafe=runCli([...args.slice(0,1),link,...args.slice(2)]);
  assert.equal(unsafe.status,2,unsafe.stderr);
  const hard=join(d,'hard');linkSync(join(d,'policy.dsse'),hard);
  const unsafeHard=runCli([...args.slice(0,1),hard,...args.slice(2)]);
  assert.equal(unsafeHard.status,2,unsafeHard.stderr);
});


// Phase 2: delegated signing authority must remain valid for the *entire*
// asserted evidence window, not merely at the verifier's current instant.
// Each of the following was previously accepted as a local candidate.
const lifetimeRegressions = [
  ['checkpoint outlives governance signing delegation',
    {policyEdit:p=>p.keys[1].not_after='2026-11-07T00:02:00Z'}],
  ['intent outlives release-approval delegation',
    {policyEdit:p=>p.keys[2].not_after='2026-11-07T00:02:00Z'}],
  ['intent outlives candidate signing delegation',
    {policyEdit:p=>p.keys[0].not_after='2026-11-07T00:02:00Z'}],
  ['checkpoint outlives scheduled governance revocation',
    {policyEdit:p=>p.keys[1].revoked_at='2026-11-07T00:02:00Z'}],
  ['intent outlives scheduled release-approval revocation',
    {policyEdit:p=>p.keys[2].revoked_at='2026-11-07T00:02:00Z'}],
  ['intent outlives scheduled candidate-signer revocation',
    {policyEdit:p=>p.keys[0].revoked_at='2026-11-07T00:02:00Z'}],
  ['intent outlives governance checkpoint',
    {checkpointEdit:c=>c.expires_at='2026-11-07T00:02:00Z'}],
  ['checkpoint and intent outlive root-signed registry',
    {policyEdit:p=>{
      p.not_after='2026-11-07T00:02:00Z';
      for(const k of p.keys)k.not_after='2026-11-07T00:02:00Z';
    }}],
];
for(const [name, options] of lifetimeRegressions)
  test('deny lifetime boundary: '+name,()=>denied(options));

test('allowed exclusive expiry equality: checkpoint and intent finish with delegations',()=>{
  const v=run({policyEdit:p=>{
    for(const k of p.keys)k.not_after='2026-11-07T00:04:00Z';
  },checkpointEdit:c=>c.expires_at='2026-11-07T00:04:00Z'});
  assert.equal(v.classification,'SEQUENCE_LINKED_LOCAL_CANDIDATE',JSON.stringify(v));
  assert.equal(v.release_authorized,false);
  assert.equal(v.ledger_cas_committed,false);
});

test('allowed exclusive revocation equality at the end of checkpoint and intent',()=>{
  const v=run({policyEdit:p=>{
    for(const k of p.keys)k.revoked_at='2026-11-07T00:04:00Z';
  },checkpointEdit:c=>c.expires_at='2026-11-07T00:04:00Z'});
  assert.equal(v.classification,'SEQUENCE_LINKED_LOCAL_CANDIDATE',JSON.stringify(v));
  assert.equal(v.release_authorized,false);
});

for(const field of ['schema','repository','policy_id','policy_sequence',
 'registry_sha256','ledger_id','last_sequence','last_intent_sha256',
 'last_nonce','observed_at','expires_at']) {
  test('missing signed checkpoint field: '+field,()=>denied({
    checkpointEdit:c=>{delete c[field];}
  }));
}
for(const field of ['schema','repository','head_sha','tree_sha',
 'artifact_sha256','candidate_envelope_sha256','policy_id','policy_sequence',
 'registry_sha256','ledger_id','sequence','previous_intent_sha256',
 'nonce','issued_at','expires_at']) {
  test('missing signed intent field: '+field,()=>denied({
    intentEdit:i=>{delete i[field];}
  }));
}
for(const field of ['schema','checkpoint_sha256','intent_sha256','ledger_id',
 'next_sequence','previous_intent_sha256']) {
  test('missing externally pinned ledger field: '+field,()=>denied({
    pinEdit:p=>{delete p[field];}
  }));
}


// Two different, validly signed intents for the same checkpoint can both
// pass *local* evaluation. Neither can consume that high-water state.
// Only an independently authenticated, linearizable CAS can choose a winner.
test('parallel fork: same checkpoint and sequence cannot claim a ledger commit',()=>{
  const a=make();
  const b=make({intentEdit:i=>i.nonce='4'.repeat(64)});
  assert.equal(sha(a.checkpointEnvelopeBytes),sha(b.checkpointEnvelopeBytes));
  assert.notEqual(sha(a.intentEnvelopeBytes),sha(b.intentEnvelopeBytes));
  for(const fixture of [a,b]){
    const v=verifySequenceLinkedCandidate(fixture);
    assert.equal(v.classification,'SEQUENCE_LINKED_LOCAL_CANDIDATE');
    assert.equal(v.sequence,12);
    assert.equal(v.release_authorized,false);
    assert.equal(v.ledger_cas_committed,false);
    assert.equal(v.authenticated_github,false);
  }
});

// Each mutation deliberately re-pins the *changed* bytes to ensure it is
// rejected by envelope admission/signature verification, not merely because
// the outer envelope digest was different from the externally supplied pin.
const signedEnvelopeMutations=[
  ['missing payload type',e=>{delete e.payloadType;}],
  ['wrong DSSE domain',e=>{e.payloadType='application/vnd.other+json';}],
  ['missing payload',e=>{delete e.payload;}],
  ['noncanonical base64 payload',e=>{e.payload='Zg=';}],
  ['invalid JSON payload',e=>{e.payload=Buffer.from('{').toString('base64');}],
  ['missing signature array',e=>{delete e.signatures;}],
  ['empty signature array',e=>{e.signatures=[];}],
  ['multiple signatures',e=>{e.signatures.push({...e.signatures[0]});}],
  ['extra envelope key',e=>{e.extra='untrusted';}],
  ['unknown signing keyid',e=>{e.signatures[0].keyid=id(outsider);}],
  ['zeroed signature bytes',e=>{e.signatures[0].sig=Buffer.alloc(64).toString('base64');}],
  ['noncanonical signature base64',e=>{e.signatures[0].sig='AA=';}],
  ['missing signature field',e=>{delete e.signatures[0].sig;}],
  ['altered signed payload',e=>{e.payload=Buffer.from('{}').toString('base64');}],
  ['uppercase keyid alias',e=>{e.signatures[0].keyid=e.signatures[0].keyid.toUpperCase();}],
];
for(const [side,field,pinField] of [
 ['checkpoint','checkpointEnvelopeBytes','checkpoint_sha256'],
 ['intent','intentEnvelopeBytes','intent_sha256']
]){
  for(const [name,mutate] of signedEnvelopeMutations){
    test('deny signed '+side+' DSSE: '+name,()=>{
      const v=make(),env=JSON.parse(v[field]);
      mutate(env);
      v[field]=Buffer.from(JSON.stringify(env));
      v.ledgerPin[pinField]=sha(v[field]);
      const verdict=verifySequenceLinkedCandidate(v);
      assert.equal(verdict.classification,'DENIED',JSON.stringify(verdict));
      assert.equal(verdict.release_authorized,false);
      assert.equal(verdict.ledger_cas_committed,false);
    });
  }
}
