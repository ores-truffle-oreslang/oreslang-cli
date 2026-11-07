import test from 'node:test';
import assert from 'node:assert/strict';
import {pinOperatorEvidence,verifySignedServiceRequest,
  consumeVerifiedSignedServiceRequest} from '../tools/release-ledger-service-v2/signed-claim.mjs';
import {signV2DiagnosticRequest,verifyV2DiagnosticAuth,
  createSignedDiagnosticHttpService} from '../tools/release-ledger-service-v2/http.mjs';
import {makeFixture,keys,NOW} from './fixtures/release-ledger-service-v2-signed.mjs';
const SECRET='ab'.repeat(32),CLIENT='signed-client',T=Math.floor(Date.parse(NOW)/1000);
const fixture=makeFixture({ledgerId:'atto-unit-signed-v2'});
const pinned=pinOperatorEvidence(fixture.operatorPin);
const run=(body=fixture.body,operatorPin=pinned,now=NOW)=>
  verifySignedServiceRequest({body,operatorPin,now});
function denied(v){
  assert.equal(v.classification,'DENIED',JSON.stringify(v));
  assert.equal(v.release_authorized,false);
  assert.equal(v.authenticated_github,false);
  assert.equal(v.compiler_guest_parity_proven,false);
  assert.equal(v.ledger_cas_committed,false);
}
test('valid role-separated DSSE chain is only a local candidate',()=>{
  const v=run();assert.equal(v.classification,'SIGNED_LOCAL_DIAGNOSTIC_CANDIDATE',JSON.stringify(v));
  assert.equal(v.ledger_cas_committed,false);assert.equal(v.release_authorized,false);
  assert.equal(v.claim.sequence,1);assert.equal(v.claim.policy_sequence,8);
});
test('server-held pins are immutable snapshots',()=>{
  const q=structuredClone(fixture.operatorPin),v=pinOperatorEvidence(q);
  q.expected.head_sha='f'.repeat(40);q.ledgerPin.intent_sha256='f'.repeat(64);
  assert.equal(run(fixture.body,v).classification,'SIGNED_LOCAL_DIAGNOSTIC_CANDIDATE');
});
test('mutable caller policy and extra authority flags rejected',()=>{
  denied(run(fixture.body,fixture.operatorPin));
  assert.throws(()=>pinOperatorEvidence({...fixture.operatorPin,release_authorized:true}));
});
for(const field of Object.keys(fixture.operatorPin)){
  test('missing trusted operator field '+field,()=>{
    const q=structuredClone(fixture.operatorPin);delete q[field];
    assert.throws(()=>pinOperatorEvidence(q));
  });
}
for(const field of Object.keys(fixture.operatorPin.expected)){
  test('missing expected pin '+field,()=>{
    const q=structuredClone(fixture.operatorPin);delete q.expected[field];
    assert.throws(()=>pinOperatorEvidence(q));
  });
}
for(const field of Object.keys(fixture.operatorPin.ledgerPin)){
  test('missing signed checkpoint pin '+field,()=>{
    const q=structuredClone(fixture.operatorPin);delete q.ledgerPin[field];
    assert.throws(()=>pinOperatorEvidence(q));
  });
}
for(const field of Object.keys(fixture.body)){
  test('missing signed request field '+field,()=>{
    const q={...fixture.body};delete q[field];denied(run(q));
  });
  test('extraneous authority field with '+field,()=>denied(run({
    ...fixture.body,authority:'publish'
  })));
}
for(const [i,id] of [null,1,{},[],true,'','a','A'.repeat(64),
  'a'.repeat(63),'a'.repeat(65),'z'.repeat(64)].entries()){
  test('invalid request id '+i,()=>denied(run({...fixture.body,client_request_id:id})));
}
// Over 110 independently asserted hostile signed-byte mutations, pinned to
// original external hashes. Client MAC may be regenerated but cannot promote.
for(const [name,field] of [
  ['registry','registry_b64'],['candidate','candidate_b64'],
  ['checkpoint','checkpoint_b64'],['intent','intent_b64'],
  ['artifact','artifact_b64']
]){
  for(let i=0;i<24;i++){
    test('reject tampered signed '+name+' byte index '+i,()=>{
      const raw=Buffer.from(fixture.body[field],'base64');
      raw[Math.floor(i*(raw.length-1)/23)]^=(i%3)+1;
      denied(run({...fixture.body,[field]:raw.toString('base64')}));
    });
  }
}
for(const field of ['registry_b64','candidate_b64','checkpoint_b64',
  'intent_b64','artifact_b64']){
  for(const [name,value] of [
    ['empty',''],['invalid-padding','Zg='],['no-padding','Zg'],
    ['url-encoding','___'],['space',' YWJj'],['unicode','😀'],
    ['number',42],['null',null],['array',[]],['oversize','A'.repeat(65540)]
  ]){
    test('reject malformed '+field+' '+name,()=>{
      denied(run({...fixture.body,[field]:value}));
    });
  }
}
// Signed/re-pinned self-consistent attacks prove semantics, not just mismatch
// against stale digest pins.
const attacks=[
 ['wrong root',{rootOverride:keys.outsider}],
 ['root policy signer',{registrySigner:keys.outsider}],
 ['candidate signer',{candidateSigner:keys.outsider}],
 ['checkpoint signer',{checkpointSigner:keys.outsider}],
 ['intent signer',{intentSigner:keys.outsider}],
 ['candidate as checkpoint',{checkpointSigner:keys.candidate}],
 ['approval as checkpoint',{checkpointSigner:keys.approval}],
 ['governance as intent',{intentSigner:keys.governance}],
 ['candidate as approval',{intentSigner:keys.candidate}],
 ['candidate delegation role',{policyMutate:p=>p.keys[0].role='release-approval'}],
 ['checkpoint delegation role',{policyMutate:p=>p.keys[1].role='candidate-signing'}],
 ['approval delegation role',{policyMutate:p=>p.keys[2].role='governance-review'}],
 ['candidate delegation repo',{policyMutate:p=>p.keys[0].repository='ores-truffle-oreslang/other'}],
 ['checkpoint delegation repo',{policyMutate:p=>p.keys[1].repository='ores-truffle-oreslang/other'}],
 ['approval delegation repo',{policyMutate:p=>p.keys[2].repository='ores-truffle-oreslang/other'}],
 ['candidate revoked',{policyMutate:p=>p.keys[0].revoked_at='2026-11-07T00:01:00Z'}],
 ['checkpoint revoked',{policyMutate:p=>p.keys[1].revoked_at='2026-11-07T00:01:00Z'}],
 ['approval revoked',{policyMutate:p=>p.keys[2].revoked_at='2026-11-07T00:01:00Z'}],
 ['candidate expiry',{policyMutate:p=>p.keys[0].not_after='2026-11-07T00:02:00Z'}],
 ['checkpoint expiry',{policyMutate:p=>p.keys[1].not_after='2026-11-07T00:02:00Z'}],
 ['approval expiry',{policyMutate:p=>p.keys[2].not_after='2026-11-07T00:02:00Z'}],
 ['root policy future',{policyMutate:p=>p.not_before='2026-11-08T00:00:00Z'}],
 ['root policy expired',{policyMutate:p=>p.not_after='2026-11-06T00:00:00Z'}],
 ['root policy rollback',{policyMutate:p=>p.sequence=7}],
 ['root policy id',{policyMutate:p=>p.policy_id='other-policy'}],
 ['checkpoint ledger',{checkpointMutate:p=>p.ledger_id='another-ledger'}],
 ['checkpoint repository',{checkpointMutate:p=>p.repository='ores-truffle-oreslang/other'}],
 ['checkpoint future',{checkpointMutate:p=>p.observed_at='2026-11-07T01:00:00Z'}],
 ['checkpoint expired',{checkpointMutate:p=>p.expires_at='2026-11-07T00:00:00Z'}],
 ['checkpoint sequence',{checkpointMutate:p=>p.last_sequence=-1}],
 ['checkpoint nonce',{checkpointMutate:p=>p.last_nonce='1'.repeat(64)}],
 ['checkpoint predecessor',{checkpointMutate:p=>p.last_intent_sha256='1'.repeat(64)}],
 ['intent head',{intentMutate:p=>p.head_sha='f'.repeat(40)}],
 ['intent tree',{intentMutate:p=>p.tree_sha='f'.repeat(40)}],
 ['intent artifact',{intentMutate:p=>p.artifact_sha256='f'.repeat(64)}],
 ['intent candidate digest',{intentMutate:p=>p.candidate_envelope_sha256='f'.repeat(64)}],
 ['intent registry digest',{intentMutate:p=>p.registry_sha256='f'.repeat(64)}],
 ['intent policy',{intentMutate:p=>p.policy_sequence=9}],
 ['intent nonce',{intentMutate:p=>p.nonce='0'.repeat(64)}],
 ['intent predecessor',{intentMutate:p=>p.previous_intent_sha256='a'.repeat(64)}],
 ['intent expired',{intentMutate:p=>p.expires_at='2026-11-07T00:01:00Z'}],
 ['intent future',{intentMutate:p=>p.issued_at='2026-11-07T00:02:00Z'}],
 ['intent outlives checkpoint',{intentMutate:p=>p.expires_at='2026-11-07T00:05:00Z'}],
 ['manifest head',{manifestMutate:m=>m.subject.head_sha='f'.repeat(40)}],
 ['manifest tree',{manifestMutate:m=>m.subject.tree_sha='f'.repeat(40)}],
 ['manifest review',{manifestMutate:m=>m.reviews[0].state='COMMENTED'}],
 ['manifest failed CI',{manifestMutate:m=>m.workflow.conclusion='failure'}],
 ['manifest zero steps',{manifestMutate:m=>m.workflow.steps=[]}],
 ['manifest host-only guest',{manifestMutate:m=>m.backends[0].classification='HOST_ONLY'}],
 ['manifest missing backend',{manifestMutate:m=>m.backends.pop()}],
 ['manifest unprotected main',{manifestMutate:m=>m.governance.protected_main=false}],
 ['expected head',{expectedMutate:e=>e.head_sha='f'.repeat(40)}],
 ['expected signer digest',{expectedMutate:e=>e.envelope_sha256='f'.repeat(64)}],
 ['expected root',{expectedMutate:e=>e.root_keyid='f'.repeat(64)}],
 ['pinned intent',{pinMutate:p=>p.intent_sha256='f'.repeat(64)}],
 ['pinned checkpoint',{pinMutate:p=>p.checkpoint_sha256='f'.repeat(64)}],
 ['pinned next sequence',{pinMutate:p=>p.next_sequence=2}],
 ['pinned predecessor',{pinMutate:p=>p.previous_intent_sha256='f'.repeat(64)}],
 ['clock late',{now:'2026-11-07T00:05:00Z'}],
 ['clock too early',{now:'2026-11-07T00:00:00Z'}],
 ['impossible date',{now:'2026-02-30T00:00:00Z'}]
];
for(const [name,options] of attacks){
  test('reject re-signed hostile semantic '+name,()=>{
    const f=makeFixture(options);
    denied(verifySignedServiceRequest({
      body:f.body,operatorPin:pinOperatorEvidence(f.operatorPin),now:f.now
    }));
  });
}
test('invalid signed evidence is rejected before any database access',async()=>{
  const pool={connect:async()=>{throw Error('UNREACHABLE')},
    query:async()=>{throw Error('UNREACHABLE')}};
  denied(await consumeVerifiedSignedServiceRequest({
    pool,client:CLIENT,authNonce:'f'.repeat(64),bodyDigest:'a'.repeat(64),
    body:{...fixture.body,release_authorized:true},
    operatorPin:pinned,now:NOW
  }));
});
const sign=(body=fixture.body,extras={})=>signV2DiagnosticRequest({
  secret:SECRET,client:CLIENT,body,timestamp:T,nonce:'4'.repeat(64),...extras
});
const auth=(v,extras={})=>verifyV2DiagnosticAuth({
  secret:SECRET,expectedClient:CLIENT,method:v.method,path:v.path,
  rawHeaders:Object.entries(v.headers).flatMap(([k,x])=>[k,x]),
  rawBody:v.body,nowSeconds:T,...extras
});
test('v2 domain HMAC authenticates exactly canonical signed material',()=>{
  assert.equal(auth(sign()).ok,true);
});
for(const [name,change] of [
 ['wrong secret',{secret:'cd'.repeat(32)}],
 ['wrong client',{expectedClient:'other-client'}],
 ['wrong method',{method:'GET'}],['wrong route',{path:'/v2/receipt'}],
 ['old clock',{nowSeconds:T-31}],['future clock',{nowSeconds:T+31}],
 ['no headers',{rawHeaders:[]}],['wrong body',{rawBody:Buffer.from('{}')}]
]){
  test('reject v2 HMAC attack '+name,()=>assert.equal(auth(sign(),change).ok,false));
}
for(const key of ['x-atto-client','x-atto-time','x-atto-nonce','x-atto-mac']){
  test('reject missing v2 HMAC header '+key,()=>{
    const q=sign();delete q.headers[key];assert.equal(auth(q).ok,false);
  });
  test('reject duplicate v2 HMAC header '+key,()=>{
    const q=sign(),headers=Object.entries(q.headers).flatMap(([k,x])=>[k,x]);
    headers.push(key.toUpperCase(),q.headers[key]);
    assert.equal(auth(q,{rawHeaders:headers}).ok,false);
  });
}
test('signed v2 diagnostic server health cannot authorize releases',async()=>{
  const pool={connect:async()=>{throw Error('NO_DB')},query:async()=>{throw Error('NO_DB')}};
  const srv=createSignedDiagnosticHttpService({
    pool,secret:SECRET,expectedClient:CLIENT,operatorPin:fixture.operatorPin,
    nowSeconds:()=>T,nowUtc:()=>NOW
  });
  await new Promise(resolve=>srv.listen(0,'127.0.0.1',resolve));
  try{
    const response=await fetch('http://127.0.0.1:'+srv.address().port+'/healthz');
    const body=await response.json();
    assert.equal(response.status,200);
    assert.equal(body.release_authorized,false);
    assert.equal(body.release_publisher_enabled,false);
  }finally{await new Promise(resolve=>srv.close(resolve));}
});
