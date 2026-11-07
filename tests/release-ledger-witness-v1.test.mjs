import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {signWitnessReceipt,verifyWitnessReceipt} from '../tools/release-ledger-witness-v1/receipt.mjs';
import {runWitnessedSignedClaim,reconcileWitnessPending,
  digestSignedRequest} from '../tools/release-ledger-witness-v1/coordinator.mjs';
import {pinOperatorEvidence,verifySignedServiceRequest} from '../tools/release-ledger-service-v2/signed-claim.mjs';
import {makeFixture,REPO,NOW,ZERO} from './fixtures/release-ledger-service-v2-signed.mjs';
const original=makeFixture({ledgerId:'atto-witness-unit-first'});
const signed=verifySignedServiceRequest({
  body:original.body,operatorPin:pinOperatorEvidence(original.operatorPin),now:NOW});
assert.equal(signed.classification,'SIGNED_LOCAL_DIAGNOSTIC_CANDIDATE');
const key=generateKeyPairSync('ed25519'),rogue=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const fields={
  ledger_id:original.ledgerId,repository:REPO,sequence:1,generation:1,
  policy_sequence:8,intent_sha256:signed.claim.intent_sha256,
  nonce:signed.claim.nonce,reservation_id:'f'.repeat(64)
};
const denied=v=>{
  assert.equal(v.release_authorized,false,JSON.stringify(v));
  assert.equal(v.authenticated_github,false);
  assert.equal(v.compiler_guest_parity_proven,false);
  assert.equal(v.classification,'DENIED',JSON.stringify(v));
};
test('actual Ed25519 witness signature validates for exact independent pubkey',()=>{
  const r=signWitnessReceipt(fields,key.privateKey);
  const v=verifyWitnessReceipt(r,pem(key),fields);
  assert.equal(v.classification,'WITNESS_SIGNATURE_VERIFIED_NOT_AUTHORIZING',JSON.stringify(v));
  assert.equal(v.release_authorized,false);
});
test('wrong trust principal cannot verify actual witness receipt',()=>{
  denied(verifyWitnessReceipt(signWitnessReceipt(fields,key.privateKey),pem(rogue),fields));
});
test('signer has no release permission even for completed witness record',()=>{
  const v=verifyWitnessReceipt(signWitnessReceipt(fields,key.privateKey),pem(key),fields);
  assert.equal(v.witness_finalized,true);assert.equal(v.ledger_cas_committed,false);
  assert.equal(v.release_authorized,false);
});
for(const k of Object.keys(fields)){
  test('missing witness attestation field '+k+' fails signed issue',()=>{
    const q={...fields};delete q[k];
    assert.throws(()=>signWitnessReceipt(q,key.privateKey));
  });
  test('unexpected witness attestation field alongside '+k,()=>{
    assert.throws(()=>signWitnessReceipt({...fields,extra:'publish'},key.privateKey));
  });
}
for(const [name,value] of [
  ['null',null],['negative',-1],['fraction',1.2],
  ['string','1'],['zero',0],['huge',Number.MAX_SAFE_INTEGER]
]){
  for(const k of ['sequence','generation','policy_sequence']){
    test('invalid '+k+' '+name+' witness receipt refuses signing',()=>{
      assert.throws(()=>signWitnessReceipt({...fields,[k]:value},key.privateKey));
    });
  }
}
for(const [name,keyName,value] of [
  ['repository pivot','repository','ores-truffle-oreslang/other'],
  ['ledger pivot','ledger_id','atto-another'],
  ['digest pivot','intent_sha256','a'.repeat(64)],
  ['nonce pivot','nonce','a'.repeat(64)],
  ['reservation pivot','reservation_id','a'.repeat(64)],
  ['policy generation pivot','policy_sequence',9],
  ['sequence pivot','sequence',2]
]){
  test('signed receipt cannot validate modified expected '+name,()=>{
    const receipt=signWitnessReceipt(fields,key.privateKey);
    denied(verifyWitnessReceipt(receipt,pem(key),{...fields,[keyName]:value}));
  });
}
for(const [i,v] of [
  '',null,'a','a'.repeat(63),'g'.repeat(64),42,{},[],
  'A'.repeat(64),true
].entries()){
  test('invalid receipt-intent hash type/length '+i+' rejected',()=>{
    assert.throws(()=>signWitnessReceipt({...fields,intent_sha256:v},key.privateKey));
  });
}
const receipt=signWitnessReceipt(fields,key.privateKey);
for(const k of ['payload','signature','keyid']){
  test('receipt missing '+k+' rejected',()=>{
    const q={...receipt};delete q[k];
    denied(verifyWitnessReceipt(q,pem(key),fields));
  });
  test('receipt extra field with '+k+' rejected',()=>denied(verifyWitnessReceipt({
    ...receipt,authorization:true
  },pem(key),fields)));
}
for(let i=0;i<100;i++){
  test('Ed25519 receipt signature tamper at position '+i+' rejected',()=>{
    const raw=Buffer.from(receipt.signature,'base64');
    raw[i%raw.length]^=(i%7)+1;
    const q={...receipt,signature:raw.toString('base64')};
    denied(verifyWitnessReceipt(q,pem(key),fields));
  });
}
for(let i=0;i<40;i++){
  test('witness canonical payload tampering index '+i+' rejected',()=>{
    const value=receipt.payload;
    const at=i%value.length;
    const next=value.slice(0,at)+(value[at]==='x'?'y':'x')+value.slice(at+1);
    denied(verifyWitnessReceipt({...receipt,payload:next},pem(key),fields));
  });
}
test('signed service request digest canonical, deterministic and order-independent',()=>{
  assert.equal(digestSignedRequest(original.body),
    digestSignedRequest(Object.fromEntries(Object.entries(original.body).reverse())));
});
const goodPrimary={
  ledger_id:original.ledgerId,repository:REPO,sequence:0,policy_sequence:0,
  last_intent_sha256:ZERO,last_nonce:ZERO
};
const goodWitness={
  classification:'WITNESS_SNAPSHOT',release_authorized:false,
  authenticated_github:false,compiler_guest_parity_proven:false,
  ledger_cas_committed:false,witness_finalized:false,
  ...goodPrimary,generation:0,pending:null
};
const expectedPrimary=()=>({rows:[{...goodPrimary}]});
const fakePool={query:async()=>expectedPrimary()};
const operatorPin=pinOperatorEvidence(original.operatorPin);
const params={primaryPool:fakePool,witnessPublicPem:pem(key),
  operatorPin,body:original.body,now:NOW,
  client:'unit-client',authNonce:'d'.repeat(64),
  bodyDigest:digestSignedRequest(original.body)};
const refusal=async(witness,primaryPool=fakePool,body=original.body)=>{
  const v=await runWitnessedSignedClaim({...params,
    witness,primaryPool,body});
  assert.equal(v.release_authorized,false);
  assert.equal(v.ledger_cas_committed,null);
  assert.equal(v.classification,'WITNESS_COORDINATION_UNVERIFIED');
};
for(let i=0;i<120;i++){
  test('wrong witness state/epoch sample '+i+' blocks before reservation',async()=>{
    const varied={...goodWitness};
    if(i%6===0)varied.generation=i+1;
    else if(i%6===1)varied.sequence=i+1;
    else if(i%6===2)varied.last_intent_sha256=i.toString(16).padStart(64,'1');
    else if(i%6===3)varied.last_nonce=i.toString(16).padStart(64,'1');
    else if(i%6===4)varied.repository='ores-truffle-oreslang/other';
    else varied.pending={reservation_id:'a'.repeat(64)};
    await refusal({
      read:async()=>varied,
      reserve:async()=>{throw Error('MUST_NOT_RESERVE')},
      finalize:async()=>{throw Error('MUST_NOT_FINALIZE')}
    });
  });
}
for(let i=0;i<100;i++){
  test('primary rollback / mismatch sample '+i+' prevents witness reservation',async()=>{
    const changed={...goodPrimary};
    if(i%5===0)changed.sequence=i+1;
    else if(i%5===1)changed.last_intent_sha256=i.toString(16).padStart(64,'2');
    else if(i%5===2)changed.last_nonce=i.toString(16).padStart(64,'2');
    else if(i%5===3)changed.repository='ores-truffle-oreslang/other';
    else changed.policy_sequence=9+i;
    await refusal({
      read:async()=>({...goodWitness}),
      reserve:async()=>{throw Error('MUST_NOT_RESERVE')},
      finalize:async()=>{throw Error('MUST_NOT_FINALIZE')}
    },{query:async()=>({rows:[changed]})});
  });
}
for(const [i,s] of [
  'witness-unreachable','network-partition','primary-timeout',
  'lost-reservation-ack','worker-cancelled','reservation-persisted',
  'process-killed','connection-broken','unavailable-operator',
  'worker-restarted','control-lease-expired','witness-primary-disagree'
].entries()){
  test('crash after witness reserve '+i+' retains reconciliation obligation',async()=>{
    let wrote=false;
    const witness={
      read:async()=>({...goodWitness}),
      reserve:async()=>({classification:'WITNESS_RESERVED',
        generation:1,reservation_id:'f'.repeat(64)}),
      finalize:async()=>{wrote=true;throw Error('NO_FINALIZE');}
    };
    const v=await runWitnessedSignedClaim({...params,witness,
      afterReservation:()=>{throw Error(s);}});
    assert.equal(v.classification,'WITNESS_COORDINATION_UNVERIFIED');
    assert.equal(v.requires_manual_reconciliation,true);
    assert.equal(v.release_authorized,false);
    assert.equal(wrote,false);
  });
}
test('invalid DSSE is rejected before witness access',async()=>{
  const witness={read:async()=>{throw Error('MUST_NOT_READ_WITNESS')},
    reserve:async()=>{throw Error('NO')},finalize:async()=>{throw Error('NO')}};
  const v=await runWitnessedSignedClaim({...params,witness,
    body:{...original.body,registry_b64:'ZmFrZQ=='}});
  denied(v);
});
test('manual reconciliation never accepts fabricated finalized witness',async()=>{
  const v=await reconcileWitnessPending({
    witness:{read:async()=>({...goodWitness}),finalize:async()=>({})},
    claim:signed.claim,reservationId:'f'.repeat(64),witnessPublicPem:pem(key)
  });
  assert.equal(v.classification,'WITNESS_COORDINATION_UNVERIFIED');
  assert.equal(v.release_authorized,false);
});
