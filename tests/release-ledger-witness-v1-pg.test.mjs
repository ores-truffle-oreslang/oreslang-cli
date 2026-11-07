import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,randomBytes} from 'node:crypto';
import {createPgPool,installForIsolatedTests,bootstrapPg,readPgState,
  commitPgClaim} from '../tools/release-ledger-service-v1/postgres.mjs';
import {installWitnessForIsolatedTests,bootstrapWitness,readWitness,
  reserveWitness,finalizeWitness} from '../tools/release-ledger-witness-v1/witness.mjs';
import {primaryEventCommitted} from '../tools/release-ledger-witness-v1/primary-evidence.mjs';
import {signPersistedWitnessReceipt,verifyWitnessReceipt} from '../tools/release-ledger-witness-v1/receipt.mjs';
import {createIsolatedTestWitnessOperator,runWitnessedSignedClaim,
  reconcileWitnessPending,digestSignedRequest} from '../tools/release-ledger-witness-v1/coordinator.mjs';
import {pinOperatorEvidence,verifySignedServiceRequest
} from '../tools/release-ledger-service-v2/signed-claim.mjs';
import {makeFixture,REPO,NOW,ZERO,keys} from './fixtures/release-ledger-service-v2-signed.mjs';
const P=process.env.ATTO_LEDGER_TEST_PG_URL, W=process.env.ATTO_WITNESS_TEST_PG_URL;
if(!P||!W||P===W)throw Error('TWO_SEPARATE_TEST_DATABASE_URLS_REQUIRED');
let primary,witnessDB,readOnlyPrimary,operator;
const signing=generateKeyPairSync('ed25519'),pub=signing.publicKey.export({format:'pem',type:'spki'});
const nonce=()=>randomBytes(32).toString('hex');
const isDenied=x=>{assert.equal(x.classification,'DENIED',JSON.stringify(x));
  assert.equal(x.release_authorized,false);};
const isUnknown=x=>{assert.equal(x.classification,'WITNESS_COORDINATION_UNVERIFIED',
  JSON.stringify(x));assert.equal(x.ledger_cas_committed,null);
  assert.equal(x.release_authorized,false);
  assert.equal(x.requires_manual_reconciliation,true);};
before(async()=>{
  primary=await createPgPool({connectionString:P,max:35,connectionTimeoutMillis:5000});
  readOnlyPrimary=await createPgPool({connectionString:P,max:12,connectionTimeoutMillis:5000});
  witnessDB=await createPgPool({connectionString:W,max:35,connectionTimeoutMillis:5000});
  await Promise.all([primary.query('SELECT 1'),witnessDB.query('SELECT 1')]);
  await installForIsolatedTests(primary);
  await installWitnessForIsolatedTests(witnessDB);
  operator=createIsolatedTestWitnessOperator({witnessPool:witnessDB,
    primaryReadPool:readOnlyPrimary,privateSigningKey:signing.privateKey});
});
after(async()=>{await Promise.all([primary,readOnlyPrimary,witnessDB].filter(Boolean).map(p=>p.end()));});
const setup=async f=>{
  const scope={ledger_id:f.ledgerId,repository:REPO};
  assert.equal((await bootstrapPg(primary,scope)).classification,'PG_BOOTSTRAP_CONFIRMED');
  assert.equal((await bootstrapWitness(witnessDB,scope)).classification,'WITNESS_BOOTSTRAP_CONFIRMED');
};
const claim=f=>verifySignedServiceRequest({body:f.body,
  operatorPin:pinOperatorEvidence(f.operatorPin),now:f.now}).claim;
const call=(f,overrides={})=>runWitnessedSignedClaim({
  primaryPool:primary,witness:operator,
  operatorPin:pinOperatorEvidence(f.operatorPin),
  witnessPublicPem:pub,body:f.body,now:f.now,
  client:'witness-test-client',authNonce:nonce(),
  bodyDigest:digestSignedRequest(f.body),...overrides
});
const readW=async id=>{
  const x=await readWitness(witnessDB,id);
  assert.equal(x.classification,'WITNESS_SNAPSHOT',JSON.stringify(x));return x;
};
const readP=async id=>{
  const x=await readPgState(primary,id);
  assert.equal(x.classification,'PG_LEDGER_SNAPSHOT',JSON.stringify(x));return x;
};
test('separate witness and primary bootstrap start genesis and never publish',async()=>{
  const f=makeFixture();await setup(f);
  const w=await readW(f.ledgerId),p=await readP(f.ledgerId);
  assert.equal(w.pending,null);assert.equal(w.generation,0);assert.equal(p.sequence,0);
  assert.equal(w.release_authorized,false);
});
test('witness bootstrap refuses repository pivot',async()=>{
  const f=makeFixture();await setup(f);
  isDenied(await bootstrapWitness(witnessDB,{
    ledger_id:f.ledgerId,repository:'ores-truffle-oreslang/other'}));
});
test('repeat witness bootstrap never deletes pending reservation',async()=>{
  const f=makeFixture();await setup(f);
  const res=await reserveWitness(witnessDB,{claim:claim(f),expectedGeneration:0});
  assert.equal(res.classification,'WITNESS_RESERVED');
  await bootstrapWitness(witnessDB,{ledger_id:f.ledgerId,repository:REPO});
  assert.equal((await readW(f.ledgerId)).pending.reservation_id,res.reservation_id);
});
test('signed DSSE witness→primary→witness complete emits independent signed receipt',async()=>{
  const f=makeFixture();await setup(f);
  const v=await call(f);
  assert.equal(v.classification,'WITNESSED_DIAGNOSTIC_CAS',JSON.stringify(v));
  assert.equal(v.ledger_cas_committed,true);
  assert.equal(v.witness_finalized,true);assert.equal(v.release_authorized,false);
  const w=await readW(f.ledgerId);
  assert.equal(w.sequence,1);assert.equal(w.generation,1);assert.equal(w.pending,null);
  assert.equal((await readP(f.ledgerId)).sequence,1);
  const persisted=await signPersistedWitnessReceipt(witnessDB,{
    ledgerId:f.ledgerId,sequence:1,privateKey:signing.privateKey});
  assert.equal(persisted.classification,'PERSISTED_WITNESS_SIGNED_RECEIPT');
  assert.equal(verifyWitnessReceipt(v.witness_receipt,pub,persisted.fields).classification,
    'WITNESS_SIGNATURE_VERIFIED_NOT_AUTHORIZING');
});
test('same signed intent replay after witnessed finalization is quarantined',async()=>{
  const f=makeFixture();await setup(f);
  assert.equal((await call(f)).classification,'WITNESSED_DIAGNOSTIC_CAS');
  isUnknown(await call(f));assert.equal((await readW(f.ledgerId)).sequence,1);
});
test('unbootstrapped primary causes fail-closed refusal',async()=>{
  const f=makeFixture();
  assert.equal((await bootstrapWitness(witnessDB,{ledger_id:f.ledgerId,
    repository:REPO})).classification,'WITNESS_BOOTSTRAP_CONFIRMED');
  isUnknown(await call(f));
});
test('unbootstrapped witness causes fail-closed refusal',async()=>{
  const f=makeFixture();
  assert.equal((await bootstrapPg(primary,{ledger_id:f.ledgerId,
    repository:REPO})).classification,'PG_BOOTSTRAP_CONFIRMED');
  isUnknown(await call(f));
});
test('forged root denied before witness reservation',async()=>{
  const f=makeFixture({rootOverride:keys.outsider});await setup(f);
  isDenied(await call(f));assert.equal((await readW(f.ledgerId)).pending,null);
});
test('tampered signed intent denied before witness reservation',async()=>{
  const f=makeFixture();await setup(f);
  isDenied(await call(f,{body:{...f.body,intent_b64:'Zm9yZ2Vk'}}));
  assert.equal((await readW(f.ledgerId)).pending,null);
});
test('crash immediately after witness reservation preserves persistent pending',async()=>{
  const f=makeFixture();await setup(f);
  isUnknown(await call(f,{afterReservation:()=>{throw Error('CRASH');}}));
  const w=await readW(f.ledgerId);
  assert(w.pending);assert.equal(w.sequence,0);
  isUnknown(await call(f));
  assert.equal((await readW(f.ledgerId)).pending.reservation_id,w.pending.reservation_id);
});
test('pending never automatically expires, despite simulated retries',async()=>{
  const f=makeFixture();await setup(f);
  const c=claim(f),reservation=await reserveWitness(witnessDB,{claim:c,expectedGeneration:0});
  assert.equal(reservation.classification,'WITNESS_RESERVED');
  for(let i=0;i<25;i++)
    assert.equal((await readW(f.ledgerId)).pending.reservation_id,reservation.reservation_id);
  isUnknown(await reconcileWitnessPending({witness:operator,claim:c,
    reservationId:reservation.reservation_id,witnessPublicPem:pub}));
});
test('witness never finalizes before independently observed primary event',async()=>{
  const f=makeFixture();await setup(f);
  const c=claim(f),res=await reserveWitness(witnessDB,{claim:c,expectedGeneration:0});
  const v=await finalizeWitness(witnessDB,{claim:c,reservationId:res.reservation_id,
    independentlyReadPrimaryEvent:async()=>false});
  assert.equal(v.classification,'WITNESS_OUTCOME_UNVERIFIED');
  assert((await readW(f.ledgerId)).pending);
});
test('primary partition leaves witness reservation fenced',async()=>{
  const f=makeFixture();await setup(f);
  const c=claim(f),res=await reserveWitness(witnessDB,{claim:c,expectedGeneration:0});
  const v=await finalizeWitness(witnessDB,{claim:c,reservationId:res.reservation_id,
    independentlyReadPrimaryEvent:async()=>{throw Error('PARTITION');}});
  assert.equal(v.classification,'WITNESS_OUTCOME_UNVERIFIED');
  assert((await readW(f.ledgerId)).pending);
});
test('lost primary COMMIT acknowledgement recovers from independently observed event',async()=>{
  const f=makeFixture();await setup(f);
  const c=claim(f),res=await reserveWitness(witnessDB,{claim:c,expectedGeneration:0});
  assert.equal(res.classification,'WITNESS_RESERVED');
  const pg=await commitPgClaim(primary,{client:'witness-test-client',authNonce:nonce(),
    bodyDigest:digestSignedRequest(f.body),claim:c});
  assert.equal(pg.classification,'LOCAL_PG_CAS_COMMITTED');
  const after=await reconcileWitnessPending({witness:operator,claim:c,
    reservationId:res.reservation_id,witnessPublicPem:pub});
  assert.equal(after.classification,'MANUALLY_RECONCILED_WITNESS_DIAGNOSTIC',JSON.stringify(after));
  assert.equal(after.release_authorized,false);
  assert.equal((await readW(f.ledgerId)).generation,1);
});
test('lost witness FINALIZE acknowledgement recovers persisted signed witness event',async()=>{
  const f=makeFixture();await setup(f);
  let reservationId;
  const broken={read:operator.read,reserve:operator.reserve,
    finalize:async(c,id)=>{reservationId=id;
      const v=await operator.finalize(c,id);
      assert.equal(v.classification,'WITNESS_FINALIZED_DIAGNOSTIC');
      throw Error('LOST_ACK');
    }};
  isUnknown(await call(f,{witness:broken}));
  assert.equal((await readW(f.ledgerId)).sequence,1);
  const recovery=await reconcileWitnessPending({witness:operator,claim:claim(f),
    reservationId,witnessPublicPem:pub});
  assert.equal(recovery.classification,'MANUALLY_RECONCILED_WITNESS_DIAGNOSTIC',JSON.stringify(recovery));
});
test('wrong independently pinned witness key cannot validate success',async()=>{
  const f=makeFixture();await setup(f);
  const other=generateKeyPairSync('ed25519');
  isUnknown(await call(f,{witnessPublicPem:other.publicKey.export({type:'spki',format:'pem'})}));
  assert.equal((await readW(f.ledgerId)).sequence,1);
});
test('wrong reservation token never finalizes even with forged true primary flag',async()=>{
  const f=makeFixture();await setup(f);
  const c=claim(f),res=await reserveWitness(witnessDB,{claim:c,expectedGeneration:0});
  isDenied(await finalizeWitness(witnessDB,{claim:c,reservationId:nonce(),
    independentlyReadPrimaryEvent:async()=>true}));
  assert.equal((await readW(f.ledgerId)).pending.reservation_id,res.reservation_id);
});
test('wrong claim cannot finalize existing reservation',async()=>{
  const f=makeFixture();await setup(f);
  const c=claim(f),res=await reserveWitness(witnessDB,{claim:c,expectedGeneration:0});
  isDenied(await finalizeWitness(witnessDB,{claim:{...c,intent_sha256:nonce()},
    reservationId:res.reservation_id,independentlyReadPrimaryEvent:async()=>true}));
});
test('stale witness generation cannot reserve',async()=>{
  const f=makeFixture();await setup(f);
  isDenied(await reserveWitness(witnessDB,{claim:claim(f),expectedGeneration:1}));
});
test('cross-repository claim cannot reserve',async()=>{
  const f=makeFixture();await setup(f);
  isDenied(await reserveWitness(witnessDB,{claim:{...claim(f),repository:'ores-truffle-oreslang/other'},
    expectedGeneration:0}));
});
test('policy-generation rollback after witnessed event cannot reserve',async()=>{
  const f=makeFixture();await setup(f);
  assert.equal((await call(f)).classification,'WITNESSED_DIAGNOSTIC_CAS');
  const c={...claim(f),sequence:2,previous_intent_sha256:
    (await readW(f.ledgerId)).last_intent_sha256,
    policy_sequence:7,intent_sha256:nonce(),nonce:nonce(),client_request_id:nonce()};
  isDenied(await reserveWitness(witnessDB,{claim:c,expectedGeneration:1}));
});
test('replayed previous witness nonce cannot reserve',async()=>{
  const f=makeFixture();await setup(f);
  assert.equal((await call(f)).classification,'WITNESSED_DIAGNOSTIC_CAS');
  const c={...claim(f),sequence:2,previous_intent_sha256:
    (await readW(f.ledgerId)).last_intent_sha256,
    intent_sha256:nonce(),client_request_id:nonce()};
  isDenied(await reserveWitness(witnessDB,{claim:c,expectedGeneration:1}));
});
test('100 simultaneous witness reservations have exactly one owner',async()=>{
  const f=makeFixture();await setup(f);
  const c=claim(f);
  const outcome=await Promise.all(Array.from({length:100},()=>reserveWitness(witnessDB,{
    claim:{...c,client_request_id:nonce()},expectedGeneration:0})));
  assert.equal(outcome.filter(x=>x.classification==='WITNESS_RESERVED').length,1);
  assert.equal(outcome.filter(x=>x.classification==='DENIED').length,99);
  assert.equal((await readW(f.ledgerId)).sequence,0);
});
test('100 concurrent signed claims have one witnessed COMMIT',async()=>{
  const f=makeFixture();await setup(f);
  const results=await Promise.all(Array.from({length:100},()=>call(f,{
    body:{...f.body,client_request_id:nonce()}})));
  assert.equal(results.filter(x=>x.classification==='WITNESSED_DIAGNOSTIC_CAS').length,1,
    JSON.stringify(results.filter(x=>x.ledger_cas_committed===true)));
  assert(results.every(x=>x.release_authorized===false));
  assert.equal((await readW(f.ledgerId)).sequence,1);
  assert.equal((await readP(f.ledgerId)).sequence,1);
});
test('100 identical retries still commit just one witnessed generation',async()=>{
  const f=makeFixture();await setup(f);
  const results=await Promise.all(Array.from({length:100},()=>call(f)));
  assert.equal(results.filter(x=>x.classification==='WITNESSED_DIAGNOSTIC_CAS').length,1);
  assert.equal((await readW(f.ledgerId)).sequence,1);
});
test('20 different ledgers commit without witness state aliasing',async()=>{
  const f=Array.from({length:20},()=>makeFixture());await Promise.all(f.map(setup));
  const res=await Promise.all(f.map(x=>call(x)));
  assert(res.every(x=>x.classification==='WITNESSED_DIAGNOSTIC_CAS'));
  for(const x of f)assert.equal((await readW(x.ledgerId)).sequence,1);
});
test('primary restored from old snapshot detected against independent witness',async()=>{
  const f=makeFixture();await setup(f);
  assert.equal((await call(f)).classification,'WITNESSED_DIAGNOSTIC_CAS');
  await primary.query('DELETE FROM ledger_service_event WHERE ledger_id=$1',[f.ledgerId]);
  await primary.query('UPDATE ledger_service_state SET sequence=0,policy_sequence=0,last_intent_sha256=$2,last_nonce=$2 WHERE ledger_id=$1',[f.ledgerId,ZERO]);
  isUnknown(await call(f));
  assert.equal((await readW(f.ledgerId)).sequence,1);
  assert.equal((await readP(f.ledgerId)).sequence,0);
});
test('witness restored from old snapshot detected against primary',async()=>{
  const f=makeFixture();await setup(f);
  assert.equal((await call(f)).classification,'WITNESSED_DIAGNOSTIC_CAS');
  await witnessDB.query('DELETE FROM witness_event WHERE ledger_id=$1',[f.ledgerId]);
  await witnessDB.query('UPDATE witness_state SET sequence=0,generation=0,policy_sequence=0,last_intent_sha256=$2,last_nonce=$2 WHERE ledger_id=$1',[f.ledgerId,ZERO]);
  isUnknown(await call(f));
  assert.equal((await readW(f.ledgerId)).sequence,0);
  assert.equal((await readP(f.ledgerId)).sequence,1);
});
test('primary record alone is not independently verified unless state matches',async()=>{
  const f=makeFixture();await setup(f);const c=claim(f);
  assert.equal(await primaryEventCommitted(readOnlyPrimary,c),false);
  assert.equal((await commitPgClaim(primary,{client:'witness-test-client',
    authNonce:nonce(),bodyDigest:digestSignedRequest(f.body),claim:c}))
    .classification,'LOCAL_PG_CAS_COMMITTED');
  assert.equal(await primaryEventCommitted(readOnlyPrimary,c),true);
  await primary.query('UPDATE ledger_service_state SET last_nonce=$2 WHERE ledger_id=$1',[f.ledgerId,nonce()]);
  assert.equal(await primaryEventCommitted(readOnlyPrimary,c),false);
});
test('witness receipt absent until event is finalized',async()=>{
  const f=makeFixture();await setup(f);const c=claim(f);
  assert.equal((await reserveWitness(witnessDB,{claim:c,expectedGeneration:0}))
    .classification,'WITNESS_RESERVED');
  isDenied(await signPersistedWitnessReceipt(witnessDB,{ledgerId:f.ledgerId,
    sequence:1,privateKey:signing.privateKey}));
});
test('wrong manual reconciliation ID cannot remove pending state',async()=>{
  const f=makeFixture();await setup(f);const c=claim(f);
  const res=await reserveWitness(witnessDB,{claim:c,expectedGeneration:0});
  isUnknown(await reconcileWitnessPending({witness:operator,claim:c,
    reservationId:nonce(),witnessPublicPem:pub}));
  assert.equal((await readW(f.ledgerId)).pending.reservation_id,res.reservation_id);
});
