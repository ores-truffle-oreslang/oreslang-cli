import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createPgPool,installForIsolatedTests,bootstrapPg,
  readPgState,readPgReceipt} from '../tools/release-ledger-service-v1/postgres.mjs';
import {hash,canonical} from '../tools/release-ledger-service-v1/protocol.mjs';
import {pinOperatorEvidence,verifySignedServiceRequest,
  consumeVerifiedSignedServiceRequest} from '../tools/release-ledger-service-v2/signed-claim.mjs';
import {signV2DiagnosticRequest,
  createSignedDiagnosticHttpService} from '../tools/release-ledger-service-v2/http.mjs';
import {makeFixture,REPO,NOW} from './fixtures/release-ledger-service-v2-signed.mjs';
const URL=process.env.ATTO_LEDGER_TEST_PG_URL;
if(!URL)throw Error('REAL_POSTGRESQL_TEST_DATABASE_REQUIRED');
const SECRET='ab'.repeat(32),CLIENT='signed-client';
const TIMESTAMP=Math.floor(Date.parse(NOW)/1000);
const rand=()=>randomBytes(32).toString('hex');
let pool;
before(async()=>{
  pool=await createPgPool({connectionString:URL,max:32,
    connectionTimeoutMillis:4000,idleTimeoutMillis:1000});
  await pool.query('SELECT 1');
  await installForIsolatedTests(pool);
});
after(async()=>{if(pool)await pool.end();});
const denied=v=>{
  assert.equal(v.classification,'DENIED',JSON.stringify(v));
  assert.equal(v.release_authorized,false);
  assert.equal(v.ledger_cas_committed,false);
};
const bootstrap=async f=>{
  const v=await bootstrapPg(pool,{ledger_id:f.ledgerId,repository:REPO});
  assert.equal(v.classification,'PG_BOOTSTRAP_CONFIRMED',JSON.stringify(v));
};
const submit=async(f,opts={})=>consumeVerifiedSignedServiceRequest({
  pool,client:CLIENT,authNonce:opts.authNonce||rand(),
  bodyDigest:hash(canonical(opts.body||f.body)),
  body:opts.body||f.body,
  operatorPin:pinOperatorEvidence(opts.operatorPin||f.operatorPin),
  now:opts.now||f.now
});
test('valid role-separated synthetic DSSE proof commits local PG sequence once',async()=>{
  const f=makeFixture();await bootstrap(f);
  const v=await submit(f);
  assert.equal(v.classification,'LOCAL_PG_CAS_COMMITTED',JSON.stringify(v));
  assert.equal(v.ledger_cas_committed,true);assert.equal(v.release_authorized,false);
  assert.equal(v.authenticated_github,false);
  assert.equal(v.compiler_guest_parity_proven,false);
  const state=await readPgState(pool,f.ledgerId);
  assert.equal(state.sequence,1);assert.equal(state.policy_sequence,8);
  assert.equal(state.last_nonce,f.intent.nonce);
  assert.equal(state.last_intent_sha256,hash(f.intentEnvelopeBytes));
  const receipt=await readPgReceipt(pool,CLIENT,f.body.client_request_id);
  assert.equal(receipt.classification,'PG_RECEIPT_COMMITTED');
  assert.equal(receipt.release_authorized,false);
});
test('same exact signed intent cannot consume sequence twice',async()=>{
  const f=makeFixture();await bootstrap(f);
  assert.equal((await submit(f)).ledger_cas_committed,true);
  denied(await submit(f));
  assert.equal((await readPgState(pool,f.ledgerId)).sequence,1);
});
test('new client request ID cannot replay stale signed checkpoint',async()=>{
  const f=makeFixture();await bootstrap(f);
  assert.equal((await submit(f)).ledger_cas_committed,true);
  const altered={...f.body,client_request_id:rand()};
  denied(await submit(f,{body:altered}));
  assert.equal((await readPgState(pool,f.ledgerId)).sequence,1);
});
test('post-commit high-water protects against different HMAC nonce replay',async()=>{
  const f=makeFixture();await bootstrap(f);
  assert.equal((await submit(f,{authNonce:rand()})).ledger_cas_committed,true);
  denied(await submit(f,{authNonce:rand()}));
});
test('signed intent cannot bootstrap an uninitialized ledger implicitly',async()=>{
  const f=makeFixture();
  denied(await submit(f));
  const snapshot=await readPgState(pool,f.ledgerId);
  assert.equal(snapshot.classification,'DENIED');
});
test('invalid signed root is rejected without DB claims or state mutation',async()=>{
  const f=makeFixture({rootOverride: (await import('./fixtures/release-ledger-service-v2-signed.mjs')).keys.outsider});
  await bootstrap(f);
  denied(await submit(f));
  assert.equal((await readPgState(pool,f.ledgerId)).sequence,0);
});
test('valid HMAC cannot substitute malformed signed intent',async()=>{
  const f=makeFixture();await bootstrap(f);
  denied(await submit(f,{body:{...f.body,intent_b64:Buffer.from('{}').toString('base64')}}));
  assert.equal((await readPgState(pool,f.ledgerId)).sequence,0);
});
test('forged claim fields appended to signed wire are never consumed',async()=>{
  const f=makeFixture();await bootstrap(f);
  denied(await submit(f,{body:{...f.body,publisher:true}}));
  assert.equal((await readPgState(pool,f.ledgerId)).sequence,0);
});
test('tampered signed artifact bytes cannot consume sequence',async()=>{
  const f=makeFixture();await bootstrap(f);
  const fake={...f.body,artifact_b64:Buffer.from('tampered').toString('base64')};
  denied(await submit(f,{body:fake}));
  assert.equal((await readPgState(pool,f.ledgerId)).sequence,0);
});
test('100 concurrent signed claims have exactly one durable winner',async()=>{
  const f=makeFixture();await bootstrap(f);
  const cases=Array.from({length:100},(_,i)=>({...f.body,
    client_request_id:hash(Buffer.from('signed-request-'+f.ledgerId+'-'+i))}));
  const results=await Promise.all(cases.map(body=>submit(f,{body,authNonce:rand()})));
  assert.equal(results.filter(v=>v.classification==='LOCAL_PG_CAS_COMMITTED').length,1,
    JSON.stringify(results.filter(v=>v.classification!=='DENIED')));
  assert.equal(results.filter(v=>v.classification==='DENIED').length,99);
  assert(results.every(v=>v.release_authorized===false));
  assert.equal((await readPgState(pool,f.ledgerId)).sequence,1);
});
test('100 simultaneous retries of the same signed request produce one commit',async()=>{
  const f=makeFixture();await bootstrap(f);
  const results=await Promise.all(Array.from({length:100},()=>submit(f,{authNonce:rand()})));
  assert.equal(results.filter(v=>v.classification==='LOCAL_PG_CAS_COMMITTED').length,1);
  assert.equal((await readPgState(pool,f.ledgerId)).sequence,1);
});
test('signed HTTP request signs canonical v2 body, commits and verifies receipt',async()=>{
  const f=makeFixture();await bootstrap(f);
  const srv=createSignedDiagnosticHttpService({pool,secret:SECRET,
    expectedClient:CLIENT,operatorPin:f.operatorPin,
    nowSeconds:()=>TIMESTAMP,nowUtc:()=>NOW});
  await new Promise(res=>srv.listen(0,'127.0.0.1',res));
  try{
    const base='http://127.0.0.1:'+srv.address().port;
    const q=signV2DiagnosticRequest({secret:SECRET,client:CLIENT,body:f.body,
      timestamp:TIMESTAMP});
    const send=()=>fetch(base+q.path,{method:'POST',headers:q.headers,body:q.body});
    let result=await send();
    assert.equal(result.status,200);
    let v=await result.json();
    assert.equal(v.classification,'LOCAL_PG_CAS_COMMITTED',JSON.stringify(v));
    assert.equal(v.release_authorized,false);
    result=await send();
    assert.equal(result.status,403);
    v=await result.json();denied(v);
    const receipt=signV2DiagnosticRequest({secret:SECRET,client:CLIENT,
      body:{client_request_id:f.body.client_request_id},
      path:'/v2/receipt',timestamp:TIMESTAMP});
    result=await fetch(base+receipt.path,{
      method:'POST',headers:receipt.headers,body:receipt.body});
    assert.equal(result.status,200);
    v=await result.json();
    assert.equal(v.classification,'PG_RECEIPT_COMMITTED');
    assert.equal(v.release_authorized,false);
  }finally{await new Promise(res=>srv.close(res));}
});
test('authenticated client cannot replace externally pinned signed envelopes',async()=>{
  const f=makeFixture();await bootstrap(f);
  const srv=createSignedDiagnosticHttpService({pool,secret:SECRET,
    expectedClient:CLIENT,operatorPin:f.operatorPin,
    nowSeconds:()=>TIMESTAMP,nowUtc:()=>NOW});
  await new Promise(res=>srv.listen(0,'127.0.0.1',res));
  try{
    const base='http://127.0.0.1:'+srv.address().port;
    const f2=makeFixture({ledgerId:f.ledgerId,
      intentMutate:intent=>{intent.nonce='4'.repeat(64);}});
    const q=signV2DiagnosticRequest({secret:SECRET,client:CLIENT,body:f2.body,
      timestamp:TIMESTAMP});
    const response=await fetch(base+q.path,{
      method:'POST',headers:q.headers,body:q.body});
    denied(await response.json());
    assert.equal(response.status,403);
    assert.equal((await readPgState(pool,f.ledgerId)).sequence,0);
  }finally{await new Promise(res=>srv.close(res));}
});
test('valid HMAC but malformed DSSE cannot change durable high-water',async()=>{
  const f=makeFixture();await bootstrap(f);
  const srv=createSignedDiagnosticHttpService({pool,secret:SECRET,
    expectedClient:CLIENT,operatorPin:f.operatorPin,
    nowSeconds:()=>TIMESTAMP,nowUtc:()=>NOW});
  await new Promise(res=>srv.listen(0,'127.0.0.1',res));
  try{
    const q=signV2DiagnosticRequest({secret:SECRET,client:CLIENT,
      body:{...f.body,registry_b64:'Zm9yZ2Vk'},
      timestamp:TIMESTAMP});
    const response=await fetch('http://127.0.0.1:'+srv.address().port+q.path,{
      method:'POST',headers:q.headers,body:q.body});
    assert.equal(response.status,403);
    denied(await response.json());
    assert.equal((await readPgState(pool,f.ledgerId)).sequence,0);
  }finally{await new Promise(res=>srv.close(res));}
});
