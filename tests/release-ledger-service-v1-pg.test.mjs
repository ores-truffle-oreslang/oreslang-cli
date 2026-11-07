import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {createLedgerHttpService} from '../tools/release-ledger-service-v1/server.mjs';
import {signedLocalRequest} from '../tools/release-ledger-service-v1/client.mjs';
import {createPgPool,installForIsolatedTests,bootstrapPg,readPgState,
  readPgReceipt,commitPgClaim} from '../tools/release-ledger-service-v1/postgres.mjs';
import {canonical,hash,local,deny,ZERO_DIGEST} from '../tools/release-ledger-service-v1/protocol.mjs';
const URL=process.env.ATTO_LEDGER_TEST_PG_URL;
if(!URL)throw Error('POSTGRES_INTEGRATION_MUST_USE_A_REAL_DISPOSABLE_DATABASE');
const SECRET='ab'.repeat(32);
const CLIENT='atto-service-client';
let pool,counter=0;
const repo='ores-truffle-oreslang/oreslang-cli';
const h=()=>randomBytes(32).toString('hex');
const ledger=()=>('ledger-'+(++counter).toString(36)+'-test');
const scope=(id)=>({ledger_id:id,repository:repo});
const claim=(id,{sequence=1,previous_intent_sha256=ZERO_DIGEST,
  policy_sequence=8,repository=repo,nonce=h(),intent_sha256=h(),
  client_request_id=h()}={})=>({
  artifact_sha256:'a'.repeat(64),client_request_id,head_sha:'b'.repeat(40),
  intent_sha256,ledger_id:id,nonce,policy_sequence,
  previous_intent_sha256,repository,sequence
});
const submit=(c,{client=CLIENT,authNonce=h()}={})=>
  commitPgClaim(pool,{client,authNonce,bodyDigest:hash(canonical(c)),claim:c});
const bootstrap=async id=>{
  const v=await bootstrapPg(pool,scope(id));
  assert.equal(v.classification,'PG_BOOTSTRAP_CONFIRMED',JSON.stringify(v));
  assert.equal(v.release_authorized,false);
};
const guard=v=>{assert.equal(v.release_authorized,false,JSON.stringify(v));
  assert.equal(v.authenticated_github,false);
  assert.equal(v.compiler_guest_parity_proven,false);};
const cleanDeny=v=>{
  assert.equal(v.classification,'DENIED',JSON.stringify(v));
  guard(v);assert.equal(v.ledger_cas_committed,false);
};
const state=async id=>{
  const s=await readPgState(pool,id);
  assert.equal(s.classification,'PG_LEDGER_SNAPSHOT',JSON.stringify(s));
  guard(s);return s;
};
before(async()=>{
  pool=await createPgPool({connectionString:URL,max:35,
    connectionTimeoutMillis:4000,idleTimeoutMillis:1000});
  await pool.query('SELECT 1');
  await installForIsolatedTests(pool);
});
after(async()=>{if(pool)await pool.end();});
test('operator bootstrap creates monotonic state at genesis',async()=>{
  const id=ledger();await bootstrap(id);
  const s=await state(id);
  assert.equal(s.sequence,0);assert.equal(s.policy_sequence,0);
  assert.equal(s.last_nonce,ZERO_DIGEST);
});
test('operator cannot bootstrap an invalid ledger identity',async()=>{
  cleanDeny(await bootstrapPg(pool,{ledger_id:'../x',repository:repo}));
});
test('operator cannot bootstrap foreign repository',async()=>{
  cleanDeny(await bootstrapPg(pool,{ledger_id:ledger(),repository:'evil-org/x'}));
});
test('operator cannot bootstrap with extra privileges flag',async()=>{
  cleanDeny(await bootstrapPg(pool,{ledger_id:ledger(),repository:repo,allow_release:true}));
});
test('repeat operator bootstrap never resets consumed state',async()=>{
  const id=ledger();await bootstrap(id);
  assert.equal((await submit(claim(id))).ledger_cas_committed,true);
  const v=await bootstrapPg(pool,scope(id));
  assert.equal(v.sequence,1);guard(v);
  assert.equal((await state(id)).sequence,1);
});
test('different repository bootstrap for existing ledger is denied',async()=>{
  const id=ledger();await bootstrap(id);
  cleanDeny(await bootstrapPg(pool,{ledger_id:id,
    repository:'ores-truffle-oreslang/other-repo'}));
});
test('first valid claimed event commits once and never grants release',async()=>{
  const id=ledger();await bootstrap(id);
  const c=claim(id);const v=await submit(c);
  assert.equal(v.classification,'LOCAL_PG_CAS_COMMITTED',JSON.stringify(v));
  assert.equal(v.ledger_cas_committed,true);guard(v);
  const st=await state(id);
  assert.equal(st.sequence,1);assert.equal(st.policy_sequence,8);
  assert.equal(st.last_intent_sha256,c.intent_sha256);
});
test('replay of same request id with different auth nonce is denied',async()=>{
  const id=ledger();await bootstrap(id);
  const c=claim(id);
  assert.equal((await submit(c)).ledger_cas_committed,true);
  const replay=await submit(c,{authNonce:h()});
  cleanDeny(replay);assert.equal((await state(id)).sequence,1);
});
test('replay of same authentication nonce with different request id is denied',async()=>{
  const id=ledger();await bootstrap(id);
  const n=h();const c=claim(id);
  assert.equal((await submit(c,{authNonce:n})).ledger_cas_committed,true);
  cleanDeny(await submit(claim(id),{authNonce:n}));
});
test('durable replay log survives denied stale request and later state changes',async()=>{
  const id=ledger();await bootstrap(id);
  const stale=claim(id,{sequence:2,previous_intent_sha256:h()});
  const authNonce=h();
  cleanDeny(await submit(stale,{authNonce}));
  const first=claim(id);
  assert.equal((await submit(first)).ledger_cas_committed,true);
  cleanDeny(await submit(stale,{authNonce}));
  assert.equal((await state(id)).sequence,1);
});
test('authenticated receipt confirms actual durable committed intent',async()=>{
  const id=ledger();await bootstrap(id);
  const c=claim(id);assert.equal((await submit(c)).ledger_cas_committed,true);
  const v=await readPgReceipt(pool,CLIENT,c.client_request_id);
  assert.equal(v.classification,'PG_RECEIPT_COMMITTED',JSON.stringify(v));
  assert.equal(v.ledger_cas_committed,true);
  assert.equal(v.intent_sha256,c.intent_sha256);guard(v);
});
test('denied request receipt cannot become a release approval',async()=>{
  const id=ledger();await bootstrap(id);
  const c=claim(id,{sequence:3,previous_intent_sha256:h()});
  cleanDeny(await submit(c));
  const receipt=await readPgReceipt(pool,CLIENT,c.client_request_id);
  cleanDeny(receipt);
});
test('receipt lookup cannot cross client identity',async()=>{
  const id=ledger();await bootstrap(id);
  const c=claim(id);assert.equal((await submit(c)).ledger_cas_committed,true);
  cleanDeny(await readPgReceipt(pool,'other-client',c.client_request_id));
});
test('missing receipt returns only a denial, not a guessed commit',async()=>{
  cleanDeny(await readPgReceipt(pool,CLIENT,h()));
});
test('unbootstrapped ledger cannot self-create through claim API',async()=>{
  const id=ledger();cleanDeny(await submit(claim(id)));
  cleanDeny(await readPgState(pool,id));
});
test('cross-repository claim rejected against existing ledger scope',async()=>{
  const id=ledger();await bootstrap(id);
  cleanDeny(await submit(claim(id,{repository:'ores-truffle-oreslang/other'})));
  assert.equal((await state(id)).sequence,0);
});
test('same policy generation accepted across sequential commits',async()=>{
  const id=ledger();await bootstrap(id);
  const one=claim(id);assert.equal((await submit(one)).ledger_cas_committed,true);
  const two=claim(id,{sequence:2,previous_intent_sha256:one.intent_sha256});
  assert.equal((await submit(two)).ledger_cas_committed,true);
  assert.equal((await state(id)).sequence,2);
});
test('higher policy generation allowed without weakening old entries',async()=>{
  const id=ledger();await bootstrap(id);
  const one=claim(id);assert.equal((await submit(one)).ledger_cas_committed,true);
  const two=claim(id,{sequence:2,previous_intent_sha256:one.intent_sha256,policy_sequence:9});
  assert.equal((await submit(two)).ledger_cas_committed,true);
  assert.equal((await state(id)).policy_sequence,9);
});
test('policy-generation rollback after rotation is rejected',async()=>{
  const id=ledger();await bootstrap(id);
  const one=claim(id,{policy_sequence:11});
  assert.equal((await submit(one)).ledger_cas_committed,true);
  const two=claim(id,{sequence:2,previous_intent_sha256:one.intent_sha256,
    policy_sequence:10});
  cleanDeny(await submit(two));
  assert.equal((await state(id)).policy_sequence,11);
});
test('lower sequence and higher policy cannot bypass high-water CAS',async()=>{
  const id=ledger();await bootstrap(id);
  const one=claim(id);assert.equal((await submit(one)).ledger_cas_committed,true);
  cleanDeny(await submit(claim(id,{sequence:1,policy_sequence:100})));
});
test('gap in sequence is rejected with durable denial receipt',async()=>{
  const id=ledger();await bootstrap(id);
  const c=claim(id,{sequence:4,previous_intent_sha256:h()});
  cleanDeny(await submit(c));
  cleanDeny(await readPgReceipt(pool,CLIENT,c.client_request_id));
  assert.equal((await state(id)).sequence,0);
});
test('incorrect predecessor digest is rejected atomically',async()=>{
  const id=ledger();await bootstrap(id);
  const one=claim(id);assert.equal((await submit(one)).ledger_cas_committed,true);
  cleanDeny(await submit(claim(id,{sequence:2,previous_intent_sha256:h()})));
  assert.equal((await state(id)).sequence,1);
});
test('repeated previous event nonce cannot consume another generation',async()=>{
  const id=ledger();await bootstrap(id);
  const first=claim(id);assert.equal((await submit(first)).ledger_cas_committed,true);
  const second=claim(id,{sequence:2,previous_intent_sha256:first.intent_sha256,
    nonce:first.nonce});
  cleanDeny(await submit(second));
});
test('repeated intent digest cannot consume another generation',async()=>{
  const id=ledger();await bootstrap(id);
  const first=claim(id);assert.equal((await submit(first)).ledger_cas_committed,true);
  const second=claim(id,{sequence:2,previous_intent_sha256:first.intent_sha256,
    intent_sha256:first.intent_sha256});
  cleanDeny(await submit(second));
});
test('100 simultaneous clients have exactly one CAS winner',async()=>{
  const id=ledger();await bootstrap(id);
  const c=Array.from({length:100},()=>claim(id));
  const result=await Promise.all(c.map(x=>submit(x)));
  assert.equal(result.filter(x=>x.classification==='LOCAL_PG_CAS_COMMITTED').length,1,
    JSON.stringify(result.filter(x=>x.classification!=='DENIED')));
  assert.equal(result.filter(x=>x.classification==='DENIED').length,99);
  assert(result.every(v=>{guard(v);return v.release_authorized===false;}));
  assert.equal((await state(id)).sequence,1);
});
test('100 same-request retries across multiple DB clients commit at most once',async()=>{
  const id=ledger();await bootstrap(id);
  const c=claim(id);
  const result=await Promise.all(Array.from({length:100},()=>submit(c)));
  assert.equal(result.filter(x=>x.classification==='LOCAL_PG_CAS_COMMITTED').length,1);
  assert.equal((await state(id)).sequence,1);
});
test('five concurrent successive policy generations remain linearizable',async()=>{
  const id=ledger();await bootstrap(id);
  const results=[];
  for(let i=1,previous=ZERO_DIGEST;i<=5;i++){
    const cs=Array.from({length:12},()=>claim(id,{
      sequence:i,previous_intent_sha256:previous,policy_sequence:8+i
    }));
    const arr=await Promise.all(cs.map(c=>submit(c)));
    const winner=arr.find(x=>x.classification==='LOCAL_PG_CAS_COMMITTED');
    assert(winner,'at least one valid monotonic claim must win');
    assert.equal(arr.filter(x=>x.classification==='LOCAL_PG_CAS_COMMITTED').length,1);
    previous=winner.intent_sha256;
    results.push(winner);
  }
  assert.equal((await state(id)).sequence,5);
  assert.equal((await state(id)).policy_sequence,13);
});
test('row-level transactions protect independent ledgers without merging state',async()=>{
  const ids=Array.from({length:10},()=>ledger());
  await Promise.all(ids.map(id=>bootstrap(id)));
  const results=await Promise.all(ids.flatMap(id=>Array.from({length:6},()=>submit(claim(id)))));
  assert.equal(results.filter(x=>x.classification==='LOCAL_PG_CAS_COMMITTED').length,10);
  for(const id of ids)assert.equal((await state(id)).sequence,1);
});
test('operator-scoped client ID uniqueness extends across all ledgers',async()=>{
  const a=ledger(),b=ledger();
  await bootstrap(a);await bootstrap(b);
  const cid=h();const first=claim(a,{client_request_id:cid});
  assert.equal((await submit(first)).ledger_cas_committed,true);
  const second=claim(b,{client_request_id:cid});
  cleanDeny(await submit(second));
  assert.equal((await state(b)).sequence,0);
});
test('bad authentication nonce cannot even start a DB transaction',async()=>{
  const id=ledger();await bootstrap(id);
  cleanDeny(await submit(claim(id),{authNonce:'Z'.repeat(64)}));
  assert.equal((await state(id)).sequence,0);
});
test('bad client name cannot create a durable receipt',async()=>{
  const id=ledger();await bootstrap(id);
  cleanDeny(await submit(claim(id),{client:'OTHER/ORG'}));
  assert.equal((await state(id)).sequence,0);
});
test('malformed claim fails before DB mutation',async()=>{
  const id=ledger();await bootstrap(id);
  const c={...claim(id), release_authorized:true};
  cleanDeny(await submit(c));
  assert.equal((await state(id)).sequence,0);
});
test('server loopback HMAC claim, replay denial and receipt work end to end',async()=>{
  const id=ledger();await bootstrap(id);
  const server=createLedgerHttpService({pool,secret:SECRET,
    expectedClient:CLIENT,nowSeconds:()=>2000000000});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    const base='http://127.0.0.1:'+server.address().port;
    const c=claim(id);
    const q=signedLocalRequest({secret:SECRET,client:CLIENT,body:c,
      timestamp:2000000000});
    const request=()=>fetch(base+q.path,{method:q.method,headers:q.headers,body:q.raw});
    const first=await request();
    const v=await first.json();
    assert.equal(first.status,200,JSON.stringify(v));
    assert.equal(v.classification,'LOCAL_PG_CAS_COMMITTED');guard(v);
    const second=await request();
    assert.equal(second.status,409);
    cleanDeny(await second.json());
    const receiptRequest=signedLocalRequest({secret:SECRET,client:CLIENT,
      body:{client_request_id:c.client_request_id},path:'/v1/receipt',
      timestamp:2000000000});
    const receipt=await fetch(base+receiptRequest.path,{
      method:'POST',headers:receiptRequest.headers,body:receiptRequest.raw
    });
    assert.equal(receipt.status,200);
    const confirmed=await receipt.json();
    assert.equal(confirmed.classification,'PG_RECEIPT_COMMITTED');
    guard(confirmed);
  }finally{await new Promise(resolve=>server.close(resolve));}
});
test('wrong HMAC client cannot consume a sequence',async()=>{
  const id=ledger();await bootstrap(id);
  const server=createLedgerHttpService({pool,secret:SECRET,
    expectedClient:CLIENT,nowSeconds:()=>2000000000});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    const q=signedLocalRequest({secret:'cd'.repeat(32),client:CLIENT,
      body:claim(id),timestamp:2000000000});
    const res=await fetch('http://127.0.0.1:'+server.address().port+q.path,{
      method:'POST',headers:q.headers,body:q.raw});
    assert.equal(res.status,403);cleanDeny(await res.json());
    assert.equal((await state(id)).sequence,0);
  }finally{await new Promise(resolve=>server.close(resolve));}
});
for(const [name,f] of [
 ['precommit error',()=>new Error('injected connection reset')],
 ['serialization conflict',()=>Object.assign(new Error('serialization'),{code:'40001'})],
 ['statement timeout',()=>Object.assign(new Error('statement timeout'),{code:'57014'})]
]){
  test('database rejection before COMMIT never claims commit: '+name,async()=>{
    const id=ledger();await bootstrap(id);
    const fake={
      connect:async()=>{
        const original=await pool.connect();
        return {query:async(sql,args)=>{
          if(typeof sql==='string'&&sql.startsWith('INSERT INTO ledger_service_event'))
            throw f();
          return original.query(sql,args);
        },release:()=>original.release()};
      }
    };
    const v=await commitPgClaim(fake,{client:CLIENT,authNonce:h(),
      bodyDigest:h(),claim:claim(id)});
    cleanDeny(v);assert.equal((await state(id)).sequence,0);
  });
}
for(const [name,err] of [
 ['client lost COMMIT response',Object.assign(new Error('lost ACK'),{code:'08006'})],
 ['COMMIT timeout',Object.assign(new Error('network timeout'),{code:'57014'})],
 ['connection broken after durable commit',Object.assign(new Error('disconnect'),{code:'57P01'})]
]){
  test('COMMIT acknowledgement uncertain; reconcile with durable receipt: '+name,async()=>{
    const id=ledger();await bootstrap(id);
    const c=claim(id);
    const fake={
      connect:async()=>{
        const original=await pool.connect();
        return {query:async(sql,args)=>{
          const output=await original.query(sql,args);
          if(sql==='COMMIT')throw err;
          return output;
        },release:()=>original.release()};
      }
    };
    const v=await commitPgClaim(fake,{client:CLIENT,authNonce:h(),
      bodyDigest:hash(canonical(c)),claim:c});
    assert.equal(v.classification,'LOCAL_PG_COMMIT_UNVERIFIED',JSON.stringify(v));
    assert.equal(v.ledger_cas_committed,null);
    assert.equal(v.requires_manual_reconciliation,true);guard(v);
    const receipt=await readPgReceipt(pool,CLIENT,c.client_request_id);
    assert.equal(receipt.classification,'PG_RECEIPT_COMMITTED');
    assert.equal((await state(id)).sequence,1);
  });
}
