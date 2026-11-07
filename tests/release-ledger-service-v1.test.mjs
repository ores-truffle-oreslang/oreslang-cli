import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { canonical, parseBody, checkAuth, validClaim, validBootstrap,
  validReceiptRequest, validRepo, validLedger, normalizeSecret, macFor,
  local, deny, MAX_SKEW_SECONDS, ZERO_DIGEST } from '../tools/release-ledger-service-v1/protocol.mjs';
import { signedLocalRequest } from '../tools/release-ledger-service-v1/client.mjs';
import { createLedgerHttpService } from '../tools/release-ledger-service-v1/server.mjs';

const SECRET='ab'.repeat(32);
const BAD_SECRET='cd'.repeat(32);
const CLIENT='atto-service-client';
const NOW=2000000000;
const NONCE='2'.repeat(64);
const HEX=n=>n.toString(16).padStart(64,'0');
const claim=()=>({
  artifact_sha256:'a'.repeat(64),
  client_request_id:'b'.repeat(64),
  head_sha:'c'.repeat(40),
  intent_sha256:'d'.repeat(64),
  ledger_id:'atto-release-ledger',
  nonce:'e'.repeat(64),
  policy_sequence:8,
  previous_intent_sha256:ZERO_DIGEST,
  repository:'ores-truffle-oreslang/oreslang-cli',
  sequence:1
});
const signed=(body=claim(),more={})=>signedLocalRequest({
  body,secret:SECRET,client:CLIENT,timestamp:NOW,nonce:NONCE,...more});
const verify=(v,{secret=SECRET,client=CLIENT,now=NOW,method=v.method,
  path=v.path,raw=v.raw,headers=v.headers}={})=>checkAuth({
  headers,rawHeaders:Object.entries(headers).flatMap(([k,x])=>[k,x]),
  rawBody:raw,method,path,secret,expectedClient:client,nowSeconds:now
});
const notAuthorized=result=>{
  assert.equal(result.release_authorized,false);
  assert.equal(result.authenticated_github,false);
  assert.equal(result.compiler_guest_parity_proven,false);
};
test('valid canonical signed request passes MAC and remains unprivileged',()=>{
  const v=verify(signed());
  assert.equal(v.ok,true,JSON.stringify(v));
  assert.equal(v.client,CLIENT);
  assert.equal(v.body.sequence,1);
});
test('source-free diagnostic response cannot claim external authority',()=>{
  const x=local('LOCAL_PG_CAS_COMMITTED',{ledger_cas_committed:true});
  notAuthorized(x);
});
test('clean denial cannot claim committed sequence',()=>{
  const x=deny('invalid');
  notAuthorized(x);assert.equal(x.ledger_cas_committed,false);
});
test('valid receipt request carries a strict digest only',()=>{
  assert.equal(validReceiptRequest({client_request_id:'a'.repeat(64)}),true);
  assert.equal(validReceiptRequest({client_request_id:'a'.repeat(64),trusted:true}),false);
});
test('operator bootstrap never infers ledger from caller metadata',()=>{
  assert.equal(validBootstrap({ledger_id:'atto-release-ledger',
    repository:'ores-truffle-oreslang/oreslang-cli'}),true);
  assert.equal(validBootstrap({ledger_id:'atto-release-ledger',
    repository:'attacker/repo'}),false);
});
test('request body canonical ordering is deterministic',()=>{
  assert.equal(canonical({b:2,a:[null,true,'x']}),'{"a":[null,true,"x"],"b":2}');
});
test('MAC is deterministic under same full request',()=>{
  assert.equal(signed().headers['x-atto-mac'],signed().headers['x-atto-mac']);
});
test('different route changes MAC',()=>{
  assert.notEqual(signed().headers['x-atto-mac'],
    signed(claim(),{path:'/v1/receipt'}).headers['x-atto-mac']);
});
for(const [name,v] of Object.entries({
  nonce:NONCE,time:NOW,secret:SECRET,client:CLIENT,
  method:'POST',path:'/v1/claim'
})){
  test('bound authentication attribute '+name,()=>{
    const original=signed();
    const tampered={...original,headers:{...original.headers}};
    if(name==='nonce')tampered.headers['x-atto-nonce']='1'.repeat(64);
    else if(name==='time')tampered.headers['x-atto-time']=String(NOW+5);
    else if(name==='client')tampered.headers['x-atto-client']='other-client';
    else if(name==='method')tampered.method='GET';
    else if(name==='path')tampered.path='/v1/receipt';
    else return assert.equal(verify(tampered,{secret:BAD_SECRET}).ok,false);
    assert.equal(verify(tampered).ok,false);
  });
}
const invalid=[
 ['sequence-zero','sequence',0],['sequence-negative','sequence',-1],
 ['sequence-fraction','sequence',1.5],['sequence-string','sequence','1'],
 ['sequence-max','sequence',1e100],['sequence-maxsafe','sequence',Number.MAX_SAFE_INTEGER],
 ['sequence-oversize','sequence',1000001],
 ['seq-null','sequence',null],['seq-boolean','sequence',true],
 ['policy-zero','policy_sequence',0],['policy-negative','policy_sequence',-1],
 ['policy-fraction','policy_sequence',8.1],['policy-oversize','policy_sequence',1000001],
 ['policy-string','policy_sequence','8'],['policy-null','policy_sequence',null],
 ['ledger-empty','ledger_id',''],['ledger-short','ledger_id','x'],
 ['ledger-uppercase','ledger_id','Atto'],['ledger-slash','ledger_id','atto/ledger'],
 ['ledger-colon','ledger_id','atto:ledger'],['ledger-space','ledger_id','atto ledger'],
 ['ledger-dotdot','ledger_id','..'],['ledger-zero','ledger_id',0],
 ['ledger-object','ledger_id',{}],['ledger-emoji','ledger_id','atto-😀'],
 ['ledger-too-long','ledger_id','x'.repeat(65)],
 ['repo-foreign-org','repository','attacker/oreslang-cli'],
 ['repo-uppercase','repository','ores-truffle-oreslang/Oreslang-cli'],
 ['repo-traversal','repository','ores-truffle-oreslang/../s'],
 ['repo-subpath','repository','ores-truffle-oreslang/repo/other'],
 ['repo-empty','repository',''],['repo-null','repository',null],
 ['repo-number','repository',7],['repo-backslash','repository','ores-truffle-oreslang\\repo'],
 ['repo-long','repository','ores-truffle-oreslang/'+'a'.repeat(130)],
 ['head-short','head_sha','c'.repeat(39)],['head-long','head_sha','c'.repeat(41)],
 ['head-upper','head_sha','C'.repeat(40)],['head-nonhex','head_sha','z'.repeat(40)],
 ['head-null','head_sha',null],['head-number','head_sha',3],
 ['artifact-short','artifact_sha256','a'.repeat(63)],
 ['artifact-long','artifact_sha256','a'.repeat(65)],
 ['artifact-upper','artifact_sha256','A'.repeat(64)],
 ['artifact-nonhex','artifact_sha256','G'.repeat(64)],
 ['artifact-null','artifact_sha256',null],
 ['intent-short','intent_sha256','d'.repeat(63)],['intent-long','intent_sha256','d'.repeat(65)],
 ['intent-upper','intent_sha256','D'.repeat(64)],['intent-nonhex','intent_sha256','z'.repeat(64)],
 ['intent-zero','intent_sha256',ZERO_DIGEST],['intent-null','intent_sha256',null],
 ['nonce-short','nonce','e'.repeat(63)],['nonce-long','nonce','e'.repeat(65)],
 ['nonce-upper','nonce','E'.repeat(64)],['nonce-nonhex','nonce','z'.repeat(64)],
 ['nonce-zero','nonce',ZERO_DIGEST],['nonce-null','nonce',null],
 ['request-short','client_request_id','b'.repeat(63)],
 ['request-long','client_request_id','b'.repeat(65)],
 ['request-upper','client_request_id','B'.repeat(64)],
 ['request-nonhex','client_request_id','z'.repeat(64)],
 ['request-null','client_request_id',null],
 ['prev-short','previous_intent_sha256','0'.repeat(63)],
 ['prev-upper','previous_intent_sha256','A'.repeat(64)],
 ['prev-nonhex','previous_intent_sha256','z'.repeat(64)],
 ['prev-null','previous_intent_sha256',null],
 ['genesis-nonzero-prev','previous_intent_sha256','a'.repeat(64)],
];
for(const [name,key,val] of invalid){
  test('invalid claim rejects '+name,()=>{
    const x=claim();x[key]=val;
    assert.equal(validClaim(x),false);
    const v=verify(signed(x));
    assert.equal(v.ok,false,name+' '+JSON.stringify(v));
    assert.equal(v.release_authorized,false);
  });
}
for(const key of Object.keys(claim())){
  test('missing claim field '+key+' is rejected',()=>{
    const x=claim();delete x[key];
    assert.equal(validClaim(x),false);
    assert.equal(verify(signed(x)).ok,false);
  });
  test('unexpected extra field with '+key+' is rejected',()=>{
    const x={...claim(),['unexpected_'+key]:true};
    assert.equal(validClaim(x),false);
    assert.equal(verify(signed(x)).ok,false);
  });
}
const badBodies=[
 ['missing',''],['whitespace',' '],['object-leading-space',' {"a":1}'],
 ['object-trailing-space','{"a":1} '],['unsorted-keys','{"z":2,"a":1}'],
 ['duplicate-key','{"a":1,"a":2}'],['duplicate-claim','{"sequence":1,"sequence":2}'],
 ['array','[1,2]'],['null','null'],['number','123'],
 ['boolean','true'],['empty-object','{}'],['nested-extra','{"a":{"c":2,"b":1}}'],
 ['float','{"a":1.5}'],['negative-zero','{"a":-0}'],
 ['unicode-escape','{"a":"\\u0061"}'],['slash-escape','{"a":"\\/"}'],
 ['newline','{"a":1}\n'],['utf8-bom','\uFEFF{}'],['comment','{/*a*/}'],
 ['trailing-comma','{"a":1,}'],['NaN','{"a":NaN}'],
 ['Infinity','{"a":Infinity}'],['leading-zero','{"a":01}'],
 ['exponent','{"a":1e3}'],['undefined','undefined'],
 ['json-lines','{}\n{}'],['semicolon','{};'],['nul','{}\0'],
 ['json5','{foo:1}'],['unclosed','{"a":1'],['colon','{"a" 1}']
];
for(const [name,raw] of badBodies){
  test('noncanonical or malformed body '+name,()=>{
    assert.throws(()=>parseBody(Buffer.from(raw)),name);
  });
}
test('invalid UTF-8 bytes cannot be silently replaced',()=>{
  assert.throws(()=>parseBody(Buffer.from([123,34,97,34,58,34,0xff,34,125])));
});
test('body over maximum is denied',()=>{
  assert.throws(()=>parseBody(Buffer.from('a'.repeat(32769))));
});
test('empty buffer denied',()=>assert.throws(()=>parseBody(Buffer.alloc(0))));
test('non-buffer input denied',()=>assert.throws(()=>parseBody('{}')));
for(const [name,raw] of [
 ['trailing-space',' '],['trailing-newline','\n'],['trailing-zero','\0'],
 ['prefixed-space','\t'],['modified-sequence','"sequence":2'],['malformed-utf8','\ufffd']
]){
  test('MAC-bound body rejects '+name,()=>{
    const v=signed();
    const changed={...v,raw:Buffer.concat([v.raw,Buffer.from(raw)])};
    assert.equal(verify(changed).ok,false);
  });
}
for(const key of ['x-atto-client','x-atto-time','x-atto-nonce','x-atto-mac']){
  test('missing auth header '+key,()=>{
    const v=signed();delete v.headers[key];
    assert.equal(verify(v).ok,false);
  });
  test('duplicate auth header '+key,()=>{
    const v=signed();
    const rawHeaders=Object.entries(v.headers).flatMap(([k,x])=>[k,x]);
    rawHeaders.push(key.toUpperCase(),v.headers[key]);
    const result=checkAuth({headers:v.headers,rawHeaders,method:v.method,path:v.path,
      rawBody:v.raw,secret:SECRET,expectedClient:CLIENT,nowSeconds:NOW});
    assert.equal(result.ok,false);
  });
}
for(const name of ['x-atto-admin','x-atto-bypass','x-atto-issuer','x-atto-release']){
  test('unknown authority header '+name,()=>{
    const v=signed();v.headers[name]='true';
    assert.equal(verify(v).ok,false);
  });
}
for(const [name,value] of [
 ['noncanonical-ts','02000000000'],['negative-ts','-1'],['float-ts','2000000000.0'],
 ['future-extreme','9999999999999999999'],['not-number','yesterday'],
 ['timestamp-plus','+2000000000'],['timestamp-space',' 2000000000'],
 ['timestamp-empty',''],['timestamp-null','null'],['timestamp-hex','0x123']
]){
  test('invalid timestamp '+name,()=>{
    const v=signed();v.headers['x-atto-time']=value;
    assert.equal(verify(v).ok,false);
  });
}
for(const offset of [-3600,-31,31,3600,-1000000,1000000]){
  test('deny outside server clock skew '+offset,()=>{
    const v=signed(claim(),{timestamp:NOW+offset});
    assert.equal(verify(v).ok,false);
  });
}
for(const offset of [-30,-29,0,29,30]){
  test('accept within server clock skew '+offset,()=>{
    const v=signed(claim(),{timestamp:NOW+offset});
    assert.equal(verify(v).ok,true);
  });
}
for(const [name,value] of [
 ['empty',''],['uppercase','A'.repeat(64)],['short','a'.repeat(63)],
 ['long','a'.repeat(65)],['nonhex','g'.repeat(64)],['number',4],
 ['null',null],['zeros','0'],['separator','ab-cd'],
 ['unicode','😀'.repeat(32)]
]){
  test('reject invalid request authentication nonce '+name,()=>{
    const v=signed();v.headers['x-atto-nonce']=value;
    assert.equal(verify(v).ok,false);
  });
}
for(const [name,value] of [
 ['empty',''],['uppercase','A'.repeat(64)],['short','a'.repeat(63)],
 ['long','a'.repeat(65)],['nonhex','g'.repeat(64)],['null',null],
 ['zero','0'],['number',5],['colon','ab:cd']
]){
  test('reject malformed HMAC '+name,()=>{
    const v=signed();v.headers['x-atto-mac']=value;
    assert.equal(verify(v).ok,false);
  });
}
for(const [name,key] of [
 ['short','a'.repeat(62)],['upper','A'.repeat(64)],['nonhex','z'.repeat(64)],
 ['empty',''],['null',null],['binary',Buffer.alloc(32)],['long','a'.repeat(66)]
]){
  test('invalid shared client key '+name,()=>assert.throws(()=>normalizeSecret(key)));
}
for(const [name,client] of [
 ['empty',''],['short','a'],['upper','Atto'],['space','atto agent'],
 ['colon','atto:service'],['slash','atto/agent'],['null',null],
 ['long','a'.repeat(65)],['number',42]
]){
  test('invalid client identity '+name,()=>{
    const v=signed();
    assert.equal(verify(v,{client}).ok,false);
  });
}
for(const [name,method,path] of [
 ['GET','GET','/v1/claim'],['PUT','PUT','/v1/claim'],
 ['delete','DELETE','/v1/claim'],['trace','TRACE','/v1/claim'],
 ['path-alias','POST','/v1//claim'],['case','POST','/V1/claim'],
 ['other','POST','/admin'],['suffix','POST','/v1/claim/'],
 ['query','POST','/v1/claim?admin=1'],['encoded','POST','/v1/%63laim']
]){
  test('reject method/path mismatch '+name,()=>{
    const v=signed();assert.equal(verify(v,{method,path}).ok,false);
  });
}
for(const name of ['a','b','c','d','e','f','g','h','i','j']){
  test('signature detects digest substitution '+name,()=>{
    const v=signed();const payload=claim();
    payload.intent_sha256=name.repeat(64);
    const changed=Buffer.from(canonical(payload));
    assert.equal(verify(v,{raw:changed}).ok,false);
  });
}
test('HMAC-bound receipt request admitted when canonical and signed',()=>{
  const body={client_request_id:'a'.repeat(64)};
  const v=signed(body,{path:'/v1/receipt'});
  assert.equal(verify(v).ok,true);
});
test('receipt request cannot carry authorize flag',()=>{
  const v=signed({client_request_id:'a'.repeat(64),release_authorized:true},
    {path:'/v1/receipt'});
  assert.equal(verify(v).ok,false);
});
test('receipt request cannot use absent client request id',()=>{
  const v=signed({},{path:'/v1/receipt'});
  assert.equal(verify(v).ok,false);
});
test('HMAC signing rejects unsupported method and route',()=>{
  assert.throws(()=>macFor({secret:SECRET,method:'GET',path:'/v1/claim',
    client:CLIENT,timestamp:NOW,nonce:NONCE,body:'{}'}));
});
test('canonicalizer rejects unsafe JS numeric values',()=>{
  for(const v of [NaN,Infinity,-Infinity,1.2,Number.MAX_SAFE_INTEGER+1,-0])
    assert.throws(()=>canonical(v));
});
test('server health is alive but non-publishing and has no enabled publisher',async()=>{
  const pool={connect:async()=>{throw Error('should not connect')},
    query:async()=>{throw Error('should not query')}};
  const server=createLedgerHttpService({pool,secret:SECRET,
    expectedClient:CLIENT,nowSeconds:()=>NOW});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    const port=server.address().port;
    const v=await fetch('http://127.0.0.1:'+port+'/healthz');
    const body=await v.json();
    assert.equal(v.status,200);
    assert.equal(body.release_authorized,false);
    assert.equal(body.release_publisher_enabled,false);
    assert.equal(body.classification,'SERVICE_ALIVE_NOT_A_RELEASE_AUTHORITY');
  }finally{await new Promise(resolve=>server.close(resolve));}
});
for(const [name,method,path] of [
 ['unknown-get','GET','/v1/claim'],['unknown-post','POST','/admin'],
 ['case-variant','POST','/V1/claim'],['query-extension','POST','/v1/claim?x=1']
]){
  test('HTTP server denies unknown surface '+name,async()=>{
    const pool={connect:async()=>{throw Error('should not connect')},
      query:async()=>{throw Error('should not query')}};
    const server=createLedgerHttpService({pool,secret:SECRET,
      expectedClient:CLIENT,nowSeconds:()=>NOW});
    await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
    try{
      const port=server.address().port;
      const v=await fetch('http://127.0.0.1:'+port+path,{method});
      assert.equal(v.status,404);
      assert.equal((await v.json()).release_authorized,false);
    }finally{await new Promise(resolve=>server.close(resolve));}
  });
}
