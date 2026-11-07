import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, linkSync,
  chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { bootstrapLocalLedger, readLocalLedger,
  consumeLocalAdvisoryClaim, consumeSignedIntent } from '../tools/release-ledger-v1/sqlite-ledger.mjs';
import { trustKeyId, PAYLOAD_TYPE, dssePAE } from '../tools/release-assurance-v1/verify.mjs';
import { REGISTRY_TYPE, registryPAE } from '../tools/release-trust-registry-v1/verify.mjs';
import { CHECKPOINT_TYPE, INTENT_TYPE } from '../tools/release-checkpoint-v1/verify.mjs';

const ZERO='0'.repeat(64);
const hash=b=>createHash('sha256').update(b).digest('hex');
const LEDGER='atto-local-ledger';
const REPO='ores-truffle-oreslang/oreslang-cli';
const HEAD='a'.repeat(40),TREE='b'.repeat(40);
const ARTIFACT=Buffer.from('SYNTHETIC ATTO TEST ARTIFACT');
function fresh(){
  const dir=mkdtempSync(join(tmpdir(),'atto-ledger-test-'));
  const file=join(dir,'atto.sqlite');
  const boot=bootstrapLocalLedger(file,LEDGER);
  assert.equal(boot.classification,'LOCAL_LEDGER_BOOTSTRAPPED',JSON.stringify(boot));
  return {dir,file,close:()=>rmSync(dir,{recursive:true,force:true})};
}
const snapshot=()=>({ledger_id:LEDGER,sequence:0,
  last_intent_sha256:ZERO,last_nonce:ZERO});
const claim=(n=1)=>({ledger_id:LEDGER,sequence:1,
  previous_intent_sha256:ZERO,intent_sha256:n.toString(16).padStart(64,'0'),
  nonce:(n+1000).toString(16).padStart(64,'0'),repository:REPO,
  head_sha:HEAD,artifact_sha256:hash(ARTIFACT),policy_sequence:8});
const copy=x=>structuredClone(x);
const denied=v=>{
  assert.equal(v.classification,'DENIED',JSON.stringify(v));
  assert.equal(v.ledger_cas_committed,false);
  assert.equal(v.release_authorized,false);
  assert.equal(v.authenticated_github,false);
};
function scoped(name,fn){
  test(name,async()=>{const s=fresh();try{await fn(s);}finally{s.close();}});
}
const worker=resolve(import.meta.dirname,'../tools/release-ledger-v1/claim.mjs');
const cli=(file,kind,body,env={})=>spawnSync(process.execPath,
  [worker,file,kind,Buffer.from(JSON.stringify(body)).toString('base64')],
  {encoding:'utf8',env:{...process.env,...env},timeout:30000});
function child(file,body,env={}){
  return new Promise((resolvePromise,reject)=>{
    const proc=spawn(process.execPath,[worker,file,'consume',
      Buffer.from(JSON.stringify(body)).toString('base64')],
      {env:{...process.env,...env},stdio:['ignore','pipe','pipe']});
    let out='',err='';
    proc.stdout.on('data',chunk=>out+=chunk);
    proc.stderr.on('data',chunk=>err+=chunk);
    proc.on('error',reject);
    proc.on('close',(code,signal)=>{
      try{resolvePromise({code,signal,out,err,
        verdict:out.trim()?JSON.parse(out):null});}catch(e){reject(e);}
    });
  });
}
scoped('bootstrap returns genesis and never authorizes release',({file})=>{
  const v=readLocalLedger(file,LEDGER);
  assert.equal(v.classification,'LOCAL_LEDGER_SNAPSHOT');
  assert.equal(v.sequence,0);assert.equal(v.last_intent_sha256,ZERO);
  assert.equal(v.release_authorized,false);
  assert.equal(v.ledger_cas_committed,false);
});
scoped('bootstrap cannot overwrite or reset an existing ledger',({file})=>{
  denied(bootstrapLocalLedger(file,LEDGER));
  const a=consumeLocalAdvisoryClaim(file,snapshot(),claim());
  assert.equal(a.ledger_cas_committed,true);
  denied(bootstrapLocalLedger(file,LEDGER));
  assert.equal(readLocalLedger(file,LEDGER).sequence,1);
});
scoped('valid local CAS changes both event and high-water atomically',({file})=>{
  const v=consumeLocalAdvisoryClaim(file,snapshot(),claim());
  assert.equal(v.classification,'LOCAL_LEDGER_CAS_COMMITTED',JSON.stringify(v));
  assert.equal(v.ledger_cas_committed,true);
  assert.equal(v.release_authorized,false);
  const st=readLocalLedger(file,LEDGER);
  assert.equal(st.sequence,1);
  assert.equal(st.last_intent_sha256,claim().intent_sha256);
  assert.equal(st.last_nonce,claim().nonce);
});
scoped('second use of the same signed intent sequence is always denied',({file})=>{
  const a=consumeLocalAdvisoryClaim(file,snapshot(),claim());
  assert.equal(a.ledger_cas_committed,true);
  denied(consumeLocalAdvisoryClaim(file,snapshot(),claim()));
});
scoped('strictly increasing local sequences maintain an ordered chain',({file})=>{
  for(let i=1;i<=16;i++){
    const s=readLocalLedger(file,LEDGER);
    const c=claim(i);
    c.sequence=i;c.previous_intent_sha256=s.last_intent_sha256;
    const v=consumeLocalAdvisoryClaim(file,{
      ledger_id:s.ledger_id,sequence:s.sequence,
      last_intent_sha256:s.last_intent_sha256,last_nonce:s.last_nonce
    },c);
    assert.equal(v.classification,'LOCAL_LEDGER_CAS_COMMITTED',JSON.stringify(v));
  }
  assert.equal(readLocalLedger(file,LEDGER).sequence,16);
});
const claimFields=Object.keys(claim());
for(const field of claimFields){
  scoped('reject missing claim field '+field,({file})=>{
    const c=claim();delete c[field];
    denied(consumeLocalAdvisoryClaim(file,snapshot(),c));
    assert.equal(readLocalLedger(file,LEDGER).sequence,0);
  });
}
for(const field of Object.keys(snapshot())){
  scoped('reject missing pinned snapshot field '+field,({file})=>{
    const pin=snapshot();delete pin[field];
    denied(consumeLocalAdvisoryClaim(file,pin,claim()));
  });
}
const badClaim=[
 ['sequence-zero','sequence',0],['sequence-negative','sequence',-1],
 ['sequence-fractional','sequence',1.1],['sequence-string','sequence','1'],
 ['sequence-nan','sequence',null],['sequence-overflow','sequence',4097],
 ['sequence-infinity','sequence',1e100],['sequence-maxsafe','sequence',Number.MAX_SAFE_INTEGER],
 ['ledger-short','ledger_id','x'],['ledger-uppercase','ledger_id','ATTO'],
 ['ledger-cross-scope','ledger_id','other-ledger'],
 ['ledger-null','ledger_id',null],['ledger-object','ledger_id',{}],
 ['previous-uppercase','previous_intent_sha256','A'.repeat(64)],
 ['previous-short','previous_intent_sha256','a'.repeat(63)],
 ['previous-nonhex','previous_intent_sha256','z'.repeat(64)],
 ['intent-zero-hash','intent_sha256',ZERO],
 ['intent-short','intent_sha256','0'],
 ['intent-nonhex','intent_sha256','g'.repeat(64)],
 ['intent-uppercase','intent_sha256','A'.repeat(64)],
 ['nonce-zero','nonce',ZERO],['nonce-short','nonce','a'],
 ['nonce-upper','nonce','A'.repeat(64)],['nonce-negative','nonce',-1],
 ['repo-wrong-org','repository','attacker/oreslang-cli'],
 ['repo-upper','repository','ORES-TRUFFLE-ORESLANG/oreslang-cli'],
 ['repo-escape','repository','ores-truffle-oreslang/../../x'],
 ['repo-empty','repository',''],
 ['head-missing','head_sha',null],['head-short','head_sha','a'.repeat(39)],
 ['head-uppercase','head_sha','A'.repeat(40)],
 ['artifact-short','artifact_sha256','a'.repeat(63)],
 ['artifact-nonhex','artifact_sha256','Z'.repeat(64)],
 ['policy-zero','policy_sequence',0],['policy-negative','policy_sequence',-4],
 ['policy-fractional','policy_sequence',1.7],
 ['policy-string','policy_sequence','8'],
];
for(const [name,field,value] of badClaim){
  scoped('reject invalid claim '+name,({file})=>{
    const c=claim();c[field]=value;
    denied(consumeLocalAdvisoryClaim(file,snapshot(),c));
    assert.equal(readLocalLedger(file,LEDGER).sequence,0);
  });
}
const badPins=[
 ['seq-negative','sequence',-1],['seq-string','sequence','0'],
 ['seq-fraction','sequence',0.1],['seq-excess','sequence',4097],
 ['id-wrong','ledger_id','wrong-ledger'],['id-uppercase','ledger_id','ATTO'],
 ['id-null','ledger_id',null],['prev-upper','last_intent_sha256','A'.repeat(64)],
 ['prev-short','last_intent_sha256','a'.repeat(60)],
 ['nonce-bad','last_nonce','f'],['nonce-upper','last_nonce','F'.repeat(64)],
 ['nonce-nonzero-genesis','last_nonce','1'.repeat(64)],
 ['prev-nonzero-genesis','last_intent_sha256','1'.repeat(64)]
];
for(const [name,field,value] of badPins){
  scoped('reject invalid pin '+name,({file})=>{
    const pin=snapshot();pin[field]=value;
    denied(consumeLocalAdvisoryClaim(file,pin,claim()));
    assert.equal(readLocalLedger(file,LEDGER).sequence,0);
  });
}
scoped('reject unknown claim object fields',({file})=>{
  denied(consumeLocalAdvisoryClaim(file,snapshot(),{...claim(),authorized:true}));
});
scoped('reject unknown pin object fields',({file})=>{
  denied(consumeLocalAdvisoryClaim(file,{...snapshot(),trusted:true},claim()));
});
scoped('reject repeated previous nonce even with a different intent',({file})=>{
  let c=claim();c.nonce=ZERO;
  denied(consumeLocalAdvisoryClaim(file,snapshot(),c));
});
scoped('deny sequence skipping without mutation',({file})=>{
  const c=claim();c.sequence=2;
  denied(consumeLocalAdvisoryClaim(file,snapshot(),c));
});
scoped('reject original head malformed without state change',({file})=>{
  const c=claim();c.head_sha='a'.repeat(41);
  denied(consumeLocalAdvisoryClaim(file,snapshot(),c));
});
for(let i=2;i<=35;i++){
  scoped('race/replay variation '+i+' cannot reuse a consumed high-water',({file})=>{
    const first=consumeLocalAdvisoryClaim(file,snapshot(),claim(1));
    assert.equal(first.ledger_cas_committed,true);
    const alternative=claim(i);
    denied(consumeLocalAdvisoryClaim(file,snapshot(),alternative));
    assert.equal(readLocalLedger(file,LEDGER).sequence,1);
  });
}
scoped('independent process reopens durable committed state',({file})=>{
  const c=cli(file,'consume',{pin:snapshot(),claim:claim()});
  assert.equal(c.status,3,c.stderr+' '+c.stdout);
  assert.equal(JSON.parse(c.stdout).release_authorized,false);
  const s=cli(file,'read',{ledger_id:LEDGER});
  assert.equal(s.status,3,s.stderr+' '+s.stdout);
  assert.equal(JSON.parse(s.stdout).sequence,1);
});
scoped('many competing processes: exactly one CAS winner',async({file})=>{
  const jobs=Array.from({length:20},(_,i)=>child(file,
    {pin:snapshot(),claim:claim(i+1)}));
  const result=await Promise.all(jobs);
  const winners=result.filter(x=>x.verdict?.classification==='LOCAL_LEDGER_CAS_COMMITTED');
  const losers=result.filter(x=>x.verdict?.classification==='DENIED');
  assert.equal(winners.length,1,JSON.stringify(result));
  assert.equal(losers.length,19);
  assert(result.every(x=>x.verdict?.release_authorized===false));
  assert.equal(readLocalLedger(file,LEDGER).sequence,1);
});
for(const fault of ['BEFORE_INSERT','AFTER_INSERT','BEFORE_COMMIT','AFTER_COMMIT']){
  scoped('process crash and recovery at '+fault,({file})=>{
    const crashed=cli(file,'consume',{pin:snapshot(),claim:claim()},{
      ATTO_LEDGER_TEST_FAULT:fault});
    assert.equal(crashed.status,86,crashed.stderr+' '+crashed.stdout);
    const s=readLocalLedger(file,LEDGER);
    assert.equal(s.classification,'LOCAL_LEDGER_SNAPSHOT',JSON.stringify(s));
    const wasCommitted=fault==='AFTER_COMMIT';
    assert.equal(s.sequence,wasCommitted?1:0);
    const retry=consumeLocalAdvisoryClaim(file,snapshot(),claim());
    assert.equal(retry.classification,wasCommitted?'DENIED':'LOCAL_LEDGER_CAS_COMMITTED');
    assert.equal(readLocalLedger(file,LEDGER).sequence,1);
  });
}
scoped('symlink ledger file denied',({dir,file})=>{
  const alias=join(dir,'link.sqlite');symlinkSync(file,alias);
  denied(readLocalLedger(alias,LEDGER));
  denied(consumeLocalAdvisoryClaim(alias,snapshot(),claim()));
});
scoped('hardlink ledger file denied',({dir,file})=>{
  const alias=join(dir,'hard.sqlite');linkSync(file,alias);
  denied(readLocalLedger(file,LEDGER));
  denied(readLocalLedger(alias,LEDGER));
});
scoped('world-readable ledger file denied',({file})=>{
  chmodSync(file,0o644);
  denied(readLocalLedger(file,LEDGER));
});
scoped('world-readable ledger directory denied',({dir,file})=>{
  chmodSync(dir,0o755);
  denied(readLocalLedger(file,LEDGER));
  chmodSync(dir,0o700);
});
scoped('symlink parent directory denied',({dir,file})=>{
  const alias=join(tmpdir(),'atto-ledger-link-'+hash(Buffer.from(dir)).slice(0,12));
  symlinkSync(dir,alias);
  try{denied(readLocalLedger(join(alias,'atto.sqlite'),LEDGER));}
  finally{rmSync(alias,{force:true});}
});
scoped('corrupt high-water state denies reads and consumes',({file})=>{
  const db=new DatabaseSync(file);
  db.prepare('UPDATE ledger_state SET last_nonce=?').run('f'.repeat(64));
  db.close();
  denied(readLocalLedger(file,LEDGER));
  denied(consumeLocalAdvisoryClaim(file,snapshot(),claim()));
});
scoped('missing ledger row never silently initializes',({file})=>{
  const db=new DatabaseSync(file);
  db.exec('DELETE FROM ledger_state');
  db.close();
  denied(readLocalLedger(file,LEDGER));
  denied(consumeLocalAdvisoryClaim(file,snapshot(),claim()));
});
scoped('schema tampering denies instead of rebuilding table',({file})=>{
  const db=new DatabaseSync(file);
  db.exec('DROP TABLE ledger_events');
  db.close();
  denied(readLocalLedger(file,LEDGER));
  denied(consumeLocalAdvisoryClaim(file,snapshot(),claim()));
});
scoped('wrong user_version denies instead of reinitializing',({file})=>{
  const db=new DatabaseSync(file);
  db.exec('PRAGMA user_version=2');
  db.close();
  denied(readLocalLedger(file,LEDGER));
});
scoped('failed bootstrap with preexisting file does not replace bytes',({dir})=>{
  const fake=join(dir,'fake.sqlite');writeFileSync(fake,Buffer.from('tampered'),{mode:0o600});
  denied(bootstrapLocalLedger(fake,LEDGER));
});
test('absent database denied without automatic creation',()=>{
  const dir=mkdtempSync(join(tmpdir(),'atto-missing-ledger-'));
  try{
    denied(readLocalLedger(join(dir,'missing.sqlite'),LEDGER));
    denied(consumeLocalAdvisoryClaim(join(dir,'missing.sqlite'),snapshot(),claim()));
  }finally{rmSync(dir,{recursive:true,force:true});}
});
test('bootstrap with invalid ledger name is denied',()=>{
  const dir=mkdtempSync(join(tmpdir(),'atto-bad-ledger-'));
  try{denied(bootstrapLocalLedger(join(dir,'atto.sqlite'),'../x'));}
  finally{rmSync(dir,{recursive:true,force:true});}
});
test('world-readable directory cannot bootstrap ledger',()=>{
  const dir=mkdtempSync(join(tmpdir(),'atto-bad-dir-'));
  chmodSync(dir,0o755);
  try{denied(bootstrapLocalLedger(join(dir,'atto.sqlite'),LEDGER));}
  finally{chmodSync(dir,0o700);rmSync(dir,{recursive:true,force:true});}
});
test('CLI rejects usage, never returns a release-authorized exit zero',()=>{
  const v=spawnSync(process.execPath,[worker],{encoding:'utf8'});
  assert.equal(v.status,2);
  const firstJson=v.stderr.split(String.fromCharCode(10)).find(s=>s.startsWith('{'));
  assert.equal(JSON.parse(firstJson).release_authorized,false);
});

// Full in-memory synthetic signature fixture bridges #153 + #154 + #159
// into the durable local ledger. No private or production signer is used.
const kp=()=>generateKeyPairSync('ed25519');
const root=kp(),candidateSigner=kp(),governance=kp(),approver=kp();
const pem=k=>k.publicKey.export({format:'pem',type:'spki'});
const keyid=k=>trustKeyId(pem(k)).keyid;
const delegated=(k,role)=>({keyid:keyid(k),spki_pem:pem(k),role,repository:REPO,
  not_before:'2026-01-01T00:00:00Z',not_after:'2028-01-01T00:00:00Z',revoked_at:null});
function signed(type,payload,key){
  const bytes=Buffer.from(JSON.stringify(payload));
  const message=(type===PAYLOAD_TYPE)?dssePAE(type,bytes):
    (type===REGISTRY_TYPE)?registryPAE(bytes):
    Buffer.concat([Buffer.from('DSSEv1 '+Buffer.byteLength(type)+' '),
      Buffer.from(type),Buffer.from(' '+bytes.length+' '),bytes]);
  return Buffer.from(JSON.stringify({payloadType:type,payload:bytes.toString('base64'),
    signatures:[{keyid:keyid(key),
      sig:sign(null,message,key.privateKey).toString('base64')}]}));
}
function signedFixture(){
  const now='2026-11-07T00:01:30Z';
  const registry=signed(REGISTRY_TYPE,{schema:'atto.trust-registry.v1',
    policy_id:'atto-release-policy',sequence:8,
    not_before:'2026-01-01T00:00:00Z',not_after:'2029-01-01T00:00:00Z',
    keys:[delegated(candidateSigner,'candidate-signing'),
      delegated(governance,'governance-review'),
      delegated(approver,'release-approval')]},root);
  const manifest={schema:'atto.release-assurance.v1',
    subject:{repository:REPO,head_sha:HEAD,tree_sha:TREE,
      artifact:{filename:'release.tgz',size:ARTIFACT.length,sha256:hash(ARTIFACT)}},
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
    backends:['java','llvm','net','wasm','forge'].map((backend,i)=>({
      backend,repository:'ores-truffle-oreslang/oreslang-source.'+backend,
      head_sha:String(i+1).repeat(40),tree_sha:String(i+5).repeat(40),
      classification:'EXECUTED_COMPILER_GUEST',run_id:100+i,
      run_attempt:1,job_id:200+i,runner_id:300+i,executed_steps:3,
      toolchain_sha256:'e'.repeat(64),fixture_sha256:'f'.repeat(64),
      output_sha256:'d'.repeat(64)}))};
  const candidateEnvelopeBytes=signed(PAYLOAD_TYPE,manifest,candidateSigner);
  const cp=signed(CHECKPOINT_TYPE,{schema:'atto.release-checkpoint.v1',
    repository:REPO,policy_id:'atto-release-policy',policy_sequence:8,
    registry_sha256:hash(registry),ledger_id:LEDGER,
    last_sequence:0,last_intent_sha256:ZERO,last_nonce:ZERO,
    observed_at:'2026-11-07T00:00:00Z',
    expires_at:'2026-11-07T00:04:00Z'},governance);
  const intent=signed(INTENT_TYPE,{schema:'atto.release-intent.v1',
    repository:REPO,head_sha:HEAD,tree_sha:TREE,artifact_sha256:hash(ARTIFACT),
    candidate_envelope_sha256:hash(candidateEnvelopeBytes),policy_id:'atto-release-policy',
    policy_sequence:8,registry_sha256:hash(registry),ledger_id:LEDGER,
    sequence:1,previous_intent_sha256:ZERO,nonce:'3'.repeat(64),
    issued_at:'2026-11-07T00:01:00Z',
    expires_at:'2026-11-07T00:03:00Z'},approver);
  return {registryEnvelopeBytes:registry,trustedRootPem:pem(root),
    candidateEnvelopeBytes,artifactBytes:ARTIFACT,
    expected:{policy_id:'atto-release-policy',minimum_sequence:8,
      root_keyid:keyid(root),repository:REPO,head_sha:HEAD,tree_sha:TREE,
      artifact_sha256:hash(ARTIFACT),envelope_sha256:hash(candidateEnvelopeBytes)},
    checkpointEnvelopeBytes:cp,intentEnvelopeBytes:intent,
    ledgerPin:{schema:'atto.release-link-pin.v1',
      checkpoint_sha256:hash(cp),intent_sha256:hash(intent),
      ledger_id:LEDGER,next_sequence:1,previous_intent_sha256:ZERO},
    now};
}
scoped('real signed fixture can consume one local CAS, never authorize release',({file})=>{
  const v=consumeSignedIntent(file,signedFixture());
  assert.equal(v.classification,'LOCAL_LEDGER_CAS_COMMITTED',JSON.stringify(v));
  assert.equal(v.ledger_cas_committed,true);
  assert.equal(v.release_authorized,false);
  assert.equal(v.authenticated_github,false);
  assert.equal(v.compiler_guest_parity_proven,false);
  assert.equal(readLocalLedger(file,LEDGER).sequence,1);
});
scoped('replaying identical valid signed intent after commit is rejected',({file})=>{
  const f=signedFixture();
  assert.equal(consumeSignedIntent(file,f).ledger_cas_committed,true);
  denied(consumeSignedIntent(file,f));
  assert.equal(readLocalLedger(file,LEDGER).sequence,1);
});
scoped('tampered signed intent rejected before any local storage mutation',({file})=>{
  const f=signedFixture();
  f.intentEnvelopeBytes=Buffer.from('{}');
  denied(consumeSignedIntent(file,f));
  assert.equal(readLocalLedger(file,LEDGER).sequence,0);
});
scoped('tampered candidate or artifact rejected before local mutation',({file})=>{
  const f=signedFixture();
  f.artifactBytes=Buffer.from('tampered');
  denied(consumeSignedIntent(file,f));
  assert.equal(readLocalLedger(file,LEDGER).sequence,0);
});


// Phase 2 audit: a ledger is a single repository-scoped monotonic policy
// history, not a bag of independently acceptable signed candidates.
function secondAgainstCommittedFirst(file,change){
  const first=consumeLocalAdvisoryClaim(file,snapshot(),claim(1));
  assert.equal(first.classification,'LOCAL_LEDGER_CAS_COMMITTED');
  const current=readLocalLedger(file,LEDGER);
  const pin={ledger_id:current.ledger_id,sequence:current.sequence,
    last_intent_sha256:current.last_intent_sha256,last_nonce:current.last_nonce};
  const next=claim(2);next.sequence=2;
  next.previous_intent_sha256=pin.last_intent_sha256;
  change(next,pin);
  const verdict=consumeLocalAdvisoryClaim(file,pin,next);
  return {verdict,after:readLocalLedger(file,LEDGER)};
}
scoped('deny policy generation rollback after existing release',({file})=>{
  const {verdict,after}=secondAgainstCommittedFirst(file,c=>{c.policy_sequence=7;});
  denied(verdict);
  assert.equal(after.sequence,1);
});
scoped('deny zero or lower policy generation after a different first policy',({file})=>{
  const {verdict,after}=secondAgainstCommittedFirst(file,c=>{c.policy_sequence=1;});
  denied(verdict);
  assert.equal(after.sequence,1);
});
scoped('deny same ledger identity reused by another repository',({file})=>{
  const {verdict,after}=secondAgainstCommittedFirst(file,c=>{
    c.repository='ores-truffle-oreslang/other-cli';
  });
  denied(verdict);
  assert.equal(after.sequence,1);
});
scoped('deny case-different repository alias across ledger history',({file})=>{
  const {verdict,after}=secondAgainstCommittedFirst(file,c=>{
    c.repository='ores-truffle-oreslang/Oreslang-cli';
  });
  denied(verdict);
  assert.equal(after.sequence,1);
});
scoped('postcommit observer exception must not misreport a consumed claim as DENIED',({file})=>{
  const v=consumeLocalAdvisoryClaim(file,snapshot(),claim(),phase=>{
    if(phase==='AFTER_COMMIT')throw Error('observer post-commit failure');
  });
  assert.equal(v.classification,'LOCAL_LEDGER_CAS_COMMITTED',JSON.stringify(v));
  assert.equal(v.release_authorized,false);
  assert.equal(readLocalLedger(file,LEDGER).sequence,1);
});
scoped('postcommit file permission drift cannot be classified as clean precommit rejection',({file})=>{
  const v=consumeLocalAdvisoryClaim(file,snapshot(),claim(),phase=>{
    if(phase==='AFTER_COMMIT')chmodSync(file,0o644);
  });
  assert.notEqual(v.classification,'DENIED',JSON.stringify(v));
  assert.equal(v.release_authorized,false);
  chmodSync(file,0o600);
  assert.equal(readLocalLedger(file,LEDGER).sequence,1);
});
scoped('historical row policy decrease detected on ledger reopen',({file})=>{
  let first=consumeLocalAdvisoryClaim(file,snapshot(),claim(1));
  assert.equal(first.ledger_cas_committed,true);
  const current=readLocalLedger(file,LEDGER);
  const c=claim(2);c.sequence=2;c.previous_intent_sha256=current.last_intent_sha256;
  c.policy_sequence=9;
  const pin={ledger_id:current.ledger_id,sequence:current.sequence,
    last_intent_sha256:current.last_intent_sha256,last_nonce:current.last_nonce};
  assert.equal(consumeLocalAdvisoryClaim(file,pin,c).ledger_cas_committed,true);
  const db=new DatabaseSync(file);
  db.prepare('UPDATE ledger_events SET policy_sequence=? WHERE sequence=?').run(7,2);
  db.close();
  denied(readLocalLedger(file,LEDGER));
});
scoped('historical row cross-repository pivot detected on ledger reopen',({file})=>{
  assert.equal(consumeLocalAdvisoryClaim(file,snapshot(),claim(1)).ledger_cas_committed,true);
  const current=readLocalLedger(file,LEDGER);
  const c=claim(2);c.sequence=2;c.previous_intent_sha256=current.last_intent_sha256;
  const pin={ledger_id:current.ledger_id,sequence:current.sequence,
    last_intent_sha256:current.last_intent_sha256,last_nonce:current.last_nonce};
  assert.equal(consumeLocalAdvisoryClaim(file,pin,c).ledger_cas_committed,true);
  const db=new DatabaseSync(file);
  db.prepare('UPDATE ledger_events SET repository=? WHERE sequence=?').run('ores-truffle-oreslang/other-cli',2);
  db.close();
  denied(readLocalLedger(file,LEDGER));
});
