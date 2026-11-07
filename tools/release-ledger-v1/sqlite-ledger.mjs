#!/usr/bin/env node
// LOCAL, single-host SQLite release intent ledger. Non-authorizing by design.
import { DatabaseSync } from 'node:sqlite';
import { constants as C, closeSync, fstatSync, lstatSync, openSync, statSync } from 'node:fs';
import { basename, dirname, isAbsolute, resolve } from 'node:path';
import { verifySequenceLinkedCandidate } from '../release-checkpoint-v1/verify.mjs';

const H64=/^[0-9a-f]{64}$/, H40=/^[0-9a-f]{40}$/;
const ID=/^[a-z][a-z0-9._-]{2,63}$/;
const REPO=/^ores-truffle-oreslang\/[a-z0-9][a-z0-9._-]{0,119}$/;
const ZERO='0'.repeat(64), MAX=4096;
const obj=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const keys=(v,n)=>obj(v)&&Object.keys(v).length===n.length&&n.every(k=>Object.hasOwn(v,k));
const h=v=>typeof v==='string'&&H64.test(v);
const pos=v=>Number.isSafeInteger(v)&&v>0;
const deny=reason=>({classification:'DENIED',reason,ledger_cas_committed:false,
  release_authorized:false,authenticated_github:false,compiler_guest_parity_proven:false});
const result=(classification,fields)=>({...fields,classification,release_authorized:false,
  authenticated_github:false,compiler_guest_parity_proven:false});
const snapshotValid=s=>keys(s,['ledger_id','sequence','last_intent_sha256','last_nonce'])&&
  ID.test(s.ledger_id)&&Number.isSafeInteger(s.sequence)&&s.sequence>=0&&s.sequence<=MAX&&
  h(s.last_intent_sha256)&&h(s.last_nonce)&&
  (s.sequence===0?(s.last_intent_sha256===ZERO&&s.last_nonce===ZERO):
    (s.last_intent_sha256!==ZERO&&s.last_nonce!==ZERO));
const claimValid=c=>keys(c,['ledger_id','sequence','previous_intent_sha256',
    'intent_sha256','nonce','repository','head_sha','artifact_sha256','policy_sequence'])&&
  ID.test(c.ledger_id)&&pos(c.sequence)&&c.sequence<=MAX&&
  h(c.previous_intent_sha256)&&h(c.intent_sha256)&&c.intent_sha256!==ZERO&&
  h(c.nonce)&&c.nonce!==ZERO&&REPO.test(c.repository)&&
  typeof c.head_sha==='string'&&H40.test(c.head_sha)&&
  h(c.artifact_sha256)&&pos(c.policy_sequence);
const stateSql=[
'CREATE TABLE ledger_state (',
'ledger_id TEXT PRIMARY KEY,',
'sequence INTEGER NOT NULL CHECK(sequence>=0 AND sequence<=4096),',
'last_intent_sha256 TEXT NOT NULL,',
'last_nonce TEXT NOT NULL',
') STRICT'].join(' ');
const eventSql=[
'CREATE TABLE ledger_events (',
'ledger_id TEXT NOT NULL,',
'sequence INTEGER NOT NULL CHECK(sequence>0 AND sequence<=4096),',
'previous_intent_sha256 TEXT NOT NULL,',
'intent_sha256 TEXT NOT NULL,',
'nonce TEXT NOT NULL,',
'repository TEXT NOT NULL,',
'head_sha TEXT NOT NULL,',
'artifact_sha256 TEXT NOT NULL,',
'policy_sequence INTEGER NOT NULL CHECK(policy_sequence>0),',
'PRIMARY KEY (ledger_id,sequence),',
'UNIQUE (ledger_id,intent_sha256),',
'UNIQUE (ledger_id,nonce),',
'FOREIGN KEY (ledger_id) REFERENCES ledger_state(ledger_id)',
') STRICT'].join(' ');

// A private same-host directory prevents ordinary link attacks, but is not
// a defense against compromise by the same Unix identity or disk rollback.
function admit(file, create=false) {
  if(typeof file!=='string'||!isAbsolute(file)||resolve(file)!==file||
      !/^[a-z0-9][a-z0-9._-]{0,99}\.sqlite$/.test(basename(file)))
    throw Error('INVALID_LEDGER_PATH');
  const dir=lstatSync(dirname(file));
  if(!dir.isDirectory()||dir.isSymbolicLink()||(dir.mode&0o777)!==0o700||
      (process.getuid&&dir.uid!==process.getuid()))
    throw Error('UNTRUSTED_LEDGER_DIRECTORY');
  if(!create){
    const f=lstatSync(file);
    if(!f.isFile()||f.isSymbolicLink()||f.nlink!==1||(f.mode&0o777)!==0o600||
        (process.getuid&&f.uid!==process.getuid()))
      throw Error('UNTRUSTED_LEDGER_FILE');
  }
}
function checkSame(file,original){
  admit(file);
  const now=statSync(file);
  if(now.dev!==original.dev||now.ino!==original.ino||
      now.nlink!==1||(now.mode&0o777)!==0o600)
    throw Error('LEDGER_FILE_REPLACED');
}
function openLedger(file) {
  admit(file);
  const first=statSync(file);
  const db=new DatabaseSync(file,{timeout:10000});
  try {
    db.exec('PRAGMA busy_timeout=10000;PRAGMA foreign_keys=ON;PRAGMA synchronous=FULL;');
    if(db.prepare('PRAGMA journal_mode').get().journal_mode!=='wal'||
       db.prepare('PRAGMA synchronous').get().synchronous!==2||
       db.prepare('PRAGMA foreign_keys').get().foreign_keys!==1||
       db.prepare('PRAGMA user_version').get().user_version!==1||
       db.prepare('PRAGMA quick_check').get().quick_check!=='ok')
      throw Error('CORRUPT_OR_UNSAFE_LEDGER');
    for(const [name,sql] of [['ledger_state',stateSql],['ledger_events',eventSql]]){
      const found=db.prepare('SELECT sql FROM sqlite_master WHERE type=? AND name=?')
        .get('table',name);
      if(!found||found.sql!==sql)throw Error('LEDGER_SCHEMA_MISMATCH');
    }
    checkSame(file,first);
    return {db,first};
  }catch(e){db.close();throw e;}
}
function guarded(file,fn){
  const {db,first}=openLedger(file);
  try {
    const v=fn(db);
    checkSame(file,first);
    return v;
  }finally{db.close();}
}
function state(db,id){
  const row=db.prepare('SELECT * FROM ledger_state WHERE ledger_id=?').get(id);
  if(!row)throw Error('LEDGER_NOT_BOOTSTRAPPED');
  const s={ledger_id:row.ledger_id,sequence:row.sequence,
    last_intent_sha256:row.last_intent_sha256,last_nonce:row.last_nonce};
  if(!snapshotValid(s))throw Error('CORRUPT_HIGH_WATER_STATE');
  const events=db.prepare('SELECT * FROM ledger_events WHERE ledger_id=? ORDER BY sequence')
    .all(id);
  if(events.length!==s.sequence||events.length>MAX)throw Error('BROKEN_EVENT_COUNT');
  let prev=ZERO, repoScope=null, policyFloor=0;
  for(const [i,e] of events.entries()){
    if(!claimValid(e)||e.sequence!==i+1||e.ledger_id!==id||
      e.previous_intent_sha256!==prev)throw Error('BROKEN_EVENT_CHAIN');
    // A logical release ledger cannot change ownership or roll back its
    // governing policy generation at a later committed sequence.
    if(repoScope!==null && (e.repository!==repoScope||
       e.policy_sequence<policyFloor))
      throw Error('BROKEN_LEDGER_SCOPE_OR_POLICY_MONOTONICITY');
    repoScope=e.repository;policyFloor=e.policy_sequence;
    prev=e.intent_sha256;
  }
  if(s.last_intent_sha256!==prev||
    (events.length>0&&s.last_nonce!==events.at(-1).nonce))
    throw Error('BROKEN_HIGH_WATER_LINK');
  return s;
}
export function bootstrapLocalLedger(file,id) {
  try {
    if(!ID.test(id))throw Error('INVALID_LEDGER_ID');
    admit(file,true);
    const fd=openSync(file,C.O_WRONLY|C.O_CREAT|C.O_EXCL|C.O_NOFOLLOW,0o600);
    try {const f=fstatSync(fd);if(!f.isFile()||f.nlink!==1)throw Error('UNSAFE_FILE');}
    finally{closeSync(fd);}
    const db=new DatabaseSync(file,{timeout:10000});
    try {
      db.exec('PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;PRAGMA foreign_keys=ON;');
      if(db.prepare('PRAGMA journal_mode').get().journal_mode!=='wal'||
          db.prepare('PRAGMA synchronous').get().synchronous!==2)
        throw Error('UNSAFE_JOURNAL_MODE');
      db.exec('BEGIN IMMEDIATE');
      try {
        db.exec(stateSql+';'+eventSql+';PRAGMA user_version=1;');
        db.prepare('INSERT INTO ledger_state VALUES (?,0,?,?)').run(id,ZERO,ZERO);
        db.exec('COMMIT');
      }catch(e){db.exec('ROLLBACK');throw e;}
    }finally{db.close();}
    const v=readLocalLedger(file,id);
    if(v.classification!=='LOCAL_LEDGER_SNAPSHOT')throw Error(v.reason);
    return result('LOCAL_LEDGER_BOOTSTRAPPED',{...v,ledger_cas_committed:false});
  }catch(e){return deny('BOOTSTRAP_DENIED: '+e.message);}
}
export function readLocalLedger(file,id) {
  try {
    if(!ID.test(id))throw Error('INVALID_LEDGER_ID');
    return guarded(file,db=>result('LOCAL_LEDGER_SNAPSHOT',{
      ...state(db,id),ledger_cas_committed:false
    }));
  }catch(e){return deny('READ_DENIED: '+e.message);}
}
// Low-level LOCAL advisory primitive: it does not verify signatures.
// Not an authorization API. Only consumeSignedIntent is signature-bound.
export function consumeLocalAdvisoryClaim(file,pin,claim,onStep) {
  if(!snapshotValid(pin)||!claimValid(claim))return deny('INVALID_PIN_OR_CLAIM');
  if(claim.ledger_id!==pin.ledger_id||
      claim.sequence!==pin.sequence+1||
      claim.previous_intent_sha256!==pin.last_intent_sha256||
      claim.nonce===pin.last_nonce)return deny('INVALID_CLAIM_LINK');
  // A successful COMMIT followed by path drift or observer failure cannot
  // truthfully be classified as an unconsumed/cleanly DENIED sequence.
  let sqliteCommitReturned=false;
  try {
    return guarded(file,db=>{
      db.exec('BEGIN IMMEDIATE');
      let begun=true;
      try {
        const cur=state(db,pin.ledger_id);
        if(cur.sequence!==pin.sequence||
            cur.last_intent_sha256!==pin.last_intent_sha256||
            cur.last_nonce!==pin.last_nonce){
          db.exec('ROLLBACK');begun=false;
          return deny('STALE_HIGH_WATER_PIN');
        }
        if(cur.sequence>0){
          const previous=db.prepare(
            'SELECT repository,policy_sequence FROM ledger_events WHERE ledger_id=? AND sequence=?'
          ).get(cur.ledger_id,cur.sequence);
          if(!previous||claim.repository!==previous.repository||
              claim.policy_sequence<previous.policy_sequence){
            db.exec('ROLLBACK');begun=false;
            return deny('LEDGER_REPOSITORY_OR_POLICY_REGRESSION');
          }
        }
        // Optional callback is for process-crash fault injection in tests only.
        // Signature-bound consumeSignedIntent does not accept a callback.
        if(onStep)onStep('BEFORE_INSERT');
        db.prepare(['INSERT INTO ledger_events (',
          'ledger_id,sequence,previous_intent_sha256,intent_sha256,nonce,',
          'repository,head_sha,artifact_sha256,policy_sequence',
          ') VALUES (?,?,?,?,?,?,?,?,?)'].join(' ')).run(
          claim.ledger_id,claim.sequence,claim.previous_intent_sha256,
          claim.intent_sha256,claim.nonce,claim.repository,claim.head_sha,
          claim.artifact_sha256,claim.policy_sequence);
        if(onStep)onStep('AFTER_INSERT');
        const update=db.prepare(['UPDATE ledger_state SET sequence=?,',
          'last_intent_sha256=?,last_nonce=? WHERE ledger_id=? AND',
          'sequence=? AND last_intent_sha256=? AND last_nonce=?'].join(' ')).run(
          claim.sequence,claim.intent_sha256,claim.nonce,claim.ledger_id,
          pin.sequence,pin.last_intent_sha256,pin.last_nonce);
        if(update.changes!==1)throw Error('ATOMIC_CAS_FAILED');
        if(onStep)onStep('BEFORE_COMMIT');
        db.exec('COMMIT');begun=false;sqliteCommitReturned=true;
        // Post-commit test hooks are observers only. Their exceptions cannot
        // undo a committed SQLite transaction or relabel it as clean denial.
        let postcommit_observer_failed=false;
        if(onStep)try{onStep('AFTER_COMMIT');}
          catch{postcommit_observer_failed=true;}
        return result('LOCAL_LEDGER_CAS_COMMITTED',{ledger_cas_committed:true,
          ledger_id:claim.ledger_id,sequence:claim.sequence,
          intent_sha256:claim.intent_sha256,postcommit_observer_failed});
      }catch(e){
        if(begun){try{db.exec('ROLLBACK');}catch{}}
        throw e;
      }
    });
  }catch(e){
    if(sqliteCommitReturned)
      return result('LOCAL_LEDGER_COMMIT_UNVERIFIED',{
        ledger_cas_committed:null,requires_manual_reconciliation:true,
        reason:'POSTCOMMIT_STATE_UNVERIFIED: '+e.message
      });
    return deny('CAS_DENIED: '+e.message);
  }
}
// Existing #159 signature/revocation/checkpoint verifier runs BEFORE local CAS.
// Caller-provided clock/pins are still not externally authenticated.
export function consumeSignedIntent(file,input) {
  try {
    const v=verifySequenceLinkedCandidate(input);
    if(v.classification!=='SEQUENCE_LINKED_LOCAL_CANDIDATE')
      return deny('SIGNED_CHAIN_DENIED: '+v.reason);
    const signedPayload=bytes=>JSON.parse(Buffer.from(
      JSON.parse(bytes.toString('utf8')).payload,'base64').toString('utf8'));
    const c=signedPayload(input.checkpointEnvelopeBytes);
    const i=signedPayload(input.intentEnvelopeBytes);
    const pin={ledger_id:c.ledger_id,sequence:c.last_sequence,
      last_intent_sha256:c.last_intent_sha256,last_nonce:c.last_nonce};
    const claim={ledger_id:i.ledger_id,sequence:i.sequence,
      previous_intent_sha256:i.previous_intent_sha256,
      intent_sha256:v.intent_sha256,nonce:i.nonce,repository:i.repository,
      head_sha:i.head_sha,artifact_sha256:i.artifact_sha256,
      policy_sequence:i.policy_sequence};
    return consumeLocalAdvisoryClaim(file,pin,claim);
  }catch(e){return deny('SIGNED_CAS_DENIED: '+e.message);}
}
