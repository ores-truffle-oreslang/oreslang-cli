// Non-authorizing witness ledger. Requires a separate operator-run database.
// This library has NO publisher, auto-abort, privileged HTTP or independent
// consensus. CI uses two databases of ONE disposable PG server solely as test.
import {randomBytes} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {validBootstrap,validClaim,hex64,deny,local} from '../release-ledger-service-v1/protocol.mjs';

const ERROR=e=>'WITNESS_DB_ERROR: '+String(e.code||e.message||'unknown').slice(0,80);
const UNKNOWN=(reason)=>local('WITNESS_OUTCOME_UNVERIFIED',{
  ledger_cas_committed:null,witness_finalized:null,
  requires_manual_reconciliation:true,reason});
const reject=(reason)=>deny(reason,409);
const reservationFields=['ledger_id','repository','sequence','policy_sequence',
  'previous_intent_sha256','intent_sha256','nonce','client_request_id'];

export async function installWitnessForIsolatedTests(pool){
  const path=fileURLToPath(new URL('./schema.sql',import.meta.url));
  await pool.query(readFileSync(path,'utf8'));
}
export async function bootstrapWitness(pool,scope){
  if(!validBootstrap(scope))return deny('INVALID_WITNESS_BOOTSTRAP');
  const c=await pool.connect();let begun=false,commitStarted=false;
  try{
    await c.query('BEGIN');begun=true;
    await c.query('SET LOCAL lock_timeout = 10000');
    await c.query('INSERT INTO witness_state(ledger_id,repository) VALUES($1,$2) ON CONFLICT DO NOTHING',
      [scope.ledger_id,scope.repository]);
    const {rows}=await c.query('SELECT * FROM witness_state WHERE ledger_id=$1 FOR UPDATE',[scope.ledger_id]);
    if(rows.length!==1||rows[0].repository!==scope.repository){
      await c.query('ROLLBACK');begun=false;return reject('WITNESS_BOOTSTRAP_SCOPE_CONFLICT');
    }
    commitStarted=true;await c.query('COMMIT');begun=false;
    return local('WITNESS_BOOTSTRAP_CONFIRMED',{ledger_cas_committed:false,
      witness_finalized:false,ledger_id:scope.ledger_id,repository:scope.repository,
      sequence:Number(rows[0].sequence),generation:Number(rows[0].generation)});
  }catch(e){
    if(begun)try{await c.query('ROLLBACK');}catch{}
    return commitStarted?UNKNOWN('BOOTSTRAP_COMMIT_ACK_UNCERTAIN'):deny(ERROR(e),503);
  }finally{c.release();}
}
function normalizedPending(row){
  if(!row)return null;
  return Object.fromEntries(reservationFields.concat(['reservation_id','generation'])
    .map(k=>[k,['sequence','policy_sequence','generation'].includes(k)?Number(row[k]):row[k]]));
}
const equalClaim=(pending,claim)=>reservationFields.every(k=>pending[k]===claim[k]);
export async function readWitness(pool,ledgerId){
  try{
    if(typeof ledgerId!=='string'||!/^[a-z][a-z0-9._-]{2,63}$/.test(ledgerId))
      return deny('INVALID_WITNESS_LEDGER_ID');
    const c=await pool.connect();
    try{
      await c.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      const {rows}=await c.query('SELECT * FROM witness_state WHERE ledger_id=$1',[ledgerId]);
      if(rows.length!==1){
        await c.query('ROLLBACK');return deny('WITNESS_NOT_BOOTSTRAPPED',404);
      }
      const {rows:p}=await c.query('SELECT * FROM witness_pending WHERE ledger_id=$1',[ledgerId]);
      await c.query('COMMIT');
      const s=rows[0];
      return local('WITNESS_SNAPSHOT',{
        ledger_cas_committed:false,witness_finalized:false,
        ledger_id:s.ledger_id,repository:s.repository,
        sequence:Number(s.sequence),policy_sequence:Number(s.policy_sequence),
        generation:Number(s.generation),last_intent_sha256:s.last_intent_sha256,
        last_nonce:s.last_nonce,pending:normalizedPending(p[0])
      });
    }catch(e){try{await c.query('ROLLBACK');}catch{}throw e;}
    finally{c.release();}
  }catch(e){return UNKNOWN('WITNESS_READ_UNVERIFIED');}
}
export async function reserveWitness(pool,{claim,expectedGeneration}){
  if(!validClaim(claim)||!Number.isSafeInteger(expectedGeneration)||
     expectedGeneration<0||expectedGeneration>1000000)
    return deny('INVALID_WITNESS_RESERVATION');
  const c=await pool.connect();
  let begun=false,commitStarted=false;
  try{
    await c.query('BEGIN');begun=true;
    await c.query('SET LOCAL lock_timeout = 10000');
    const {rows}=await c.query('SELECT * FROM witness_state WHERE ledger_id=$1 FOR UPDATE',
      [claim.ledger_id]);
    if(rows.length!==1){
      await c.query('ROLLBACK');begun=false;return reject('WITNESS_NOT_BOOTSTRAPPED');
    }
    const s=rows[0];
    const {rows:pendingRows}=await c.query(
      'SELECT * FROM witness_pending WHERE ledger_id=$1 FOR UPDATE',[claim.ledger_id]);
    const p=normalizedPending(pendingRows[0]);
    if(s.repository!==claim.repository||Number(s.generation)!==expectedGeneration||
       claim.sequence!==Number(s.sequence)+1||
       claim.previous_intent_sha256!==s.last_intent_sha256||
       claim.policy_sequence<Number(s.policy_sequence)||
       claim.nonce===s.last_nonce){
      await c.query('ROLLBACK');begun=false;return reject('WITNESS_HIGH_WATER_OR_GENERATION_MISMATCH');
    }
    if(p){
      await c.query('ROLLBACK');begun=false;
      if(equalClaim(p,claim)&&p.generation===expectedGeneration+1)
        return local('WITNESS_ALREADY_RESERVED',{
          ledger_cas_committed:false,witness_finalized:false,
          reservation_id:p.reservation_id,ledger_id:claim.ledger_id,
          sequence:claim.sequence,generation:p.generation});
      return reject('WITNESS_PENDING_CONFLICT_REQUIRES_RECONCILIATION');
    }
    const id=randomBytes(32).toString('hex'),generation=expectedGeneration+1;
    await c.query('INSERT INTO witness_pending (ledger_id,repository,sequence,policy_sequence,previous_intent_sha256,intent_sha256,nonce,client_request_id,reservation_id,generation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [claim.ledger_id,claim.repository,claim.sequence,claim.policy_sequence,
       claim.previous_intent_sha256,claim.intent_sha256,claim.nonce,
       claim.client_request_id,id,generation]);
    commitStarted=true;await c.query('COMMIT');begun=false;
    return local('WITNESS_RESERVED',{
      ledger_cas_committed:false,witness_finalized:false,
      reservation_id:id,ledger_id:claim.ledger_id,
      sequence:claim.sequence,generation});
  }catch(e){
    if(begun)try{await c.query('ROLLBACK');}catch{}
    return commitStarted?UNKNOWN('WITNESS_RESERVATION_ACK_UNCERTAIN'):deny(ERROR(e),503);
  }finally{c.release();}
}
export async function finalizeWitness(pool,{
  claim,reservationId,independentlyReadPrimaryEvent
}){
  if(!validClaim(claim)||!hex64(reservationId)||
     typeof independentlyReadPrimaryEvent!=='function')
    return deny('INVALID_WITNESS_FINALIZATION');
  const c=await pool.connect();
  let begun=false,commitStarted=false;
  try{
    await c.query('BEGIN');begun=true;
    await c.query('SET LOCAL lock_timeout = 10000');
    const {rows}=await c.query('SELECT * FROM witness_state WHERE ledger_id=$1 FOR UPDATE',
      [claim.ledger_id]);
    if(rows.length!==1){await c.query('ROLLBACK');begun=false;
      return reject('WITNESS_NOT_BOOTSTRAPPED');}
    const s=rows[0];
    const {rows:pendingRows}=await c.query(
      'SELECT * FROM witness_pending WHERE ledger_id=$1 FOR UPDATE',[claim.ledger_id]);
    const p=normalizedPending(pendingRows[0]);
    if(!p||!equalClaim(p,claim)||p.reservation_id!==reservationId||
       p.generation!==Number(s.generation)+1||claim.sequence!==Number(s.sequence)+1||
       claim.previous_intent_sha256!==s.last_intent_sha256||
       claim.policy_sequence<Number(s.policy_sequence)){
      await c.query('ROLLBACK');begun=false;return reject('WITNESS_MISSING_OR_STALE_RESERVATION');
    }
    // Witness-owned read-only PG credentials must verify the durable primary
    // state/event. Untrusted client claims or a client-supplied "success" flag
    // cannot substitute. If primary is partitioned, pending stays forever.
    let observed=false;
    try{observed=await independentlyReadPrimaryEvent(claim)===true;}catch{}
    if(!observed){
      await c.query('ROLLBACK');begun=false;
      return UNKNOWN('PRIMARY_COMMIT_NOT_INDEPENDENTLY_VERIFIED_PENDING_FENCED');
    }
    await c.query('INSERT INTO witness_event (ledger_id,sequence,generation,repository,policy_sequence,previous_intent_sha256,intent_sha256,nonce,client_request_id,reservation_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [claim.ledger_id,claim.sequence,p.generation,claim.repository,
       claim.policy_sequence,claim.previous_intent_sha256,claim.intent_sha256,
       claim.nonce,claim.client_request_id,reservationId]);
    const changed=await c.query(
      'UPDATE witness_state SET sequence=$2,policy_sequence=$3,last_intent_sha256=$4,last_nonce=$5,generation=$6 WHERE ledger_id=$1 AND sequence=$7 AND generation=$8 AND last_intent_sha256=$9 AND policy_sequence<=$3',
      [claim.ledger_id,claim.sequence,claim.policy_sequence,
       claim.intent_sha256,claim.nonce,p.generation,claim.sequence-1,p.generation-1,
       claim.previous_intent_sha256]);
    if(changed.rowCount!==1)throw Error('WITNESS_CAS_REJECTED');
    const removed=await c.query(
      'DELETE FROM witness_pending WHERE ledger_id=$1 AND reservation_id=$2',
      [claim.ledger_id,reservationId]);
    if(removed.rowCount!==1)throw Error('WITNESS_PENDING_GONE');
    commitStarted=true;await c.query('COMMIT');begun=false;
    return local('WITNESS_FINALIZED_DIAGNOSTIC',{
      ledger_cas_committed:true,witness_finalized:true,
      ledger_id:claim.ledger_id,repository:claim.repository,
      sequence:claim.sequence,generation:p.generation,
      policy_sequence:claim.policy_sequence,
      intent_sha256:claim.intent_sha256,reservation_id:reservationId});
  }catch(e){
    if(begun)try{await c.query('ROLLBACK');}catch{}
    return commitStarted?UNKNOWN('WITNESS_FINALIZATION_COMMIT_ACK_UNCERTAIN'):deny(ERROR(e),503);
  }finally{c.release();}
}
// NO AUTOMATIC UNRESERVE OR LEASE EXPIRY. After a crash, operator must reconcile
// same reservation with observed primary event; even an old timeout is NOT
// proof that a primary commit never happened.
