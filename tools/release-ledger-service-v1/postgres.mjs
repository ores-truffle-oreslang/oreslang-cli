// PostgreSQL implementation of a NON-AUTHORIZING release-intent CAS service.
// Requires a dedicated DB role and operator-managed schema; never provisions DB.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { hash, validBootstrap, validClaim, validClient, hex64, deny, local,
  ZERO_DIGEST } from './protocol.mjs';

const STATUS={stale:'STALE_HIGH_WATER',scope:'LEDGER_REPOSITORY_MISMATCH',
  policy:'POLICY_GENERATION_ROLLBACK',duplicate:'INTENT_OR_NONCE_REPLAY'};
const sorted=x=>JSON.stringify(x);
const outcome=(reason)=>deny(reason,409);

export async function installForIsolatedTests(pool) {
  // Never called by the HTTP server. Must be an isolated disposable PG DB.
  const path=fileURLToPath(new URL('./schema.sql',import.meta.url));
  await pool.query(readFileSync(path,'utf8'));
}
export async function bootstrapPg(pool,scope) {
  if(!validBootstrap(scope))return deny('INVALID_BOOTSTRAP');
  const c=await pool.connect();let begun=false;
  try{
    await c.query('BEGIN');begun=true;
    await c.query('SET LOCAL lock_timeout = 10000');
    await c.query('INSERT INTO ledger_service_state (ledger_id,repository) VALUES($1,$2) ON CONFLICT DO NOTHING',
      [scope.ledger_id,scope.repository]);
    const {rows}=await c.query('SELECT ledger_id,repository,sequence,policy_sequence,last_intent_sha256,last_nonce FROM ledger_service_state WHERE ledger_id=$1 FOR UPDATE',
      [scope.ledger_id]);
    if(rows.length!==1||rows[0].repository!==scope.repository){
      await c.query('ROLLBACK');begun=false;
      return deny('BOOTSTRAP_SCOPE_CONFLICT');
    }
    // Repeat bootstrap is read-only and never resets existing state.
    await c.query('COMMIT');begun=false;
    return local('PG_BOOTSTRAP_CONFIRMED',{ledger_id:scope.ledger_id,
      repository:scope.repository,sequence:Number(rows[0].sequence),
      ledger_cas_committed:false});
  }catch(e){
    if(begun)try{await c.query('ROLLBACK');}catch{}
    return deny('BOOTSTRAP_DB_ERROR: '+e.code);
  }finally{c.release();}
}
export async function readPgState(pool,ledgerId) {
  const {rows}=await pool.query('SELECT * FROM ledger_service_state WHERE ledger_id=$1',[ledgerId]);
  if(rows.length!==1)return deny('LEDGER_NOT_BOOTSTRAPPED',404);
  const row=rows[0];
  return local('PG_LEDGER_SNAPSHOT',{
    ledger_id:row.ledger_id,repository:row.repository,
    sequence:Number(row.sequence),policy_sequence:Number(row.policy_sequence),
    last_intent_sha256:row.last_intent_sha256,last_nonce:row.last_nonce,
    ledger_cas_committed:false
  });
}
export async function readPgReceipt(pool,client,requestId){
  if(!validClient(client)||!hex64(requestId))return deny('INVALID_RECEIPT_QUERY');
  const {rows}=await pool.query('SELECT outcome,reason,ledger_id,committed_sequence,committed_intent_sha256 FROM ledger_service_request WHERE client=$1 AND client_request_id=$2',
    [client,requestId]);
  if(rows.length!==1)return deny('RECEIPT_NOT_FOUND',404);
  const x=rows[0];
  if(x.outcome==='COMMITTED')
    return local('PG_RECEIPT_COMMITTED',{ledger_id:x.ledger_id,
      sequence:Number(x.committed_sequence),intent_sha256:x.committed_intent_sha256,
      ledger_cas_committed:true});
  if(x.outcome==='DENIED')return deny('PG_RECEIPT_DENIED: '+x.reason,409);
  return local('PG_RECEIPT_UNRESOLVED',{
    ledger_cas_committed:null,requires_manual_reconciliation:true});
}
export async function commitPgClaim(pool,{client,authNonce,bodyDigest,claim}){
  if(!validClient(client)||!hex64(authNonce)||!hex64(bodyDigest)||
     !validClaim(claim))return deny('INVALID_SERVICE_CLAIM');
  const c=await pool.connect();
  let begun=false,commitStarted=false;
  try{
    await c.query('BEGIN');begun=true;
    await c.query('SET LOCAL lock_timeout = 10000');
    await c.query('SET LOCAL statement_timeout = 15000');
    const inserted=await c.query(
      'INSERT INTO ledger_service_request (client,auth_nonce,client_request_id,ledger_id,body_sha256,outcome,reason) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING RETURNING client',
      [client,authNonce,claim.client_request_id,claim.ledger_id,bodyDigest,'PENDING','IN_PROGRESS']);
    if(inserted.rowCount!==1){
      await c.query('ROLLBACK');begun=false;
      return outcome('REPLAYED_AUTH_NONCE_OR_REQUEST_ID');
    }
    const record=await c.query(
      'SELECT * FROM ledger_service_state WHERE ledger_id=$1 FOR UPDATE',[claim.ledger_id]);
    const current=record.rows[0];
    let reason;
    if(!current)reason='LEDGER_NOT_BOOTSTRAPPED';
    else if(current.repository!==claim.repository)reason=STATUS.scope;
    else if(claim.policy_sequence<Number(current.policy_sequence))reason=STATUS.policy;
    else if(claim.sequence!==Number(current.sequence)+1||
      claim.previous_intent_sha256!==current.last_intent_sha256||
      claim.nonce===current.last_nonce)reason=STATUS.stale;
    else {
      const replays=await c.query(
        'SELECT 1 FROM ledger_service_event WHERE ledger_id=$1 AND (intent_sha256=$2 OR nonce=$3) LIMIT 1',
        [claim.ledger_id,claim.intent_sha256,claim.nonce]);
      if(replays.rowCount!==0)reason=STATUS.duplicate;
    }
    if(reason){
      await c.query('UPDATE ledger_service_request SET outcome=$3,reason=$4 WHERE client=$1 AND auth_nonce=$2',
        [client,authNonce,'DENIED',reason]);
      commitStarted=true;await c.query('COMMIT');begun=false;
      return outcome(reason);
    }
    await c.query(
      'INSERT INTO ledger_service_event (ledger_id,sequence,previous_intent_sha256,intent_sha256,nonce,repository,head_sha,artifact_sha256,policy_sequence,client,client_request_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
      [claim.ledger_id,claim.sequence,claim.previous_intent_sha256,claim.intent_sha256,
       claim.nonce,claim.repository,claim.head_sha,claim.artifact_sha256,
       claim.policy_sequence,client,claim.client_request_id]);
    const update=await c.query(
      'UPDATE ledger_service_state SET sequence=$2,policy_sequence=$3,last_intent_sha256=$4,last_nonce=$5 WHERE ledger_id=$1 AND sequence=$6 AND last_intent_sha256=$7 AND last_nonce=$8 AND policy_sequence<=$3',
      [claim.ledger_id,claim.sequence,claim.policy_sequence,claim.intent_sha256,claim.nonce,
       claim.sequence-1,claim.previous_intent_sha256,current.last_nonce]);
    if(update.rowCount!==1)throw Error('ATOMIC_CAS_FAILED');
    await c.query('UPDATE ledger_service_request SET outcome=$3,reason=$4,committed_sequence=$5,committed_intent_sha256=$6 WHERE client=$1 AND auth_nonce=$2',
      [client,authNonce,'COMMITTED','LOCAL_ONLY',claim.sequence,claim.intent_sha256]);
    commitStarted=true;await c.query('COMMIT');begun=false;
    return local('LOCAL_PG_CAS_COMMITTED',{ledger_id:claim.ledger_id,
      sequence:claim.sequence,intent_sha256:claim.intent_sha256,ledger_cas_committed:true});
  }catch(e){
    if(begun)try{await c.query('ROLLBACK');}catch{}
    if(commitStarted)return local('LOCAL_PG_COMMIT_UNVERIFIED',{
      ledger_cas_committed:null,requires_manual_reconciliation:true,
      reason:'DATABASE_COMMIT_ACK_UNCERTAIN'});
    return deny('POSTGRES_TRANSACTION_REJECTED: '+String(e.code||e.message).slice(0,80),503);
  }finally{c.release();}
}

// Exact PostgreSQL driver dependency is declared in this component's package.json.
export async function createPgPool(config) {
  const {default:pg}=await import('pg');
  return new pg.Pool(config);
}
