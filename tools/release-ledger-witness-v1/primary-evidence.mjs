// Primary evidence must be read with a separate witness-controlled READ-ONLY
// PostgreSQL identity. Never trust a client "commit succeeded" flag.
import {validClaim} from '../release-ledger-service-v1/protocol.mjs';

export async function primaryEventCommitted(primaryReadPool,claim){
  if(!validClaim(claim)||!primaryReadPool||typeof primaryReadPool.connect!=='function')
    return false;
  const c=await primaryReadPool.connect();
  try{
    await c.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const state=await c.query(
      'SELECT ledger_id,repository,sequence,policy_sequence,last_intent_sha256,last_nonce FROM ledger_service_state WHERE ledger_id=$1',
      [claim.ledger_id]);
    const event=await c.query(
      'SELECT ledger_id,sequence,repository,policy_sequence,previous_intent_sha256,intent_sha256,nonce,client_request_id,head_sha,artifact_sha256 FROM ledger_service_event WHERE ledger_id=$1 AND sequence=$2',
      [claim.ledger_id,claim.sequence]);
    await c.query('COMMIT');
    if(state.rows.length!==1||event.rows.length!==1)return false;
    const s=state.rows[0],e=event.rows[0];
    // Equal current high-water is required. An advanced or restored primary
    // cannot satisfy a stale request with merely a matching old event.
    if(Number(s.sequence)!==claim.sequence||s.repository!==claim.repository||
       Number(s.policy_sequence)!==claim.policy_sequence||
       s.last_intent_sha256!==claim.intent_sha256||s.last_nonce!==claim.nonce)
      return false;
    for(const [k,v] of Object.entries(claim)){
      if(k==='client_request_id'||k==='sequence'||k==='policy_sequence'){
        if(String(e[k])!==String(v))return false;
      }else if(k!=='ledger_id'&&String(e[k])!==String(v))return false;
    }
    return e.ledger_id===claim.ledger_id&&Number(e.sequence)===claim.sequence;
  }catch{
    try{await c.query('ROLLBACK');}catch{}
    return false;
  }finally{c.release();}
}
