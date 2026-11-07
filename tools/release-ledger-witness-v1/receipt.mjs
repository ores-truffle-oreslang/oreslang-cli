// Ed25519 witness attestation. Signing key belongs to a distinct operator.
// Never checked into Git; synthetic signing keys exist only in isolated tests.
import {createPublicKey,sign,verify,createHash} from 'node:crypto';
import {canonical,exact,hex64,validLedger,validRepo,local,deny} from '../release-ledger-service-v1/protocol.mjs';
const KIND='atto.monotonic-witness-receipt.v1';
const F=['generation','intent_sha256','ledger_id','nonce','policy_sequence',
  'repository','reservation_id','sequence'];
const receiptKeys=['keyid','payload','signature'];
const sha=s=>createHash('sha256').update(s).digest('hex');
const domain=bytes=>Buffer.concat([Buffer.from('ATTO-MONOTONIC-WITNESS-v1\n'),bytes]);
function normalize(fields){
  if(!exact(fields,F)||!validLedger(fields.ledger_id)||!validRepo(fields.repository)||
    !Number.isSafeInteger(fields.sequence)||fields.sequence<=0||
    fields.sequence>1000000||fields.generation!==fields.sequence||
    !Number.isSafeInteger(fields.policy_sequence)||fields.policy_sequence<=0||
    fields.policy_sequence>1000000||
    !hex64(fields.intent_sha256)||!hex64(fields.nonce)||!hex64(fields.reservation_id))
    throw Error('INVALID_WITNESS_ATTESTATION_FIELDS');
  return {schema:KIND,...fields};
}
export function signWitnessReceipt(fields,privateKey){
  const obj=normalize(fields);
  const publicKey=createPublicKey(privateKey);
  const keyid=sha(publicKey.export({format:'der',type:'spki'}));
  const payload=canonical(obj);
  const signature=sign(null,domain(Buffer.from(payload)),privateKey).toString('base64');
  return {keyid,payload,signature};
}
export function verifyWitnessReceipt(receipt,trustedPublicPem,expected){
  try{
    if(!exact(receipt,receiptKeys)||typeof receipt.payload!=='string'||
       receipt.payload.length>4096||typeof receipt.signature!=='string'||
       !hex64(receipt.keyid)||typeof trustedPublicPem!=='string'||
       !exact(expected,F))throw Error('INVALID_WITNESS_RECEIPT_ENVELOPE');
    const publicKey=createPublicKey(trustedPublicPem);
    if(publicKey.asymmetricKeyType!=='ed25519')throw Error('NOT_ED25519_WITNESS');
    if(sha(publicKey.export({format:'der',type:'spki'}))!==receipt.keyid)
      throw Error('WITNESS_KEY_NOT_INDEPENDENTLY_PINNED');
    const payload=normalize(expected);
    if(receipt.payload!==canonical(payload))throw Error('WITNESS_RECORD_NOT_CURRENT');
    const sig=Buffer.from(receipt.signature,'base64');
    if(sig.length!==64||sig.toString('base64')!==receipt.signature||
       !verify(null,domain(Buffer.from(receipt.payload)),publicKey,sig))
      throw Error('BAD_WITNESS_SIGNATURE');
    return local('WITNESS_SIGNATURE_VERIFIED_NOT_AUTHORIZING',{
      ledger_cas_committed:false,witness_finalized:true,
      witness_keyid:receipt.keyid,
      ledger_id:expected.ledger_id,sequence:expected.sequence,
      generation:expected.generation,intent_sha256:expected.intent_sha256
    });
  }catch(e){return deny('WITNESS_SIGNATURE_DENIED: '+e.message);}
}
export async function signPersistedWitnessReceipt(witnessPool,{
  ledgerId,sequence,privateKey
}){
  try{
    if(!validLedger(ledgerId)||!Number.isSafeInteger(sequence)||sequence<1)
      return deny('INVALID_WITNESS_RECEIPT_REQUEST');
    const {rows}=await witnessPool.query(
      'SELECT ledger_id,repository,sequence,policy_sequence,intent_sha256,nonce,reservation_id,generation FROM witness_event WHERE ledger_id=$1 AND sequence=$2',
      [ledgerId,sequence]);
    if(rows.length!==1)return deny('WITNESS_EVENT_NOT_FINALIZED',404);
    const row=rows[0];
    const {rows:state}=await witnessPool.query(
      'SELECT sequence,generation,last_intent_sha256,last_nonce FROM witness_state WHERE ledger_id=$1',
      [ledgerId]);
    if(state.length!==1||Number(state[0].sequence)<sequence||
       Number(state[0].generation)<sequence)
      return deny('WITNESS_HIGH_WATER_BEHIND_EVENT');
    // The most recent event must still match witness high-water state.
    if(Number(state[0].sequence)===sequence&&
       (state[0].last_intent_sha256!==row.intent_sha256||
        state[0].last_nonce!==row.nonce))
      return deny('WITNESS_EVENT_STATE_TAMPER_DETECTED');
    const fields={
      ledger_id:row.ledger_id,repository:row.repository,
      sequence:Number(row.sequence),generation:Number(row.generation),
      policy_sequence:Number(row.policy_sequence),
      intent_sha256:row.intent_sha256,nonce:row.nonce,
      reservation_id:row.reservation_id
    };
    return local('PERSISTED_WITNESS_SIGNED_RECEIPT',{
      ledger_cas_committed:true,witness_finalized:true,
      fields,receipt:signWitnessReceipt(fields,privateKey)
    });
  }catch{return deny('WITNESS_SIGNING_OR_STORAGE_REJECTED',503);}
}
