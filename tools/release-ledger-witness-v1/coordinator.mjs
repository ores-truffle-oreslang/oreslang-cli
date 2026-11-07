// Diagnostic two-phase workflow; NEVER grants release authorization.
// Primary and witness must be separate trust principals in a real deployment.
import {hash,canonical,deny,local,validClient,hex64} from '../release-ledger-service-v1/protocol.mjs';
import {readPgState,commitPgClaim} from '../release-ledger-service-v1/postgres.mjs';
import {verifySignedServiceRequest,pinOperatorEvidence} from '../release-ledger-service-v2/signed-claim.mjs';
import {readWitness,reserveWitness,finalizeWitness,
  bootstrapWitness} from './witness.mjs';
import {primaryEventCommitted} from './primary-evidence.mjs';
import {signPersistedWitnessReceipt,verifyWitnessReceipt} from './receipt.mjs';

const pending=(reason,extras={})=>local('WITNESS_COORDINATION_UNVERIFIED',{
  ledger_cas_committed:null,witness_finalized:null,
  requires_manual_reconciliation:true,reason,...extras
});
export const createIsolatedTestWitnessOperator=({
  witnessPool,primaryReadPool,privateSigningKey
})=>{
  if(!witnessPool||!primaryReadPool||!privateSigningKey)
    throw Error('ISOLATED_TEST_WITNESS_CONFIG_REQUIRED');
  // In CI the separate databases share one disposable Postgres server.
  // This adapter is NOT an independent deployed service or a quorum.
  return Object.freeze({
    read:id=>readWitness(witnessPool,id),
    prove:async(ledgerId,sequence)=>signPersistedWitnessReceipt(witnessPool,{
      ledgerId,sequence,privateKey:privateSigningKey
    }),
    bootstrap:scope=>bootstrapWitness(witnessPool,scope),
    reserve:(claim,generation)=>reserveWitness(witnessPool,{
      claim,expectedGeneration:generation
    }),
    finalize:async(claim,reservationId)=>{
      const v=await finalizeWitness(witnessPool,{
        claim,reservationId,
        independentlyReadPrimaryEvent:c=>primaryEventCommitted(primaryReadPool,c)
      });
      if(v.classification!=='WITNESS_FINALIZED_DIAGNOSTIC')return v;
      const receipt=await signPersistedWitnessReceipt(witnessPool,{
        ledgerId:claim.ledger_id,sequence:claim.sequence,
        privateKey:privateSigningKey
      });
      if(receipt.classification!=='PERSISTED_WITNESS_SIGNED_RECEIPT')
        return pending('WITNESS_FINALIZED_BUT_SIGNED_RECEIPT_UNAVAILABLE');
      return {...v,receipt:receipt.receipt,fields:receipt.fields};
    }
  });
};
function statesMatch(signed,primary,witness){
  const cp=signed.checkpoint,c=signed.claim;
  return primary.classification==='PG_LEDGER_SNAPSHOT'&&
    witness.classification==='WITNESS_SNAPSHOT'&&
    witness.pending===null&&
    witness.ledger_id===cp.ledger_id&&
    witness.repository===cp.repository&&
    witness.sequence===cp.last_sequence&&
    witness.generation===cp.last_sequence&&
    witness.last_intent_sha256===cp.last_intent_sha256&&
    witness.last_nonce===cp.last_nonce&&
    witness.policy_sequence<=c.policy_sequence&&
    primary.ledger_id===cp.ledger_id&&
    primary.repository===cp.repository&&
    primary.sequence===cp.last_sequence&&
    primary.last_intent_sha256===cp.last_intent_sha256&&
    primary.last_nonce===cp.last_nonce&&
    primary.policy_sequence<=c.policy_sequence;
}
function verifiedFinalReceipt(finalized,claim,witnessPublicPem){
  if(finalized.classification!=='WITNESS_FINALIZED_DIAGNOSTIC'||
     finalized.witness_finalized!==true||!finalized.receipt||
     !finalized.fields)return deny('MISSING_AUTHENTIC_FINALIZED_WITNESS');
  const expected={
    ledger_id:claim.ledger_id,repository:claim.repository,
    sequence:claim.sequence,generation:claim.sequence,
    intent_sha256:claim.intent_sha256,nonce:claim.nonce,
    policy_sequence:claim.policy_sequence,
    reservation_id:finalized.reservation_id
  };
  const v=verifyWitnessReceipt(finalized.receipt,witnessPublicPem,expected);
  return v.classification==='WITNESS_SIGNATURE_VERIFIED_NOT_AUTHORIZING'?v:
    deny('EXTERNAL_WITNESS_SIGNATURE_UNVERIFIED');
}
export async function runWitnessedSignedClaim({
  primaryPool,witness,operatorPin,witnessPublicPem,
  body,now,client,authNonce,bodyDigest,afterReservation
}){
  if(!primaryPool||!witness||typeof witness.read!=='function'||
     typeof witness.reserve!=='function'||typeof witness.finalize!=='function'||
     typeof witnessPublicPem!=='string'||!validClient(client)||
     !hex64(authNonce)||!hex64(bodyDigest))
    return deny('WITNESS_CONTROL_PLANE_CONFIGURATION_INVALID');
  const signed=verifySignedServiceRequest({body,operatorPin,now});
  if(signed.classification!=='SIGNED_LOCAL_DIAGNOSTIC_CANDIDATE')return signed;
  const c=signed.claim;
  try{
    const [primary,witnessState]=await Promise.all([
      readPgState(primaryPool,c.ledger_id),witness.read(c.ledger_id)
    ]);
    if(!statesMatch(signed,primary,witnessState))
      return pending('PRIMARY_WITNESS_OR_SIGNED_CHECKPOINT_NOT_CONSISTENT');
    const reserve=await witness.reserve(c,witnessState.generation);
    if(reserve.classification!=='WITNESS_RESERVED'||
       reserve.generation!==c.sequence||!hex64(reserve.reservation_id))
      return pending('WITNESS_NOT_FRESHLY_RESERVED');
    // Test-only crash hook. Unknown outcome must leave pending fenced.
    try{if(afterReservation)await afterReservation();}
    catch{return pending('TEST_CRASH_AFTER_WITNESS_RESERVATION',{
      reservation_id:reserve.reservation_id});}
    const committed=await commitPgClaim(primaryPool,{
      client,authNonce,bodyDigest,claim:c
    });
    if(committed.classification!=='LOCAL_PG_CAS_COMMITTED')
      return pending('PRIMARY_COMMIT_DENIED_OR_UNVERIFIED_PENDING_FENCED',{
        reservation_id:reserve.reservation_id,
        primary_outcome:committed.classification
      });
    const finalized=await witness.finalize(c,reserve.reservation_id);
    if(finalized.classification!=='WITNESS_FINALIZED_DIAGNOSTIC')
      return pending('WITNESS_FINALIZATION_PENDING_OR_UNVERIFIED',{
        reservation_id:reserve.reservation_id,
        witness_outcome:finalized.classification
      });
    const proof=verifiedFinalReceipt(finalized,c,witnessPublicPem);
    if(proof.classification==='DENIED')
      return pending('WITNESS_FINALIZED_BUT_RECEIPT_SIGNATURE_UNVERIFIED');
    return local('WITNESSED_DIAGNOSTIC_CAS',{
      ledger_cas_committed:true,witness_finalized:true,
      ledger_id:c.ledger_id,sequence:c.sequence,
      generation:finalized.generation,
      intent_sha256:c.intent_sha256,
      witness_receipt:finalized.receipt
    });
  }catch{
    return pending('WITNESS_OR_PRIMARY_NETWORK_ERROR_UNVERIFIED');
  }
}
// Operator-controlled reconciliation, NOT a client endpoint. This cannot
// unreserve or infer that a timed-out primary claim was uncommitted.
export async function reconcileWitnessPending({
  witness,claim,reservationId,witnessPublicPem
}){
  try{
    if(!witness||typeof witness.read!=='function'||
       typeof witness.finalize!=='function'||!hex64(reservationId)||
       typeof witnessPublicPem!=='string')
      return deny('INVALID_MANUAL_RECONCILIATION_CONFIG');
    const state=await witness.read(claim.ledger_id);
    if(state.classification!=='WITNESS_SNAPSHOT')
      return pending('WITNESS_SNAPSHOT_UNAVAILABLE');
    if(!state.pending&&state.sequence===claim.sequence&&
       state.last_intent_sha256===claim.intent_sha256&&
       typeof witness.prove==='function'){
      const recorded=await witness.prove(claim.ledger_id,claim.sequence);
      if(recorded.classification!=='PERSISTED_WITNESS_SIGNED_RECEIPT'||
         recorded.fields.reservation_id!==reservationId)
        return pending('FINALIZED_RECORD_UNVERIFIED');
      const proof=verifyWitnessReceipt(recorded.receipt,witnessPublicPem,{
        ledger_id:claim.ledger_id,repository:claim.repository,
        sequence:claim.sequence,generation:claim.sequence,
        intent_sha256:claim.intent_sha256,nonce:claim.nonce,
        policy_sequence:claim.policy_sequence,reservation_id:reservationId
      });
      if(proof.classification!=='WITNESS_SIGNATURE_VERIFIED_NOT_AUTHORIZING')
        return pending('FINALIZED_SIGNATURE_UNVERIFIED');
      return local('MANUALLY_RECONCILED_WITNESS_DIAGNOSTIC',{
        ledger_cas_committed:true,witness_finalized:true,
        ledger_id:claim.ledger_id,sequence:claim.sequence,
        witness_receipt:recorded.receipt
      });
    }
    if(!state.pending||state.pending.reservation_id!==reservationId||
       state.pending.intent_sha256!==claim.intent_sha256)
      return pending('NO_MATCHING_PENDING_WITNESS_TO_RECONCILE');
    const finalized=await witness.finalize(claim,reservationId);
    if(finalized.classification!=='WITNESS_FINALIZED_DIAGNOSTIC')
      return pending('PRIMARY_NOT_OBSERVED_BY_WITNESS');
    const proof=verifiedFinalReceipt(finalized,claim,witnessPublicPem);
    if(proof.classification==='DENIED')return pending('RECONCILIATION_PROOF_UNVERIFIED');
    return local('MANUALLY_RECONCILED_WITNESS_DIAGNOSTIC',{
      ledger_cas_committed:true,witness_finalized:true,
      ledger_id:claim.ledger_id,sequence:claim.sequence,
      witness_receipt:finalized.receipt
    });
  }catch{return pending('RECONCILIATION_OUTCOME_UNVERIFIED');}
}
export const digestSignedRequest=body=>hash(canonical(body));
