// Source-free, NON-AUTHORIZING signed-evidence admission for the PostgreSQL
// diagnostic service. All trust anchors/pins are operator-side only.
import { verifySequenceLinkedCandidate } from '../release-checkpoint-v1/verify.mjs';
import { validClaim, exact, hex64, hash, deny, local } from '../release-ledger-service-v1/protocol.mjs';
import { readPgState, commitPgClaim } from '../release-ledger-service-v1/postgres.mjs';

const FIELDS=['artifact_b64','candidate_b64','checkpoint_b64','client_request_id','intent_b64','registry_b64'];
const LIMIT=32768;
function bytes64(s){
  if(typeof s!=='string'||s.length<4||s.length>LIMIT*2||
     !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))
    throw Error('INVALID_CANONICAL_BASE64');
  const v=Buffer.from(s,'base64');
  if(v.length<1||v.length>LIMIT||v.toString('base64')!==s)
    throw Error('INVALID_CANONICAL_BASE64_BYTES');
  return v;
}
export function pinOperatorEvidence(config){
  if(!exact(config,['trustedRootPem','expected','ledgerPin'])||
    typeof config.trustedRootPem!=='string'||config.trustedRootPem.length>4096||
    !exact(config.expected,['policy_id','minimum_sequence','root_keyid',
      'repository','head_sha','tree_sha','artifact_sha256','envelope_sha256'])||
    !exact(config.ledgerPin,['schema','checkpoint_sha256','intent_sha256',
      'ledger_id','next_sequence','previous_intent_sha256']))
    throw Error('INVALID_OPERATOR_TRUST_CONFIGURATION');
  // Snapshot the policy before accepting any untrusted request. Caller cannot
  // mutate the trust root/pin between verification and the PostgreSQL CAS.
  const copy=structuredClone(config);
  Object.freeze(copy.expected);Object.freeze(copy.ledgerPin);
  return Object.freeze(copy);
}
const parseVerifiedIntent=bytes=>{
  const env=JSON.parse(bytes.toString('utf8'));
  const raw=Buffer.from(env.payload,'base64');
  return JSON.parse(raw.toString('utf8'));
};
export function verifySignedServiceRequest({body,operatorPin,now}){
  try{
    if(!exact(body,FIELDS)||!hex64(body.client_request_id)||
       !operatorPin||!Object.isFrozen(operatorPin)||
       !Object.isFrozen(operatorPin.expected)||!Object.isFrozen(operatorPin.ledgerPin)||
       typeof now!=='string')
      return deny('UNPINNED_OR_MALFORMED_SIGNED_REQUEST');
    const registryEnvelopeBytes=bytes64(body.registry_b64);
    const candidateEnvelopeBytes=bytes64(body.candidate_b64);
    const checkpointEnvelopeBytes=bytes64(body.checkpoint_b64);
    const intentEnvelopeBytes=bytes64(body.intent_b64);
    const artifactBytes=bytes64(body.artifact_b64);
    const verdict=verifySequenceLinkedCandidate({
      trustedRootPem:operatorPin.trustedRootPem,
      expected:operatorPin.expected,ledgerPin:operatorPin.ledgerPin,now,
      registryEnvelopeBytes,candidateEnvelopeBytes,checkpointEnvelopeBytes,
      intentEnvelopeBytes,artifactBytes
    });
    if(verdict.classification!=='SEQUENCE_LINKED_LOCAL_CANDIDATE')
      return deny('SIGNED_CHAIN_DENIED: '+verdict.reason);
    // Only parse signed data AFTER #159 verifies canonical DSSE, signatures,
    // role separation, timestamps, root policy and independently pinned hashes.
    const cp=parseVerifiedIntent(checkpointEnvelopeBytes);
    const intent=parseVerifiedIntent(intentEnvelopeBytes);
    const claim={
      ledger_id:intent.ledger_id,sequence:intent.sequence,
      previous_intent_sha256:intent.previous_intent_sha256,
      intent_sha256:hash(intentEnvelopeBytes),nonce:intent.nonce,
      repository:intent.repository,head_sha:intent.head_sha,
      artifact_sha256:intent.artifact_sha256,
      policy_sequence:intent.policy_sequence,
      client_request_id:body.client_request_id
    };
    if(!validClaim(claim)||claim.intent_sha256!==verdict.intent_sha256||
       claim.ledger_id!==verdict.ledger_id||claim.sequence!==verdict.sequence||
       claim.policy_sequence!==verdict.policy_sequence||
       claim.head_sha!==verdict.head_sha||
       cp.ledger_id!==claim.ledger_id||
       cp.repository!==claim.repository||
       cp.last_sequence!==claim.sequence-1||
       cp.last_intent_sha256!==claim.previous_intent_sha256)
      return deny('SIGNED_CLAIM_MISMATCH');
    return local('SIGNED_LOCAL_DIAGNOSTIC_CANDIDATE',{
      ledger_cas_committed:false,claim,
      checkpoint:{ledger_id:cp.ledger_id,repository:cp.repository,
        last_sequence:cp.last_sequence,last_intent_sha256:cp.last_intent_sha256,
        last_nonce:cp.last_nonce},
      checkpoint_sha256:verdict.checkpoint_sha256,
      signed_intent_sha256:verdict.intent_sha256
    });
  }catch(e){return deny('SIGNED_INPUT_DENIED: '+e.message);}
}
export async function consumeVerifiedSignedServiceRequest({
  pool,client,authNonce,bodyDigest,body,operatorPin,now
}){
  const signed=verifySignedServiceRequest({body,operatorPin,now});
  if(signed.classification!=='SIGNED_LOCAL_DIAGNOSTIC_CANDIDATE')
    return signed;
  try{
    const db=await readPgState(pool,signed.claim.ledger_id);
    if(db.classification!=='PG_LEDGER_SNAPSHOT')
      return deny('LEDGER_STATE_NOT_AUTHENTICATED_OR_PRESENT');
    const c=signed.checkpoint;
    if(db.repository!==c.repository||db.sequence!==c.last_sequence||
       db.last_intent_sha256!==c.last_intent_sha256||
       db.last_nonce!==c.last_nonce||
       db.policy_sequence>signed.claim.policy_sequence)
      return deny('SIGNED_CHECKPOINT_NOT_CURRENT_IN_DATABASE');
    // The DB high-water CAS then serializes verification-vs-commit races.
    const v=await commitPgClaim(pool,{client,authNonce,bodyDigest,claim:signed.claim});
    // Even a successfully committed signed intent is not a publication permit.
    return {...v,release_authorized:false,authenticated_github:false,
      compiler_guest_parity_proven:false};
  }catch(e){
    return local('SIGNED_LEDGER_OUTCOME_UNVERIFIED',{
      ledger_cas_committed:null,requires_manual_reconciliation:true,
      reason:'DATABASE_OR_TRANSPORT_UNVERIFIED'});
  }
}
