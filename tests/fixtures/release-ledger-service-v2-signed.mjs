// Synthetic Ed25519-only source-free fixtures. NEVER production credentials.
import { generateKeyPairSync, sign, createHash } from 'node:crypto';
import { trustKeyId, PAYLOAD_TYPE, dssePAE } from '../../tools/release-assurance-v1/verify.mjs';
import { REGISTRY_TYPE, registryPAE } from '../../tools/release-trust-registry-v1/verify.mjs';
import { CHECKPOINT_TYPE, INTENT_TYPE } from '../../tools/release-checkpoint-v1/verify.mjs';

export const REPO='ores-truffle-oreslang/oreslang-cli';
export const HEAD='a'.repeat(40), TREE='b'.repeat(40), ZERO='0'.repeat(64);
export const ARTIFACT=Buffer.from('SYNTHETIC SIGNED V2 ARTIFACT');
export const NOW='2026-11-07T00:01:30Z';
export const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const kp=()=>generateKeyPairSync('ed25519');
export const keys={
  root:kp(),candidate:kp(),governance:kp(),approval:kp(),outsider:kp()
};
export const pem=key=>key.publicKey.export({format:'pem',type:'spki'});
export const keyid=key=>trustKeyId(pem(key)).keyid;
const delegate=(key,role)=>({
  keyid:keyid(key),spki_pem:pem(key),role,repository:REPO,
  not_before:'2026-01-01T00:00:00Z',
  not_after:'2028-01-01T00:00:00Z',revoked_at:null
});
export function signEnvelope(type,payload,key){
  const raw=Buffer.from(JSON.stringify(payload));
  const pae=type===PAYLOAD_TYPE?dssePAE(type,raw):
    type===REGISTRY_TYPE?registryPAE(raw):
    Buffer.concat([Buffer.from('DSSEv1 '+Buffer.byteLength(type)+' '),
      Buffer.from(type),Buffer.from(' '+raw.length+' '),raw]);
  const envelope={payloadType:type,payload:raw.toString('base64'),
    signatures:[{keyid:keyid(key),sig:sign(null,pae,key.privateKey).toString('base64')}]};
  return Buffer.from(JSON.stringify(envelope));
}
let count=0;
export function makeFixture(options={}){
  const ledgerId=options.ledgerId||('atto-service-v2-'+(++count).toString(36));
  const policy={
    schema:'atto.trust-registry.v1',policy_id:'atto-release-policy',
    sequence:8,not_before:'2026-01-01T00:00:00Z',
    not_after:'2029-01-01T00:00:00Z',
    keys:[delegate(keys.candidate,'candidate-signing'),
      delegate(keys.governance,'governance-review'),
      delegate(keys.approval,'release-approval')]
  };
  options.policyMutate?.(policy);
  const registryEnvelopeBytes=signEnvelope(REGISTRY_TYPE,policy,
    options.registrySigner||keys.root);
  const artifactBytes=options.artifactBytes||ARTIFACT;
  const manifest={
    schema:'atto.release-assurance.v1',
    subject:{repository:REPO,head_sha:HEAD,tree_sha:TREE,
      artifact:{filename:'release.tgz',size:artifactBytes.length,
        sha256:hash(artifactBytes)}},
    governance:{
      protected_main:true,no_bypass:true,require_codeowner_review:true,
      dismiss_stale_reviews:true,author:'BuildAuthor',
      codeowners:['IndependentOwner'],required_contexts:['release-assurance']
    },
    reviews:[{reviewer:'IndependentOwner',state:'APPROVED',
      commit_id:HEAD,submitted_at:'2026-11-06T20:40:00Z'}],
    workflow:{run_id:12,run_attempt:2,job_id:15,runner_id:16,
      job_name:'release-assurance',head_sha:HEAD,tree_sha:TREE,
      status:'completed',conclusion:'success',
      steps:[{number:1,name:'Verify immutable source',status:'completed',
        conclusion:'success'},{number:2,name:'Execute source tests',
        status:'completed',conclusion:'success'}],
      checkout_step_number:1,test_step_number:2
    },
    backends:['java','llvm','net','wasm','forge'].map((backend,i)=>({
      backend,repository:'ores-truffle-oreslang/oreslang-source.'+backend,
      head_sha:String(i+1).repeat(40),tree_sha:String(i+5).repeat(40),
      classification:'EXECUTED_COMPILER_GUEST',run_id:100+i,
      run_attempt:1,job_id:200+i,runner_id:300+i,executed_steps:3,
      toolchain_sha256:'e'.repeat(64),
      fixture_sha256:'f'.repeat(64),output_sha256:'d'.repeat(64)
    }))
  };
  options.manifestMutate?.(manifest);
  const candidateEnvelopeBytes=signEnvelope(PAYLOAD_TYPE,manifest,
    options.candidateSigner||keys.candidate);
  const checkpoint={
    schema:'atto.release-checkpoint.v1',repository:REPO,
    policy_id:'atto-release-policy',policy_sequence:8,
    registry_sha256:hash(registryEnvelopeBytes),ledger_id:ledgerId,
    last_sequence:0,last_intent_sha256:ZERO,last_nonce:ZERO,
    observed_at:'2026-11-07T00:00:00Z',
    expires_at:'2026-11-07T00:04:00Z'
  };
  options.checkpointMutate?.(checkpoint);
  const checkpointEnvelopeBytes=signEnvelope(CHECKPOINT_TYPE,checkpoint,
    options.checkpointSigner||keys.governance);
  const intent={
    schema:'atto.release-intent.v1',repository:REPO,
    head_sha:HEAD,tree_sha:TREE,artifact_sha256:hash(artifactBytes),
    candidate_envelope_sha256:hash(candidateEnvelopeBytes),
    policy_id:'atto-release-policy',policy_sequence:8,
    registry_sha256:hash(registryEnvelopeBytes),ledger_id:ledgerId,
    sequence:1,previous_intent_sha256:ZERO,nonce:'3'.repeat(64),
    issued_at:'2026-11-07T00:01:00Z',
    expires_at:'2026-11-07T00:03:00Z'
  };
  options.intentMutate?.(intent);
  const intentEnvelopeBytes=signEnvelope(INTENT_TYPE,intent,
    options.intentSigner||keys.approval);
  const expected={
    policy_id:'atto-release-policy',minimum_sequence:8,
    root_keyid:keyid(keys.root),repository:REPO,
    head_sha:HEAD,tree_sha:TREE,
    artifact_sha256:hash(artifactBytes),
    envelope_sha256:hash(candidateEnvelopeBytes)
  };
  options.expectedMutate?.(expected);
  const ledgerPin={
    schema:'atto.release-link-pin.v1',
    checkpoint_sha256:hash(checkpointEnvelopeBytes),
    intent_sha256:hash(intentEnvelopeBytes),
    ledger_id:ledgerId,next_sequence:1,
    previous_intent_sha256:ZERO
  };
  options.pinMutate?.(ledgerPin);
  const operatorPin={trustedRootPem:pem(options.rootOverride||keys.root),
    expected,ledgerPin};
  const body={
    artifact_b64:artifactBytes.toString('base64'),
    candidate_b64:candidateEnvelopeBytes.toString('base64'),
    checkpoint_b64:checkpointEnvelopeBytes.toString('base64'),
    client_request_id:options.requestId||hash(Buffer.from('request-'+ledgerId)),
    intent_b64:intentEnvelopeBytes.toString('base64'),
    registry_b64:registryEnvelopeBytes.toString('base64')
  };
  return {body,operatorPin,now:options.now||NOW,ledgerId,policy,
    manifest,checkpoint,intent,registryEnvelopeBytes,candidateEnvelopeBytes,
    checkpointEnvelopeBytes,intentEnvelopeBytes,artifactBytes};
}
