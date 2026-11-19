import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { POLICIES,verifySnapshot,policyFor,ACTIONS_APP_ID } from '../tools/live-merge-evidence-v1/verify.mjs';
import { captureEvidence,githubGetter,cli } from '../tools/live-merge-evidence-v1/collect.mjs';
import { pae,verifyExternalSignature,ATTESTATION_PAYLOAD_TYPE } from '../tools/live-merge-evidence-v1/attest.mjs';

const SHA='a'.repeat(40), BASE='b'.repeat(40), TREE='c'.repeat(40);
const TIME='2026-11-07T00:01:00Z', NEXT='2026-11-07T00:03:00Z';
const repositories=Object.keys(POLICIES);
function sample(repo=repositories[0]) {
  const p=policyFor(repo), pr=158;
  const before={number:pr,state:'open',draft:false,
    user:{id:998,login:'pr-author'},
    head:{sha:SHA,repo:{id:p.repo_id}},
    base:{sha:BASE,ref:'main',repo:{id:p.repo_id}} };
  const checks=p.jobs.map((name,i)=>({
    id:2000+i,name,head_sha:SHA,status:'completed',conclusion:'success',
    app:{id:ACTIONS_APP_ID},started_at:TIME,completed_at:NEXT
  }));
  const run={id:3333,workflow_id:p.workflow_id,path:'.github/workflows/ci.yml',
    head_sha:SHA,event:'pull_request',status:'completed',conclusion:'success',run_attempt:1};
  const jobs=p.jobs.map((name,i)=>({
    id:2000+i,name,run_id:3333,run_attempt:1,runner_id:1000+i,
    status:'completed',conclusion:'success',started_at:TIME,completed_at:NEXT,
    steps:[{name:'Set up job',status:'completed',conclusion:'success'},
      {name:p.source_guard,status:'completed',conclusion:'success'},
      {name:'Run tests',status:'completed',conclusion:'success'},
      {name:'Complete job',status:'completed',conclusion:'success'}]
  }));
  const protection={
    required_status_checks:{strict:true,checks:p.jobs.map(context=>({context,app_id:ACTIONS_APP_ID})),contexts:[]},
    required_pull_request_reviews:{
      required_approving_review_count:1,require_code_owner_reviews:true,
      dismiss_stale_reviews:true,require_last_push_approval:true,
      bypass_pull_request_allowances:{users:[],teams:[],apps:[]}
    },
    enforce_admins:{enabled:true},
    allow_deletions:{enabled:false},allow_force_pushes:{enabled:false},
    required_conversation_resolution:{enabled:true}
  };
  return {schema:'atto.github.live-readback.v1',repo,pr_number:pr,
    repository:{id:p.repo_id,full_name:repo,default_branch:'main'},
    branch_before:{name:'main',protected:true,commit:{sha:BASE}},
    branch_after:{name:'main',protected:true,commit:{sha:BASE}},
    pr_before:before,pr_after:structuredClone(before),
    head_commit:{sha:SHA,tree:{sha:TREE}},
    workflow_file:{sha:p.workflow_blob,path:'.github/workflows/ci.yml',type:'file'},
    codeowners_main:{sha:'d'.repeat(40),type:'file'},
    protection,rulesets:[],effective_rules:[],
    reviews:[{id:5000,user:{id:200001,login:'external-reviewer'},
      submitted_at:NEXT,state:'APPROVED',commit_id:SHA}],
    check_runs:checks,runs:[{run,jobs}]};
}
function denied(repo,mutate,expected) {
  const s=sample(repo);
  mutate(s);
  const v=verifySnapshot(s);
  assert.equal(v.evidence_consistent,false,repo+':'+JSON.stringify(v));
  assert.equal(v.candidate_sha256,null);
  assert.equal(v.merge_authorized,false);
  assert.equal(v.release_authorized,false);
  assert.equal(v.private_source_export_authorized,false);
  assert.ok(v.reasons.some(r=>r.startsWith(expected)),JSON.stringify(v.reasons));
}
test('policy registry is four repositories with unique pinned IDs, workflows and jobs',()=>{
  assert.equal(repositories.length,4);
  assert.equal(new Set(repositories.map(k=>POLICIES[k].repo_id)).size,4);
  assert.equal(new Set(repositories.map(k=>POLICIES[k].workflow_id)).size,4);
  for(const repo of repositories) {
    const p=policyFor(repo);
    assert.match(p.workflow_blob,/^[a-f0-9]{40}$/);
    assert.equal(new Set(p.jobs).size,p.jobs.length);
    assert.ok(p.jobs.length>=1);
  }
  assert.throws(()=>policyFor('evil/private'),/UNKNOWN_REPOSITORY/);
});
for(const repo of repositories) {
  test('consistent but NON-AUTHORIZING evidence: '+repo,()=>{
    const s=sample(repo);
    const a=verifySnapshot(s),b=verifySnapshot(structuredClone(s));
    assert.deepEqual(a,b);
    assert.equal(a.evidence_consistent,true,JSON.stringify(a.reasons));
    assert.match(a.candidate_sha256,/^[a-f0-9]{64}$/);
    assert.equal(a.merge_authorized,false);
    assert.equal(a.release_authorized,false);
    assert.equal(a.private_source_export_authorized,false);
  });
  const attacks=[
    ['REPOSITORY_ID_MISMATCH',s=>{s.repository.id=55555;}],
    ['REPOSITORY_ID_MISMATCH',s=>{s.repository.full_name='evil/forged';}],
    ['REPOSITORY_ID_MISMATCH',s=>{s.repository.default_branch='master';}],
    ['PR_IDENTITY_OR_READINESS',s=>{s.pr_before.draft=true;}],
    ['PR_IDENTITY_OR_READINESS',s=>{s.pr_before.head.repo.id=44;}],
    ['PR_IDENTITY_OR_READINESS',s=>{s.pr_before.state='merged';}],
    ['PR_HEAD_OR_BASE_DRIFT',s=>{s.pr_after.head.sha='e'.repeat(40);}],
    ['PR_HEAD_OR_BASE_DRIFT',s=>{s.pr_after.base.sha='e'.repeat(40);}],
    ['PR_HEAD_OR_BASE_DRIFT',s=>{s.pr_after.draft=true;}],
    ['BASE_DRIFT_OR_UNPROTECTED',s=>{s.branch_before.protected=false;}],
    ['BASE_DRIFT_OR_UNPROTECTED',s=>{s.branch_after.protected=false;}],
    ['BASE_DRIFT_OR_UNPROTECTED',s=>{s.branch_after.commit.sha='f'.repeat(40);}],
    ['HEAD_TREE_UNBOUND',s=>{s.head_commit.tree.sha='invalid';}],
    ['HEAD_TREE_UNBOUND',s=>{s.head_commit.sha='f'.repeat(40);}],
    ['MAIN_CODEOWNERS_UNKNOWN',s=>{delete s.codeowners_main;}],
    ['WORKFLOW_DEFINITION_NOT_PINNED',s=>{s.workflow_file.sha='f'.repeat(40);}],
    ['WORKFLOW_DEFINITION_NOT_PINNED',s=>{s.workflow_file.path='.github/workflows/evil.yml';}],
    ['REQUIRED_CHECKS_OR_ISSUER_NOT_ENFORCED',s=>{s.protection.required_status_checks.strict=false;}],
    ['REQUIRED_CHECKS_OR_ISSUER_NOT_ENFORCED',s=>{s.protection.required_status_checks.checks[0].app_id=1;}],
    ['REQUIRED_CHECKS_OR_ISSUER_NOT_ENFORCED',s=>{s.protection.required_status_checks.checks.push({context:'fake',app_id:15368});}],
    ['REQUIRED_CHECKS_OR_ISSUER_NOT_ENFORCED',s=>{s.protection.required_status_checks.contexts=['evil'];}],
    ['REQUIRED_CHECKS_OR_ISSUER_NOT_ENFORCED',s=>{const n=policyFor(repo).jobs[0];s.protection.required_status_checks.contexts=[n,n];}],
    ['GOVERNANCE_POLICY_NOT_ENFORCED',s=>{s.protection.enforce_admins.enabled=false;}],
    ['GOVERNANCE_POLICY_NOT_ENFORCED',s=>{s.protection.required_pull_request_reviews.required_approving_review_count=0;}],
    ['GOVERNANCE_POLICY_NOT_ENFORCED',s=>{s.protection.required_pull_request_reviews.dismiss_stale_reviews=false;}],
    ['GOVERNANCE_POLICY_NOT_ENFORCED',s=>{s.protection.required_pull_request_reviews.require_code_owner_reviews=false;}],
    ['GOVERNANCE_POLICY_NOT_ENFORCED',s=>{s.protection.required_pull_request_reviews.require_last_push_approval=false;}],
    ['GOVERNANCE_POLICY_NOT_ENFORCED',s=>{s.protection.required_pull_request_reviews.bypass_pull_request_allowances.teams=['operator'];}],
    ['GOVERNANCE_POLICY_NOT_ENFORCED',s=>{s.protection.allow_force_pushes.enabled=true;}],
    ['GOVERNANCE_POLICY_NOT_ENFORCED',s=>{s.protection.allow_deletions.enabled=true;}],
    ['GOVERNANCE_POLICY_NOT_ENFORCED',s=>{s.protection.required_conversation_resolution.enabled=false;}],
    ['RULESET_READBACK_MISSING',s=>{s.rulesets=null;}],
    ['RULESET_READBACK_MISSING',s=>{s.effective_rules=null;}],
    ['RULESET_AMBIGUOUS_OR_BYPASS',s=>{s.rulesets=[{id:99,enforcement:'active'}];}],
    ['RULESET_AMBIGUOUS_OR_BYPASS',s=>{s.rulesets=[{id:99,enforcement:'active',bypass_actors:[{actor_id:998}]}];}],
    ['RULESET_AMBIGUOUS_OR_BYPASS',s=>{s.rulesets=[{id:99,enforcement:'mystery'}];}],
    ['EFFECTIVE_RULE_REQUIRES_EXTERNAL_REVIEW',s=>{s.effective_rules=[{type:'untrusted_rule'}];}],
    ['NO_CURRENT_INDEPENDENT_APPROVAL',s=>{s.reviews=[];}],
    ['APPROVAL_STALE',s=>{s.reviews[0].commit_id=BASE;}],
    ['APPROVAL_NOT_INDEPENDENT',s=>{s.reviews[0].user.id=2148448;}],
    ['APPROVAL_NOT_INDEPENDENT',s=>{s.reviews[0].user.id=11139560;}],
    ['APPROVAL_NOT_INDEPENDENT',s=>{s.reviews[0].user.id=998;}],
    ['NO_CURRENT_INDEPENDENT_APPROVAL',s=>{s.reviews[0].state='CHANGES_REQUESTED';}],
    ['REVIEW_MALFORMED_OR_DUPLICATE',s=>{s.reviews.push({...s.reviews[0]});}],
    ['REVIEW_MALFORMED_OR_DUPLICATE',s=>{s.reviews[0].submitted_at='2030-02-31T00:00:00Z';}],
    ['CHECK_MISSING_OR_DUPLICATE:',s=>{s.check_runs.pop();}],
    ['CHECK_MISSING_OR_DUPLICATE:',s=>{s.check_runs.push(structuredClone(s.check_runs[0]));}],
    ['CHECK_INVALID:',s=>{s.check_runs[0].app.id=999;}],
    ['CHECK_INVALID:',s=>{s.check_runs[0].conclusion='neutral';}],
    ['CHECK_INVALID:',s=>{s.check_runs[0].head_sha=BASE;}],
    ['CHECK_INVALID:',s=>{s.check_runs[0].status='queued';}],
    ['RUN_JOB_PROVENANCE_UNKNOWN:',s=>{s.runs[0].run.workflow_id=999;}],
    ['RUN_JOB_PROVENANCE_UNKNOWN:',s=>{s.runs[0].run.path='.github/workflows/attacker.yml';}],
    ['RUN_JOB_PROVENANCE_UNKNOWN:',s=>{s.runs[0].run.head_sha=BASE;}],
    ['RUN_JOB_PROVENANCE_UNKNOWN:',s=>{s.runs[0].run.event='push';}],
    ['RUN_JOB_PROVENANCE_UNKNOWN:',s=>{s.runs[0].jobs[0].id=999;}],
    ['UNEXECUTED_OR_UNBOUND_JOB:',s=>{s.runs[0].jobs[0].runner_id=null;}],
    ['UNEXECUTED_OR_UNBOUND_JOB:',s=>{s.runs[0].jobs[0].steps=[];}],
    ['UNEXECUTED_OR_UNBOUND_JOB:',s=>{s.runs[0].jobs[0].steps[1].conclusion='skipped';}],
    ['UNEXECUTED_OR_UNBOUND_JOB:',s=>{s.runs[0].jobs[0].run_attempt=2;}],
    ['UNEXECUTED_OR_UNBOUND_JOB:',s=>{s.runs[0].jobs[0].conclusion='failure';}],
  ];
  for (let i=0;i<attacks.length;i++) {
    const [reason,mutate]=attacks[i];
    test('negative '+repo+' '+i+' '+reason,()=>denied(repo,mutate,reason));
  }
}
test('comment after a submitted approval does NOT clear approval',()=>{
  const s=sample();
  s.reviews.push({id:5001,user:{id:200001,login:'EXTERNAL-REVIEWER'},
    submitted_at:'2026-11-07T00:04:00Z',state:'COMMENTED',commit_id:SHA});
  assert.equal(verifySnapshot(s).evidence_consistent,true);
});
test('later changes requested rescinds earlier independent approval',()=>{
  const s=sample();
  s.reviews.push({id:5001,user:{id:200001,login:'EXTERNAL-REVIEWER'},
    submitted_at:'2026-11-07T00:04:00Z',state:'CHANGES_REQUESTED',commit_id:SHA});
  assert.ok(verifySnapshot(s).reasons.includes('NO_CURRENT_INDEPENDENT_APPROVAL'));
});
test('newest new-commit approval supersedes stale older approval',()=>{
  const s=sample();
  s.reviews[0].commit_id=BASE;
  s.reviews.push({id:5001,user:{id:200001,login:'EXTERNAL-REVIEWER'},
    submitted_at:'2026-11-07T00:04:00Z',state:'APPROVED',commit_id:SHA});
  assert.equal(verifySnapshot(s).evidence_consistent,true);
});
test('duplicate workflow runs for same required check are ambiguous',()=>{
  const s=sample();
  const copy=structuredClone(s.runs[0]);copy.run.id=3334;copy.jobs.forEach(j=>j.run_id=3334);
  s.runs.push(copy);
  assert.ok(verifySnapshot(s).reasons.some(x=>x.startsWith('RUN_JOB_PROVENANCE_UNKNOWN:')));
});
test('unknown repository and malformed snapshots never authorize',()=>{
  for(const val of [null,false,[],{},'bad',{repo:'attacker/private'}]) {
    const v=verifySnapshot(val);
    assert.equal(v.evidence_consistent,false);
    assert.equal(v.merge_authorized,false);
  }
});

function apiFixture(s) {
  const api='/repos/'+s.repo, pr=s.pr_number, head=s.pr_before.head.sha;
  const records=new Map([
    [api,s.repository],
    [api+'/branches/main',s.branch_before],
    [api+'/pulls/'+pr,s.pr_before],
    [api+'/branches/main/protection',s.protection],
    [api+'/rulesets?includes_parents=true&per_page=100',s.rulesets],
    [api+'/rules/branches/main',s.effective_rules],
    [api+'/contents/.github/CODEOWNERS?ref='+BASE,s.codeowners_main],
    [api+'/contents/.github/workflows/ci.yml?ref='+head,s.workflow_file],
    [api+'/git/commits/'+head,s.head_commit],
    [api+'/pulls/'+pr+'/reviews?per_page=100',s.reviews],
    [api+'/commits/'+head+'/check-runs?per_page=100',{total_count:s.check_runs.length,check_runs:s.check_runs}],
    [api+'/actions/runs?event=pull_request&head_sha='+head+'&per_page=100',
      {total_count:s.runs.length,workflow_runs:s.runs.map(v=>v.run)}],
    ...s.runs.map(v=>[api+'/actions/runs/'+v.run.id+'/jobs?filter=latest&per_page=100',
      {total_count:v.jobs.length,jobs:v.jobs}])
  ]);
  return async path=>{
    if(!records.has(path)) throw Error('UNEXPECTED_PATH:'+path);
    const v=records.get(path);
    return structuredClone(v);
  };
}
test('collector retrieves complete current-head API evidence from explicit GET allowlist',async()=>{
  const s=sample();
  const captured=await captureEvidence(s.repo,s.pr_number,apiFixture(s));
  assert.equal(captured.schema,'atto.github.live-readback.v1');
  assert.equal(captured.pr_after.head.sha,SHA);
  assert.equal(verifySnapshot(captured).evidence_consistent,true);
});
test('collector rejects unauthorized admin protection GET, never silently substitutes unprotected',async()=>{
  const s=sample(), api='/repos/'+s.repo+'/branches/main/protection';
  const get=apiFixture(s);
  await assert.rejects(captureEvidence(s.repo,s.pr_number,p=>
    p===api ? Promise.reject(Error('API_READ_FAILED_403')) : get(p)),/API_READ_FAILED_403/);
});
test('collector denies concurrent PR head or main branch drift',async()=>{
  const s=sample(), q='/repos/'+s.repo+'/pulls/'+s.pr_number, b='/repos/'+s.repo+'/branches/main';
  const get=apiFixture(s);
  let n=0;
  await assert.rejects(captureEvidence(s.repo,s.pr_number,async p=>{
    const val=await get(p);if(p===q && ++n===2)val.head.sha=BASE;return val;
  }),/CONCURRENT_BRANCH_OR_PR_DRIFT/);
  n=0;
  await assert.rejects(captureEvidence(s.repo,s.pr_number,async p=>{
    const val=await get(p);if(p===b && ++n===2)val.commit.sha=SHA;return val;
  }),/CONCURRENT_BRANCH_OR_PR_DRIFT/);
});
test('collector denies unpaginated reviews/checks/jobs and duplicate IDs',async()=>{
  const s=sample(), api='/repos/'+s.repo;
  const get=apiFixture(s);
  for(const [endpoint,mutation,needle] of [
    [api+'/pulls/'+s.pr_number+'/reviews?per_page=100', x=>Array.from({length:100},(_,i)=>({...s.reviews[0],id:i+1})), 'INCOMPLETE_REVIEWS'],
    [api+'/commits/'+SHA+'/check-runs?per_page=100', x=>({...x,total_count:x.total_count+1}), 'CHECK_RUN_PAGINATION'],
    [api+'/actions/runs?event=pull_request&head_sha='+SHA+'&per_page=100',x=>({...x,total_count:x.total_count+1}), 'WORKFLOW_RUN_PAGINATION'],
    [api+'/actions/runs/3333/jobs?filter=latest&per_page=100',x=>({...x,total_count:x.total_count+1}), 'JOB_PAGINATION']
  ]) {
    await assert.rejects(captureEvidence(s.repo,s.pr_number,async p=>
      p===endpoint ? mutation(await get(p)) : get(p)),new RegExp(needle));
  }
});
test('collector never accepts a repo outside pinned allowlist',async()=>{
  await assert.rejects(captureEvidence('attacker/private',1,()=>{}),/UNKNOWN_REPOSITORY/);
  await assert.rejects(captureEvidence(repositories[0],0,()=>{}),/INVALID_CAPTURE_ARGUMENTS/);
});
test('live getter refuses absent token and PR-controlled foreign URL',async()=>{
  assert.throws(()=>githubGetter(''),/MISSING_ADMIN_READ_TOKEN/);
  const get=githubGetter('this-is-a-placeholder-credential-not-sent');
  await assert.rejects(get('/orgs/orestra/secrets'),/UNTRUSTED_API_PATH/);
  await assert.rejects(get('/repos/ores-truffle-oreslang/../x'),/UNTRUSTED_API_PATH/);
});
test('capture CLI argument/credential failures cannot write or authorize',async()=>{
  await assert.rejects(cli(['--repo',repositories[0],'--pr','NaN','--out','/tmp/no-file'],{}),/INVALID_PR/);
  await assert.rejects(cli(['--repo',repositories[0],'--pr','1','--out','/tmp/no-file'],{}),/MISSING_ADMIN_READ_TOKEN/);
});

const keys=generateKeyPairSync('ed25519');
const pub=keys.publicKey.export({type:'spki',format:'pem'});
const der=keys.publicKey.export({type:'spki',format:'der'});
const keyid='sha256:'+createHash('sha256').update(der).digest('hex');
const anchor={keyid,spki_pem:pub,revoked:false};
function envelope(digest) {
  const payload=Buffer.from(digest+'\n','utf8');
  return {payloadType:ATTESTATION_PAYLOAD_TYPE,payload:payload.toString('base64'),
    signatures:[{keyid,sig:sign(null,pae(ATTESTATION_PAYLOAD_TYPE,payload),keys.privateKey).toString('base64')}]};
}
test('real Ed25519 DSSE signature over exact candidate digest verifies, but never authorizes',()=>{
  const digest=verifySnapshot(sample()).candidate_sha256;
  const v=verifyExternalSignature(digest,envelope(digest),anchor);
  assert.equal(v.signature_valid,true,JSON.stringify(v.reasons));
  assert.equal(v.merge_authorized,false);
  assert.equal(v.release_authorized,false);
  assert.equal(v.private_source_export_authorized,false);
});
for(const [name,attack,reason] of [
  ['tampered digest',(e,a)=>{},'DSSE_PAYLOAD_UNBOUND'],
  ['wrong signature',(e,a)=>{e.signatures[0].sig=Buffer.alloc(64).toString('base64');},'BAD_EXTERNAL_SIGNATURE'],
  ['signer alias',(e,a)=>{e.signatures[0].keyid='sha256:'+'0'.repeat(64);},'EXTERNAL_SIGNER_IDENTITY_MISMATCH'],
  ['wrong trust anchor',(e,a)=>{a.keyid='sha256:'+'f'.repeat(64);},'EXTERNAL_SIGNER_IDENTITY_MISMATCH'],
  ['revoked key',(e,a)=>{a.revoked=true;},'EXTERNAL_TRUST_ANCHOR_MISSING_OR_REVOKED'],
  ['embedded rogue key',(e,a)=>{e.publicKey=a.spki_pem;},'DSSE_ENVELOPE_INVALID'],
  ['extra signature',(e,a)=>{e.signatures.push(e.signatures[0]);},'DSSE_ENVELOPE_INVALID'],
  ['invalid payload type',(e,a)=>{e.payloadType='text/plain';},'DSSE_ENVELOPE_INVALID'],
  ['invalid base64',(e,a)=>{e.payload='?';},'DSSE_PAYLOAD_UNBOUND'],
]) {
  test('DSSE rejects '+name,()=>{
    const d=verifySnapshot(sample()).candidate_sha256,e=envelope(d),a={...anchor};
    attack(e,a);
    const hash=name==='tampered digest'?'e'.repeat(64):d;
    const v=verifyExternalSignature(hash,e,a);
    assert.equal(v.signature_valid,false);
    assert.ok(v.reasons.includes(reason),JSON.stringify(v.reasons));
    assert.equal(v.merge_authorized,false);
  });
}
test('separate key with arbitrary self-chosen keyid cannot impersonate trusted signer',()=>{
  const other=generateKeyPairSync('ed25519'),digest=verifySnapshot(sample()).candidate_sha256,e=envelope(digest);
  e.signatures[0].sig=sign(null,pae(ATTESTATION_PAYLOAD_TYPE,Buffer.from(digest+'\n')),other.privateKey).toString('base64');
  assert.ok(verifyExternalSignature(digest,e,anchor).reasons.includes('BAD_EXTERNAL_SIGNATURE'));
});

test('GitHub GET boundary consumes only bounded JSON and uses the immutable api.github.com host',async()=>{
  const token='test-credential-without-network';
  let requests=[];
  const get=githubGetter(token,async (url,options)=>{
    requests.push({url,method:options.method,redirect:options.redirect,auth:options.headers.authorization});
    return new Response('{"safe":true}',{status:200,headers:{'content-type':'application/json'}});
  });
  const r=await get('/repos/ores-truffle-oreslang/oreslang-cli');
  assert.deepEqual(r,{safe:true});
  assert.deepEqual(requests,[{url:'https://api.github.com/repos/ores-truffle-oreslang/oreslang-cli',
    method:'GET',redirect:'error',auth:'Bearer '+token}]);
});
test('GitHub GET boundary denies 403 without decoding or trusting an error body',async()=>{
  const get=githubGetter('test-credential-without-network',async()=>new Response('{"authorized":true}',{status:403}));
  await assert.rejects(get('/repos/ores-truffle-oreslang/oreslang-cli'),/API_READ_FAILED_403/);
});
test('GitHub GET boundary refuses unbounded and explicitly oversized response',async()=>{
  const oversized=Buffer.alloc(2*1024*1024+1,32);
  for(const body of [oversized,Buffer.from('{}'.padEnd(2*1024*1024+1,' '))]){
    const get=githubGetter('test-credential-without-network',
      async()=>new Response(body,{status:200}));
    await assert.rejects(get('/repos/ores-truffle-oreslang/oreslang-cli'),/API_RESPONSE_TOO_LARGE/);
  }
});
test('GitHub GET boundary rejects invalid UTF-8 and malformed JSON bytes',async()=>{
  for(const body of [Buffer.from([0xc0,0xaf]),Buffer.from('{"truncated":')]){
    const get=githubGetter('test-credential-without-network',async()=>new Response(body,{status:200}));
    await assert.rejects(get('/repos/ores-truffle-oreslang/oreslang-cli'));
  }
});
test('GitHub GET boundary refuses API URL authority and invalid injected transport',async()=>{
  assert.throws(()=>githubGetter('test-credential-without-network',null),/INVALID_READ_ONLY_FETCHER/);
  const get=githubGetter('test-credential-without-network',()=>{throw Error('SHOULD_NOT_SEND_REQUEST');});
  for(const path of [
    '/repos/ores-truffle-oreslang/../secrets',
    '/repos/ores-truffle-oreslang//foreign',
    '/orgs/ores-truffle-oreslang/secrets'
  ])await assert.rejects(get(path),/UNTRUSTED_API_PATH/);
});
