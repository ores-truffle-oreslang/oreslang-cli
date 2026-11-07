import { test } from 'node:test';
import assert from 'node:assert/strict';
import { qualifyWave } from '../tools/merge-wave-preflight-v1/qualify.mjs';

const SHA = n => n.toString(16).padStart(40, '0');
const T = '2026-11-06T23:30:00.000Z';
const clone = x => structuredClone(x);
const goodPolicy = () => ({
  protected: true, rulesets_verified: true, independent_review_enforced: true,
  stale_review_dismissal: true, required_checks_enforced: true,
  admin_bypass_disabled: true, bypass_actors: [],
});
function candidate(i) {
  const repo = 'ores-truffle-oreslang/' + ['repo-a','repo-b','repo-c','repo-d','repo-e'][i % 5];
  const head = SHA(i + 10), tree = SHA(i + 20), base = SHA(i + 30);
  return {
    repo, number: i + 1, state: 'open', draft: false,
    mergeable: true, conflict_free: true, active_agent_lease: false,
    head_sha: head, observed_head_sha: head, tree_sha: tree,
    base_sha: base, observed_base_sha: base, author: 'author',
    policy: goodPolicy(),
    reviews: [{user:'independent',state:'APPROVED',commit_id:head,submitted_at:T,verified_independent:true}],
    ci: {
      source_owned: true, conclusion: 'success', run_id: i + 100, run_attempt: 1,
      head_sha: head, checkout_sha: head, tree_sha: tree,
      source_integrity_verified: true, run_event: 'pull_request',
      jobs: [{name:'test',runner_id:44,conclusion:'success',steps:[
        {name:'checkout',kind:'checkout',status:'completed',conclusion:'success'},
        {name:'test',kind:'source_test',status:'completed',conclusion:'success'},
      ]}],
    },
  };
}
function wave() {
  return {as_of:T, candidates:[0,1,2,3,4].map(candidate),
    agent_coordinator_verified:true,live_head_refresh_required:true,post_merge_base_refresh_required:true};
}
const qualifies = w => qualifyWave(w, T);
function blocked(title, mutate, expected) {
  test(title, () => {
    const w = wave(); mutate(w);
    const result = qualifies(w);
    assert.equal(result.status, 'BLOCKED');
    assert.equal(result.merge_authorized, false);
    assert.ok(result.reasons.some(s=>s.includes(expected)), JSON.stringify(result.reasons));
  });
}

test('synthetic valid 5-in-5 is ONLY advisory, never authorization', () => {
  const x = qualifies(wave());
  assert.equal(x.status, 'READY_FOR_LIVE_RECHECK');
  assert.deepEqual(x.reasons, []);
  assert.equal(x.merge_authorized, false);
  assert.equal(x.release_authorized, false);
  assert.equal(x.guest_parity_proven, false);
  assert.equal(x.max_merge_attempts_authorized, 0);
  assert.equal(x.live_recheck_required, true);
  assert.ok(Object.isFrozen(x));
});
test('five PRs over exactly three repos meets quorum without authorizing the wave', () => {
  const w = wave();
  w.candidates[3].repo=w.candidates[0].repo;
  w.candidates[4].repo=w.candidates[1].repo;
  assert.equal(qualifies(w).status,'READY_FOR_LIVE_RECHECK');
  assert.equal(qualifies(w).max_merge_attempts_authorized,0);
});
blocked('4 PRs fails five-PR quorum', w=>w.candidates.pop(), 'FIVE_PR_QUORUM');
blocked('51 PRs fails bounded input', w=>w.candidates.push(...Array.from({length:46},(_,i)=>candidate(i+5))), 'FIVE_PR_QUORUM');
blocked('5 PRs in only two repos fails three-repo quorum', w=>w.candidates.forEach((c,i)=>{c.repo='ores-truffle-oreslang/repo-'+i%2}),'THREE_REPO_QUORUM');
blocked('duplicate PR identity fails even across five slots', w=>{w.candidates[4].repo=w.candidates[0].repo;w.candidates[4].number=w.candidates[0].number}, 'DUPLICATE_PR');
blocked('invalid repo fails identity check', w=>w.candidates[0].repo='outside/repo','BAD_PR_IDENTITY');
blocked('non-positive PR number fails', w=>w.candidates[0].number=0,'BAD_PR_IDENTITY');
blocked('missing author identity fails', w=>delete w.candidates[0].author,'BAD_PR_IDENTITY');
blocked('closed PR fails', w=>w.candidates[0].state='closed','NOT_READY');
blocked('draft PR fails', w=>w.candidates[0].draft=true,'NOT_READY');
blocked('false mergeability fails', w=>w.candidates[0].mergeable=false,'MERGE_CONFLICT_OR_UNKNOWN');
blocked('unknown mergeability fails', w=>w.candidates[0].mergeable=null,'MERGE_CONFLICT_OR_UNKNOWN');
blocked('semantic conflict fails', w=>w.candidates[0].conflict_free=false,'MERGE_CONFLICT_OR_UNKNOWN');
blocked('agent lease active fails', w=>w.candidates[0].active_agent_lease=true,'ACTIVE_OR_UNKNOWN_LEASE');
blocked('missing lease evidence fails', w=>delete w.candidates[0].active_agent_lease,'ACTIVE_OR_UNKNOWN_LEASE');
blocked('non SHA-1 commit identity fails', w=>w.candidates[0].head_sha='abc','INVALID_SOURCE_IDENTITY');
blocked('force-push after qualification fails', w=>w.candidates[0].observed_head_sha=SHA(999),'HEAD_DRIFT');
blocked('target branch moved before qualification fails', w=>w.candidates[0].observed_base_sha=SHA(999),'BASE_DRIFT');
blocked('subsequent same-repo merge moves base requiring fresh qualification', w=>{
  w.candidates[4].repo=w.candidates[0].repo; w.candidates[4].observed_base_sha=SHA(999);
}, 'BASE_DRIFT');
for (const key of ['protected','rulesets_verified','independent_review_enforced',
                   'stale_review_dismissal','required_checks_enforced','admin_bypass_disabled']) {
  blocked('policy '+key+'=false fails closed', w=>w.candidates[0].policy[key]=false,'UNENFORCED_MAIN_POLICY');
  blocked('policy '+key+'=unknown fails closed', w=>delete w.candidates[0].policy[key],'UNENFORCED_MAIN_POLICY');
}
blocked('bypass actor defeats policy', w=>w.candidates[0].policy.bypass_actors=['admin'],'UNENFORCED_MAIN_POLICY');
blocked('requested review is not submitted approval', w=>w.candidates[0].reviews=[],'NO_CURRENT_INDEPENDENT_APPROVAL');
blocked('self approval is not independent', w=>w.candidates[0].reviews[0].user='author','NO_CURRENT_INDEPENDENT_APPROVAL');
blocked('unverified reviewer identity fails', w=>w.candidates[0].reviews[0].verified_independent=false,'NO_CURRENT_INDEPENDENT_APPROVAL');
blocked('approval on old commit fails', w=>w.candidates[0].reviews[0].commit_id=SHA(333),'NO_CURRENT_INDEPENDENT_APPROVAL');
blocked('comment is not approval', w=>w.candidates[0].reviews[0].state='COMMENTED','NO_CURRENT_INDEPENDENT_APPROVAL');
blocked('dismissed approval fails', w=>w.candidates[0].reviews.push({...w.candidates[0].reviews[0],state:'DISMISSED'}),'NO_CURRENT_INDEPENDENT_APPROVAL');
blocked('changes requested after approval fails', w=>w.candidates[0].reviews.push({...w.candidates[0].reviews[0],state:'CHANGES_REQUESTED'}),'OUTSTANDING_CHANGES_REQUESTED');
blocked('one reviewer changes-requested despite another approval fails', w=>w.candidates[0].reviews.push({
  user:'reviewer-2',state:'CHANGES_REQUESTED',commit_id:w.candidates[0].head_sha,submitted_at:T
}), 'OUTSTANDING_CHANGES_REQUESTED');
blocked('later comment does not clear changes requested', w=>{
  const r=w.candidates[0].reviews[0];
  w.candidates[0].reviews=[r,{...r,user:'second',state:'CHANGES_REQUESTED',submitted_at:'2026-11-06T23:29:00.000Z'},
                             {...r,user:'second',state:'COMMENTED',submitted_at:T}];
},'OUTSTANDING_CHANGES_REQUESTED');
blocked('reviewer state malformed fails', w=>w.candidates[0].reviews[0].state='SUPER_APPROVED','MALFORMED_REVIEW_TIMELINE');
blocked('review future-dated relative to snapshot fails', w=>w.candidates[0].reviews[0].submitted_at='2026-11-07T00:00:00.000Z','MALFORMED_REVIEW_TIMELINE');
blocked('no submitted reviews array fails', w=>delete w.candidates[0].reviews,'MISSING_REVIEWS');
blocked('CI run failure blocks', w=>w.candidates[0].ci.conclusion='failure','INVALID_EXACT_HEAD_CI');
blocked('source-free successful step zero blocks', w=>w.candidates[0].ci.jobs[0].steps=[],'ZERO_STEP_OR_INCOMPLETE_CI');
blocked('runner admission fails', w=>w.candidates[0].ci.jobs[0].runner_id=null,'ZERO_STEP_OR_INCOMPLETE_CI');
blocked('runner id zero fails', w=>w.candidates[0].ci.jobs[0].runner_id=0,'ZERO_STEP_OR_INCOMPLETE_CI');
blocked('skipped job with no test blocks', w=>w.candidates[0].ci.jobs[0].steps=[
  {name:'checkout',kind:'checkout',status:'completed',conclusion:'success'}
],'ZERO_STEP_OR_INCOMPLETE_CI');
blocked('bad step conclusion blocks', w=>w.candidates[0].ci.jobs[0].steps[1].conclusion='failure','ZERO_STEP_OR_INCOMPLETE_CI');
blocked('test step queued blocks', w=>w.candidates[0].ci.jobs[0].steps[1].status='queued','ZERO_STEP_OR_INCOMPLETE_CI');
blocked('duplicate job names block', w=>w.candidates[0].ci.jobs.push(clone(w.candidates[0].ci.jobs[0])),'ZERO_STEP_OR_INCOMPLETE_CI');
blocked('synthetic CI without source-owned job blocks', w=>w.candidates[0].ci.source_owned=false,'INVALID_EXACT_HEAD_CI');
blocked('synthetic merge checkout blocks', w=>w.candidates[0].ci.checkout_sha=SHA(555),'INVALID_EXACT_HEAD_CI');
blocked('mismatched test source tree blocks', w=>w.candidates[0].ci.tree_sha=SHA(555),'INVALID_EXACT_HEAD_CI');
blocked('job provenance without source integrity verification blocks', w=>w.candidates[0].ci.source_integrity_verified=false,'INVALID_EXACT_HEAD_CI');
blocked('wrong event blocks', w=>w.candidates[0].ci.run_event='push','INVALID_EXACT_HEAD_CI');
blocked('invalid run attempt blocks', w=>w.candidates[0].ci.run_attempt=0,'INVALID_EXACT_HEAD_CI');
blocked('no agent coordination fails', w=>w.agent_coordinator_verified=false,'AGENT_COORDINATION_UNVERIFIED');
blocked('no live head refresh plan fails', w=>w.live_head_refresh_required=false,'MISSING_SEQUENTIAL_RECHECK');
blocked('no post-merge base refresh plan fails', w=>w.post_merge_base_refresh_required=false,'MISSING_SEQUENTIAL_RECHECK');
blocked('invalid calendar date fails', w=>w.as_of='2026-02-30T00:00:00.000Z','BAD_SNAPSHOT_OR_TIME');
blocked('stale snapshot fails', w=>w.as_of='2026-11-06T20:30:00.000Z','STALE_OR_FUTURE_SNAPSHOT');
blocked('future snapshot fails', w=>w.as_of='2026-11-07T00:00:00.000Z','STALE_OR_FUTURE_SNAPSHOT');
blocked('missing candidates fails', w=>delete w.candidates,'MISSING_CANDIDATES');

test('null snapshot is blocked',()=>assert.ok(qualifyWave(null,T).reasons.includes('BAD_SNAPSHOT_OR_TIME')));
test('malformed review chronology is blocked',()=>{
 const w=wave(); const r=w.candidates[0].reviews[0];
 w.candidates[0].reviews.unshift({...r,submitted_at:'2026-11-06T23:29:00.000Z'});
 w.candidates[0].reviews.push({...r,submitted_at:'2026-11-06T23:28:00.000Z'});
 assert.ok(qualifies(w).reasons.some(x=>x.includes('MALFORMED_REVIEW_TIMELINE')));
});
test('valid same reviewer changes-requested followed by verified approval clears history',()=>{
 const w=wave(); const r=w.candidates[0].reviews[0];
 w.candidates[0].reviews=[{...r,submitted_at:'2026-11-06T23:28:00.000Z',state:'CHANGES_REQUESTED'},r];
 assert.equal(qualifies(w).status,'READY_FOR_LIVE_RECHECK');
});
test('deterministic reason codes with no duplicates',()=>{
 const w=wave();w.candidates[0].draft=true; w.candidates[0].policy.protected=false;
 assert.deepEqual(qualifies(w),qualifies(clone(w)));
 assert.equal(new Set(qualifies(w).reasons).size,qualifies(w).reasons.length);
});
test('positive status never grants authorization across 100 mutation-free inputs',()=>{
 for(let i=0;i<100;i++){
   const w=wave(); w.candidates.forEach((p,j)=>p.number+=i*10+j);
   const result=qualifies(w);
   assert.equal(result.status,'READY_FOR_LIVE_RECHECK');
   assert.equal(result.merge_authorized,false);
   assert.equal(result.max_merge_attempts_authorized,0);
 }
});