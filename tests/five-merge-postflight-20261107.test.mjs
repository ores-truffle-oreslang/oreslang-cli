import assert from 'node:assert/strict';
import test from 'node:test';
import {WAVE,evaluateEvidence,evaluateWave} from '../tools/five-merge-postflight-20261107.mjs';
function fixture(t=WAVE[0]){
return {
pr:{merged:true,merged_at:'2026-11-07T00:22:22Z',merge_commit_sha:t.merge,head:{sha:t.head},base:{ref:'main'},user:{id:11}},
branch:{name:'main',protected:true,commit:{sha:t.merge}},
protection:{enforce_admins:{enabled:true},allow_force_pushes:{enabled:false},allow_deletions:{enabled:false},required_status_checks:{strict:true,contexts:['CI / rust']},required_pull_request_reviews:{required_approving_review_count:1,require_code_owner_reviews:true,dismiss_stale_reviews:true}},
rulesets:[],compare:{status:'identical',behind_by:0,base_commit:{sha:t.merge}},
run:{id:t.run,event:'push',head_sha:t.merge,status:'completed',conclusion:'success',run_attempt:1},
jobs:{total_count:1,jobs:[{id:99,name:'test',run_id:t.run,run_attempt:1,runner_id:42,status:'completed',conclusion:'success',steps:[{number:1,name:'Test',status:'completed',conclusion:'success'}]}]},
reviews:[{user:{id:22},state:'APPROVED',commit_id:t.head,submitted_at:'2026-11-07T00:10:00Z'}]
};
}
const failures=x=>evaluateEvidence(WAVE[0],x).failures;
const denied=(e,code)=>assert.ok(failures(e).includes(code),code);
test('wave pins five merge heads across four repositories',()=>{
assert.equal(WAVE.length,5);assert.equal(new Set(WAVE.map(x=>x.repo)).size,4);
for(const x of WAVE){assert.match(x.head,/^[a-f0-9]{40}$/);assert.match(x.merge,/^[a-f0-9]{40}$/)}
});
test('even perfect current evidence cannot authorize release retroactively',()=>{
assert.deepEqual(failures(fixture()),['HISTORICAL_ENFORCEMENT_AND_RELEASE_RECERTIFICATION_REQUIRED']);
assert.equal(evaluateEvidence(WAVE[0],fixture()).verdict,'BLOCKED');
});
test('unprotected branch and missing permission deny promotion',()=>{
const a=fixture();a.branch.protected=false;denied(a,'ENFORCED_BRANCH_POLICY_UNVERIFIED');
const b=fixture();b.protection=null;denied(b,'ENFORCED_BRANCH_POLICY_UNVERIFIED');
});
test('CODEOWNERS is not enforcement without reviews, stale review removal and admin rules',()=>{
for(const prop of ['require_code_owner_reviews','dismiss_stale_reviews']){const e=fixture();e.protection.required_pull_request_reviews[prop]=false;denied(e,'ENFORCED_BRANCH_POLICY_UNVERIFIED')}
const e=fixture();e.protection.enforce_admins.enabled=false;denied(e,'ENFORCED_BRANCH_POLICY_UNVERIFIED');
});
test('missing, self, stale, and post-merge approval all fail',()=>{
for(const mutate of [
e=>{e.reviews=[]},e=>{e.reviews[0].user.id=11},e=>{e.reviews[0].commit_id='f'.repeat(40)},e=>{e.reviews[0].submitted_at='2026-11-07T00:40:00Z'}
]){const e=fixture();mutate(e);denied(e,'INDEPENDENT_PRE_MERGE_APPROVAL_ABSENT')}
});
test('zero/null steps, setup-only jobs and incomplete pagination fail',()=>{
for(const mutate of [
e=>{e.jobs.jobs[0].steps=[]},e=>{e.jobs.jobs[0].steps=null},
e=>{e.jobs.jobs[0].steps=[{name:'Set up job',status:'completed',conclusion:'success'}]},
e=>{e.jobs.total_count=2}
]){const e=fixture();mutate(e);denied(e,'MEANINGFUL_EXECUTED_TEST_UNVERIFIED')}
});
test('wrong workflow event, run SHA or run attempt fails',()=>{
for(const mutate of [
e=>{e.run.event='pull_request'},e=>{e.run.head_sha='a'.repeat(40)},e=>{e.run.run_attempt=0}
]){const e=fixture();mutate(e);denied(e,'POST_MERGE_RUN_UNVERIFIED')}
});
test('wrong merge, stale original PR head and lost ancestry fail',()=>{
for(const [mutate,code] of [
[e=>{e.pr.merge_commit_sha='a'.repeat(40)},'MERGE_IDENTITY_UNVERIFIED'],
[e=>{e.pr.head.sha='b'.repeat(40)},'MERGE_IDENTITY_UNVERIFIED'],
[e=>{e.compare.behind_by=1},'MAIN_ANCESTRY_UNVERIFIED'],
[e=>{e.compare=null},'MAIN_ANCESTRY_UNVERIFIED']
]){const e=fixture();mutate(e);denied(e,code)}
});
test('empty/untrusted evidence is never green',()=>{
const e=evaluateWave({});assert.equal(e.verdict,'BLOCKED');assert.equal(e.records.length,5);
for(const r of e.records)assert.ok(r.failures.length>=3);
});


// Each case is independently reported; even a historically qualified-looking
// snapshot must remain BLOCKED and expose the specific missing evidence.
const reviewMutations=[
 ['approval later dismissed',e=>e.reviews.push({user:{id:22},state:'DISMISSED',commit_id:WAVE[0].head,submitted_at:'2026-11-07T00:12:00Z'})],
 ['approval followed by changes requested',e=>e.reviews.push({user:{id:22},state:'CHANGES_REQUESTED',commit_id:WAVE[0].head,submitted_at:'2026-11-07T00:12:00Z'})],
 ['approval followed by comment',e=>e.reviews.push({user:{id:22},state:'COMMENTED',commit_id:WAVE[0].head,submitted_at:'2026-11-07T00:12:00Z'})],
 ['approval then new-head review',e=>e.reviews.push({user:{id:22},state:'APPROVED',commit_id:'f'.repeat(40),submitted_at:'2026-11-07T00:12:00Z'})],
 ['author impersonates independent reviewer',e=>e.reviews[0].user.id=e.pr.user.id],
 ['missing reviewer identity',e=>e.reviews[0].user={}],
 ['zero reviewer ID',e=>e.reviews[0].user.id=0],
 ['noninteger reviewer ID',e=>e.reviews[0].user.id='22'],
 ['invalid review state',e=>e.reviews[0].state='PENDING'],
 ['missing review source head',e=>delete e.reviews[0].commit_id],
 ['incorrect review source SHA',e=>e.reviews[0].commit_id='f'.repeat(40)],
 ['approval after merge',e=>e.reviews[0].submitted_at='2026-11-07T00:55:00Z'],
 ['invalid Gregorian leap day',e=>e.reviews[0].submitted_at='2026-02-29T00:00:00Z'],
 ['invalid February 30 normalization',e=>e.reviews[0].submitted_at='2026-02-30T00:00:00Z'],
 ['impossible hour 24',e=>e.reviews[0].submitted_at='2026-11-07T24:00:00Z'],
 ['leap second 60',e=>e.reviews[0].submitted_at='2026-11-07T00:00:60Z'],
 ['timezone normalization',e=>e.reviews[0].submitted_at='2026-11-07T00:10:00+00:00'],
 ['missing review time',e=>delete e.reviews[0].submitted_at],
 ['duplicate equal timestamp',e=>e.reviews.push({...e.reviews[0],state:'COMMENTED'})],
 ['missing review list',e=>delete e.reviews],
 ['missing historical merged timestamp',e=>delete e.pr.merged_at],
 ['invalid historical merge calendar day',e=>e.pr.merged_at='2026-02-30T00:00:00Z'],
];
for(const [name,mutate] of reviewMutations)test('review timeline rejects '+name,()=>{
 const e=fixture();mutate(e);denied(e,'INDEPENDENT_PRE_MERGE_APPROVAL_ABSENT');
 assert.equal(evaluateEvidence(WAVE[0],e).verdict,'BLOCKED');
});
const jobMutations=[
 ['missing runner',e=>delete e.jobs.jobs[0].runner_id],
 ['zero runner',e=>e.jobs.jobs[0].runner_id=0],
 ['string runner',e=>e.jobs.jobs[0].runner_id='42'],
 ['missing run identity',e=>delete e.jobs.jobs[0].run_id],
 ['wrong run identity',e=>e.jobs.jobs[0].run_id=5],
 ['wrong run attempt',e=>e.jobs.jobs[0].run_attempt=2],
 ['missing run attempt',e=>delete e.jobs.jobs[0].run_attempt],
 ['duplicate job ID',e=>{e.jobs.jobs.push({...e.jobs.jobs[0]});e.jobs.total_count=2;}],
 ['duplicate job name',e=>{e.jobs.jobs.push({...e.jobs.jobs[0],id:100});e.jobs.total_count=2;}],
 ['partial successful job plus failed',e=>{e.jobs.jobs.push({...e.jobs.jobs[0],id:100,name:'failed',conclusion:'failure'});e.jobs.total_count=2;}],
 ['zero-step companion',e=>{e.jobs.jobs.push({...e.jobs.jobs[0],id:100,name:'empty',steps:[]});e.jobs.total_count=2;}],
 ['failed test step',e=>e.jobs.jobs[0].steps[0].conclusion='failure'],
 ['skipped test step',e=>e.jobs.jobs[0].steps[0].conclusion='skipped'],
 ['setup-only CI',e=>e.jobs.jobs[0].steps[0].name='Set up job'],
 ['invalid job status',e=>e.jobs.jobs[0].status='queued'],
 ['unrecorded job pagination',e=>e.jobs.total_count=2],
 ['empty job collection',e=>{e.jobs.jobs=[];e.jobs.total_count=0;}],
];
for(const [name,mutate] of jobMutations)test('executed CI receipt rejects '+name,()=>{
 const e=fixture();mutate(e);denied(e,'MEANINGFUL_EXECUTED_TEST_UNVERIFIED');
 assert.equal(evaluateEvidence(WAVE[0],e).verdict,'BLOCKED');
});
test('latest valid independent approval alone is still not release certification',()=>{
 const e=fixture();
 e.reviews.push({user:{id:22},state:'COMMENTED',commit_id:WAVE[0].head,submitted_at:'2026-11-07T00:06:00Z'});
 assert.deepEqual(failures(e),['HISTORICAL_ENFORCEMENT_AND_RELEASE_RECERTIFICATION_REQUIRED']);
});
test('changes requested by another reviewer remains an explicit blocker',()=>{
 const e=fixture();
 e.reviews.push({user:{id:55},state:'CHANGES_REQUESTED',commit_id:WAVE[0].head,submitted_at:'2026-11-07T00:13:00Z'});
 denied(e,'OUTSTANDING_CHANGES_REQUESTED');
});


const protectionMutations=[
 ['missing approval minimum',e=>delete e.protection.required_pull_request_reviews.required_approving_review_count],
 ['zero approval minimum',e=>e.protection.required_pull_request_reviews.required_approving_review_count=0],
 ['string approval minimum',e=>e.protection.required_pull_request_reviews.required_approving_review_count='1'],
 ['fractional approval minimum',e=>e.protection.required_pull_request_reviews.required_approving_review_count=0.5],
 ['null review policy',e=>e.protection.required_pull_request_reviews=null],
 ['missing enforce administrators',e=>delete e.protection.enforce_admins],
 ['force pushes allowed',e=>e.protection.allow_force_pushes.enabled=true],
 ['force push setting missing',e=>delete e.protection.allow_force_pushes],
 ['deletion allowed',e=>e.protection.allow_deletions.enabled=true],
 ['deletion setting missing',e=>delete e.protection.allow_deletions],
 ['empty required checks',e=>e.protection.required_status_checks.contexts=[]],
 ['missing check list',e=>delete e.protection.required_status_checks.contexts],
 ['duplicate required check',e=>e.protection.required_status_checks.contexts=['CI / rust','CI / rust']],
 ['blank required check',e=>e.protection.required_status_checks.contexts=['']],
 ['whitespace check spoof',e=>e.protection.required_status_checks.contexts=['CI / rust ']],
 ['missing strict status setting',e=>delete e.protection.required_status_checks.strict],
 ['required status strict false',e=>e.protection.required_status_checks.strict=false],
 ['protected branch false',e=>e.branch.protected=false],
 ['missing ruleset collection',e=>delete e.rulesets],
];
for(const [name,mutate] of protectionMutations)test('branch governance fail-closed: '+name,()=>{
 const e=fixture();mutate(e);denied(e,'ENFORCED_BRANCH_POLICY_UNVERIFIED');
 assert.equal(evaluateEvidence(WAVE[0],e).verdict,'BLOCKED');
});
