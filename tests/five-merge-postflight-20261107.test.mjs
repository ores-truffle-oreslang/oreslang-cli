import assert from 'node:assert/strict';
import test from 'node:test';
import {WAVE,evaluateEvidence,evaluateWave} from '../tools/five-merge-postflight-20261107.mjs';
function fixture(t=WAVE[0]){
return {
pr:{merged:true,merged_at:'2026-11-07T00:22:22Z',merge_commit_sha:t.merge,head:{sha:t.head},base:{ref:'main'},user:{id:11}},
branch:{name:'main',protected:true,commit:{sha:t.merge}},
protection:{enforce_admins:{enabled:true},required_status_checks:{strict:true},required_pull_request_reviews:{required_approving_review_count:1,require_code_owner_reviews:true,dismiss_stale_reviews:true}},
rulesets:[],compare:{status:'identical',behind_by:0,base_commit:{sha:t.merge}},
run:{id:t.run,event:'push',head_sha:t.merge,status:'completed',conclusion:'success',run_attempt:1},
jobs:{total_count:1,jobs:[{status:'completed',conclusion:'success',steps:[{name:'Test',status:'completed',conclusion:'success'}]}]},
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
