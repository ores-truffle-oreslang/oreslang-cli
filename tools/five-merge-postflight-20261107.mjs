#!/usr/bin/env node
// Public source-free postflight audit, never a merge or release authorization.
const sha40=/^[a-f0-9]{40}$/;
export const WAVE=Object.freeze([
{repo:'html-js-css-syntax-highlighter',pr:269,head:'c138d109cc6ce121dfc89e25c701a81a0b26fe9e',merge:'30dc3935c71207118149809d713f8d1d8d66154d',run:42317820906},
{repo:'oreslang-cli',pr:151,head:'3235b6d71866593a16e705936fe54afe65b4e5c2',merge:'7eaa52e4f52d95df670d516d34d4907872be1730',run:42317841429},
{repo:'sublime-text-plugins',pr:144,head:'4317e69cbb9640ba5e8008f088d290cf36f1881a',merge:'2f6530a587f69ac5efb68ddfa1321e521bac2422',run:42317848407},
{repo:'vscode-plugins',pr:217,head:'3ed1ff258dfbeb17331c99efd07bf441e42ae3b4',merge:'73b4ae187c68878631649e7936051002605238ff',run:42317855556},
{repo:'html-js-css-syntax-highlighter',pr:267,head:'2defb44bb5f36379c546436909678f76a16872fd',merge:'e53e657a5404fdd465ffbdd2a403b0d67a965c55',run:42317954805}
]);
const meaningful=/\b(test|tests|pytest|unittest|npm run ci|lint|format|smoke|model|render|package|archive|compile|build|verify|validation|validate|chromium|syntax assertions)\b/i;
const excluded=/^(set up job|complete job|post |run actions\/checkout|run actions\/setup-)/i;

function strictUtc(value){
  if(typeof value!=='string')return false;
  const m=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/.exec(value);
  if(!m)return false;
  const [y,mon,day,h,min,s]=m.slice(1).map(Number);
  if(y<1970||mon<1||mon>12||day<1||h>23||min>59||s>59)return false;
  const d=new Date(Date.UTC(y,mon-1,day,h,min,s));
  return d.getUTCFullYear()===y&&d.getUTCMonth()+1===mon&&d.getUTCDate()===day&&d.getUTCHours()===h&&d.getUTCMinutes()===min&&d.getUTCSeconds()===s;
}
export function evaluateEvidence(t,e){
const failures=[];
const fail=x=>{if(!failures.includes(x))failures.push(x)};
const {pr,branch,protection,rulesets,compare,run,jobs,reviews}=e||{};
if(!sha40.test(t.head)||!sha40.test(t.merge))fail('INVALID_PINNED_SHA');
if(pr?.merged!==true||pr?.merge_commit_sha!==t.merge||pr?.head?.sha!==t.head||pr?.base?.ref!=='main'||typeof pr?.merged_at!=='string')fail('MERGE_IDENTITY_UNVERIFIED');
if(branch?.name!=='main'||!sha40.test(branch?.commit?.sha||'')||!['ahead','identical'].includes(compare?.status)||compare?.behind_by!==0||compare?.base_commit?.sha!==t.merge)fail('MAIN_ANCESTRY_UNVERIFIED');
const reviewRule=protection?.required_pull_request_reviews;
const checkRule=protection?.required_status_checks;
const statusNames=[
  ...(Array.isArray(checkRule?.contexts)?checkRule.contexts:[]),
  ...(Array.isArray(checkRule?.checks)?checkRule.checks.map(c=>c?.context):[])
];
if(branch?.protected!==true||!Array.isArray(rulesets)||!protection||
   protection?.enforce_admins?.enabled!==true||
   protection?.allow_force_pushes?.enabled!==false||
   protection?.allow_deletions?.enabled!==false||
   !Number.isSafeInteger(reviewRule?.required_approving_review_count)||
   reviewRule.required_approving_review_count<1||
   reviewRule.require_code_owner_reviews!==true||
   reviewRule.dismiss_stale_reviews!==true||
   checkRule?.strict!==true||
   statusNames.length===0||
   statusNames.some(n=>typeof n!=='string'||n.trim()!==n||n.length===0)||
   new Set(statusNames).size!==statusNames.length)
  fail('ENFORCED_BRANCH_POLICY_UNVERIFIED');
if(run?.id!==t.run||run?.event!=='push'||run?.head_sha!==t.merge||run?.status!=='completed'||run?.conclusion!=='success'||!Number.isSafeInteger(run?.run_attempt)||run.run_attempt<1)fail('POST_MERGE_RUN_UNVERIFIED');
const jobList=jobs?.jobs;
if(!Array.isArray(jobList)||jobList.length===0||
   jobs?.total_count!==jobList.length||
   new Set(jobList.map(j=>j.id)).size!==jobList.length||
   new Set(jobList.map(j=>j.name)).size!==jobList.length||
   jobList.some(j=>!Number.isSafeInteger(j.id)||j.id<=0||
      !Number.isSafeInteger(j.run_id)||j.run_id!==t.run||
      !Number.isSafeInteger(j.run_attempt)||j.run_attempt!==run?.run_attempt||
      !Number.isSafeInteger(j.runner_id)||j.runner_id<=0||
      j.status!=='completed'||j.conclusion!=='success'||
      !Array.isArray(j.steps)||j.steps.length===0||
      j.steps.some(s=>s.status!=='completed'||s.conclusion!=='success'))||
   !jobList?.some(j=>j.steps?.some(s=>s.status==='completed'&&
      s.conclusion==='success'&&meaningful.test(s.name||'')&&!excluded.test(s.name||''))))
  fail('MEANINGFUL_EXECUTED_TEST_UNVERIFIED');
const mergedAt=pr?.merged_at;
let timelineValid=Array.isArray(reviews)&&strictUtc(mergedAt);
const latestByReviewer=new Map();
if(timelineValid){
  for(const r of reviews){
    if(!Number.isSafeInteger(r.user?.id)||r.user.id<=0||
       !['APPROVED','CHANGES_REQUESTED','COMMENTED','DISMISSED'].includes(r.state)||
       !sha40.test(r.commit_id||'')||!strictUtc(r.submitted_at)||
       r.submitted_at>mergedAt){
      timelineValid=false;break;
    }
    const previous=latestByReviewer.get(r.user.id);
    if(previous&&previous.submitted_at===r.submitted_at){
      timelineValid=false;break;
    }
    if(!previous||previous.submitted_at<r.submitted_at)latestByReviewer.set(r.user.id,r);
  }
}
if(!timelineValid)fail('REVIEW_TIMELINE_INVALID_OR_INCOMPLETE');
const latest=[...latestByReviewer.values()];
if(latest.some(r=>r.state==='CHANGES_REQUESTED'))fail('OUTSTANDING_CHANGES_REQUESTED');
const approvers=timelineValid?latest.filter(r=>r.state==='APPROVED'&&r.commit_id===t.head&&r.user.id!==pr?.user?.id):[];
if(approvers.length===0)fail('INDEPENDENT_PRE_MERGE_APPROVAL_ABSENT');
// Current settings cannot certify historical enforcement; release remains blocked.
fail('HISTORICAL_ENFORCEMENT_AND_RELEASE_RECERTIFICATION_REQUIRED');
return {repository:'ores-truffle-oreslang/'+t.repo,pr:t.pr,merge:t.merge,verdict:'BLOCKED',failures};
}
export function evaluateWave(snapshot){
const records=WAVE.map(t=>evaluateEvidence(t,snapshot?.[t.repo+'#'+t.pr]));
return {schema:'atto-five-merge-postflight-v1',verdict:'BLOCKED',merges:records.length,repositories:new Set(WAVE.map(t=>t.repo)).size,records};
}
async function api(path,token){
if(!/^\/repos\/ores-truffle-oreslang\/[a-z0-9.-]+\/(?:pulls\/\d+(?:\/reviews)?|branches\/main(?:\/protection)?|rulesets|compare\/[a-f0-9]{40}\.\.\.main|actions\/runs\/\d+(?:\/jobs)?)$/.test(path))throw Error('UNSAFE_API_PATH');
const headers={Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'};
if(token)headers.Authorization='Bearer '+token;
const res=await fetch('https://api.github.com'+path,{headers,redirect:'error',signal:AbortSignal.timeout(12000)});
if(!res.ok)throw Error('HTTP_'+res.status);
if(Number(res.headers.get('content-length')||0)>1048576)throw Error('OVERSIZE_API_RESPONSE');
const body=await res.text();
if(body.length>1048576)throw Error('OVERSIZE_API_RESPONSE');
if(res.headers.get('link')?.includes('rel="next"'))throw Error('PAGINATION_NOT_EXHAUSTED');
return JSON.parse(body);
}
export async function collectLive(token=''){
const snapshot={};
for(const t of WAVE){
const base='/repos/ores-truffle-oreslang/'+t.repo, data={}, errors={};
const paths={pr:base+'/pulls/'+t.pr,branch:base+'/branches/main',protection:base+'/branches/main/protection',rulesets:base+'/rulesets',compare:base+'/compare/'+t.merge+'...main',run:base+'/actions/runs/'+t.run,jobs:base+'/actions/runs/'+t.run+'/jobs',reviews:base+'/pulls/'+t.pr+'/reviews'};
for(const [k,path] of Object.entries(paths)){
try{data[k]=await api(path,token)}catch(err){data[k]=null;errors[k]=String(err.message).slice(0,60)}
}
snapshot[t.repo+'#'+t.pr]={...data,errors};
}
return snapshot;
}
if(process.argv[1]?.endsWith('/tools/five-merge-postflight-20261107.mjs')){
if(process.argv.length!==3||process.argv[2]!=='--live'){process.stderr.write('Usage: node tools/five-merge-postflight-20261107.mjs --live\n');process.exitCode=64}
else{
try{
const data=await collectLive(process.env.GITHUB_TOKEN||''),result=evaluateWave(data);
for(const r of result.records)r.api_errors=data[r.repository.split('/')[1]+'#'+r.pr].errors;
process.stdout.write(JSON.stringify(result,null,2)+'\n');
process.exitCode=2;
}catch(e){process.stderr.write('POSTFLIGHT_UNVERIFIED: '+e.message+'\n');process.exitCode=2}
}
}
