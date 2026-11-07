#!/usr/bin/env node
// READ ONLY. Run only on an administrator-controlled host, NEVER inside an untrusted PR.
import { openSync, writeFileSync, closeSync, constants } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { policyFor } from './verify.mjs';

const SHA = /^[a-f0-9]{40}$/;
const isObj = x => x !== null && typeof x === 'object' && !Array.isArray(x);
function requireArray(v, name) {
  if (!Array.isArray(v) || v.length >= 100) throw Error('INCOMPLETE_' + name);
  return v;
}
function requireUniqueIds(list,name) {
  const seen=new Set();
  for (const x of list) {
    if (!Number.isSafeInteger(x?.id) || x.id<=0 || seen.has(x.id)) throw Error('DUPLICATE_OR_BAD_' + name);
    seen.add(x.id);
  }
  return list;
}
export function githubGetter(token,fetcher=fetch) {
  if (typeof token !== 'string' || token.length < 10) throw Error('MISSING_ADMIN_READ_TOKEN');
  if (typeof fetcher !== 'function') throw Error('INVALID_READ_ONLY_FETCHER');
  return async path => {
    if (typeof path !== 'string' || !path.startsWith('/repos/ores-truffle-oreslang/') ||
        path.includes('..') || path.includes('//') || /[^\x21-\x7e]/.test(path)) throw Error('UNTRUSTED_API_PATH');
    const response = await fetcher('https://api.github.com' + path, {
      method:'GET', redirect:'error',
      headers: {
        authorization:'Bearer ' + token,
        accept:'application/vnd.github+json',
        'x-github-api-version':'2022-11-28',
        'user-agent':'atto-independent-evidence-readonly-v1'
      },
      signal:AbortSignal.timeout(10000)
    });
    if (!response.ok) throw Error('API_READ_FAILED_' + response.status);
    const MAX=2*1024*1024;
    const contentLength=response.headers?.get?.('content-length');
    if (contentLength && /^\d+$/.test(contentLength) && Number(contentLength)>MAX) throw Error('API_RESPONSE_TOO_LARGE');
    const reader=response.body?.getReader?.();
    if (!reader) throw Error('API_BODY_UNAVAILABLE');
    let size=0;
    const chunks=[];
    try {
      while (true) {
        const part=await reader.read();
        if (part.done) break;
        if (!(part.value instanceof Uint8Array)) throw Error('INVALID_API_BODY_CHUNK');
        size+=part.value.byteLength;
        if (size>MAX) {
          await reader.cancel();
          throw Error('API_RESPONSE_TOO_LARGE');
        }
        chunks.push(Buffer.from(part.value));
      }
    } finally {
      reader.releaseLock();
    }
    return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,size)));
  };
}
export async function captureEvidence(repo,prNumber,get) {
  const policy = policyFor(repo);
  if (!Number.isSafeInteger(prNumber) || prNumber <= 0 || typeof get !== 'function') throw Error('INVALID_CAPTURE_ARGUMENTS');
  const api = '/repos/' + repo;
  const read = path => get(api+path);
  const repository = await read('');
  if (repository.id !== policy.repo_id || repository.full_name.toLowerCase() !== repo.toLowerCase()) throw Error('WRONG_REPOSITORY');
  const branch_before = await read('/branches/main');
  const pr_before = await read('/pulls/' + prNumber);
  const head = pr_before?.head?.sha;
  if (typeof head !== 'string' || !SHA.test(head)) throw Error('UNTRUSTED_HEAD');
  const protection = await read('/branches/main/protection'); // NO 403 fallback.
  const rawRules = requireArray(await read('/rulesets?includes_parents=true&per_page=100'), 'RULESETS');
  requireUniqueIds(rawRules,'RULESETS');
  const rulesets=[];
  for (const r of rawRules) {
    const full = await read('/rulesets/'+r.id); // inherited 403 => fail closed.
    if (full.id !== r.id) throw Error('RULESET_DETAIL_ID_MISMATCH');
    rulesets.push(full);
  }
  const effective_rules = requireArray(await read('/rules/branches/main'), 'EFFECTIVE_RULES');
  const codeowners_main = await read('/contents/.github/CODEOWNERS?ref='+branch_before.commit.sha);
  const workflow_file = await read('/contents/.github/workflows/ci.yml?ref='+head);
  const head_commit = await read('/git/commits/'+head);
  const reviews = requireUniqueIds(requireArray(await read('/pulls/'+prNumber+'/reviews?per_page=100'), 'REVIEWS'), 'REVIEWS');
  const checksResponse = await read('/commits/'+head+'/check-runs?per_page=100');
  const check_runs = requireUniqueIds(requireArray(checksResponse?.check_runs,'CHECK_RUNS'),'CHECK_RUNS');
  if (checksResponse.total_count !== check_runs.length) throw Error('CHECK_RUN_PAGINATION');
  const runsResponse = await read('/actions/runs?event=pull_request&head_sha='+head+'&per_page=100');
  const rawRuns = requireUniqueIds(requireArray(runsResponse?.workflow_runs,'WORKFLOW_RUNS'),'WORKFLOW_RUNS');
  if (runsResponse.total_count !== rawRuns.length) throw Error('WORKFLOW_RUN_PAGINATION');
  const runs = [];
  for (const run of rawRuns) {
    if (run.head_sha !== head) throw Error('WORKFLOW_RUN_WRONG_SHA');
    if (run.workflow_id !== policy.workflow_id) continue;
    const jr = await read('/actions/runs/'+run.id+'/jobs?filter=latest&per_page=100');
    const jobs = requireUniqueIds(requireArray(jr?.jobs,'JOBS'),'JOBS');
    if (jr.total_count !== jobs.length) throw Error('JOB_PAGINATION');
    runs.push({run,jobs});
  }
  const pr_after = await read('/pulls/'+prNumber);
  const branch_after = await read('/branches/main');
  // Fail closed even before the pure verification stage.
  if (pr_before.head?.sha !== pr_after.head?.sha || pr_before.base?.sha !== pr_after.base?.sha ||
      branch_before.commit?.sha !== branch_after.commit?.sha ||
      pr_after.base?.sha !== branch_after.commit?.sha) throw Error('CONCURRENT_BRANCH_OR_PR_DRIFT');
  return { schema:'atto.github.live-readback.v1', repo, pr_number:prNumber,
    repository, branch_before, branch_after, pr_before,pr_after,
    head_commit,workflow_file,codeowners_main,protection,rulesets,effective_rules,reviews,check_runs,runs };
}
export async function cli(args,env=process.env) {
  if (args.length !== 6 || args[0] !== '--repo' || args[2] !== '--pr' || args[4] !== '--out') {
    throw Error('USAGE_REPO_PR_OUT');
  }
  const pr = Number(args[3]);
  if (!/^[1-9][0-9]*$/.test(args[3]) || !Number.isSafeInteger(pr)) throw Error('INVALID_PR');
  policyFor(args[1]);
  const snapshot = await captureEvidence(args[1],pr,githubGetter(env.GH_TOKEN));
  const data = JSON.stringify(snapshot) + '\n';
  if (Buffer.byteLength(data)>1024*1024) throw Error('SNAPSHOT_TOO_LARGE');
  const fd = openSync(args[5],constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try { writeFileSync(fd,data,{encoding:'utf8'}); }
  finally { closeSync(fd); }
  return {saved:true, merge_authorized:false, release_authorized:false};
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  cli(process.argv.slice(2)).then(()=> {
    process.stdout.write('SAVED_UNTRUSTED_READBACK_NEVER_AUTHORIZES_MERGE\n');
  }).catch(e=> {
    // Never echo untrusted API response body or bearer token.
    process.stderr.write('READ_ONLY_CAPTURE_DENIED:' + (e?.message?.startsWith('API_READ_FAILED_')?e.message:'INVALID_OR_INCOMPLETE_EVIDENCE') + '\n');
    process.exitCode=2;
  });
}
