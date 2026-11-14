import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {
  REPOSITORIES, assess, audit, auditRepository, githubReader, main,
} from '../tools/branch-governance-audit-v1/verify.mjs';

const REPO = 'ores-truffle-oreslang/oreslang-cli';
const SOURCE = 'ores-truffle-oreslang/oreslang-source.java';
const HEAD = 'a'.repeat(40);
const validBranch = () => ({name:'main',protected:true,commit:{sha:HEAD}});
const validProtection = () => ({
  required_pull_request_reviews: {
    required_approving_review_count:1,
    require_code_owner_reviews:true,
    dismiss_stale_reviews:true,
    require_last_push_approval:true,
    bypass_pull_request_allowances:{users:[],teams:[],apps:[]},
  },
  enforce_admins:{enabled:true},
  allow_force_pushes:{enabled:false},
  allow_deletions:{enabled:false},
  required_conversation_resolution:{enabled:true},
  required_status_checks:{
    strict:true,
    contexts:['CI','private-ci-policy'],
    checks:[{context:'CI',app_id:15368},{context:'private-ci-policy',app_id:15368}],
  },
});
const result = (repo = REPO, a = validBranch(), b = validProtection(), c = validBranch()) =>
  assess(repo,a,b,c);

test('inventory covers five compilers, six platform members, conformance, editors and CLI', () => {
  assert.equal(REPOSITORIES.length,16);
  assert.equal(new Set(REPOSITORIES).size,16);
  for (const repo of REPOSITORIES) assert.match(repo, /^ores-truffle-oreslang\//);
  for (const suffix of ['java','llvm','wasm','forge','net'])
    assert.ok(REPOSITORIES.includes('ores-truffle-oreslang/oreslang-source.' + suffix));
});

test('valid classic branch policy is only advisory, never merge or release authority', () => {
  for (const repo of [REPO,SOURCE]) {
    const entry = result(repo);
    assert.equal(entry.policy_state,'REQUIREMENTS_OBSERVED');
    assert.deepEqual(entry.blockers,[]);
    assert.equal(entry.release_authorized,false);
    assert.equal(entry.merge_authorized,false);
    assert.equal(entry.private_source_export_authorized,false);
    assert.equal(entry.observed_main_sha,HEAD);
  }
});

test('unprotected main is always denied', () => {
  const before = validBranch();
  before.protected = false;
  assert.ok(result(REPO,before).blockers.includes('MAIN_UNPROTECTED'));
});

test('branch movement or malformed SHA is blocked', () => {
  const later = validBranch(); later.commit.sha = 'b'.repeat(40);
  assert.ok(result(REPO,validBranch(),validProtection(),later).blockers.includes('MAIN_MOVED_DURING_AUDIT'));
  const wrong = validBranch(); wrong.commit.sha = 'wrong';
  assert.ok(result(REPO,wrong).blockers.includes('BRANCH_IDENTITY_INVALID'));
});

for (const [name,modify,expected] of [
  ['approvals zero',p=>{p.required_pull_request_reviews.required_approving_review_count=0;},'APPROVAL_COUNT_MISSING'],
  ['codeowners off',p=>{p.required_pull_request_reviews.require_code_owner_reviews=false;},'CODEOWNER_REVIEW_MISSING'],
  ['stale approvals allowed',p=>{p.required_pull_request_reviews.dismiss_stale_reviews=false;},'STALE_APPROVALS_NOT_DISMISSED'],
  ['last push self-approval allowed',p=>{p.required_pull_request_reviews.require_last_push_approval=false;},'LAST_PUSH_APPROVAL_MISSING'],
  ['last push approval field absent',p=>{delete p.required_pull_request_reviews.require_last_push_approval;},'LAST_PUSH_APPROVAL_MISSING'],
  ['user bypass',p=>{p.required_pull_request_reviews.bypass_pull_request_allowances.users=['example'];},'PR_BYPASS_NOT_PROVEN_EMPTY'],
  ['app bypass',p=>{p.required_pull_request_reviews.bypass_pull_request_allowances.apps=[{id:1}];},'PR_BYPASS_NOT_PROVEN_EMPTY'],
  ['bypass metadata missing',p=>{delete p.required_pull_request_reviews.bypass_pull_request_allowances;},'PR_BYPASS_NOT_PROVEN_EMPTY'],
  ['admin enforcement absent',p=>{p.enforce_admins.enabled=false;},'ADMIN_ENFORCEMENT_MISSING'],
  ['force push allowed',p=>{p.allow_force_pushes.enabled=true;},'FORCE_PUSH_NOT_DENIED'],
  ['deletion allowed',p=>{p.allow_deletions.enabled=true;},'BRANCH_DELETE_NOT_DENIED'],
  ['conversation resolution absent',p=>{p.required_conversation_resolution.enabled=false;},'CONVERSATION_RESOLUTION_MISSING'],
  ['non-strict checks',p=>{p.required_status_checks.strict=false;},'STRICT_STATUS_CHECKS_MISSING'],
  ['unbound status app',p=>{p.required_status_checks.checks[0].app_id=-1;},'ISSUER_BOUND_CHECKS_MISSING'],
  ['only legacy contexts',p=>{delete p.required_status_checks.checks; p.required_status_checks.contexts=['CI'];},'ISSUER_BOUND_CHECKS_MISSING'],
  ['duplicate check names',p=>{p.required_status_checks.checks.push({context:'CI',app_id:15368});},'ISSUER_BOUND_CHECKS_MISSING'],
  ['unbound legacy context alongside bound check',p=>{p.required_status_checks.contexts.push('attacker-legacy');},'UNBOUND_LEGACY_STATUS_CONTEXTS'],
  ['unbound context from missing issuer',p=>{p.required_status_checks.checks[0].app_id=null;},'UNBOUND_LEGACY_STATUS_CONTEXTS'],
  ['duplicate legacy context',p=>{p.required_status_checks.contexts.push('CI');},'UNBOUND_LEGACY_STATUS_CONTEXTS'],
  ['missing legacy-context inventory',p=>{delete p.required_status_checks.contexts;},'UNBOUND_LEGACY_STATUS_CONTEXTS'],
]) {
  test('negative policy: ' + name, () => {
    const policy=validProtection(); modify(policy);
    assert.ok(result(REPO, validBranch(), policy).blockers.includes(expected));
  });
}

test('compiler requires GitHub Actions private-ci-policy from exact app ID', () => {
  const p=validProtection();
  p.required_status_checks.checks[1].app_id=99;
  assert.ok(result(SOURCE,validBranch(),p).blockers.includes('PRIVATE_CI_POLICY_APP_NOT_REQUIRED'));
  p.required_status_checks.checks[1].app_id=15368;
  assert.equal(result(SOURCE,validBranch(),p).policy_state,'REQUIREMENTS_OBSERVED');
});

test('missing protection API, branch API and recheck fail closed', async () => {
  const initial = validBranch(), good = validProtection();
  const get = async path => path.endsWith('/protection') ? good : initial;
  assert.equal((await auditRepository(REPO,get)).policy_state,'REQUIREMENTS_OBSERVED');
  const failure = () => {throw Error('403 unknown private metadata');};
  assert.deepEqual((await auditRepository(REPO,failure)).blockers,['BRANCH_API_UNAVAILABLE']);
  const denyProtection=async path => path.endsWith('/protection') ? failure() : initial;
  assert.deepEqual((await auditRepository(REPO,denyProtection)).blockers,['PROTECTION_API_UNAVAILABLE']);
  let reads=0;
  const denyRecheck=async path => {
    if(path.endsWith('/protection')) return good;
    if(++reads===2) throw Error('failed last read');
    return initial;
  };
  assert.deepEqual((await auditRepository(REPO,denyRecheck)).blockers,['BRANCH_RECHECK_UNAVAILABLE']);
});

test('immutable main HEAD is not enough: policy bypass introduced between reads blocks', async () => {
  let policyReads=0;
  const read=async path => {
    if (!path.endsWith('/protection')) return validBranch();
    const p=validProtection();
    if (++policyReads === 2) {
      p.required_pull_request_reviews.bypass_pull_request_allowances.apps.push({id:5});
    }
    return p;
  };
  const receipt=await auditRepository(REPO,read);
  assert.equal(policyReads,2);
  assert.equal(receipt.observed_main_sha,HEAD);
  assert.equal(receipt.policy_state,'BLOCKED');
  assert.deepEqual(receipt.blockers,['PROTECTION_CHANGED_DURING_AUDIT']);
  assert.equal(receipt.release_authorized,false);
});

test('policy snapshot freezes earlier returned objects and detects mutation', async () => {
  const p=validProtection();
  let reads=0;
  const receipt=await auditRepository(REPO,async path => {
    if (!path.endsWith('/protection')) return validBranch();
    if (++reads === 2) p.required_status_checks.strict=false;
    return p;
  });
  assert.deepEqual(receipt.blockers,['PROTECTION_CHANGED_DURING_AUDIT']);
  assert.equal(receipt.policy_state,'BLOCKED');
});

test('shared branch API object mutation does not erase first HEAD identity',async()=>{
  const branch=validBranch();
  let branchReads=0;
  const receipt=await auditRepository(REPO,async path=>{
    if(path.endsWith('/protection')) return validProtection();
    if(++branchReads===2) branch.commit.sha='b'.repeat(40);
    return branch;
  });
  assert.equal(receipt.policy_state,'BLOCKED');
  assert.equal(receipt.observed_main_sha,HEAD);
  assert.ok(receipt.blockers.includes('MAIN_MOVED_DURING_AUDIT'));
});

test('policy GET member order does not create a spurious drift alarm',async()=>{
  let reads=0;
  const receipt=await auditRepository(REPO,async path => {
    if (!path.endsWith('/protection')) return validBranch();
    const p=validProtection();
    if (++reads === 2) return Object.fromEntries(Object.entries(p).reverse());
    return p;
  });
  assert.equal(receipt.policy_state,'REQUIREMENTS_OBSERVED');
  assert.deepEqual(receipt.blockers,[]);
});

test('second policy GET outage, invalid result and excessive depth fail closed',async()=>{
  let reads=0;
  const denied=await auditRepository(REPO,async path=>{
    if (!path.endsWith('/protection')) return validBranch();
    if (++reads===2) throw Error('403');
    return validProtection();
  });
  assert.deepEqual(denied.blockers,['PROTECTION_RECHECK_UNAVAILABLE']);
  assert.equal(denied.release_authorized,false);
  reads=0;
  const missing=await auditRepository(REPO,async path=>{
    if (!path.endsWith('/protection')) return validBranch();
    return ++reads===2?null:validProtection();
  });
  assert.deepEqual(missing.blockers,['PROTECTION_RECHECK_UNAVAILABLE']);
  let nested={};
  for(let i=0;i<40;i++) nested={next:nested};
  const tooDeep=await auditRepository(REPO,async path=>
    path.endsWith('/protection')?nested:validBranch());
  assert.deepEqual(tooDeep.blockers,['PROTECTION_RECHECK_UNAVAILABLE']);
});

test('audit aggregates blockers, preserves ordered identity, never produces release permission',async()=>{
  const a=validBranch(), p=validProtection();
  const get=async path=>path.endsWith('/protection')?p:a;
  const receipt=await audit(get,[REPO,SOURCE]);
  assert.equal(receipt.status,'POLICY_METADATA_OBSERVED');
  assert.equal(receipt.release_authorized,false);
  assert.equal(receipt.independent_pr_reviews_verified,false);
  assert.equal(receipt.compiler_guest_execution_verified,false);
  assert.deepEqual(receipt.results.map(x=>x.repository),[REPO,SOURCE]);
  const denied=await audit(async()=>{throw Error('permission denied');},[REPO]);
  assert.equal(denied.status,'BLOCKED');
  assert.equal(denied.merge_authorized,false);
  await assert.rejects(audit(get,[REPO,REPO]),/invalid/);
  await assert.rejects(audit(get,['external/private']),/invalid/);
});

test('GitHub REST reader only performs pinned host read-only GET and never echoes token', async()=>{
  const calls=[];
  const read=githubReader('super-secret-token',async(url,options)=>{
    calls.push({url,method:options.method,redirect:options.redirect,auth:options.headers.Authorization});
    return {status:200,text:async()=>JSON.stringify(validBranch())};
  });
  assert.equal((await read('/repos/'+REPO+'/branches/main')).protected,true);
  assert.deepEqual(calls.map(x=>x.method),['GET']);
  assert.ok(calls[0].url.startsWith('https://api.github.com/repos/'));
  assert.equal(calls[0].redirect,'error');
  assert.equal(calls[0].auth,'Bearer super-secret-token');
  await assert.rejects(read('/users/me'),/unapproved/);
  await assert.rejects(githubReader('x',async()=>({status:403}))(('/repos/'+REPO+'/branches/main')),/GITHUB_METADATA_UNAVAILABLE/);
});

test('missing admin token and unsupported args deny before network or code-zero', async()=>{
  let output='';
  const write = {write:s=>{output+=s;}};
  const code=await main([],{},write);
  assert.equal(code,2);
  assert.match(output,/ADMIN_TOKEN_REQUIRED/);
  assert.doesNotMatch(output,/super-secret/);
  assert.deepEqual(Object.fromEntries(Object.entries(JSON.parse(output)).filter(([key]) =>
    key.endsWith('_authorized'))), {
      merge_authorized:false, release_authorized:false,
      private_source_export_authorized:false
    });
  output='';
  assert.equal(await main([],{GH_TOKEN:'  '},write),2);
  assert.match(output,/ADMIN_TOKEN_REQUIRED/);
  output='';
  assert.equal(await main(['--repo','external/private'],{GH_TOKEN:'x'},write),2);
  assert.equal(JSON.parse(output).merge_authorized,false);
  assert.equal(JSON.parse(output).private_source_export_authorized,false);
  const result=spawnSync(process.execPath,[fileURLToPath(new URL('../tools/branch-governance-audit-v1/verify.mjs',import.meta.url))],
    {encoding:'utf8',env:{PATH:process.env.PATH}});
  assert.equal(result.status,2);
  assert.match(result.stdout,/ADMIN_TOKEN_REQUIRED/);
});
