// Public source-free diagnostic model. NEVER an authorization decision.
import { createHash } from 'node:crypto';

export const ACTIONS_APP_ID = 15368;
export const OPERATOR_IDS = Object.freeze([2148448, 11139560]);
export const POLICIES = Object.freeze({
  'ores-truffle-oreslang/oreslang-cli': {
    repo_id: 1402495995, workflow_id: 373591906, workflow_blob: '3aabb5e5607f907493198429afd71c1fd0c8b03f',
    jobs: ['rust'], source_guard: 'Verify exact PR head and clean source tree'
  },
  'ores-truffle-oreslang/html-js-css-syntax-highlighter': {
    repo_id: 1409308342, workflow_id: 377788496, workflow_blob: '94704a367584ccc76a6f482b27a09377e56f4941',
    jobs: ['test', 'browser-dom', 'release-package'],
    source_guard: 'Verify immutable PR head and physical Git source before any execution'
  },
  'ores-truffle-oreslang/sublime-text-plugins': {
    repo_id: 1402482919, workflow_id: 373587523, workflow_blob: '3b208b8b7b6b0e17a238a896c27cd30f08ca4d9c',
    jobs: ['package', 'sublime-syntax-engine', 'release-package'],
    source_guard: 'Verify exact source HEAD before executing tests or publishing artifacts'
  },
  'ores-truffle-oreslang/vscode-plugins': {
    repo_id: 1402488145, workflow_id: 373588125, workflow_blob: 'deea3f598736cc326314e06d9c930aaf78a7d0ec',
    jobs: ['test', 'vscode-restricted-mode', 'release-vsix',
      'Native VS Code extension-host smoke (not compiler guest)',
      'Windows archive extraction (not IDE GUI)'],
    source_guard: 'Prove original PR source head and committed tree'
  }
});
const obj = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const sha = x => typeof x === 'string' && /^[a-f0-9]{40}$/.test(x);
const utc = x => typeof x === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(x) && !Number.isNaN(Date.parse(x))
  && new Date(x).toISOString().replace('.000Z','Z') === x;
const positive = x => Number.isSafeInteger(x) && x > 0;
const login = x => typeof x === 'string' && /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37})$/.test(x) ? x.toLowerCase() : null;
const exact = (a,b) => typeof a === 'string' && a.toLowerCase() === b.toLowerCase();
const nonemptyArray = x => Array.isArray(x) && x.length > 0;
const noBypass = x => obj(x) && ['users','teams','apps'].every(k => Array.isArray(x[k]) && x[k].length === 0)
  && Object.keys(x).every(k => ['users','teams','apps'].includes(k));

// No arbitrary user policy paths. This allowlist is an auditable reference,
// NOT a trusted root when executed from a PR-controlled branch.
export function policyFor(repo) {
  if (typeof repo !== 'string' || !Object.hasOwn(POLICIES,repo)) throw Error('UNKNOWN_REPOSITORY');
  return POLICIES[repo];
}
function reviewStates(reviews, head, authorId, errors) {
  if (!Array.isArray(reviews) || reviews.length >= 100) {
    errors.push('REVIEWS_MISSING_OR_PAGINATED');
    return [];
  }
  const seen = new Set(), byId = new Map();
  for (const r of reviews) {
    if (!obj(r) || !positive(r.id) || seen.has(r.id) || !positive(r.user?.id) ||
        !login(r.user?.login) || !utc(r.submitted_at) ||
        !['APPROVED','CHANGES_REQUESTED','DISMISSED','COMMENTED'].includes(r.state) ||
        !sha(r.commit_id)) {
      errors.push('REVIEW_MALFORMED_OR_DUPLICATE'); continue;
    }
    seen.add(r.id);
    const key = login(r.user.login);
    if (!byId.has(key)) byId.set(key, []);
    byId.get(key).push(r);
  }
  const approved = [];
  for (const group of byId.values()) {
    const ids = new Set(group.map(r=>r.user.id));
    if (ids.size !== 1) { errors.push('REVIEW_LOGIN_ID_COLLISION'); continue; }
    // COMMENTED is not a replacement for the previous approval or changes request.
    const events = group.filter(r => r.state !== 'COMMENTED').sort((a,b)=>
      a.submitted_at.localeCompare(b.submitted_at) || a.id-b.id);
    if (events.length === 0) continue;
    const latest = events.at(-1);
    if (latest.state !== 'APPROVED') continue;
    if (latest.commit_id !== head) { errors.push('APPROVAL_STALE'); continue; }
    if (OPERATOR_IDS.includes(latest.user.id) || latest.user.id === authorId) {
      errors.push('APPROVAL_NOT_INDEPENDENT'); continue;
    }
    approved.push({ id: latest.user.id, login: login(latest.user.login),
      review_id: latest.id, at: latest.submitted_at });
  }
  if (approved.length === 0) errors.push('NO_CURRENT_INDEPENDENT_APPROVAL');
  return approved.sort((a,b) => a.id-b.id);
}

export function verifySnapshot(s) {
  const errors = [];
  const deny = e => errors.push(e);
  if (!obj(s)) s = {};
  const repo = s.repo;
  const p = Object.hasOwn(POLICIES,repo) ? POLICIES[repo] : null;
  if (!p) {
    return { evidence_consistent: false, reasons: ['UNKNOWN_REPOSITORY'],
      merge_authorized: false, release_authorized: false, private_source_export_authorized: false };
  }
  const prNo = s.pr_number;
  if (!positive(prNo)) deny('INVALID_PR_NUMBER');
  const metadata = s.repository;
  if (!obj(metadata) || metadata.id !== p.repo_id || !exact(metadata.full_name,repo) ||
      metadata.default_branch !== 'main') deny('REPOSITORY_ID_MISMATCH');
  const first = s.pr_before, last = s.pr_after;
  const head = first?.head?.sha, base = first?.base?.sha;
  if (!sha(head) || !sha(base) || !positive(first?.number) || first.number !== prNo ||
      first.state !== 'open' || first.draft !== false ||
      first.head?.repo?.id !== p.repo_id || first.base?.repo?.id !== p.repo_id ||
      first.base?.ref !== 'main' || !positive(first.user?.id) ||
      !login(first.user?.login)) deny('PR_IDENTITY_OR_READINESS');
  if (!obj(last) || last.number !== prNo || last.head?.sha !== head ||
      last.base?.sha !== base || last.state !== 'open' || last.draft !== false ||
      last.head?.repo?.id !== p.repo_id) deny('PR_HEAD_OR_BASE_DRIFT');
  if (!sha(s.head_commit?.tree?.sha) || s.head_commit?.sha !== head) deny('HEAD_TREE_UNBOUND');
  if (s.branch_before?.name !== 'main' || s.branch_before?.protected !== true ||
      s.branch_before?.commit?.sha !== base || s.branch_after?.name !== 'main' ||
      s.branch_after?.commit?.sha !== base || s.branch_after?.protected !== true) {
    deny('BASE_DRIFT_OR_UNPROTECTED');
  }
  const c = s.codeowners_main;
  if (!obj(c) || !sha(c.sha) || c.type !== 'file') deny('MAIN_CODEOWNERS_UNKNOWN');
  const wf = s.workflow_file;
  if (!obj(wf) || wf.sha !== p.workflow_blob || wf.path !== '.github/workflows/ci.yml' ||
      wf.type !== 'file') deny('WORKFLOW_DEFINITION_NOT_PINNED');
  const prot = s.protection;
  const stat = prot?.required_status_checks;
  if (stat?.strict !== true || !Array.isArray(stat.checks) ||
      stat.checks.length !== p.jobs.length ||
      p.jobs.some(name => stat.checks.filter(x=>x?.context===name && x.app_id===ACTIONS_APP_ID).length !== 1) ||
      (stat.contexts !== undefined && (!Array.isArray(stat.contexts) ||
        stat.contexts.some(v=>typeof v !== 'string' || !p.jobs.includes(v))))) deny('REQUIRED_CHECKS_OR_ISSUER_NOT_ENFORCED');
  const rv = prot?.required_pull_request_reviews;
  if (prot?.enforce_admins?.enabled !== true ||
      rv?.required_approving_review_count < 1 || !Number.isInteger(rv?.required_approving_review_count) ||
      rv?.dismiss_stale_reviews !== true || rv?.require_last_push_approval !== true ||
      rv?.require_code_owner_reviews !== true || !noBypass(rv?.bypass_pull_request_allowances) ||
      prot?.allow_deletions?.enabled !== false ||
      prot?.allow_force_pushes?.enabled !== false ||
      prot?.required_conversation_resolution?.enabled !== true) deny('GOVERNANCE_POLICY_NOT_ENFORCED');
  if (!Array.isArray(s.rulesets) || !Array.isArray(s.effective_rules)) deny('RULESET_READBACK_MISSING');
  else {
    const seen = new Set();
    for (const r of s.rulesets) {
      if (!positive(r?.id) || seen.has(r.id) || !['active','disabled','evaluate'].includes(r.enforcement) ||
          (r.enforcement === 'active' && (!Array.isArray(r.bypass_actors) || r.bypass_actors.length > 0))) {
        deny('RULESET_AMBIGUOUS_OR_BYPASS');
      }
      if (positive(r?.id)) seen.add(r.id);
    }
    // Unknown effective rules must be reviewed by the external administrator.
    // We cannot assert these are harmless from raw names alone.
    if (s.effective_rules.length > 0) deny('EFFECTIVE_RULE_REQUIRES_EXTERNAL_REVIEW');
  }
  const approved = reviewStates(s.reviews,head,first?.user?.id,errors);
  const runs = s.runs, checks = s.check_runs;
  const validated = [];
  if (!Array.isArray(checks) || checks.length >= 100 ||
      !Array.isArray(runs) || runs.length >= 100) deny('CHECK_OR_RUN_DATA_INCOMPLETE');
  else for (const name of p.jobs) {
    const cands = checks.filter(c=>c?.name === name);
    if (cands.length !== 1) { deny('CHECK_MISSING_OR_DUPLICATE:'+name); continue; }
    const chk = cands[0];
    if (!positive(chk.id) || chk.head_sha !== head || chk.status !== 'completed' ||
        chk.conclusion !== 'success' || chk.app?.id !== ACTIONS_APP_ID ||
        !utc(chk.started_at) || !utc(chk.completed_at)) { deny('CHECK_INVALID:'+name); continue; }
    let matching = [];
    for (const rec of runs) {
      const run = rec?.run;
      if (run?.workflow_id !== p.workflow_id || run?.path !== '.github/workflows/ci.yml' ||
          run?.head_sha !== head || run?.event !== 'pull_request' ||
          run?.status !== 'completed' || run?.conclusion !== 'success' ||
          !positive(run?.id) || !positive(run?.run_attempt)) continue;
      const found = Array.isArray(rec.jobs) ? rec.jobs.filter(j=>j?.id === chk.id && j?.name === name) : [];
      for (const job of found) matching.push({run,job});
    }
    if (matching.length !== 1) { deny('RUN_JOB_PROVENANCE_UNKNOWN:'+name); continue; }
    const {run,job} = matching[0];
    if (job.run_id !== run.id || job.run_attempt !== run.run_attempt ||
        !positive(job.runner_id) || job.status !== 'completed' || job.conclusion !== 'success' ||
        !utc(job.started_at) || !utc(job.completed_at) || !nonemptyArray(job.steps) ||
        !job.steps.some(st=>st.name === p.source_guard && st.status === 'completed' && st.conclusion === 'success') ||
        !job.steps.some(st=>st.name !== p.source_guard && /(?:test|validate|run |compile|build|smoke|render|execute)/i.test(st.name) &&
          st.status === 'completed' && st.conclusion === 'success' && !/^Post /i.test(st.name))) {
      deny('UNEXECUTED_OR_UNBOUND_JOB:'+name); continue;
    }
    validated.push({name,check_run_id:chk.id,run_id:run.id,run_attempt:run.run_attempt,
      workflow_id:run.workflow_id,runner_id:job.runner_id});
  }
  const consistent = errors.length === 0;
  const candidate = consistent ? {
    schema: 'atto.live-merge-evidence.v1', repo, repository_id:p.repo_id, pr_number:prNo,
    head_sha:head, head_tree:s.head_commit.tree.sha, base_sha:base,
    workflow_id:p.workflow_id, workflow_blob:p.workflow_blob,
    independent_review_ids:approved.map(r=>r.review_id),
    ci:validated.sort((a,b)=>a.name.localeCompare(b.name))
  } : null;
  return {
    evidence_consistent: consistent, reasons:[...new Set(errors)],
    candidate_sha256: candidate ? createHash('sha256').update(JSON.stringify(candidate)).digest('hex') : null,
    // This source is PR-authored; a real independent and protected service must re-fetch,
    // attest, and atomically consume evidence before any merge.
    merge_authorized: false, release_authorized: false, private_source_export_authorized: false
  };
}
