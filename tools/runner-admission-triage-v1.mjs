#!/usr/bin/env node
// Read-only GitHub Actions runner-admission triage; never authorizes a merge.
import { pathToFileURL } from 'node:url';

const SHA = /^[0-9a-f]{40}$/;
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const MAX_PAGES = 10;
const MAX_BYTES = 1024 * 1024;

export function validateInput(repo, runId, head) {
  if (typeof repo !== 'string' || !REPO.test(repo) ||
      repo.split('/').some(part => part === '.' || part === '..' || part.startsWith('.'))) {
    throw new Error('INVALID_REPOSITORY');
  }
  if (!Number.isSafeInteger(runId) || runId < 1) throw new Error('INVALID_RUN_ID');
  if (typeof head !== 'string' || !SHA.test(head)) throw new Error('INVALID_HEAD_SHA');
  return { repo, runId, head };
}

function isHousekeeping(name) {
  return /^(?:Set up job|Complete job|Post |Initialize containers|Stop containers)/.test(name);
}

export function classifyRun(run, jobs, expected) {
  const result = {
    repository: expected.repo,
    run_id: expected.runId,
    expected_head: expected.head,
    classification: 'BLOCKED_UNKNOWN',
    source_steps_observed: false,
    runner_identity_observed: false,
    test_result_claimed: false,
    authorizes_merge: false,
    claims_compiler_guest_execution: false,
    reasons: [],
    jobs: []
  };
  if (!run || run.id !== expected.runId || run.head_sha !== expected.head ||
      !Number.isSafeInteger(run.run_attempt) || run.run_attempt < 1) {
    result.classification = 'BLOCKED_IDENTITY';
    result.reasons.push('RUN_ID_HEAD_OR_ATTEMPT_MISMATCH');
    return result;
  }
  if (!Array.isArray(jobs) || jobs.length === 0 || jobs.length > 1000) {
    result.classification = 'BLOCKED_JOB_INVENTORY';
    result.reasons.push('MISSING_OR_UNBOUNDED_JOBS');
    return result;
  }
  const ids = new Set();
  for (const job of jobs) {
    if (!job || !Number.isSafeInteger(job.id) || job.id < 1 || ids.has(job.id) ||
        (job.run_id !== undefined && job.run_id !== run.id) ||
        (job.run_attempt !== undefined && job.run_attempt !== run.run_attempt) ||
        (job.head_sha !== undefined && job.head_sha !== expected.head) ||
        typeof job.name !== 'string' || !job.name) {
      result.classification = 'BLOCKED_JOB_IDENTITY';
      result.reasons.push('JOB_ID_OR_ATTEMPT_CONFLICT');
      return result;
    }
    ids.add(job.id);
  }
  let incomplete = false;
  let unexecuted = false;
  let failed = false;
  let ambiguous = false;
  let runnerMissing = false;
  for (const job of jobs) {
    const steps = job.steps;
    const meaningful = Array.isArray(steps)
      ? steps.filter(step => step && typeof step.name === 'string' &&
          !isHousekeeping(step.name) && step.status === 'completed')
      : [];
    const successful = meaningful.filter(step => step.conclusion === 'success').length;
    const failedSteps = meaningful.filter(step => step.conclusion === 'failure').length;
    const executed = meaningful.length > 0;
    const runner = Number.isSafeInteger(job.runner_id) && job.runner_id > 0;
    result.jobs.push({
      id: job.id, name: job.name, status: job.status, conclusion: job.conclusion,
      steps: Array.isArray(steps) ? steps.length : null,
      executed_non_housekeeping_steps: meaningful.length,
      successful_non_housekeeping_steps: successful,
      failed_non_housekeeping_steps: failedSteps,
      runner_id_observed: runner
    });
    if (job.status !== 'completed') incomplete = true;
    else if (!executed) unexecuted = true;
    else if (!runner) runnerMissing = true;
    if (job.status === 'completed' && executed &&
        (job.conclusion === 'failure' || job.conclusion === 'timed_out' ||
         job.conclusion === 'cancelled' || failedSteps > 0)) failed = true;
    if (job.status === 'completed' && executed &&
        (!['success','failure','timed_out','cancelled'].includes(job.conclusion) ||
         (job.conclusion === 'success' &&
          (successful === 0 || failedSteps !== 0)))) ambiguous = true;
  }
  result.source_steps_observed = result.jobs.some(job => job.executed_non_housekeeping_steps > 0);
  result.runner_identity_observed = result.jobs.every(job => job.runner_id_observed);
  if (run.status !== 'completed' || incomplete) {
    result.classification = 'PENDING';
    result.reasons.push('RUN_OR_JOB_NOT_COMPLETE');
  } else if (unexecuted) {
    result.classification = 'NOT_EXECUTED_OR_UNOBSERVED';
    result.reasons.push('COMPLETED_JOB_WITH_ZERO_MEANINGFUL_STEPS');
  } else if (ambiguous || !['success','failure','timed_out','cancelled'].includes(run.conclusion)) {
    result.classification = 'BLOCKED_CONTRADICTORY_CONCLUSION';
    result.reasons.push('UNRELIABLE_STEP_OR_RUN_CONCLUSION');
  } else if (failed || run.conclusion !== 'success') {
    result.classification = 'EXECUTED_UNSUCCESSFUL';
    result.reasons.push('EXECUTED_STEPS_DID_NOT_SUCCEED');
  } else {
    result.classification = 'EXECUTED_STEPS_SUCCESS';
    result.reasons.push('STEPS_OBSERVED_NOT_GUEST_OR_RELEASE_PROOF');
    if (runnerMissing) result.reasons.push('RUNNER_ID_UNOBSERVED');
  }
  return result;
}

export function compareAdmission(source, control) {
  return {
    conclusion: source.classification === 'NOT_EXECUTED_OR_UNOBSERVED' &&
      control.classification === 'EXECUTED_STEPS_SUCCESS'
      ? 'OBSERVED_ADMISSION_DIFFERENCE_CAUSE_UNKNOWN' : 'NO_VERIFIED_DIFFERENTIAL',
    same_job_definition_verified: false,
    billing_or_policy_cause_established: false,
    authorizes_private_source_transfer: false,
    authorizes_merge: false
  };
}

export async function boundedGitHubGet(apiPath, fetcher = fetch) {
  if (!/^repos\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/actions\/runs\/[0-9]+(?:\/attempts\/[0-9]+\/jobs\?per_page=100&page=[0-9]+)?$/.test(apiPath)) {
    throw new Error('UNTRUSTED_API_PATH');
  }
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'AttoLang-read-only-runner-admission-audit'
  };
  if (token) headers.Authorization = 'Bearer ' + token;
  const response = await fetcher('https://api.github.com/' + apiPath, {
    method: 'GET', redirect: 'error', headers, signal: AbortSignal.timeout(12000)
  });
  if (!response.ok || !response.body) throw new Error('GITHUB_READ_FAILED_' + response.status);
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > MAX_BYTES) throw new Error('GITHUB_RESPONSE_TOO_LARGE');
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const buffer = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer)); }
  catch { throw new Error('INVALID_GITHUB_JSON'); }
}

export async function collectRunEvidence(identity, get = boundedGitHubGet) {
  const { repo, runId, head } = validateInput(identity.repo, identity.runId, identity.head);
  const root = 'repos/' + repo + '/actions/runs/' + runId;
  const run = await get(root);
  if (!run || run.id !== runId || run.head_sha !== head ||
      !Number.isSafeInteger(run.run_attempt) || run.run_attempt < 1) {
    return classifyRun(run, [], { repo, runId, head });
  }
  let jobs = [];
  let total = null;
  for (let page = 1; page <= MAX_PAGES; page++) {
    const payload = await get(root + '/attempts/' + run.run_attempt +
      '/jobs?per_page=100&page=' + page);
    if (!payload || !Number.isSafeInteger(payload.total_count) ||
        payload.total_count < 0 || payload.total_count > 1000 ||
        !Array.isArray(payload.jobs) || payload.jobs.length > 100 ||
        (total !== null && payload.total_count !== total)) {
      return { ...classifyRun(run, [], {repo,runId,head}),
        classification: 'BLOCKED_JOB_INVENTORY',
        reasons: ['INVALID_OR_INCONSISTENT_PAGINATION'] };
    }
    total = payload.total_count;
    jobs.push(...payload.jobs);
    if (jobs.length === total) return classifyRun(run, jobs, {repo,runId,head});
    if (payload.jobs.length === 0 || jobs.length > total || page === MAX_PAGES) break;
  }
  return { ...classifyRun(run, [], {repo,runId,head}),
    classification: 'BLOCKED_JOB_INVENTORY',
    reasons: ['INCOMPLETE_JOB_PAGINATION'] };
}

function parseFlags(argv) {
  const allowed = new Set(['--repo','--run','--head','--control-repo','--control-run','--control-head']);
  if (argv.length === 0 || argv.length % 2) throw new Error('REQUIRED_FLAGS_MISSING');
  const values = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!allowed.has(argv[i]) || values[argv[i]] !== undefined) throw new Error('INVALID_OR_DUPLICATE_FLAG');
    values[argv[i]] = argv[i+1];
  }
  const source = validateInput(values['--repo'], Number(values['--run']), values['--head']);
  const anyControl = ['--control-repo','--control-run','--control-head'].some(f => values[f] !== undefined);
  const control = anyControl
    ? validateInput(values['--control-repo'], Number(values['--control-run']), values['--control-head'])
    : null;
  return {source,control};
}

async function main(argv) {
  const {source,control} = parseFlags(argv);
  const observed = await collectRunEvidence(source);
  const comparison = control ? compareAdmission(observed, await collectRunEvidence(control)) : null;
  process.stdout.write(JSON.stringify({observed,comparison,read_only:true,
    authorizes_merge:false,authorizes_private_source_transfer:false}) + '\n');
  if (observed.classification !== 'EXECUTED_STEPS_SUCCESS') process.exitCode = 2;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch(error => {
    process.stderr.write('RUNNER_AUDIT_BLOCKED: ' + error.message.replace(/Bearer\s+\S+/g, '[REDACTED]') + '\n');
    process.exitCode = 2;
  });
}
