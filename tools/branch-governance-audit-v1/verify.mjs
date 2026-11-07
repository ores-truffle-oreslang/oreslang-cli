#!/usr/bin/env node
// Read-only administrator evidence. NEVER a GitHub release or merge authorization.
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';

export const REPOSITORIES = Object.freeze([
  'ores-truffle-oreslang/oreslang-source.java',
  'ores-truffle-oreslang/oreslang-source.llvm',
  'ores-truffle-oreslang/oreslang-source.wasm',
  'ores-truffle-oreslang/oreslang-source.forge',
  'ores-truffle-oreslang/oreslang-source.net',
  'ores-truffle-oreslang/oreslang-platform.desktop',
  'ores-truffle-oreslang/oreslang-platform.mobile',
  'ores-truffle-oreslang/oreslang-platform.embedded',
  'ores-truffle-oreslang/oreslang-platform.iot',
  'ores-truffle-oreslang/oreslang-platform.fpga',
  'ores-truffle-oreslang/oreslang-platform.asic',
  'ores-truffle-oreslang/oreslang-platform-conformance',
  'ores-truffle-oreslang/html-js-css-syntax-highlighter',
  'ores-truffle-oreslang/vscode-plugins',
  'ores-truffle-oreslang/sublime-text-plugins',
  'ores-truffle-oreslang/oreslang-cli',
]);

const SHA = /^[0-9a-f]{40}$/;
const REPO = /^ores-truffle-oreslang\/[a-z0-9][a-z0-9._-]{1,79}$/;
const PRIVATE_POLICY_APP_ID = 15368;

export function assess(repo, before, protection, after) {
  if (!REPO.test(repo) || !REPOSITORIES.includes(repo)) {
    throw new TypeError('repository outside reviewed audit inventory');
  }
  const blockers = [];
  const block = value => { if (!blockers.includes(value)) blockers.push(value); };
  const originalSha = before?.commit?.sha;
  const finalSha = after?.commit?.sha;
  if (before?.name !== 'main' || after?.name !== 'main' ||
      !SHA.test(originalSha ?? '') || !SHA.test(finalSha ?? '')) {
    block('BRANCH_IDENTITY_INVALID');
  } else if (originalSha !== finalSha) {
    block('MAIN_MOVED_DURING_AUDIT');
  }
  if (before?.protected !== true || after?.protected !== true) {
    block('MAIN_UNPROTECTED');
  }
  const reviews = protection?.required_pull_request_reviews;
  if (!reviews || !Number.isInteger(reviews.required_approving_review_count) ||
      reviews.required_approving_review_count < 1) block('APPROVAL_COUNT_MISSING');
  if (reviews?.require_code_owner_reviews !== true) block('CODEOWNER_REVIEW_MISSING');
  if (reviews?.dismiss_stale_reviews !== true) block('STALE_APPROVALS_NOT_DISMISSED');
  const bypass = reviews?.bypass_pull_request_allowances;
  if (!bypass || !['users','teams','apps'].every(key =>
      Array.isArray(bypass[key]) && bypass[key].length === 0)) {
    block('PR_BYPASS_NOT_PROVEN_EMPTY');
  }
  if (protection?.enforce_admins?.enabled !== true) block('ADMIN_ENFORCEMENT_MISSING');
  if (protection?.allow_force_pushes?.enabled !== false) block('FORCE_PUSH_NOT_DENIED');
  if (protection?.allow_deletions?.enabled !== false) block('BRANCH_DELETE_NOT_DENIED');
  if (protection?.required_conversation_resolution?.enabled !== true) {
    block('CONVERSATION_RESOLUTION_MISSING');
  }
  const status = protection?.required_status_checks;
  if (status?.strict !== true) block('STRICT_STATUS_CHECKS_MISSING');
  const checks = status?.checks;
  if (!Array.isArray(checks) || checks.length === 0 ||
      checks.some(item => typeof item?.context !== 'string' || !item.context ||
        !Number.isInteger(item.app_id) || item.app_id <= 0) ||
      new Set(checks.map(item => item.context)).size !== checks.length) {
    block('ISSUER_BOUND_CHECKS_MISSING');
  }
  if (repo.startsWith('ores-truffle-oreslang/oreslang-source.') &&
      !checks?.some(item => item?.context === 'private-ci-policy' &&
                             item?.app_id === PRIVATE_POLICY_APP_ID)) {
    block('PRIVATE_CI_POLICY_APP_NOT_REQUIRED');
  }
  return {
    repository: repo,
    observed_main_sha: SHA.test(originalSha ?? '') ? originalSha : null,
    policy_state: blockers.length ? 'BLOCKED' : 'REQUIREMENTS_OBSERVED',
    blockers,
    merge_authorized: false,
    release_authorized: false,
    private_source_export_authorized: false,
  };
}

export async function auditRepository(repo, getJson) {
  if (!REPOSITORIES.includes(repo)) throw new TypeError('unreviewed repository');
  const base = '/repos/' + repo + '/branches/main';
  let first;
  try {
    first = await getJson(base);
  } catch {
    return {repository: repo, policy_state: 'BLOCKED', blockers:['BRANCH_API_UNAVAILABLE'],
      merge_authorized:false, release_authorized:false, private_source_export_authorized:false};
  }
  let protection;
  try {
    protection = await getJson(base + '/protection');
  } catch {
    return {repository: repo, policy_state: 'BLOCKED', blockers:[
      first?.protected === false ? 'MAIN_UNPROTECTED' : 'PROTECTION_API_UNAVAILABLE'
    ], merge_authorized:false, release_authorized:false, private_source_export_authorized:false};
  }
  let last;
  try {
    last = await getJson(base);
  } catch {
    return {repository: repo, policy_state: 'BLOCKED', blockers:['BRANCH_RECHECK_UNAVAILABLE'],
      merge_authorized:false, release_authorized:false, private_source_export_authorized:false};
  }
  return assess(repo, first, protection, last);
}

export async function audit(getJson, repositories = REPOSITORIES) {
  if (!Array.isArray(repositories) || !repositories.length ||
      repositories.length > REPOSITORIES.length ||
      new Set(repositories).size !== repositories.length ||
      repositories.some(repo => !REPOSITORIES.includes(repo))) {
    throw new TypeError('invalid repository selection');
  }
  const results = [];
  for (const repo of repositories) results.push(await auditRepository(repo, getJson));
  return {
    schema: 'atto.branch-governance-readonly/v1',
    status: results.every(result => result.policy_state === 'REQUIREMENTS_OBSERVED')
      ? 'POLICY_METADATA_OBSERVED' : 'BLOCKED',
    results,
    merge_authorized: false,
    release_authorized: false,
    private_source_export_authorized: false,
    // This tool does not authenticate submitted independent PR reviews, CI, or private-source approval.
    independent_pr_reviews_verified: false,
    compiler_guest_execution_verified: false,
  };
}

export function githubReader(token, fetchImpl = fetch) {
  if (typeof token !== 'string' || !token.trim()) {
    throw new TypeError('GH_TOKEN required for administrator protection API reads');
  }
  return async path => {
    if (typeof path !== 'string' ||
        !/^\/repos\/ores-truffle-oreslang\/[a-z0-9][a-z0-9._-]{1,79}\/branches\/main(?:\/protection)?$/.test(path)) {
      throw new TypeError('unapproved GitHub API path');
    }
    const response = await fetchImpl('https://api.github.com' + path, {
      method: 'GET', redirect: 'error', cache: 'no-store',
      signal: AbortSignal.timeout(8000),
      headers: {
        Authorization: 'Bearer ' + token,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });
    if (response.status !== 200) throw new Error('GITHUB_METADATA_UNAVAILABLE');
    const body = await response.text();
    if (body.length > 262144) throw new Error('GITHUB_METADATA_OVERSIZED');
    const data = JSON.parse(body);
    if (!data || typeof data !== 'object' || Array.isArray(data)) {
      throw new Error('GITHUB_METADATA_INVALID');
    }
    return data;
  };
}

export async function main(args, env, output = process.stdout) {
  const requested = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] !== '--repo' || !args[i + 1]) {
      output.write(JSON.stringify({status:'INVALID_ARGUMENTS',release_authorized:false}) + '\n');
      return 2;
    }
    requested.push(args[++i]);
  }
  if (requested.some(repo => !REPOSITORIES.includes(repo)) ||
      new Set(requested).size !== requested.length) {
    output.write(JSON.stringify({status:'INVALID_REPOSITORY',release_authorized:false}) + '\n');
    return 2;
  }
  if (!env.GH_TOKEN) {
    output.write(JSON.stringify({status:'ADMIN_TOKEN_REQUIRED',release_authorized:false}) + '\n');
    return 2;
  }
  const receipt = await audit(githubReader(env.GH_TOKEN), requested.length ? requested : REPOSITORIES);
  output.write(JSON.stringify(receipt, null, 2) + '\n');
  // 3 is a positive advisory; NEVER return success code zero or authorize release.
  return receipt.status === 'POLICY_METADATA_OBSERVED' ? 3 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2), process.env)
    .then(code => { process.exitCode = code; })
    .catch(() => {
      process.stdout.write(JSON.stringify({status:'AUDIT_UNAVAILABLE',release_authorized:false}) + '\n');
      process.exitCode = 2;
    });
}
