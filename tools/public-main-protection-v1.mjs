#!/usr/bin/env node
// A public, read-only ADMINISTRATOR HANDOFF; never a merge/release authority.
import { openSync, readSync, fstatSync, closeSync, constants } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const GITHUB_ACTIONS_APP_ID = 15368;
export const CLI_REPO = 'ores-truffle-oreslang/oreslang-cli';
export const WEBSITE_REPO = 'ores-truffle-oreslang/ores-truffle-oreslang.github.io';
export const REQUIRED_JOBS = Object.freeze({
  [CLI_REPO]: Object.freeze(['rust']),
  [WEBSITE_REPO]: Object.freeze(['AttoLang Site Validation']),
  'ores-truffle-oreslang/html-js-css-syntax-highlighter': Object.freeze(['test', 'browser-dom', 'release-package']),
  'ores-truffle-oreslang/sublime-text-plugins': Object.freeze(['package', 'sublime-syntax-engine', 'release-package']),
  'ores-truffle-oreslang/vscode-plugins': Object.freeze([
    'test', 'vscode-restricted-mode', 'release-vsix',
    'Native VS Code extension-host smoke (not compiler guest)',
    'Windows archive extraction (not IDE GUI)'
  ])
});
// Numeric IDs checked against authenticated repository GETs; never infer them from names alone.
export const REPOSITORY_IDS = Object.freeze({
  [CLI_REPO]: 1402495995,
  [WEBSITE_REPO]: 1409246164,
  'ores-truffle-oreslang/html-js-css-syntax-highlighter': 1409308342,
  'ores-truffle-oreslang/sublime-text-plugins': 1402482919,
  'ores-truffle-oreslang/vscode-plugins': 1402488145
});
export const REPOSITORIES = Object.freeze(Object.keys(REQUIRED_JOBS));
const SHA = /^[0-9a-f]{40}$/;
const isObject = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const hasOnlyEmptyLists = x => isObject(x)
  && Object.keys(x).length === 3
  && ['users', 'teams', 'apps'].every(k => Object.hasOwn(x, k) && Array.isArray(x[k]) && x[k].length === 0);
const sameRepo = (actual, expected) => typeof actual === 'string' && actual.toLowerCase() === expected.toLowerCase();
const MAX_AUDIT_BYTES = 1024 * 1024;
// Refuse symbolic-link swaps (O_NOFOLLOW), pipes/devices and mutable-size input.
// Remains an untrusted, non-authorizing diagnostic even when successfully read.
function readBoundedSnapshot(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || !Number.isSafeInteger(st.size) || st.size < 2 || st.size > MAX_AUDIT_BYTES) {
      throw new Error('SNAPSHOT_NOT_REGULAR_OR_TOO_LARGE');
    }
    const bytes = Buffer.alloc(st.size + 1);
    let length = 0;
    while (length < bytes.length) {
      const n = readSync(fd, bytes, length, bytes.length - length, length);
      if (!n) break;
      length += n;
    }
    if (length !== st.size) throw new Error('SNAPSHOT_CHANGED_DURING_READ');
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, length)));
  } finally { closeSync(fd); }
}

export function protectionPayload(repo, phase = 'steady') {
  if (!Object.hasOwn(REQUIRED_JOBS, repo)) throw new Error('UNKNOWN_REPOSITORY');
  if (phase !== 'bootstrap' && phase !== 'steady') throw new Error('UNKNOWN_PHASE');
  // CLI and Website do not yet have verified CODEOWNERS on main. Bootstrap
  // still requires independently approved PRs; steady adds CODEOWNER review.
  if (phase === 'bootstrap' && repo !== CLI_REPO && repo !== WEBSITE_REPO) {
    throw new Error('BOOTSTRAP_ONLY_FOR_MISSING_CODEOWNERS');
  }
  const requireOwners = phase === 'steady' || (repo !== CLI_REPO && repo !== WEBSITE_REPO);
  return {
    required_status_checks: {
      strict: true,
      contexts: [],
      checks: REQUIRED_JOBS[repo].map(context => ({ context, app_id: GITHUB_ACTIONS_APP_ID }))
    },
    enforce_admins: true,
    required_pull_request_reviews: {
      dismiss_stale_reviews: true,
      require_code_owner_reviews: requireOwners,
      required_approving_review_count: 1,
      require_last_push_approval: true,
      bypass_pull_request_allowances: { users: [], teams: [], apps: [] }
    },
    restrictions: null,
    required_linear_history: false,
    allow_force_pushes: false,
    allow_deletions: false,
    block_creations: false,
    required_conversation_resolution: true,
    lock_branch: false,
    allow_fork_syncing: false
  };
}

// A model check of supplied REST data, NOT proof of authentication, reviewer independence
// or effective GitHub policy. Both authorization decisions are unconditionally false.
export function inspectReadback(repo, phase, observed) {
  const expected = protectionPayload(repo, phase);
  const errors = [];
  const deny = reason => errors.push(reason);
  if (!isObject(observed)) observed = {};
  // Every observed field is caller-supplied; this is only an internal consistency audit.
  // Requiring an exact numeric repository ID prevents accidental cross-repo replay.
  if (!isObject(observed.repository) || !sameRepo(observed.repository.full_name, repo)
      || observed.repository.id !== REPOSITORY_IDS[repo]) deny('REPOSITORY_IDENTITY_UNKNOWN_OR_MISMATCHED');
  const branch = observed.branch;
  const p = observed.protection;
  if (!isObject(branch) || branch.name !== 'main' || branch.protected !== true) deny('MAIN_NOT_PROTECTED');
  const before = branch?.commit?.sha;
  if (typeof before !== 'string' || !SHA.test(before) || before !== observed.after_main_sha) deny('MAIN_HEAD_CHANGED_OR_UNKNOWN');
  if (!isObject(p)) deny('PROTECTION_READBACK_MISSING');
  const status = p?.required_status_checks;
  if (status?.strict !== true) deny('STRICT_CHECKS_MISSING');
  const checks = status?.checks;
  // Some GitHub GET responses echo contexts even when issuer-bound checks are used.
  // Such contexts must not introduce a second unbound or unexpected requirement.
  if (status?.contexts !== undefined) {
    if (!Array.isArray(status.contexts) || new Set(status.contexts).size !== status.contexts.length
        || status.contexts.some(s => typeof s !== 'string' || !REQUIRED_JOBS[repo].includes(s))) {
      deny('LEGACY_OR_UNEXPECTED_STATUS_CONTEXT');
    }
  }
  if (!Array.isArray(checks)) {
    deny('ISSUER_BOUND_CHECKS_UNAVAILABLE');
  } else {
    const seen = new Set();
    for (const check of checks) {
      if (!isObject(check) || typeof check.context !== 'string' || check.context.length === 0 || seen.has(check.context.toLowerCase())) {
        deny('DUPLICATE_OR_MALFORMED_CHECK');
      } else {
        seen.add(check.context.toLowerCase());
      }
    }
    for (const needed of expected.required_status_checks.checks) {
      if (!checks.some(check => isObject(check) && check.context === needed.context && check.app_id === needed.app_id)) {
        deny('CHECK_OR_ISSUER_MISSING:' + needed.context);
      }
    }
    // The old model accepted additional checks, including app_id=-1 or no issuer.
    // Audit all the checks in the live REST response, not only the expected subset.
    if (checks.length !== expected.required_status_checks.checks.length
        || checks.some(check => !isObject(check) || !expected.required_status_checks.checks.some(
          required => check.context === required.context && check.app_id === required.app_id
        ))) deny('EXTRA_OR_UNBOUND_REQUIRED_CHECK');
  }
  if (p?.enforce_admins?.enabled !== true) deny('ADMIN_ENFORCEMENT_MISSING');
  const review = p?.required_pull_request_reviews;
  if (!isObject(review) || !Number.isInteger(review.required_approving_review_count)
      || review.required_approving_review_count < 1 || review.required_approving_review_count > 6) deny('INDEPENDENT_APPROVAL_RULE_MISSING');
  if (review?.dismiss_stale_reviews !== true) deny('STALE_REVIEW_DISMISSAL_MISSING');
  if (review?.require_last_push_approval !== true) deny('LAST_PUSH_APPROVAL_MISSING');
  if (expected.required_pull_request_reviews.require_code_owner_reviews && review?.require_code_owner_reviews !== true) deny('CODEOWNER_REVIEW_RULE_MISSING');
  if (expected.required_pull_request_reviews.require_code_owner_reviews && observed.codeowners_present_on_main !== true) deny('CODEOWNERS_NOT_VERIFIED_ON_MAIN');
  // Bootstrap disables mandatory owner review ONLY for verified absence of the
  // policy file on main. Unknown or already installed CODEOWNERS must never
  // qualify as a successful bootstrap snapshot (potential policy downgrade).
  if (phase === 'bootstrap' && observed.codeowners_present_on_main !== false) {
    deny('BOOTSTRAP_CODEOWNERS_ABSENCE_UNVERIFIED');
  }
  if (!hasOnlyEmptyLists(review?.bypass_pull_request_allowances)) deny('PR_BYPASS_UNVERIFIED_OR_PRESENT');
  // No special reviewers may silently dismiss evidence while this policy is bootstrapped.
  // GitHub may omit the dismissal field; if present, inspect every member explicitly.
  if (review?.dismissal_restrictions != null) {
    const dr = review.dismissal_restrictions;
    if (!isObject(dr) || ['users','teams','apps'].some(k => !Array.isArray(dr[k]) || dr[k].length !== 0)) {
      deny('REVIEW_DISMISSAL_RESTRICTION_PRESENT_OR_UNKNOWN');
    }
  }
  if (p?.allow_force_pushes?.enabled !== false) deny('FORCE_PUSH_POLICY_UNKNOWN_OR_ENABLED');
  if (p?.allow_deletions?.enabled !== false) deny('DELETION_POLICY_UNKNOWN_OR_ENABLED');
  if (p?.required_conversation_resolution?.enabled !== true) deny('CONVERSATION_RESOLUTION_MISSING');
  if (!Array.isArray(observed.rulesets)) {
    deny('RULESETS_READBACK_UNKNOWN');
  } else {
    const seenRulesets = new Set();
    for (const r of observed.rulesets) {
      if (!isObject(r) || !Number.isSafeInteger(r.id) || r.id <= 0 || seenRulesets.has(r.id)
          || !['active', 'disabled', 'evaluate'].includes(r.enforcement)) {
        deny('RULESET_ID_OR_ENFORCEMENT_UNKNOWN');
      } else seenRulesets.add(r.id);
      if (r?.enforcement === 'active' && (!Array.isArray(r.bypass_actors) || r.bypass_actors.length !== 0)) {
        deny('ACTIVE_RULESET_BYPASS_OR_UNKNOWN');
      }
    }
  }
  return {
    repo, phase, evidence_model_consistent: errors.length === 0,
    errors: [...new Set(errors)],
    merge_authorized: false,
    release_authorized: false,
    private_source_export_authorized: false
  };
}

function main(argv) {
  if (argv[0] === '--plan' && argv.length === 3) {
    process.stdout.write(JSON.stringify(protectionPayload(argv[1], argv[2]), null, 2) + '\n');
    return;
  }
  if (argv[0] === '--audit' && argv.length === 4) {
    const data = readBoundedSnapshot(argv[3]);
    process.stdout.write(JSON.stringify(inspectReadback(argv[1], argv[2], data), null, 2) + '\n');
    // Even an internally consistent readback is advisory, not an authorization.
    process.exitCode = 3;
    return;
  }
  throw new Error('USAGE: --plan REPOSITORY bootstrap|steady OR --audit REPOSITORY bootstrap|steady REST_SNAPSHOT.json');
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try { main(process.argv.slice(2)); }
  catch (e) { process.stderr.write('PUBLIC_MAIN_POLICY_DENIED:' + e.message + '\n'); process.exitCode = 2; }
}
