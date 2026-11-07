import assert from 'node:assert/strict';
import test from 'node:test';
import {
  REPOSITORIES, CLI_REPO, REQUIRED_JOBS, GITHUB_ACTIONS_APP_ID,
  protectionPayload, inspectReadback
} from '../tools/public-main-protection-v1.mjs';

const SHA = 'a'.repeat(40);
function fixture(repo, phase = 'steady') {
  const policy = protectionPayload(repo, phase);
  return {
    branch: { name: 'main', protected: true, commit: { sha: SHA } },
    after_main_sha: SHA,
    codeowners_present_on_main: repo !== CLI_REPO || phase === 'steady',
    rulesets: [],
    protection: {
      required_status_checks: structuredClone(policy.required_status_checks),
      enforce_admins: { enabled: true },
      required_pull_request_reviews: structuredClone(policy.required_pull_request_reviews),
      required_conversation_resolution: { enabled: true },
      allow_force_pushes: { enabled: false },
      allow_deletions: { enabled: false }
    }
  };
}
function denies(repo, mutate, reason, phase = 'steady') {
  const f = fixture(repo, phase);
  mutate(f);
  const x = inspectReadback(repo, phase, f);
  assert.equal(x.evidence_model_consistent, false);
  assert.equal(x.merge_authorized, false);
  assert.equal(x.release_authorized, false);
  assert.equal(x.private_source_export_authorized, false);
  assert.ok(x.errors.some(e => e.startsWith(reason)), JSON.stringify(x.errors));
}
test('repository matrix has exactly four distinct public projects', () => {
  assert.equal(REPOSITORIES.length, 4);
  assert.equal(new Set(REPOSITORIES).size, 4);
  assert.ok(REPOSITORIES.every(x => x.startsWith('ores-truffle-oreslang/')));
});
test('unknown repository, missing or forged phase is rejected', () => {
  assert.throws(() => protectionPayload('other/private', 'steady'), /UNKNOWN_REPOSITORY/);
  assert.throws(() => protectionPayload(CLI_REPO, 'production'), /UNKNOWN_PHASE/);
  assert.throws(() => inspectReadback('other/private', 'steady', {}), /UNKNOWN_REPOSITORY/);
});
for (const repo of REPOSITORIES) {
  for (const phase of ['bootstrap', 'steady']) {
    test('admin payload: ' + repo + ' ' + phase, () => {
      const p = protectionPayload(repo, phase);
      assert.equal(p.enforce_admins, true);
      assert.equal(p.required_status_checks.strict, true);
      assert.deepEqual(p.required_status_checks.contexts, []);
      assert.deepEqual(p.required_status_checks.checks.map(c => c.context), REQUIRED_JOBS[repo]);
      assert.ok(p.required_status_checks.checks.every(c => c.app_id === GITHUB_ACTIONS_APP_ID));
      assert.equal(p.required_pull_request_reviews.required_approving_review_count, 1);
      assert.equal(p.required_pull_request_reviews.dismiss_stale_reviews, true);
      assert.equal(p.required_pull_request_reviews.require_last_push_approval, true);
      assert.equal(p.required_pull_request_reviews.require_code_owner_reviews, repo !== CLI_REPO || phase === 'steady');
      assert.deepEqual(p.required_pull_request_reviews.bypass_pull_request_allowances, { users: [], teams: [], apps: [] });
      assert.equal(p.allow_deletions, false);
      assert.equal(p.allow_force_pushes, false);
      assert.equal(p.required_conversation_resolution, true);
      assert.equal(p.restrictions, null);
      const result = inspectReadback(repo, phase, fixture(repo, phase));
      assert.equal(result.evidence_model_consistent, true, JSON.stringify(result.errors));
      assert.equal(result.merge_authorized, false);
      assert.equal(result.release_authorized, false);
    });
  }
  const cases = [
    ['MAIN_NOT_PROTECTED', f => { f.branch.protected = false; }],
    ['MAIN_NOT_PROTECTED', f => { f.branch.name = 'release'; }],
    ['MAIN_HEAD_CHANGED_OR_UNKNOWN', f => { f.after_main_sha = 'b'.repeat(40); }],
    ['MAIN_HEAD_CHANGED_OR_UNKNOWN', f => { f.branch.commit.sha = 'not-sha'; }],
    ['PROTECTION_READBACK_MISSING', f => { delete f.protection; }],
    ['STRICT_CHECKS_MISSING', f => { f.protection.required_status_checks.strict = false; }],
    ['ISSUER_BOUND_CHECKS_UNAVAILABLE', f => { delete f.protection.required_status_checks.checks; }],
    ['DUPLICATE_OR_MALFORMED_CHECK', f => { f.protection.required_status_checks.checks.push({ ...f.protection.required_status_checks.checks[0] }); }],
    ['CHECK_OR_ISSUER_MISSING:', f => { f.protection.required_status_checks.checks[0].app_id = -1; }],
    ['CHECK_OR_ISSUER_MISSING:', f => { f.protection.required_status_checks.checks.pop(); }],
    ['ADMIN_ENFORCEMENT_MISSING', f => { f.protection.enforce_admins.enabled = false; }],
    ['INDEPENDENT_APPROVAL_RULE_MISSING', f => { f.protection.required_pull_request_reviews.required_approving_review_count = 0; }],
    ['STALE_REVIEW_DISMISSAL_MISSING', f => { f.protection.required_pull_request_reviews.dismiss_stale_reviews = false; }],
    ['LAST_PUSH_APPROVAL_MISSING', f => { f.protection.required_pull_request_reviews.require_last_push_approval = false; }],
    ['CODEOWNER_REVIEW_RULE_MISSING', f => { f.protection.required_pull_request_reviews.require_code_owner_reviews = false; }],
    ['CODEOWNERS_NOT_VERIFIED_ON_MAIN', f => { f.codeowners_present_on_main = false; }],
    ['PR_BYPASS_UNVERIFIED_OR_PRESENT', f => { delete f.protection.required_pull_request_reviews.bypass_pull_request_allowances; }],
    ['PR_BYPASS_UNVERIFIED_OR_PRESENT', f => { f.protection.required_pull_request_reviews.bypass_pull_request_allowances.users = ['the1mills']; }],
    ['FORCE_PUSH_POLICY_UNKNOWN_OR_ENABLED', f => { f.protection.allow_force_pushes.enabled = true; }],
    ['DELETION_POLICY_UNKNOWN_OR_ENABLED', f => { f.protection.allow_deletions.enabled = true; }],
    ['CONVERSATION_RESOLUTION_MISSING', f => { f.protection.required_conversation_resolution.enabled = false; }],
    ['RULESETS_READBACK_UNKNOWN', f => { delete f.rulesets; }],
    ['ACTIVE_RULESET_BYPASS_OR_UNKNOWN', f => { f.rulesets = [{ enforcement: 'active', bypass_actors: [{ actor_id: 1 }] }]; }],
    ['ACTIVE_RULESET_BYPASS_OR_UNKNOWN', f => { f.rulesets = [{ enforcement: 'active' }]; }]
  ];
  for (const [reason, mutation] of cases) {
    test('fail closed: ' + repo + ' ' + reason + ' #' + cases.findIndex(x => x[1] === mutation), () => denies(repo, mutation, reason));
  }
}
test('CLI bootstrap requires independent PR approval but cannot require absent CODEOWNERS', () => {
  const f = fixture(CLI_REPO, 'bootstrap');
  assert.equal(f.codeowners_present_on_main, false);
  assert.equal(inspectReadback(CLI_REPO, 'bootstrap', f).evidence_model_consistent, true);
  f.protection.required_pull_request_reviews.required_approving_review_count = 0;
  assert.ok(inspectReadback(CLI_REPO, 'bootstrap', f).errors.includes('INDEPENDENT_APPROVAL_RULE_MISSING'));
});
test('CLI steady state refuses absent codeowner or owner policy', () => {
  denies(CLI_REPO, f => { f.codeowners_present_on_main = false; }, 'CODEOWNERS_NOT_VERIFIED_ON_MAIN');
  denies(CLI_REPO, f => { f.protection.required_pull_request_reviews.require_code_owner_reviews = false; }, 'CODEOWNER_REVIEW_RULE_MISSING');
});
test('missing/untrusted REST payload is denied without throw and without permission', () => {
  for (const value of [null, undefined, false, [], 'forged', {}, { branch: { protected: true } }]) {
    const result = inspectReadback(CLI_REPO, 'steady', value);
    assert.equal(result.evidence_model_consistent, false);
    assert.equal(result.merge_authorized, false);
    assert.ok(result.errors.length > 0);
  }
});
