import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  REPOSITORIES, CLI_REPO, WEBSITE_REPO, REQUIRED_JOBS, REPOSITORY_IDS, GITHUB_ACTIONS_APP_ID,
  protectionPayload, inspectReadback
} from '../tools/public-main-protection-v1.mjs';

const SHA = 'a'.repeat(40);
function fixture(repo, phase = 'steady') {
  const policy = protectionPayload(repo, phase);
  return {
    repository: { full_name: repo, id: REPOSITORY_IDS[repo] },
    branch: { name: 'main', protected: true, commit: { sha: SHA } },
    after_main_sha: SHA,
    codeowners_present_on_main: phase === 'steady' || (repo !== CLI_REPO && repo !== WEBSITE_REPO),
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
test('repository matrix has exactly five distinct public projects including Website', () => {
  assert.equal(REPOSITORIES.length, 5);
  assert.ok(REPOSITORIES.includes(WEBSITE_REPO));
  assert.equal(REPOSITORY_IDS[WEBSITE_REPO], 1409246164);
  assert.deepEqual(REQUIRED_JOBS[WEBSITE_REPO], ['AttoLang Site Validation']);
  assert.equal(new Set(REPOSITORIES).size, 5);
  assert.ok(REPOSITORIES.every(x => x.startsWith('ores-truffle-oreslang/')));
});
test('unknown repository, missing or forged phase is rejected', () => {
  assert.throws(() => protectionPayload('other/private', 'steady'), /UNKNOWN_REPOSITORY/);
  assert.throws(() => protectionPayload(CLI_REPO, 'production'), /UNKNOWN_PHASE/);
  assert.throws(() => inspectReadback('other/private', 'steady', {}), /UNKNOWN_REPOSITORY/);
  for (const repo of REPOSITORIES) if (repo !== CLI_REPO && repo !== WEBSITE_REPO) {
    assert.throws(() => protectionPayload(repo, 'bootstrap'), /BOOTSTRAP_ONLY_FOR_MISSING_CODEOWNERS/);
  }
});
for (const repo of REPOSITORIES) {
  for (const phase of ((repo === CLI_REPO || repo === WEBSITE_REPO) ? ['bootstrap', 'steady'] : ['steady'])) {
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
      assert.equal(p.required_pull_request_reviews.require_code_owner_reviews, phase === 'steady' || (repo !== CLI_REPO && repo !== WEBSITE_REPO));
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
    ['REPOSITORY_IDENTITY_UNKNOWN_OR_MISMATCHED', f => { delete f.repository; }],
    ['REPOSITORY_IDENTITY_UNKNOWN_OR_MISMATCHED', f => { f.repository.id = REPOSITORY_IDS[CLI_REPO] + 100; }],
    ['REPOSITORY_IDENTITY_UNKNOWN_OR_MISMATCHED', f => { f.repository.full_name = 'attacker/other'; }],
    ['REPOSITORY_IDENTITY_UNKNOWN_OR_MISMATCHED', f => { f.repository.id = String(REPOSITORY_IDS[repo]); }],
    ['MAIN_NOT_PROTECTED', f => { f.branch.protected = false; }],
    ['MAIN_NOT_PROTECTED', f => { f.branch.name = 'release'; }],
    ['MAIN_HEAD_CHANGED_OR_UNKNOWN', f => { f.after_main_sha = 'b'.repeat(40); }],
    ['MAIN_HEAD_CHANGED_OR_UNKNOWN', f => { f.branch.commit.sha = 'not-sha'; }],
    ['PROTECTION_READBACK_MISSING', f => { delete f.protection; }],
    ['STRICT_CHECKS_MISSING', f => { f.protection.required_status_checks.strict = false; }],
    ['ISSUER_BOUND_CHECKS_UNAVAILABLE', f => { delete f.protection.required_status_checks.checks; }],
    ['EXTRA_OR_UNBOUND_REQUIRED_CHECK', f => { f.protection.required_status_checks.checks.push({ context: 'malicious-ci', app_id: -1 }); }],
    ['EXTRA_OR_UNBOUND_REQUIRED_CHECK', f => { f.protection.required_status_checks.checks.push({ context: 'unbound-ci' }); }],
    ['EXTRA_OR_UNBOUND_REQUIRED_CHECK', f => { f.protection.required_status_checks.checks.push({ context: 'other-ci', app_id: GITHUB_ACTIONS_APP_ID }); }],
    ['LEGACY_OR_UNEXPECTED_STATUS_CONTEXT', f => { f.protection.required_status_checks.contexts = ['malicious-ci']; }],
    ['LEGACY_OR_UNEXPECTED_STATUS_CONTEXT', f => { f.protection.required_status_checks.contexts = ['rust', 'rust']; }],
    ['LEGACY_OR_UNEXPECTED_STATUS_CONTEXT', f => { f.protection.required_status_checks.contexts = 'rust'; }],
    ['DUPLICATE_OR_MALFORMED_CHECK', f => { f.protection.required_status_checks.checks.push({ ...f.protection.required_status_checks.checks[0] }); }],
    ['CHECK_OR_ISSUER_MISSING:', f => { f.protection.required_status_checks.checks[0].app_id = -1; }],
    ['CHECK_OR_ISSUER_MISSING:', f => { f.protection.required_status_checks.checks.pop(); }],
    ['ADMIN_ENFORCEMENT_MISSING', f => { f.protection.enforce_admins.enabled = false; }],
    ['INDEPENDENT_APPROVAL_RULE_MISSING', f => { f.protection.required_pull_request_reviews.required_approving_review_count = 0; }],
    ['INDEPENDENT_APPROVAL_RULE_MISSING', f => { f.protection.required_pull_request_reviews.required_approving_review_count = 7; }],
    ['INDEPENDENT_APPROVAL_RULE_MISSING', f => { f.protection.required_pull_request_reviews.required_approving_review_count = 1.5; }],
    ['STALE_REVIEW_DISMISSAL_MISSING', f => { f.protection.required_pull_request_reviews.dismiss_stale_reviews = false; }],
    ['LAST_PUSH_APPROVAL_MISSING', f => { f.protection.required_pull_request_reviews.require_last_push_approval = false; }],
    ['CODEOWNER_REVIEW_RULE_MISSING', f => { f.protection.required_pull_request_reviews.require_code_owner_reviews = false; }],
    ['CODEOWNERS_NOT_VERIFIED_ON_MAIN', f => { f.codeowners_present_on_main = false; }],
    ['PR_BYPASS_UNVERIFIED_OR_PRESENT', f => { delete f.protection.required_pull_request_reviews.bypass_pull_request_allowances; }],
    ['PR_BYPASS_UNVERIFIED_OR_PRESENT', f => { f.protection.required_pull_request_reviews.bypass_pull_request_allowances.users = ['the1mills']; }],
    ['PR_BYPASS_UNVERIFIED_OR_PRESENT', f => { f.protection.required_pull_request_reviews.bypass_pull_request_allowances.superusers = []; }],
    ['REVIEW_DISMISSAL_RESTRICTION_PRESENT_OR_UNKNOWN', f => { f.protection.required_pull_request_reviews.dismissal_restrictions = { users: ['attacker'], teams: [], apps: [] }; }],
    ['REVIEW_DISMISSAL_RESTRICTION_PRESENT_OR_UNKNOWN', f => { f.protection.required_pull_request_reviews.dismissal_restrictions = { users: [], teams: [], apps: null }; }],
    ['FORCE_PUSH_POLICY_UNKNOWN_OR_ENABLED', f => { f.protection.allow_force_pushes.enabled = true; }],
    ['DELETION_POLICY_UNKNOWN_OR_ENABLED', f => { f.protection.allow_deletions.enabled = true; }],
    ['CONVERSATION_RESOLUTION_MISSING', f => { f.protection.required_conversation_resolution.enabled = false; }],
    ['RULESETS_READBACK_UNKNOWN', f => { delete f.rulesets; }],
    ['RULESET_ID_OR_ENFORCEMENT_UNKNOWN', f => { f.rulesets = [{ enforcement: 'forged', id: 18, bypass_actors: [] }]; }],
    ['RULESET_ID_OR_ENFORCEMENT_UNKNOWN', f => { f.rulesets = [{ enforcement: 'active', bypass_actors: [] }]; }],
    ['RULESET_ID_OR_ENFORCEMENT_UNKNOWN', f => { f.rulesets = [{ enforcement: 'disabled', id: '18' }]; }],
    ['RULESET_ID_OR_ENFORCEMENT_UNKNOWN', f => { f.rulesets = [{ enforcement: 'active', id: 18, bypass_actors: [] }, { enforcement: 'active', id: 18, bypass_actors: [] }]; }],
    ['ACTIVE_RULESET_BYPASS_OR_UNKNOWN', f => { f.rulesets = [{ id: 1, enforcement: 'active', bypass_actors: [{ actor_id: 1 }] }]; }],
    ['ACTIVE_RULESET_BYPASS_OR_UNKNOWN', f => { f.rulesets = [{ id: 1, enforcement: 'active' }]; }]
  ];
  for (const [reason, mutation] of cases) {
    test('fail closed: ' + repo + ' ' + reason + ' #' + cases.findIndex(x => x[1] === mutation), () => denies(repo, mutation, reason));
  }
}
for (const repo of [CLI_REPO, WEBSITE_REPO]) {
  test(repo + ' bootstrap requires independent PR approval but cannot require absent CODEOWNERS', () => {
    const f = fixture(repo, 'bootstrap');
    assert.equal(f.codeowners_present_on_main, false);
    assert.equal(f.protection.required_pull_request_reviews.require_code_owner_reviews, false);
    assert.equal(inspectReadback(repo, 'bootstrap', f).evidence_model_consistent, true);
    f.protection.required_pull_request_reviews.required_approving_review_count = 0;
    assert.ok(inspectReadback(repo, 'bootstrap', f).errors.includes('INDEPENDENT_APPROVAL_RULE_MISSING'));
  });
  test(repo + ' bootstrap fails closed when CODEOWNERS is present or its absence is unverified', () => {
    for (const presence of [true, null, undefined, 'false', 0]) {
      const f = fixture(repo, 'bootstrap');
      if (presence === undefined) delete f.codeowners_present_on_main;
      else f.codeowners_present_on_main = presence;
      const result = inspectReadback(repo, 'bootstrap', f);
      assert.equal(result.evidence_model_consistent, false);
      assert.ok(result.errors.includes('BOOTSTRAP_CODEOWNERS_ABSENCE_UNVERIFIED'), JSON.stringify(result));
      assert.equal(result.merge_authorized, false);
      assert.equal(result.release_authorized, false);
      assert.equal(result.private_source_export_authorized, false);
    }
  });
  test(repo + ' steady state refuses absent CODEOWNERS or owner policy', () => {
    denies(repo, f => { f.codeowners_present_on_main = false; }, 'CODEOWNERS_NOT_VERIFIED_ON_MAIN');
    denies(repo, f => { f.protection.required_pull_request_reviews.require_code_owner_reviews = false; }, 'CODEOWNER_REVIEW_RULE_MISSING');
  });
}
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

test('readback accepts GitHub echo contexts only if every context is a pinned named check', () => {
  const f = fixture(CLI_REPO);
  f.protection.required_status_checks.contexts = ['rust'];
  assert.equal(inspectReadback(CLI_REPO, 'steady', f).evidence_model_consistent, true);
  f.protection.required_status_checks.contexts = [];
  assert.equal(inspectReadback(CLI_REPO, 'steady', f).evidence_model_consistent, true);
});
test('readback accepts only explicit empty dismissal restrictions and non-bypassing known ruleset mode', () => {
  const f = fixture(CLI_REPO);
  f.protection.required_pull_request_reviews.dismissal_restrictions = {users: [], teams: [], apps: []};
  f.rulesets = [{id: 12, enforcement:'active', bypass_actors: []}];
  assert.equal(inspectReadback(CLI_REPO, 'steady', f).evidence_model_consistent, true);
  assert.equal(inspectReadback(CLI_REPO, 'steady', f).merge_authorized, false);
});
test('repeated checked snapshots remain non-authorizing regardless of forged approval/CI fields', () => {
  const f = fixture(CLI_REPO);
  f.submitted_reviews = [{user:{login:'trusted'},state:'APPROVED'}];
  f.check_runs = [{name:'rust',conclusion:'success',steps:[{conclusion:'success'}]}];
  f.merge_commit_sha = 'b'.repeat(40);
  const a = inspectReadback(CLI_REPO, 'steady', f);
  const b = inspectReadback(CLI_REPO, 'steady', structuredClone(f));
  assert.deepEqual(a, b);
  for (const x of [a,b]) {
    assert.equal(x.merge_authorized, false);
    assert.equal(x.release_authorized, false);
    assert.equal(x.private_source_export_authorized, false);
  }
});

const cli = fileURLToPath(new URL('../tools/public-main-protection-v1.mjs', import.meta.url));
function execAudit(path) {
  return spawnSync(process.execPath, [cli, '--audit', CLI_REPO, 'steady', path], {
    encoding: 'utf8', timeout: 5000, maxBuffer: 512 * 1024
  });
}
test('CLI --plan emits exact action-free JSON; bootstrap is CLI/Website only', () => {
  const x = spawnSync(process.execPath, [cli, '--plan', CLI_REPO, 'bootstrap'], {encoding:'utf8', timeout: 5000});
  assert.equal(x.status, 0, x.stderr);
  assert.deepEqual(JSON.parse(x.stdout), protectionPayload(CLI_REPO, 'bootstrap'));
  const website = spawnSync(process.execPath, [cli, '--plan', WEBSITE_REPO, 'bootstrap'], {encoding:'utf8',timeout:5000});
  assert.equal(website.status, 0, website.stderr);
  assert.deepEqual(JSON.parse(website.stdout), protectionPayload(WEBSITE_REPO, 'bootstrap'));
  const deniedRepo = REPOSITORIES.find(r => r !== CLI_REPO && r !== WEBSITE_REPO);
  const denied = spawnSync(process.execPath, [cli, '--plan', deniedRepo, 'bootstrap'], {encoding:'utf8',timeout:5000});
  assert.equal(denied.status, 2);
  assert.match(denied.stderr, /BOOTSTRAP_ONLY_FOR_MISSING_CODEOWNERS/);
});
test('CLI --audit gives exit 3 and explicit deny even when snapshot is consistent', t => {
  const dir = mkdtempSync(join(tmpdir(), 'atto-admin-model-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const p = join(dir, 'snapshot.json');
  writeFileSync(p, JSON.stringify(fixture(CLI_REPO)));
  const x = execAudit(p);
  assert.equal(x.status, 3, x.stderr);
  const model = JSON.parse(x.stdout);
  assert.equal(model.evidence_model_consistent, true);
  assert.equal(model.merge_authorized, false);
  assert.equal(model.release_authorized, false);
  assert.equal(model.private_source_export_authorized, false);
});
test('CLI --audit rejects non-regular symlink, over-budget file, malformed JSON and invalid UTF-8', t => {
  const dir = mkdtempSync(join(tmpdir(), 'atto-admin-hostile-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const valid = join(dir, 'valid.json');
  const link = join(dir, 'alias.json');
  const large = join(dir, 'large.json');
  const malformed = join(dir, 'malformed.json');
  const nonutf8 = join(dir, 'nonutf8.json');
  writeFileSync(valid, '{}');
  symlinkSync(valid, link);
  writeFileSync(large, ' '.repeat(1024 * 1024 + 1));
  writeFileSync(malformed, '{"repository":');
  writeFileSync(nonutf8, Buffer.from([0xc0,0xaf]));
  for (const p of [link, large, malformed, nonutf8]) {
    const x = execAudit(p);
    assert.equal(x.status, 2, p + ':' + x.stderr);
    assert.match(x.stderr, /PUBLIC_MAIN_POLICY_DENIED:/);
    assert.doesNotMatch(x.stdout, /merge_authorized/);
  }
});
