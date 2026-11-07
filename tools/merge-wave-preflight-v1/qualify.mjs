// Source-free, advisory-only merge-wave admission model. Not a GitHub authorization engine.
const SHA = /^[a-f0-9]{40}$/;
const REPO = /^ores-truffle-oreslang\/[a-zA-Z0-9_.-]+$/;
const TERMINAL = new Set(['APPROVED', 'CHANGES_REQUESTED', 'DISMISSED', 'COMMENTED']);
const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/;
function validTimestamp(value) {
  return typeof value === 'string' && ISO.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}
function positive(value) { return Number.isSafeInteger(value) && value > 0; }
function record(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
const code = (reason, index = null) => index === null ? reason : 'PR_' + (index + 1) + ':' + reason;
export function qualifyWave(snapshot, now = new Date().toISOString()) {
  const reasons = [];
  const reject = (reason, index) => reasons.push(code(reason, index));
  const finish = () => Object.freeze({
    status: reasons.length === 0 ? 'READY_FOR_LIVE_RECHECK' : 'BLOCKED',
    reasons: Object.freeze([...new Set(reasons)]),
    merge_authorized: false, release_authorized: false,
    guest_parity_proven: false, max_merge_attempts_authorized: 0,
    live_recheck_required: true,
  });
  if (!record(snapshot) || !validTimestamp(now) || !validTimestamp(snapshot.as_of)) {
    reject('BAD_SNAPSHOT_OR_TIME'); return finish();
  }
  const observed = Date.parse(snapshot.as_of), clock = Date.parse(now);
  if (Math.abs(clock - observed) > 5 * 60_000) reject('STALE_OR_FUTURE_SNAPSHOT');
  if (!Array.isArray(snapshot.candidates)) { reject('MISSING_CANDIDATES'); return finish(); }
  if (snapshot.candidates.length < 5 || snapshot.candidates.length > 50) reject('FIVE_PR_QUORUM');
  const distinct = new Set(), repos = new Set();
  snapshot.candidates.forEach((p, i) => {
    if (!record(p) || !REPO.test(p.repo || '') || !positive(p.number) ||
        typeof p.author !== 'string' || !p.author.trim()) {
      reject('BAD_PR_IDENTITY', i); return;
    }
    const identity = p.repo + '#' + p.number;
    if (distinct.has(identity)) reject('DUPLICATE_PR', i);
    distinct.add(identity); repos.add(p.repo);
    if (p.state !== 'open' || p.draft !== false) reject('NOT_READY', i);
    if (p.mergeable !== true || p.conflict_free !== true) reject('MERGE_CONFLICT_OR_UNKNOWN', i);
    if (p.active_agent_lease !== false) reject('ACTIVE_OR_UNKNOWN_LEASE', i);
    if (![p.head_sha, p.observed_head_sha, p.base_sha, p.observed_base_sha, p.tree_sha].every(x =>
        typeof x === 'string' && SHA.test(x))) {
      reject('INVALID_SOURCE_IDENTITY', i);
    } else {
      if (p.head_sha !== p.observed_head_sha) reject('HEAD_DRIFT', i);
      if (p.base_sha !== p.observed_base_sha) reject('BASE_DRIFT', i);
    }
    const policy = p.policy;
    if (!record(policy) || policy.protected !== true || policy.rulesets_verified !== true ||
        policy.independent_review_enforced !== true || policy.stale_review_dismissal !== true ||
        policy.required_checks_enforced !== true || policy.admin_bypass_disabled !== true ||
        !Array.isArray(policy.bypass_actors) || policy.bypass_actors.length !== 0) {
      reject('UNENFORCED_MAIN_POLICY', i);
    }
    if (!Array.isArray(p.reviews)) {
      reject('MISSING_REVIEWS', i);
    } else {
      const latest = new Map(), outstanding = new Set();
      let malformed = false;
      for (const review of p.reviews) {
        if (!record(review) || typeof review.user !== 'string' || !review.user.trim() ||
            !TERMINAL.has(review.state) || !validTimestamp(review.submitted_at) ||
            typeof review.commit_id !== 'string' || !SHA.test(review.commit_id)) {
          malformed = true; break;
        }
        if (Date.parse(review.submitted_at) > observed) { malformed = true; break; }
        const prior = latest.get(review.user);
        if (prior && review.submitted_at < prior.submitted_at) { malformed = true; break; }
        if (review.state === 'CHANGES_REQUESTED') outstanding.add(review.user);
        // A comment cannot cancel requested changes: require a later verified approval.
        if (review.state === 'APPROVED' && review.commit_id === p.head_sha &&
            review.verified_independent === true) outstanding.delete(review.user);
        latest.set(review.user, review);
      }
      if (malformed) reject('MALFORMED_REVIEW_TIMELINE', i);
      else {
        const independent = [...latest.values()].filter(r =>
          r.user !== p.author && r.state === 'APPROVED' && r.commit_id === p.head_sha &&
          r.verified_independent === true);
        if (independent.length === 0) reject('NO_CURRENT_INDEPENDENT_APPROVAL', i);
        if ([...outstanding].some(user => user !== p.author)) {
          reject('OUTSTANDING_CHANGES_REQUESTED', i);
        }
      }
    }
    const ci = p.ci;
    if (!record(ci) || ci.source_owned !== true || ci.conclusion !== 'success' ||
        !positive(ci.run_id) || !positive(ci.run_attempt) ||
        ci.head_sha !== p.head_sha || ci.checkout_sha !== p.head_sha ||
        ci.tree_sha !== p.tree_sha || ci.source_integrity_verified !== true ||
        ci.run_event !== 'pull_request' || !Array.isArray(ci.jobs) || ci.jobs.length === 0) {
      reject('INVALID_EXACT_HEAD_CI', i);
    } else {
      const names = new Set();
      let hasTest = false, badJob = false;
      for (const job of ci.jobs) {
        if (!record(job) || !positive(job.runner_id) || job.conclusion !== 'success' ||
            typeof job.name !== 'string' || names.has(job.name) ||
            !Array.isArray(job.steps) || job.steps.length === 0) { badJob = true; break; }
        names.add(job.name);
        if (job.steps.some(s => !record(s) || s.status !== 'completed' || s.conclusion !== 'success')) {
          badJob = true; break;
        }
        if (job.steps.some(s => s.kind === 'source_test' && s.status === 'completed')) hasTest = true;
      }
      if (badJob || !hasTest) reject('ZERO_STEP_OR_INCOMPLETE_CI', i);
    }
  });
  if (repos.size < 3) reject('THREE_REPO_QUORUM');
  if (snapshot.agent_coordinator_verified !== true) reject('AGENT_COORDINATION_UNVERIFIED');
  if (snapshot.live_head_refresh_required !== true || snapshot.post_merge_base_refresh_required !== true) {
    reject('MISSING_SEQUENTIAL_RECHECK');
  }
  return finish();
}
