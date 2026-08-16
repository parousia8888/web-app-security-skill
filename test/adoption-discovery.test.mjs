#!/usr/bin/env node
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (path) => JSON.parse(readFileSync(join(ROOT, path), 'utf8'));
const listings = read('docs/adoption/listings.json');
const schedule = read('docs/adoption/publication-schedule.json');
const schema = read('docs/adoption/observation.schema.json');
const baseline = read('docs/adoption/observations/pre-publication.json');

assert.equal(listings.schemaVersion, 1);
assert.equal(listings.assessmentMethod.starsAloneSufficient, false);
assert.ok(listings.assessmentMethod.signals.includes('latest_external_merge'));
assert.ok(listings.assessmentMethod.signals.includes('open_pull_request_backlog'));
assert.match(listings.projectFacts.firstDefaultBranchCommit, /^[a-f0-9]{40}$/);
assert.equal(listings.projectFacts.hasMcpServer, false);
assert.deepEqual(listings.candidates.map((item) => item.id), [
  'awesome-claude-code', 'awesome-agent-skills', 'awesome-devsecops',
  'static-analysis', 'hahwul-devsecops', 'behisec-awesome-claude-skills',
  'awesome-codex-skills', 'awesome-web-security', 'agentic-awesome-skills',
  'composio-awesome-claude-skills', 'awesome-vibe-coding', 'mcp-registry',
]);
for (const item of listings.candidates.filter((candidate) => candidate.repository)) {
  assert.match(item.policyCommit, /^[a-f0-9]{40}$/);
  assert.ok(item.policyPaths.length > 0);
  assert.match(item.activity.observedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  assert.ok(Number.isInteger(item.activity.stars));
  assert.ok(Number.isInteger(item.activity.openPullRequests));
  assert.ok(item.activity.assessment.length > 0);
}
const byId = Object.fromEntries(listings.candidates.map((item) => [item.id, item]));
assert.equal(byId['awesome-claude-code'].status, 'ineligible');
assert.deepEqual(byId['awesome-claude-code'].unmetRules, ['at_least_14_days_old_or_100_stars']);
assert.equal(byId['awesome-agent-skills'].status, 'ineligible');
assert.equal(byId['awesome-devsecops'].status, 'submitted_pending_review');
assert.equal(byId['awesome-devsecops'].submission.url,
  'https://github.com/devsecops/awesome-devsecops/pull/172');
assert.equal(byId['awesome-devsecops'].submission.state, 'open');
assert.equal(byId['awesome-devsecops'].submission.accepted, false);
assert.equal(byId['awesome-devsecops'].activity.assessment,
  'historically_popular_currently_dormant');
assert.equal(byId['awesome-devsecops'].priority, 'do_not_count_as_effective_channel');
assert.deepEqual(byId['static-analysis'].unmetRules,
  ['more_than_one_contributor', 'more_than_20_stars', 'at_least_three_months_old']);
assert.equal(byId['hahwul-devsecops'].status, 'eligible_on_documented_scope');
assert.equal(byId['hahwul-devsecops'].activity.assessment, 'active_low_backlog');
assert.equal(byId['awesome-web-security'].priority, 'high_after_independent_usage');
assert.equal(byId['agentic-awesome-skills'].status, 'deferred');
assert.ok(byId['agentic-awesome-skills'].unmetRules.includes(
  'second_source_copy_and_private_metadata_governance'));
assert.equal(byId['composio-awesome-claude-skills'].activity.openPullRequests, 1131);
assert.equal(byId['mcp-registry'].status, 'out_of_scope');
assert.deepEqual(byId['mcp-registry'].unmetRules, ['no_mcp_server_implemented']);
assert.equal(listings.externalState, 'external_validation_pending');

assert.equal(schedule.ownerApprovalRequiredPerAction, true);
assert.equal(schedule.automatedPostingAllowed, false);
assert.equal(schedule.minimumGapHours, 48);
assert.equal(schedule.maximumPlannedGapHours, 72);
assert.deepEqual(schedule.plannedOrder.map((item) => item.channel), ['show_hn', 'v2ex', 'zenn']);
for (const [index, item] of schedule.plannedOrder.entries()) {
  assert.equal(item.sequence, index + 1);
  assert.equal(item.state, 'external_validation_pending');
  assert.equal(item.publishedAt, null);
  assert.equal(item.liveUrl, null);
  assert.equal(existsSync(join(ROOT, item.sourceDraft)), true, `${item.sourceDraft} is missing`);
}
assert.deepEqual(schedule.observationWindows.map((item) => item.offsetHours), [0, 24, 72, 168]);
assert.match(schedule.interpretation, /Do not claim.*caused/i);

assert.deepEqual(schema.properties.window.enum, ['pre_publication', 'h24', 'h72', 'd7']);
assert.equal(schema.properties.causalAttribution.const, false);
assert.equal(baseline.window, 'pre_publication');
assert.equal(baseline.channelContext.state, 'before_publication');
assert.equal(baseline.channelContext.liveUrl, null);
assert.equal(baseline.causalAttribution, false);
assert.equal(baseline.metrics.github.trafficWindowDays, 14);
assert.equal(baseline.metrics.github.stars, listings.projectFacts.stars);
for (const field of ['npmWeeklyDownloads', 'actionMarketplaceInstalls', 'independentReferences']) {
  assert.equal(baseline.metrics[field], null);
}
assert.equal(baseline.missingData.length, 3);
assert.match(baseline.limitations.join(' '), /author, CI, automation and crawler activity/);

console.log('adoption discovery ok: pinned eligibility, owner-gated schedule and non-causal baseline');
