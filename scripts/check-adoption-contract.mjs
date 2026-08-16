#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const plan = readFileSync(`${ROOT}/docs/ADOPTION_ENGINEERING_PLAN.md`, 'utf8');
const publicContract = JSON.parse(readFileSync(`${ROOT}/docs/public-contract.json`, 'utf8'));
const releaseState = JSON.parse(readFileSync(`${ROOT}/docs/release-state.json`, 'utf8'));
const currentVersion = readFileSync(`${ROOT}/VERSION`, 'utf8').trim();
const sessionSchema = JSON.parse(readFileSync(`${ROOT}/docs/usability/session.schema.json`, 'utf8'));
const tutorial = readFileSync(`${ROOT}/docs/tutorial.md`, 'utf8');
const tutorialZh = readFileSync(`${ROOT}/docs/tutorial.zh-CN.md`, 'utf8');
const listings = JSON.parse(readFileSync(`${ROOT}/docs/adoption/listings.json`, 'utf8'));
const publicationSchedule = JSON.parse(readFileSync(`${ROOT}/docs/adoption/publication-schedule.json`, 'utf8'));
const observationSchema = JSON.parse(readFileSync(`${ROOT}/docs/adoption/observation.schema.json`, 'utf8'));
const prePublication = JSON.parse(readFileSync(`${ROOT}/docs/adoption/observations/pre-publication.json`, 'utf8'));
const normalizedPlan = plan.replace(/\s+/g, ' ').trim();
let failed = false;

function requireText(label, value) {
  if (!normalizedPlan.includes(value.replace(/\s+/g, ' ').trim())) {
    console.error(`adoption contract: missing ${label}: ${JSON.stringify(value)}`);
    failed = true;
  }
}

for (const phase of ['G0', 'G1', 'G2', 'G3', 'G4', 'G5', 'G6', 'G7', 'G8', 'G9', 'G10', 'G11']) {
  requireText(`${phase} heading`, `## ${phase} -`);
  const ledger = new RegExp(`\\| ${phase} \\|[^\\n]+\\| (?:in progress|pending|completed) \\|`);
  if (!ledger.test(plan)) {
    console.error(`adoption contract: ${phase} is missing from the phase ledger`);
    failed = true;
  }
}

for (const marker of [
  'Star count is an observed downstream metric, not an engineering acceptance criterion',
  'external_validation_pending',
  'Do not make unverified `curl | sh` the recommended installation path',
  'owned local fixture',
  'confirmed/suspected/unknown/not-applicable',
  'Do not tag or publish until',
  'must never be invented to close the program',
]) requireText('program rule', marker);

const completionRecords = plan.match(/### Completion record/g)?.length ?? 0;
if (completionRecords !== 12) {
  console.error(`adoption contract: expected 12 completion records, found ${completionRecords}`);
  failed = true;
}

const publishedVersion = releaseState.publishedRelease.version;
const currentSource = publicContract.currentSourceRelease;
if (currentSource.status === 'published' && currentSource.version !== publishedVersion) {
  console.error('adoption contract: published public source must match the published release state');
  failed = true;
} else if (currentSource.status === 'candidate' && currentSource.version !== currentVersion) {
  console.error('adoption contract: candidate public source must match VERSION');
  failed = true;
} else if (!['published', 'candidate'].includes(currentSource.status)) {
  console.error('adoption contract: public source status must be published or candidate');
  failed = true;
}
for (const [label, value] of [['English tutorial', tutorial], ['Chinese tutorial', tutorialZh]]) {
  if (!value.includes(`v${publishedVersion}`) || value.includes('v0.5.0 candidate')) {
    console.error(`adoption contract: ${label} does not describe the published v${publishedVersion} path`);
    failed = true;
  }
}
const supportedNodeMajors = sessionSchema.properties.environment.properties.nodeMajor.enum;
if (JSON.stringify(supportedNodeMajors) !== JSON.stringify([22, 24])) {
  console.error('adoption contract: usability schema must match the supported Node 22/24 matrix');
  failed = true;
}
if (sessionSchema.properties.schemaVersion.const !== 2
    || sessionSchema.properties.study.const !== 'first-use-v2') {
  console.error('adoption contract: usability schema must use the first-use-v2 contract');
  failed = true;
}
if (JSON.stringify(sessionSchema.properties.entryPath.enum)
    !== JSON.stringify(['npx', 'claude_repository_plugin', 'verified_installer'])) {
  console.error('adoption contract: usability entry paths are incomplete');
  failed = true;
}
for (const field of [
  'sessionSequence', 'suspectedMeaning', 'sideEffectComprehension',
  'retestDistinctionComprehension',
]) {
  if (!sessionSchema.required.includes(field)) {
    console.error(`adoption contract: usability schema is missing ${field}`);
    failed = true;
  }
}

const listingIds = listings.candidates.map((item) => item.id);
for (const id of [
  'awesome-claude-code', 'awesome-agent-skills', 'awesome-devsecops', 'static-analysis',
  'hahwul-devsecops', 'behisec-awesome-claude-skills', 'awesome-codex-skills',
  'awesome-web-security', 'agentic-awesome-skills', 'composio-awesome-claude-skills',
  'awesome-vibe-coding', 'mcp-registry',
]) {
  if (!listingIds.includes(id)) {
    console.error(`adoption contract: listing register is missing ${id}`);
    failed = true;
  }
}
if (listings.assessmentMethod?.starsAloneSufficient !== false
    || !listings.assessmentMethod.signals?.includes('latest_external_merge')
    || !listings.assessmentMethod.signals?.includes('open_pull_request_backlog')) {
  console.error('adoption contract: directory review must not treat stars as maintenance evidence');
  failed = true;
}
const mcpListing = listings.candidates.find((item) => item.id === 'mcp-registry');
if (listings.projectFacts.hasMcpServer !== false || mcpListing?.status !== 'out_of_scope'
    || !mcpListing.unmetRules.includes('no_mcp_server_implemented')) {
  console.error('adoption contract: MCP registry must remain out of scope without an MCP server');
  failed = true;
}
const awesomeDevsecops = listings.candidates.find((item) => item.id === 'awesome-devsecops');
if (awesomeDevsecops?.status !== 'submitted_pending_review'
    || awesomeDevsecops.submissionMethod !== 'pull_request'
    || awesomeDevsecops.submission?.state !== 'open'
    || awesomeDevsecops.submission?.accepted !== false
    || !/^https:\/\/github\.com\/devsecops\/awesome-devsecops\/pull\/\d+$/.test(
      awesomeDevsecops.submission?.url || '',
    )) {
  console.error('adoption contract: awesome-devsecops submission state is incomplete or overstated');
  failed = true;
}
for (const item of listings.candidates.filter((candidate) => candidate.repository)) {
  if (!/^[a-f0-9]{40}$/.test(item.policyCommit || '') || !item.policyPaths.length
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(item.activity?.observedAt || '')
      || !Number.isInteger(item.activity?.stars)
      || !Number.isInteger(item.activity?.openPullRequests)
      || !item.activity?.assessment) {
    console.error(`adoption contract: ${item.id} policy review is not commit-pinned`);
    failed = true;
  }
}
if (awesomeDevsecops?.activity?.assessment !== 'historically_popular_currently_dormant'
    || awesomeDevsecops?.priority !== 'do_not_count_as_effective_channel') {
  console.error('adoption contract: awesome-devsecops dormancy correction is missing');
  failed = true;
}
const hahwulDevsecops = listings.candidates.find((item) => item.id === 'hahwul-devsecops');
const awesomeWebSecurity = listings.candidates.find((item) => item.id === 'awesome-web-security');
if (hahwulDevsecops?.status !== 'eligible_on_documented_scope'
    || hahwulDevsecops?.activity?.assessment !== 'active_low_backlog'
    || awesomeWebSecurity?.priority !== 'high_after_independent_usage') {
  console.error('adoption contract: active directory priorities are incomplete');
  failed = true;
}
if (publicationSchedule.ownerApprovalRequiredPerAction !== true
    || publicationSchedule.automatedPostingAllowed !== false
    || publicationSchedule.minimumGapHours !== 48
    || publicationSchedule.maximumPlannedGapHours !== 72
    || JSON.stringify(publicationSchedule.plannedOrder.map((item) => item.channel))
      !== JSON.stringify(['show_hn', 'v2ex', 'zenn'])
    || publicationSchedule.plannedOrder.some((item) =>
      item.state !== 'external_validation_pending' || item.liveUrl !== null || item.publishedAt !== null)) {
  console.error('adoption contract: publication order, spacing or owner gate drifted');
  failed = true;
}
if (JSON.stringify(publicationSchedule.observationWindows.map((item) => item.offsetHours))
    !== JSON.stringify([0, 24, 72, 168])
    || observationSchema.properties.causalAttribution.const !== false
    || prePublication.window !== 'pre_publication'
    || prePublication.causalAttribution !== false
    || prePublication.channelContext.state !== 'before_publication') {
  console.error('adoption contract: non-causal observation windows drifted');
  failed = true;
}

if (/(?:stars?|forks?)\s*(?:>=|>|=)\s*\d+|(?:stars?|forks?)\s+target\s*:\s*\d+/i.test(plan)) {
  console.error('adoption contract: star/fork targets cannot be phase acceptance criteria');
  failed = true;
}

if (failed) process.exit(1);
console.log('adoption contract ok: G0-G11, published facts, external boundary, safety rules, no star gate');
