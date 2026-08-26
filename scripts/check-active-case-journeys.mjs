#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  classifyJourneyAuditExit, journeyAdapterDefinitions, renderJourneyPrerequisiteBlock,
  sha256Bytes, toolSourceIdentity,
} from './lib/journey-contract.mjs';
import { adapterDefinitions } from './lib/adapter-definitions.mjs';
import { SOURCE_RULES } from './lib/source-rules.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const args = process.argv.slice(2);
const catalogPath = resolve(args.shift() || `${ROOT}/docs/case-studies/journeys/evidence-v0.7.3.json`);
if (args.length) {
  console.error('usage: node scripts/check-active-case-journeys.mjs [catalog.json]');
  process.exit(2);
}
const catalog = JSON.parse(readFileSync(catalogPath, 'utf8'));
const errors = [];
const fail = (condition, message) => { if (!condition) errors.push(message); };
const digest = (value) => /^[a-f0-9]{64}$/.test(value || '');

fail(catalog.schemaVersion === 3 && catalog.release === 'v0.7.3', 'active catalog identity is invalid');
fail(catalog.status === 'active', 'active catalog is not promoted');
fail(catalog.evidenceType === 'active_ordinary_project_journey_contract', 'evidence type changed');
const historicalPath = catalog.historicalSource?.path ? `${ROOT}/${catalog.historicalSource.path}` : '';
fail(Boolean(historicalPath) && existsSync(historicalPath), 'historical catalog source is missing');
if (historicalPath && existsSync(historicalPath)) {
  fail(sha256Bytes(readFileSync(historicalPath)) === catalog.historicalSource.sha256,
    'historical catalog bytes changed');
}
const currentTool = toolSourceIdentity(ROOT);
fail(digest(catalog.toolSource?.sourceDigest), 'tool source digest is invalid');
fail(catalog.toolSource?.sourceDigest === currentTool.sourceDigest, 'active catalog tool source is stale');
fail(/^[a-f0-9]{40}$/.test(catalog.toolSource?.commit || ''), 'tool source commit is not immutable');
fail(catalog.method?.sourceOnly === true && catalog.method?.hostedInstancesProbed === false
  && catalog.method?.projectDependenciesExecuted === false
  && catalog.method?.auditExitRecordedSeparately === true
  && catalog.method?.byteAndSemanticDigestsSeparated === true
  && catalog.method?.manualAnnotationIdentitySeparated === true
  && catalog.method?.gitleaksHistoryBoundary === 'target_commit_reachable_history',
'active method boundary is incomplete');
fail(catalog.journeys?.length === 5, 'exactly five active journeys are required');

const selections = new Set();
for (const journey of catalog.journeys || []) {
  let definitions = [];
  try { definitions = journeyAdapterDefinitions(journey.adapterSelection); } catch (error) {
    errors.push(`${journey.id}: ${error.message}`);
  }
  selections.add(JSON.stringify(journey.adapterSelection));
  fail(/^[a-f0-9]{40}$/.test(journey.commit || ''), `${journey.id} target commit is invalid`);
  if (journey.adapterSelection?.includes('gitleaks')) {
    fail(journey.historyBoundary?.adapter === 'gitleaks'
      && journey.historyBoundary.ref === journey.commit
      && journey.historyBoundary.semantics === 'commits_reachable_from_exact_target_commit',
    `${journey.id} Gitleaks history boundary is invalid`);
  }
  fail(Array.isArray(journey.mutableAdapters)
    && journey.mutableAdapters.every((id) => journey.adapterSelection.includes(id)),
  `${journey.id} mutable adapter declaration is invalid`);
  const expectedAdapterIds = definitions.map((item) => item.reportId);
  const observedAdapterIds = journey.corpus?.adapters?.map((item) => item.id) || [];
  fail(JSON.stringify(expectedAdapterIds) === JSON.stringify(observedAdapterIds),
    `${journey.id} adapter identities do not match adapterSelection`);
  fail(Number.isInteger(journey.corpus?.auditExit?.code)
    && journey.corpus.auditExit.classification === classifyJourneyAuditExit(journey.corpus.auditExit.code),
  `${journey.id} audit exit identity is invalid`);
  fail(digest(journey.corpus?.rulesetDigest), `${journey.id} ruleset digest is invalid`);
  for (const name of ['reportBytes', 'reportSemantics', 'stableReportSemantics', 'manualAnnotationIdentity']) {
    fail(digest(journey.corpus?.digests?.[name]), `${journey.id} ${name} digest is invalid`);
  }
  for (const adapter of journey.corpus?.adapters || []) {
    fail(Boolean(adapter.version) && digest(adapter.rulesetDigest), `${journey.id}/${adapter.id} ruleset identity is invalid`);
    if (adapter.id !== 'builtin-source') {
      fail(digest(adapter.binarySha256), `${journey.id}/${adapter.id} binary digest is invalid`);
      fail(Boolean(adapter.observedVersion) || adapter.status !== 'available',
        `${journey.id}/${adapter.id} available runtime lacks observed version`);
    }
    if (!journey.mutableAdapters.includes(adapter.id)) {
      fail(digest(adapter.deterministicFindingIdsDigest)
        && digest(adapter.deterministicFindingContentDigest),
      `${journey.id}/${adapter.id} deterministic finding digests are missing`);
    }
  }
  const requiredRules = [
    ...SOURCE_RULES,
    ...adapterDefinitions(journey.adapterSelection).flatMap((definition) => definition.rules),
  ].map((rule) => rule.id).sort();
  const coverageRules = Object.keys(journey.corpus?.coverage || {}).sort();
  fail(JSON.stringify(requiredRules) === JSON.stringify(coverageRules),
    `${journey.id} coverage rule set does not match adapterSelection`);
  fail((journey.corpus?.snapshot?.summary?.confirmed || 0)
    === (journey.corpus?.confirmedFindingIds || []).length,
  `${journey.id} confirmed findings are not individually reviewed`);
  fail((journey.corpus?.snapshot?.externalStates || [])
    .every((state) => ['suspected', 'unknown'].includes(state)),
  `${journey.id} external evidence state exceeded suspected/unknown`);
}

const readme = readFileSync(`${ROOT}/docs/case-studies/journeys/README.md`, 'utf8');
if (selections.size === 1) {
  fail(readme.includes(renderJourneyPrerequisiteBlock(JSON.parse([...selections][0]))),
    'generated journey prerequisites are stale');
} else {
  errors.push('active journeys do not share one documented adapter selection');
}

if (errors.length) {
  console.error(`active case journeys invalid:\n${[...new Set(errors)].map((error) => `- ${error}`).join('\n')}`);
  process.exit(1);
}
console.log(`active case journeys ok: ${catalog.journeys.length} projects, exact adapters/exits, separated evidence identities`);
