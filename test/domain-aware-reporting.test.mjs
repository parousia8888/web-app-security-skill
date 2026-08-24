#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  createFindingV2, createReportV2, exitCodeV2, initializeFindingsV2, policyForFailOn,
  renderHtmlV2, renderJunitV2, renderMarkdownV2, renderSarifV2,
} from '../scripts/lib/evidence-v2.mjs';
import { sha256 } from '../scripts/lib/report-v2-contract.mjs';
import { createRulesetV2 } from '../scripts/lib/ruleset-v2.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ADAPTER = { id: 'domain-fixture', version: '1.0.0', maturity: 'stable' };
const RULES = [
  ['security-confirmed', 'security_exposure', 'confirmed', 'high'],
  ['supply-suspected', 'supply_chain', 'suspected', 'medium'],
  ['discoverability-confirmed', 'search_discoverability', 'confirmed', 'high'],
  ['reliability-na', 'reliability', 'not_applicable', 'low'],
  ['integrity-unknown', 'evidence_integrity', 'unknown', 'high'],
].map(([id, domain, state, severity]) => ({ id, revision: '1', domain, state, severity }));
const ruleset = createRulesetV2([{ ...ADAPTER, rules: RULES }]);

const coverage = RULES.map((rule) => ({
  id: `coverage-${rule.id}`,
  adapterId: ADAPTER.id,
  ruleId: rule.id,
  ruleRevision: rule.revision,
  status: rule.state === 'unknown' ? 'unavailable' : rule.state === 'not_applicable' ? 'not_applicable' : 'completed',
  counts: rule.state === 'unknown'
    ? { discovered: 1, eligible: 1, scanned: 0, excluded: 0, skipped: 0, truncated: 0, errors: 1 }
    : rule.state === 'not_applicable'
      ? { discovered: 1, eligible: 0, scanned: 0, excluded: 1, skipped: 0, truncated: 0, errors: 0 }
      : { discovered: 1, eligible: 1, scanned: 1, excluded: 0, skipped: 0, truncated: 0, errors: 0 },
  reasons: rule.state === 'unknown'
    ? [{ code: 'fixture_unavailable', count: 1, samplePaths: [] }]
    : rule.state === 'not_applicable'
      ? [{ code: 'fixture_not_applicable', count: 1, samplePaths: [] }]
      : [],
}));

const findings = RULES.map((rule) => createFindingV2({
  ruleset,
  adapterId: ADAPTER.id,
  rule,
  title: `${rule.id} fixture`,
  severity: rule.severity,
  state: rule.state,
  summary: `Observed ${rule.id}.`,
  evidence: { subject: rule.id },
  remediation: 'Apply the scoped fixture remediation.',
  retest: 'Repeat the same fixture check.',
}));

function report(policy = policyForFailOn('high')) {
  return createReportV2({
    version: '0.4.0-planned',
    generatedAt: '1970-01-01T00:00:00.000Z',
    mode: 'audit',
    subject: {
      id: 'project-0123456789abcdef', binding: 'ephemeral',
      scopeDigest: sha256('domain-fixture'), localPathIncluded: false,
    },
    ruleset,
    scope: { checkModes: ['fixture'], networkAccessPerformed: false },
    coverage,
    findings: initializeFindingsV2(findings, coverage),
    policy,
    limitations: ['Controlled domain fixture only.'],
  });
}

const defaultReport = report();
assert.equal(defaultReport.summary.byDomain.security_exposure.byState.confirmed.bySeverity.high, 1);
assert.equal(defaultReport.summary.byDomain.supply_chain.byState.suspected.bySeverity.medium, 1);
assert.equal(defaultReport.summary.byDomain.evidence_integrity.byState.unknown.bySeverity.high, 1);
assert.deepEqual(defaultReport.policy.gateStates, ['confirmed', 'suspected']);
assert.equal(exitCodeV2(defaultReport), 1, 'default policy gates actionable security HIGH');

const discoverabilityOnly = report(policyForFailOn('never', ['search_discoverability=high']));
assert.equal(exitCodeV2(discoverabilityOnly), 1, 'explicit discoverability gate is enforced');
const noDiscoverabilityGate = report(policyForFailOn('never'));
assert.equal(exitCodeV2(noDiscoverabilityGate), 3, 'discoverability is not in the default gate and unknown remains visible');
const combined = policyForFailOn('medium', ['search_discoverability=high', 'reliability=low']);
assert.equal(combined.thresholds.find((item) => item.domain === 'security_exposure').failOn, 'medium');
assert.equal(combined.thresholds.find((item) => item.domain === 'supply_chain').failOn, 'medium');
assert.equal(combined.thresholds.find((item) => item.domain === 'search_discoverability').failOn, 'high');
assert.equal(combined.thresholds.find((item) => item.domain === 'reliability').failOn, 'low');
assert.throws(() => policyForFailOn('high', ['search_discoverability=high', 'search_discoverability=low']), /duplicate/);
assert.throws(() => policyForFailOn('high', ['not_a_domain=high']), /invalid domain threshold/);

const renderers = [
  renderMarkdownV2(defaultReport), renderHtmlV2(defaultReport),
  renderSarifV2(defaultReport), renderJunitV2(defaultReport),
];
for (const output of renderers) {
  for (const marker of ['security_exposure', 'supply_chain', 'search_discoverability', 'reliability', 'evidence_integrity']) {
    assert.ok(output.includes(marker), `renderer dropped domain ${marker}`);
  }
  for (const marker of ['confirmed', 'suspected', 'unknown', 'not_applicable']) {
    assert.ok(output.includes(marker), `renderer dropped evidence state ${marker}`);
  }
}
assert.match(renderers[0], /security_exposure: total=1; confirmed=1 \(high=1\)/);
assert.match(renderers[1], /Risk summary/);

const temp = mkdtempSync(join(tmpdir(), 'web-app-security-domain-demo-'));
try {
  const outputs = [join(temp, 'one'), join(temp, 'two')];
  for (const output of outputs) {
    const run = spawnSync(process.execPath, [join(ROOT, 'scripts', 'demo.mjs'), '--out', output], {
      cwd: ROOT,
      encoding: 'utf8',
      timeout: 30000,
      env: { ...process.env, SOURCE_DATE_EPOCH: '0' },
    });
    assert.equal(run.status, 0, run.stderr || run.stdout);
  }
  assert.equal(
    readFileSync(join(outputs[0], 'demo-result.json'), 'utf8'),
    readFileSync(join(outputs[1], 'demo-result.json'), 'utf8'),
    'structured demo facts must be byte-stable across repeated runs',
  );
} finally {
  rmSync(temp, { recursive: true, force: true });
}

console.log('domain-aware reporting ok: nested summary, policies, renderers and deterministic demo facts');
