#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { compareFindingsV2 } from '../scripts/lib/evidence-v2.mjs';
import { sourceCoverage, sourceRuleset } from '../scripts/lib/source-rules.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(ROOT, 'scripts', 'webapp-security.mjs');
const FIXTURE = join(ROOT, 'test', 'fixtures', 'audit-app');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-baseline-identity-'));
const env = { ...process.env, SOURCE_DATE_EPOCH: '0' };

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env });
}

function start(project, root, id) {
  const result = run(['start', project, '--out', root, '--run-id', id]);
  assert.equal(result.status, 0, result.stderr);
  return join(root, id);
}

function audit(runDir, name = 'report', expectedExit = 3) {
  const result = run(['audit', runDir, '--name', name, '--fail-on', 'never']);
  assert.equal(result.status, expectedExit, result.stderr);
  return join(runDir, `${name}.json`);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function writeForgedBaseline(path, value) {
  const bytes = `${JSON.stringify(value, null, 2)}\n`;
  writeFileSync(path, bytes);
  writeFileSync(join(dirname(path), 'report.sha256'), `${sha256(bytes)}  report.json\n`);
}

try {
  const projectA = join(temp, 'project-a');
  const projectB = join(temp, 'project-b');
  cpSync(FIXTURE, projectA, { recursive: true });
  cpSync(FIXTURE, projectB, { recursive: true });
  const runsA = join(temp, 'runs-a');
  const runsB = join(temp, 'runs-b');
  const baselineRun = start(projectA, runsA, 'baseline');
  const baselinePath = audit(baselineRun);
  const baselineEvidence = JSON.parse(readFileSync(baselinePath, 'utf8'));
  assert.ok(baselineEvidence.findings.some((finding) =>
    finding.rule.id === 'js-route-security-evidence-incomplete'
      && finding.state === 'unknown'
      && finding.evidence.reasons.framework_hinted_no_eligible_module === 1));

  const crossProjectRun = start(projectB, runsB, 'cross-project');
  let output = join(crossProjectRun, 'cross.json');
  let result = run(['retest', crossProjectRun, '--name', 'cross', '--baseline', baselinePath, '--fail-on', 'never']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /baseline subject does not match/);
  assert.equal(existsSync(output), false, 'cross-project rejection must commit no report');

  const scope = JSON.parse(readFileSync(join(crossProjectRun, 'security-scope.yml'), 'utf8'));
  scope.subject.id = JSON.parse(readFileSync(baselinePath, 'utf8')).subject.id;
  writeFileSync(join(crossProjectRun, 'security-scope.yml'), `${JSON.stringify(scope, null, 2)}\n`);
  result = run(['retest', crossProjectRun, '--name', 'forged-scope', '--baseline', baselinePath, '--fail-on', 'never']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /scope subject does not match the current project identity/);
  assert.equal(existsSync(join(crossProjectRun, 'forged-scope.json')), false);

  const sameProjectRun = start(projectA, runsA, 'tamper');
  const originalBytes = readFileSync(baselinePath);
  const baseline = JSON.parse(originalBytes.toString('utf8'));
  baseline.findings[0].summary = 'forged summary';
  writeFileSync(baselinePath, `${JSON.stringify(baseline, null, 2)}\n`);
  result = run(['retest', sameProjectRun, '--name', 'tampered', '--baseline', baselinePath, '--fail-on', 'never']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /baseline bytes do not match/);
  assert.equal(existsSync(join(sameProjectRun, 'tampered.json')), false);
  writeFileSync(baselinePath, originalBytes);

  const sidecar = join(baselineRun, 'report.sha256');
  writeFileSync(sidecar, `${'0'.repeat(64)}  report.json\n`);
  result = run(['retest', sameProjectRun, '--name', 'bad-digest', '--baseline', baselinePath, '--fail-on', 'never']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /baseline bytes do not match/);
  writeFileSync(sidecar, `${sha256(originalBytes)}  report.json\n`);

  const forgedTool = JSON.parse(originalBytes.toString('utf8'));
  forgedTool.tool.name = 'Forged Security Skill';
  writeForgedBaseline(baselinePath, forgedTool);
  result = run(['retest', sameProjectRun, '--name', 'forged-tool', '--baseline', baselinePath, '--fail-on', 'never']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /report.tool is invalid/);
  assert.equal(existsSync(join(sameProjectRun, 'forged-tool.json')), false);

  const forgedRuleset = JSON.parse(originalBytes.toString('utf8'));
  forgedRuleset.ruleset.digest = 'f'.repeat(64);
  writeForgedBaseline(baselinePath, forgedRuleset);
  result = run(['retest', sameProjectRun, '--name', 'forged-ruleset', '--baseline', baselinePath, '--fail-on', 'never']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /report ruleset digest is invalid/);

  const duplicate = JSON.parse(originalBytes.toString('utf8'));
  duplicate.findings.push(structuredClone(duplicate.findings[0]));
  duplicate.summary.total += 1;
  duplicate.summary.byDomain[duplicate.findings[0].domain].total += 1;
  duplicate.summary.bySeverity[duplicate.findings[0].severity] += 1;
  duplicate.summary.byState[duplicate.findings[0].state] += 1;
  duplicate.summary.byBaseline[duplicate.findings[0].baseline.state] += 1;
  writeForgedBaseline(baselinePath, duplicate);
  result = run(['retest', sameProjectRun, '--name', 'duplicate-fingerprint', '--baseline', baselinePath, '--fail-on', 'never']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /duplicate finding/);
  writeFileSync(baselinePath, originalBytes);
  writeFileSync(sidecar, `${sha256(originalBytes)}  report.json\n`);

  const ephemeralDir = join(temp, 'ephemeral');
  result = run(['audit', projectA, '--out', ephemeralDir, '--name', 'ephemeral', '--fail-on', 'never']);
  assert.equal(result.status, 3, result.stderr);
  result = run(['retest', sameProjectRun, '--name', 'ephemeral-retest', '--baseline', join(ephemeralDir, 'ephemeral.json'), '--fail-on', 'never']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /baseline subject is not persisted/);

  const baseReport = JSON.parse(originalBytes.toString('utf8'));
  const current = structuredClone(baseReport.findings);
  const ruleset = sourceRuleset();
  const completed = sourceCoverage([]);
  const unavailable = sourceCoverage([], {
    'production-source-map-enabled': { status: 'unavailable', reasonCode: 'adapter_unavailable' },
  });
  let compared = compareFindingsV2(
    current.filter((finding) => finding.rule.id !== 'production-source-map-enabled'), unavailable, baseReport, ruleset,
  );
  assert.equal(compared.find((finding) => finding.rule.id === 'production-source-map-enabled').baseline.state, 'unretested');

  const removed = completed.filter((entry) => entry.ruleId !== 'production-source-map-enabled');
  compared = compareFindingsV2(current.filter((finding) => finding.rule.id !== 'production-source-map-enabled'), removed, baseReport, ruleset);
  assert.equal(compared.find((finding) => finding.rule.id === 'production-source-map-enabled').baseline.reasonCode, 'rule_not_run');

  const revised = completed.map((entry) => entry.ruleId === 'production-source-map-enabled'
    ? { ...entry, ruleRevision: '2' } : entry);
  compared = compareFindingsV2(current.filter((finding) => finding.rule.id !== 'production-source-map-enabled'), revised, baseReport, ruleset);
  assert.equal(compared.find((finding) => finding.rule.id === 'production-source-map-enabled').baseline.state, 'not_comparable');
  assert.equal(compared.find((finding) => finding.rule.id === 'production-source-map-enabled').baseline.reasonCode, 'rule_revision_changed');
  assert.equal(ruleset.fingerprintVersion, 2);

  const adapterChanged = structuredClone(baseReport);
  adapterChanged.ruleset.adapters[0].version = '0.9.0';
  compared = compareFindingsV2(current, completed, adapterChanged, ruleset);
  assert.ok(compared.every((finding) => finding.baseline.state === 'not_comparable'));
  assert.ok(compared.every((finding) => finding.baseline.reasonCode === 'adapter_version_changed'));

  const added = structuredClone(current[0]);
  added.rule = { id: 'new-compatible-rule', revision: '1' };
  added.fingerprint = 'a'.repeat(64);
  added.id = 'new-compatible-rule-aaaaaaaaaaaa';
  const addedCoverage = [...completed, {
    id: 'source-new-compatible-rule', adapterId: 'builtin-source', ruleId: 'new-compatible-rule',
    ruleRevision: '1', status: 'completed',
    counts: { discovered: 1, eligible: 1, scanned: 1, excluded: 0, skipped: 0, truncated: 0, errors: 0 },
    reasons: [],
  }];
  compared = compareFindingsV2([...current, added], addedCoverage, baseReport, ruleset);
  assert.equal(compared.find((finding) => finding.rule.id === 'new-compatible-rule').baseline.state, 'new');
  assert.ok(compared.filter((finding) => finding.rule.id !== 'new-compatible-rule')
    .every((finding) => ['unchanged', 'fixed'].includes(finding.baseline.state)),
  'adding stable rule IDs under the same adapter version must preserve unchanged rule comparability');

  const legacy = {
    schemaVersion: 1, tool: { name: 'Web App Security Skill', version: '0.3.0' },
    generatedAt: '1970-01-01T00:00:00.000Z', mode: 'audit', scope: { projectRoot: '/private/old' },
    baseline: null, summary: {}, findings: [], limitations: [],
  };
  const legacyPath = join(temp, 'legacy.json');
  const legacyBytes = `${JSON.stringify(legacy, null, 2)}\n`;
  writeFileSync(legacyPath, legacyBytes);
  const migratedOut = join(temp, 'migrated');
  const scopePath = join(baselineRun, 'security-scope.yml');
  result = run([
    'migrate-report', legacyPath, '--scope', scopePath,
    '--acknowledge-subject', baseReport.subject.id, '--out', migratedOut,
  ]);
  assert.equal(result.status, 0, result.stderr);
  const migrated = JSON.parse(readFileSync(join(migratedOut, 'migrated-report.json'), 'utf8'));
  assert.equal(migrated.subject.binding, 'migrated');
  assert.equal(migrated.baseline.compatibility, 'not_comparable');
  assert.equal(migrated.tool.version, readFileSync(join(ROOT, 'VERSION'), 'utf8').trim());
  assert.deepEqual(migrated.migration.sourceTool, legacy.tool);
  assert.equal(migrated.migration.sourceDigest, sha256(legacyBytes));
  assert.equal(readFileSync(legacyPath, 'utf8'), legacyBytes);

  const clone = join(temp, 'clone');
  cpSync(FIXTURE, clone, { recursive: true });
  result = run(['rebind', clone, '--scope', scopePath, '--acknowledge-subject', baseReport.subject.id]);
  assert.equal(result.status, 0, result.stderr);
  const rebound = JSON.parse(readFileSync(join(clone, '.webapp-security', 'project.json'), 'utf8'));
  assert.equal(rebound.subjectId, baseReport.subject.id);
  assert.equal(rebound.lineage.type, 'explicit_rebind');
  result = run(['rebind', clone, '--scope', scopePath, '--acknowledge-subject', baseReport.subject.id]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /refusing to replace/);

  console.log('baseline identity ok: cross-project, tamper, rule lifecycle, migration and rebind fail closed');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
