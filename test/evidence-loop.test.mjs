#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateRuntimeReportV3 } from '../scripts/lib/evidence-v3.mjs';
import { SOURCE_RULES } from '../scripts/lib/source-rules.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(ROOT, 'scripts', 'webapp-security.mjs');
const DENY_NETWORK = join(ROOT, 'test', 'helpers', 'deny-network.cjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-evidence-v2-'));
const project = join(temp, 'project');
const runs = join(temp, 'runs');
const originalFixture = join(ROOT, 'test', 'fixtures', 'audit-app');

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, NODE_OPTIONS: `--require=${DENY_NETWORK}`, SOURCE_DATE_EPOCH: '0' },
  });
}

function start(runId) {
  const result = run(['start', project, '--out', runs, '--run-id', runId]);
  assert.equal(result.status, 0, result.stderr);
  return join(runs, runId);
}

function report(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

try {
  cpSync(originalFixture, project, { recursive: true });
  const originalPackage = readFileSync(join(project, 'package.json'), 'utf8');
  const originalConfig = readFileSync(join(project, 'next.config.mjs'), 'utf8');

  const baselineDir = start('baseline');
  let result = run(['audit', baselineDir, '--name', 'baseline', '--fail-on', 'high']);
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stdout, /network:\s+none/);
  for (const extension of ['json', 'md', 'html', 'sarif', 'junit.xml', 'sha256']) {
    const path = join(baselineDir, `baseline.${extension}`);
    assert.ok(existsSync(path), path);
    assert.equal(statSync(path).mode & 0o077, 0, `${path} must not be group/world readable`);
  }
  const baselinePath = join(baselineDir, 'baseline.json');
  const baseline = report(baselinePath);
  assert.deepEqual(validateRuntimeReportV3(baseline), []);
  assert.equal(baseline.schemaVersion, 3);
  assert.equal(baseline.generatedAt, '1970-01-01T00:00:00.000Z');
  assert.equal(baseline.subject.binding, 'persisted');
  assert.equal(JSON.stringify(baseline).includes(temp), false, 'v2 report must not contain local absolute paths');
  assert.equal(baseline.summary.byBaseline.new, 5);
  assert.equal(baseline.summary.byState.confirmed, 1);
  assert.equal(baseline.summary.byState.suspected, 3);
  assert.equal(baseline.summary.byState.unknown, 1);
  assert.equal(baseline.coverage.length, SOURCE_RULES.length);
  assert.equal(baseline.coverage.find((entry) => entry.ruleId === 'tracked-sensitive-env-file').status,
    'not_applicable');
  assert.ok(baseline.coverage.filter((entry) => ![
    'tracked-sensitive-env-file', 'js-route-security-evidence-incomplete',
  ].includes(entry.ruleId))
    .every((entry) => entry.status === 'completed'));
  assert.equal(baseline.coverage.find((entry) =>
    entry.ruleId === 'js-route-security-evidence-incomplete').status, 'unavailable');
  assert.ok(baseline.findings.every((finding) => finding.baseline.coverageRef));
  assert.equal(baseline.policy.thresholds.find((entry) => entry.domain === 'security_exposure').failOn, 'high');
  assert.equal(baseline.policy.thresholds.find((entry) => entry.domain === 'supply_chain').failOn, 'high');
  const sourceMapFinding = baseline.findings.find((finding) => finding.rule.id === 'production-source-map-enabled');
  const inspectorFinding = baseline.findings.find((finding) => finding.rule.id === 'node-inspector-public-bind');
  const lockFinding = baseline.findings.find((finding) => finding.rule.id === 'dependency-lockfile-missing');
  assert.equal(sourceMapFinding.state, 'suspected');
  assert.equal(inspectorFinding.state, 'suspected');
  assert.equal(lockFinding.state, 'confirmed');
  const sarifRules = JSON.parse(readFileSync(join(baselineDir, 'baseline.sarif'), 'utf8'))
    .runs[0].tool.driver.rules;
  assert.equal(sarifRules.find((rule) =>
    rule.id === 'js-route-security-evidence-incomplete').helpUri,
  'https://github.com/parousia8888/web-app-security-skill/blob/main/KNOWN_LIMITATIONS.md');
  assert.ok(sarifRules.filter((rule) => rule.id !== 'js-route-security-evidence-incomplete')
    .every((rule) => rule.helpUri === 'https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json'));

  const patch = readFileSync(join(baselineDir, 'proposed.patch'), 'utf8');
  assert.match(patch, /Proposed changes only/);
  assert.match(patch, /productionBrowserSourceMaps: false/);
  assert.equal(readFileSync(join(project, 'package.json'), 'utf8'), originalPackage);
  assert.equal(readFileSync(join(project, 'next.config.mjs'), 'utf8'), originalConfig);
  result = run(['audit', baselineDir, '--name', 'baseline', '--fail-on', 'never']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /refusing to overwrite existing evidence/);
  assert.equal(report(baselinePath).findings.length, 5);

  result = run(['explain', sourceMapFinding.id, '--report', baselinePath]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /security_exposure \/ medium \/ suspected/);
  assert.match(result.stdout, /Professional term:/);
  assert.match(result.stdout, /What the evidence proves:/);
  result = run(['explain', 'missing-finding', '--report', baselinePath]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /finding not found/);

  const unchangedDir = start('unchanged');
  result = run(['retest', unchangedDir, '--name', 'unchanged', '--baseline', baselinePath, '--fail-on', 'high']);
  assert.equal(result.status, 1, result.stderr);
  const unchanged = report(join(unchangedDir, 'unchanged.json'));
  assert.equal(unchanged.summary.byBaseline.unchanged, 4);
  assert.equal(unchanged.summary.byBaseline.unretested, 1);
  assert.ok(unchanged.findings.filter((finding) =>
    finding.rule.id !== 'js-route-security-evidence-incomplete')
    .every((finding) => finding.baseline.state === 'unchanged'));
  assert.equal(unchanged.findings.find((finding) =>
    finding.rule.id === 'js-route-security-evidence-incomplete').baseline.reasonCode,
  'current_check_incomplete');

  writeFileSync(join(project, 'package-lock.json'), '{"lockfileVersion":3}\n');
  writeFileSync(join(project, 'next.config.mjs'), 'export default { productionBrowserSourceMaps: false };\n');
  const fixedPackage = JSON.parse(readFileSync(join(project, 'package.json'), 'utf8'));
  fixedPackage.scripts.debug = 'node --inspect=127.0.0.1:9229 server.js';
  writeFileSync(join(project, 'package.json'), `${JSON.stringify(fixedPackage, null, 2)}\n`);
  rmSync(join(project, '.env.production'));

  const fixedDir = start('fixed');
  result = run(['retest', fixedDir, '--name', 'fixed', '--baseline', baselinePath, '--fail-on', 'low']);
  assert.equal(result.status, 3, result.stderr);
  const fixedPath = join(fixedDir, 'fixed.json');
  const fixed = report(fixedPath);
  assert.equal(fixed.mode, 'retest');
  assert.equal(fixed.summary.byBaseline.fixed, 4);
  assert.equal(fixed.summary.byBaseline.unretested, 1);
  assert.ok(fixed.findings.filter((finding) =>
    finding.rule.id !== 'js-route-security-evidence-incomplete')
    .every((finding) => finding.baseline.state === 'fixed'));
  assert.ok(fixed.findings.filter((finding) =>
    finding.rule.id !== 'js-route-security-evidence-incomplete')
    .every((finding) => finding.baseline.reasonCode === 'condition_absent_after_completed_check'));
  const incompleteRouteFinding = fixed.findings.find((finding) =>
    finding.rule.id === 'js-route-security-evidence-incomplete');
  assert.equal(incompleteRouteFinding.state, 'unknown');
  assert.equal(incompleteRouteFinding.baseline.state, 'unretested');
  assert.equal(incompleteRouteFinding.baseline.reasonCode, 'current_check_incomplete');
  const fixedSarifResults = JSON.parse(readFileSync(join(fixedDir, 'fixed.sarif'), 'utf8')).runs[0].results;
  assert.deepEqual(fixedSarifResults.map((entry) => entry.ruleId), ['js-route-security-evidence-incomplete']);
  assert.match(readFileSync(join(fixedDir, 'fixed.junit.xml'), 'utf8'),
    /tests="5" failures="0" skipped="5"/);

  writeFileSync(join(project, 'next.config.mjs'), originalConfig);
  const regressedDir = start('regressed');
  result = run(['retest', regressedDir, '--name', 'regressed', '--baseline', fixedPath, '--fail-on', 'medium']);
  assert.equal(result.status, 1, result.stderr);
  const regressed = report(join(regressedDir, 'regressed.json'));
  const regression = regressed.findings.find((finding) => finding.rule.id === 'production-source-map-enabled');
  assert.equal(regression.baseline.state, 'regressed');
  assert.equal(regression.state, 'suspected');

  rmSync(join(project, 'package-lock.json'));
  const confirmedDir = start('confirmed-regression');
  result = run(['retest', confirmedDir, '--name', 'confirmed', '--baseline', fixedPath, '--fail-on', 'low']);
  assert.equal(result.status, 1);
  const confirmed = report(join(confirmedDir, 'confirmed.json'));
  assert.equal(confirmed.findings.find((finding) => finding.rule.id === 'dependency-lockfile-missing').baseline.state, 'regressed');

  const hostile = join(temp, '<img src=x onerror=alert(1)>');
  mkdirSync(hostile);
  cpSync(originalFixture, join(hostile, 'app'), { recursive: true });
  const hostileDir = join(temp, 'hostile-report');
  result = run(['audit', hostile, '--out', hostileDir, '--name', 'hostile', '--fail-on', 'never']);
  assert.equal(result.status, 3, result.stderr);
  const html = readFileSync(join(hostileDir, 'hostile.html'), 'utf8');
  assert.equal(html.includes('<img src=x onerror=alert(1)>'), false);
  assert.equal(readFileSync(join(hostileDir, 'hostile.json'), 'utf8').includes(hostile), false);

  result = run(['retest', project, '--out', join(temp, 'no-baseline')]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /retest requires --baseline/);

  const precisionProject = join(temp, 'precision-project');
  mkdirSync(join(precisionProject, 'apps', 'web'), { recursive: true });
  mkdirSync(join(precisionProject, 'backend'), { recursive: true });
  writeFileSync(join(precisionProject, 'package.json'), JSON.stringify({ private: true, packageManager: 'yarn@4.12.0', workspaces: ['apps/*'] }));
  writeFileSync(join(precisionProject, 'yarn.lock'), '# workspace lock\n');
  writeFileSync(join(precisionProject, 'apps', 'web', 'package.json'), JSON.stringify({ private: true }));
  writeFileSync(join(precisionProject, 'backend', 'requirements.txt'), 'django==5.2.5\n');
  writeFileSync(join(precisionProject, '.env.example'), 'PUBLIC_PLACEHOLDER=change-me\n');
  writeFileSync(join(precisionProject, '.env.production'), 'DO_NOT_READ_PRECISION_SECRET=fixture-only\n');
  const precisionDir = join(temp, 'precision-report');
  result = run(['audit', precisionProject, '--out', precisionDir, '--name', 'precision', '--fail-on', 'never']);
  assert.equal(result.status, 0, result.stderr);
  const precision = report(join(precisionDir, 'precision.json'));
  assert.equal(precision.subject.binding, 'ephemeral');
  assert.ok(precision.policy.thresholds.every((entry) => entry.failOn === 'never'));
  assert.equal(precision.findings.some((finding) => finding.rule.id === 'dependency-lockfile-missing'), false);
  const environmentFindings = precision.findings.filter((finding) => finding.rule.id === 'sensitive-env-file-present');
  assert.deepEqual(environmentFindings.map((finding) => finding.location.path), ['.env.production']);
  assert.equal(JSON.stringify(precision).includes('DO_NOT_READ_PRECISION_SECRET'), false);

  console.log('✓ evidence v2 loop: private reports, persisted identity, honest fixed/regressed and ephemeral boundary');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
