#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readStableRuleCorpus, validateCorpusObservations } from '../scripts/lib/rule-corpus.mjs';
import { recordTestOutcome } from './helpers/test-outcome.mjs';

if (process.env.WEBAPP_SECURITY_REAL_ADAPTER_TEST !== 'true') {
  recordTestOutcome({
    status: 'skipped',
    reasonCode: 'opt_in_prerequisite_not_requested',
    surfaces: [{
      id: 'real-external-adapters', status: 'skipped',
      reasonCode: 'pinned_adapters_not_requested',
    }],
  });
  console.log('real adapters skipped: set WEBAPP_SECURITY_REAL_ADAPTER_TEST=true with pinned binaries');
  process.exit(0);
}

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(ROOT, 'scripts', 'webapp-security.mjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-real-adapters-'));
const plantedToken = 'ghp_123456789012345678901234567890123456';

function command(program, args, options = {}) {
  const result = spawnSync(program, args, { encoding: 'utf8', timeout: 180000, ...options });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result;
}

function project(name, vulnerable) {
  const root = join(temp, name);
  mkdirSync(root);
  writeFileSync(join(root, 'package.json'), `${JSON.stringify({ name, version: '1.0.0' })}\n`);
  const dependency = vulnerable
    ? { name: 'lodash', version: '4.17.20' }
    : { name: 'is-number', version: '7.0.0' };
  const packages = {
    '': { name, version: '1.0.0', dependencies: { [dependency.name]: dependency.version } },
    [`node_modules/${dependency.name}`]: { version: dependency.version },
  };
  writeFileSync(join(root, 'package-lock.json'), `${JSON.stringify({
    name, version: '1.0.0', lockfileVersion: 3, packages,
  }, null, 2)}\n`);
  writeFileSync(join(root, 'config.txt'), vulnerable ? `github_token = ${plantedToken}\n` : 'fixture = clean\n');
  for (const extension of ['js', 'py']) {
    writeFileSync(join(root, `source.${extension}`), readFileSync(join(
      ROOT, 'test', 'fixtures', 'opengrep-rules', `${vulnerable ? 'vulnerable' : 'safe'}.${extension}`,
    ), 'utf8'));
  }
  cpSync(join(ROOT, 'test', 'fixtures', 'checkov-rules', vulnerable ? 'vulnerable' : 'safe'), root, {
    recursive: true,
  });
  command('git', ['init', '-q'], { cwd: root });
  command('git', ['-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'add', '.'], { cwd: root });
  command('git', ['-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'], { cwd: root });
  return root;
}

try {
  for (const binary of [
    process.env.WEBAPP_SECURITY_CHECKOV_BIN,
    process.env.WEBAPP_SECURITY_GITLEAKS_BIN,
    process.env.WEBAPP_SECURITY_OPENGREP_BIN,
    process.env.WEBAPP_SECURITY_OSV_SCANNER_BIN,
  ]) {
    assert.ok(binary, 'pinned adapter binary path is required');
    chmodSync(binary, 0o755);
  }
  const vulnerable = project('vulnerable', true);
  const vulnerableOut = join(temp, 'vulnerable-report');
  let result = spawnSync(process.execPath, [
    CLI, 'audit', vulnerable, '--out', vulnerableOut, '--adapter', 'checkov', '--adapter', 'gitleaks', '--adapter', 'opengrep', '--adapter', 'osv',
    '--fail-on', 'never', '--adapter-timeout', '120',
  ], { cwd: ROOT, encoding: 'utf8', timeout: 180000, env: { ...process.env, SOURCE_DATE_EPOCH: '0' } });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const report = JSON.parse(readFileSync(join(vulnerableOut, 'report.json'), 'utf8'));
  assert.ok(report.findings.some((finding) => finding.rule.id === 'gitleaks-committed-secret'));
  assert.ok(report.findings.some((finding) => finding.rule.id === 'gitleaks-working-tree-secret'));
  assert.ok(report.findings.some((finding) => finding.rule.id === 'osv-known-vulnerability'));
  const expectedOpengrepRules = ['command', 'sql', 'ssrf', 'path', 'redirect'].flatMap((risk) => [
    `opengrep-js-request-${risk}-flow`, `opengrep-python-request-${risk}-flow`,
  ]);
  for (const ruleId of expectedOpengrepRules) {
    assert.ok(report.findings.some((finding) => finding.rule.id === ruleId), `missing ${ruleId}`);
  }
  assert.ok(report.findings.some((finding) => finding.rule.id === 'checkov-dockerfile-root-user'));
  assert.ok(report.findings.some((finding) => finding.rule.id === 'checkov-dockerfile-healthcheck-missing'));
  assert.ok(report.findings.some((finding) => finding.rule.id === 'checkov-github-actions-write-all'));
  assert.ok(report.findings.every((finding) => finding.state === 'suspected'));
  assert.ok(report.findings.some((finding) => finding.evidence.advisoryIds?.includes('GHSA-29mw-wpgm-hmr9')));
  for (const name of readdirSync(vulnerableOut)) {
    assert.equal(readFileSync(join(vulnerableOut, name), 'utf8').includes(plantedToken), false);
  }

  const clean = project('clean', false);
  const cleanOut = join(temp, 'clean-report');
  result = spawnSync(process.execPath, [
    CLI, 'audit', clean, '--out', cleanOut, '--adapter', 'checkov', '--adapter', 'gitleaks', '--adapter', 'opengrep', '--adapter', 'osv',
    '--fail-on', 'never', '--adapter-timeout', '120',
  ], { cwd: ROOT, encoding: 'utf8', timeout: 180000, env: { ...process.env, SOURCE_DATE_EPOCH: '0' } });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const cleanReport = JSON.parse(readFileSync(join(cleanOut, 'report.json'), 'utf8'));
  assert.equal(cleanReport.findings.filter((finding) => finding.state === 'confirmed').length, 0);
  assert.deepEqual(cleanReport.findings.filter((finding) => finding.adapter.id === 'opengrep')
    .map((finding) => ({
      ruleId: finding.rule.id,
      state: finding.state,
      reasonCode: finding.evidence.reasonCode || null,
    })), []);
  assert.equal(cleanReport.findings.filter((finding) => finding.adapter.id === 'checkov').length, 0);
  assert.ok(cleanReport.coverage.every((entry) => entry.status === 'completed'));

  const corpus = readStableRuleCorpus(join(ROOT, 'docs', 'stable-rule-corpus.json'));
  const externalObservations = corpus.rules.filter((rule) => rule.adapterType === 'external').map((rule) => ({
    ruleId: rule.ruleId,
    positiveState: report.findings.find((finding) => finding.rule.id === rule.ruleId)?.state,
    negativeFindingCount: cleanReport.findings.filter((finding) => finding.rule.id === rule.ruleId).length,
  }));
  assert.deepEqual(validateCorpusObservations(corpus, externalObservations, { adapterType: 'external' }), []);
  for (const rule of corpus.rules.filter((item) => item.adapterType === 'external')) {
    const mutated = externalObservations.filter((observation) => observation.ruleId !== rule.ruleId);
    assert.match(validateCorpusObservations(corpus, mutated, { adapterType: 'external' }).join('; '),
      new RegExp(`missing positive/negative observation ${rule.ruleId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
  }

  recordTestOutcome({
    surfaces: [{ id: 'real-external-adapters', status: 'passed', reasonCode: null }],
  });
  console.log('real adapters ok: 16 corpus-linked pinned adapters with 16 planted missing-observation failures');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
