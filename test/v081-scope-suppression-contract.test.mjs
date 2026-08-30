#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  appendFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditSource } from '../scripts/lib/source-audit.mjs';
import { DEFAULT_SOURCE_TRAVERSAL_LIMITS } from '../scripts/lib/project-identity.mjs';
import { createGitDiffScope, selectDiffFindings } from '../scripts/lib/git-diff-scope.mjs';
import { applySuppressions, readSuppressionPolicy } from '../scripts/lib/suppressions.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(ROOT, 'scripts', 'webapp-security.mjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-v081-contract-'));
const project = join(temp, 'project');

function run(args, options = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, SOURCE_DATE_EPOCH: '1788048000', ...options.env },
  });
}

function git(args) {
  const result = spawnSync('git', args, { cwd: project, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout.trim();
}

try {
  mkdirSync(join(project, 'src', 'private'), { recursive: true });
  mkdirSync(join(project, 'outside'), { recursive: true });
  writeFileSync(join(project, 'package.json'), '{"name":"scope-fixture","private":true}\n');
  writeFileSync(join(project, 'src', 'included.js'), 'node.innerHTML = includedValue;\n');
  writeFileSync(join(project, 'src', 'private', 'excluded.js'), 'node.innerHTML = excludedValue;\n');
  writeFileSync(join(project, 'outside', 'excluded.js'), 'node.innerHTML = outsideValue;\n');
  writeFileSync(join(project, 'src', 'routes.js'), `
import express from 'express';
const app = express();
app.get('/included', (_req, res) => res.send('ok'));
`);
  writeFileSync(join(project, 'src', 'private', 'routes.js'), `
import express from 'express';
const app = express();
app.delete('/excluded/:id', (_req, res) => res.send('no'));
`);
  writeFileSync(join(project, 'src', '.env.production'), 'INCLUDED_SCOPE_FIXTURE=true\n');
  writeFileSync(join(project, 'src', 'private', '.env.production'), 'EXCLUDED_SCOPE_FIXTURE=true\n');
  git(['init', '--quiet']);
  git(['config', 'user.email', 'scope-fixture@example.invalid']);
  git(['config', 'user.name', 'Scope Fixture']);
  git(['add', '.']);
  git(['commit', '--quiet', '-m', 'scope baseline']);

  const scoped = auditSource(project, DEFAULT_SOURCE_TRAVERSAL_LIMITS, {
    scopeBoundary: {
      sourceRoots: ['src'],
      excludedDirectories: ['private'],
    },
    gitRoot: project,
  });
  const findingPaths = scoped.findings.map((finding) => finding.location?.path).filter(Boolean);
  assert.ok(findingPaths.includes('src/included.js'));
  assert.equal(findingPaths.includes('src/private/excluded.js'), false,
    'an excluded directory is a file-read boundary');
  assert.equal(findingPaths.includes('outside/excluded.js'), false,
    'a custom source root is a file-read boundary');
  assert.ok(Object.values(scoped.coverage).some((entry) => entry.reasons
    .some((reason) => reason.code === 'scope_excluded_directory')));
  assert.equal(scoped.findings.some((finding) => finding.location?.path
    === 'src/private/.env.production'), false,
  'tracked sensitive-file evidence is post-validated by the canonical scope');
  assert.ok(scoped.findings.some((finding) => finding.location?.path === 'src/.env.production'));
  assert.equal(scoped.routeAnalysis.routes.some((route) => route.location?.path
    === 'src/private/routes.js'), false,
  'route analysis receives only admitted source files');
  assert.ok(scoped.routeAnalysis.routes.some((route) => route.location?.path === 'src/routes.js'));

  appendFileSync(join(project, 'src', 'included.js'), 'node.innerHTML = changedIncluded;\n');
  appendFileSync(join(project, 'src', 'private', 'excluded.js'), 'node.innerHTML = changedExcluded;\n');
  const diffScope = createGitDiffScope(project, { mode: 'since', ref: 'HEAD' });
  try {
    const diffAudit = auditSource(diffScope.auditRoot, DEFAULT_SOURCE_TRAVERSAL_LIMITS, {
      scopeBoundary: { sourceRoots: ['src'], excludedDirectories: ['private'] },
      gitRoot: project,
    });
    const selected = selectDiffFindings(diffAudit, diffScope);
    assert.ok(selected.some((finding) => finding.location?.path === 'src/included.js'));
    assert.equal(selected.some((finding) => finding.location?.path === 'src/private/excluded.js'), false,
      'diff snapshots preserve the same file-read boundary');
  } finally {
    diffScope.cleanup();
  }

  const suppressionProject = join(temp, 'suppression-project');
  mkdirSync(join(suppressionProject, 'src'), { recursive: true });
  writeFileSync(join(suppressionProject, 'package.json'),
    '{"name":"suppression-fixture","private":true}\n');
  writeFileSync(join(suppressionProject, 'package-lock.json'),
    '{"name":"suppression-fixture","lockfileVersion":3,"packages":{}}\n');
  writeFileSync(join(suppressionProject, 'src', 'included.js'),
    'node.innerHTML = includedValue;\n');
  const start = run(['start', suppressionProject, '--run-id', 'suppression-contract']);
  assert.equal(start.status, 0, start.stderr || start.stdout);
  const runDirectory = join(suppressionProject, '.webapp-security', 'runs', 'suppression-contract');
  const firstOutput = join(temp, 'first-output');
  const first = run(['audit', runDirectory, '--out', firstOutput, '--fail-on', 'never']);
  assert.equal(first.status, 0, first.stderr || first.stdout);
  const firstReport = JSON.parse(readFileSync(join(firstOutput, 'report.json'), 'utf8'));
  const candidate = firstReport.findings.find((finding) => finding.state === 'suspected'
    && finding.location?.path === 'src/included.js');
  assert.ok(candidate, 'fixture must produce one suppressible source lead');
  const suppressionPath = join(suppressionProject, 'webapp-security.suppressions.json');
  writeFileSync(suppressionPath, `${JSON.stringify({
    schemaVersion: 1,
    subjectId: firstReport.subject.id,
    entries: [{
      id: 'suppression-fixture-included-html',
      adapterId: candidate.adapter.id,
      ruleId: candidate.rule.id,
      path: candidate.location.path,
      fingerprint: candidate.fingerprint,
      reason: 'Exact fixture disposition for the v0.8.1 gate contract.',
      owner: '@fixture-owner',
      createdAt: '2026-08-29T00:00:00.000Z',
      expiresAt: '2026-09-30T00:00:00.000Z',
    }],
  }, null, 2)}\n`);
  const suppressedOutput = join(temp, 'suppressed-output');
  const suppressed = run(['audit', runDirectory, '--out', suppressedOutput, '--fail-on', 'low']);
  const report = JSON.parse(readFileSync(join(suppressedOutput, 'report.json'), 'utf8'));
  assert.equal(suppressed.status, 0,
    `${suppressed.stderr || suppressed.stdout}\n${JSON.stringify(report.scope.suppression)}`);
  const retained = report.findings.find((finding) => finding.fingerprint === candidate.fingerprint);
  assert.equal(retained.disposition.status, 'suppressed');
  assert.equal(report.summary.suppressedTotal, 1);
  assert.equal(report.summary.activeTotal, report.summary.total - 1);
  assert.match(readFileSync(join(suppressedOutput, 'report.md'), 'utf8'), /SUPPRESSED/);
  assert.match(readFileSync(join(suppressedOutput, 'report.html'), 'utf8'), /SUPPRESSED/);
  const suppressedSarif = JSON.parse(readFileSync(join(suppressedOutput, 'report.sarif'), 'utf8'));
  assert.equal(suppressedSarif.runs[0].results.find((result) =>
    result.fingerprints.webAppSecurityFingerprint === candidate.fingerprint).suppressions[0].status,
  'accepted');
  assert.match(readFileSync(join(suppressedOutput, 'report.junit.xml'), 'utf8'),
    /skipped message="suppressed:/);

  const exactPolicy = readSuppressionPolicy(
    suppressionProject, firstReport.subject.id, new Date('2026-08-30T00:00:00.000Z'),
    { gateEnabled: true },
  );
  assert.equal(exactPolicy.status, 'completed');
  for (const drift of [
    { location: { ...candidate.location, path: 'src/renamed.js' } },
    { rule: { ...candidate.rule, id: 'different-rule' } },
    { fingerprint: 'f'.repeat(64) },
  ]) {
    const drifted = applySuppressions([{ ...candidate, ...drift }], exactPolicy);
    assert.equal(drifted.findings[0].disposition.status, 'active');
    assert.ok(drifted.diagnostics.some((entry) => entry.code === 'suppression_target_not_found'));
  }
  for (const notSuppressible of [
    { state: 'unknown' },
    { domain: 'evidence_integrity' },
  ]) {
    const applied = applySuppressions([{ ...candidate, ...notSuppressible }], exactPolicy);
    assert.equal(applied.findings[0].disposition.status, 'active');
    assert.ok(applied.diagnostics.some((entry) =>
      entry.code === 'suppression_target_not_suppressible'));
  }

  const baselineSuppressedOutput = join(temp, 'baseline-suppressed-output');
  const baselineSuppressed = run([
    'retest', runDirectory, '--baseline', join(firstOutput, 'report.json'),
    '--out', baselineSuppressedOutput, '--fail-on', 'low',
  ]);
  assert.equal(baselineSuppressed.status, 0, baselineSuppressed.stderr || baselineSuppressed.stdout);
  const baselineSuppressedReport = JSON.parse(
    readFileSync(join(baselineSuppressedOutput, 'report.json'), 'utf8'),
  );
  const baselineRetained = baselineSuppressedReport.findings.find((finding) =>
    finding.fingerprint === candidate.fingerprint);
  assert.equal(baselineRetained.baseline.state, 'unchanged');
  assert.equal(baselineRetained.disposition.status, 'suppressed');

  const localPolicy = JSON.parse(readFileSync(suppressionPath, 'utf8'));
  delete localPolicy.entries[0].owner;
  delete localPolicy.entries[0].expiresAt;
  writeFileSync(suppressionPath, `${JSON.stringify(localPolicy, null, 2)}\n`);
  const localOutput = join(temp, 'local-output');
  const local = run(['audit', runDirectory, '--out', localOutput, '--fail-on', 'never']);
  assert.equal(local.status, 0, local.stderr || local.stdout);
  const localReport = JSON.parse(readFileSync(join(localOutput, 'report.json'), 'utf8'));
  assert.equal(localReport.findings.find((finding) => finding.fingerprint === candidate.fingerprint)
    .disposition.status, 'suppressed');

  const gatedOutput = join(temp, 'gated-output');
  const gated = run(['audit', runDirectory, '--out', gatedOutput, '--fail-on', 'low']);
  assert.equal(gated.status, 1, gated.stderr || gated.stdout);
  const gatedReport = JSON.parse(readFileSync(join(gatedOutput, 'report.json'), 'utf8'));
  assert.equal(gatedReport.findings.find((finding) => finding.fingerprint === candidate.fingerprint)
    .disposition.status, 'active');
  assert.ok(gatedReport.scope.suppression.diagnostics.some((entry) =>
    entry.code === 'suppression_governance_incomplete'));

  const externalPolicy = structuredClone(localPolicy);
  externalPolicy.entries[0].adapterId = 'opengrep';
  writeFileSync(suppressionPath, `${JSON.stringify(externalPolicy, null, 2)}\n`);
  const externalEvidenceOnly = readSuppressionPolicy(
    suppressionProject, firstReport.subject.id, new Date('2026-08-30T00:00:00.000Z'),
    { gateEnabled: false },
  );
  assert.equal(externalEvidenceOnly.entries[0].eligibility, 'governance_incomplete',
    'external suppressions always require owner and expiry');

  writeFileSync(suppressionPath, '{bad json\n');
  const malformedOutput = join(temp, 'malformed-output');
  const malformed = run(['audit', runDirectory, '--out', malformedOutput, '--fail-on', 'never']);
  assert.equal(malformed.status, 3, malformed.stderr || malformed.stdout);
  const malformedReport = JSON.parse(readFileSync(join(malformedOutput, 'report.json'), 'utf8'));
  assert.equal(malformedReport.scope.suppression.status, 'unavailable');
  assert.ok(malformedReport.findings.every((finding) => finding.disposition.status === 'active'));

  rmSync(suppressionPath);
  const suppressionTarget = join(temp, 'outside-suppressions.json');
  writeFileSync(suppressionTarget, `${JSON.stringify(localPolicy, null, 2)}\n`);
  symlinkSync(suppressionTarget, suppressionPath);
  const symlinkPolicy = readSuppressionPolicy(
    suppressionProject, firstReport.subject.id, new Date('2026-08-30T00:00:00.000Z'),
  );
  assert.equal(symlinkPolicy.status, 'unavailable');
  rmSync(suppressionPath);
  const escapingPolicy = readSuppressionPolicy(
    suppressionProject, firstReport.subject.id, new Date('2026-08-30T00:00:00.000Z'),
    { policyPath: '../outside-suppressions.json' },
  );
  assert.equal(escapingPolicy.status, 'unavailable');
  assert.equal(escapingPolicy.diagnostics[0].code, 'suppression_file_invalid');

  const activeBaselineOutput = join(temp, 'active-baseline-output');
  const activeBaseline = run([
    'retest', runDirectory, '--baseline', join(firstOutput, 'report.json'),
    '--out', activeBaselineOutput, '--fail-on', 'never',
  ]);
  assert.equal(activeBaseline.status, 0, activeBaseline.stderr || activeBaseline.stdout);
  const activeBaselineReport = JSON.parse(
    readFileSync(join(activeBaselineOutput, 'report.json'), 'utf8'),
  );
  const activeRetained = activeBaselineReport.findings.find((finding) =>
    finding.fingerprint === candidate.fingerprint);
  assert.equal(activeRetained.baseline.state, 'unchanged');
  assert.equal(activeRetained.disposition.status, 'active');

  writeFileSync(suppressionPath, `${JSON.stringify({
    ...localPolicy,
    entries: [{ ...localPolicy.entries[0], owner: '@fixture-owner',
      expiresAt: '2026-08-29T12:00:00.000Z' }],
  }, null, 2)}\n`);
  const expired = JSON.parse(readFileSync(suppressionPath, 'utf8'));
  const expiredOutput = join(temp, 'expired-output');
  const expiredRun = run(['audit', runDirectory, '--out', expiredOutput, '--fail-on', 'low']);
  assert.equal(expiredRun.status, 1, expiredRun.stderr || expiredRun.stdout);
  const expiredReport = JSON.parse(readFileSync(join(expiredOutput, 'report.json'), 'utf8'));
  assert.equal(expiredReport.findings.find((finding) => finding.fingerprint === candidate.fingerprint)
    .disposition.status, 'active');
} finally {
  rmSync(temp, { recursive: true, force: true });
}

console.log('v0.8.1 scope/suppression contract ok: scope limits reads and exact dispositions remain visible');
