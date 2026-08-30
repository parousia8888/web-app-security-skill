#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { auditSource } from '../scripts/lib/source-audit.mjs';
import { sourceCoverage } from '../scripts/lib/source-rules.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(ROOT, 'scripts', 'webapp-security.mjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-coverage-'));

function write(path, contents = '') {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
}

function supported(path) {
  write(join(path, 'package.json'), '{"private":true}\n');
  write(join(path, 'package-lock.json'), '{"lockfileVersion":3}\n');
}

function run(project, name, extra = []) {
  const out = join(temp, 'reports', name);
  const result = spawnSync(process.execPath, [
    CLI, 'audit', project, '--out', out, '--name', 'report', '--fail-on', 'never', ...extra,
  ], { encoding: 'utf8', env: { ...process.env, SOURCE_DATE_EPOCH: '0' } });
  return {
    ...result,
    out,
    report: result.status === 0 || result.status === 1 || result.status === 3
      ? JSON.parse(readFileSync(join(out, 'report.json'), 'utf8'))
      : null,
  };
}

function assertReconciled(coverage) {
  for (const entry of coverage) {
    const counts = entry.counts;
    assert.equal(counts.discovered, counts.eligible + counts.excluded, entry.ruleId);
    assert.equal(counts.eligible, counts.scanned + counts.skipped + counts.truncated + counts.errors,
      entry.ruleId);
    for (const reason of entry.reasons) {
      assert.ok(reason.samplePaths.length <= 10, reason.code);
      assert.ok(reason.samplePaths.every((path) => path.length <= 160 && !path.startsWith('/')
        && !path.split('/').includes('..') && !/[\u0000-\u001f\u007f]/.test(path)), reason.code);
    }
  }
}

try {
  const clean = join(temp, 'clean');
  supported(clean);
  const cleanAudit = auditSource(clean);
  const cleanCoverage = sourceCoverage(cleanAudit);
  assert.deepEqual(cleanAudit.findings, []);
  assert.equal(cleanCoverage.find((entry) => entry.ruleId === 'tracked-sensitive-env-file').status,
    'not_applicable');
  assert.ok(cleanCoverage.filter((entry) => ![
    'tracked-sensitive-env-file', 'js-route-security-evidence-incomplete',
  ].includes(entry.ruleId))
    .every((entry) => entry.status === 'completed'));
  assert.equal(cleanCoverage.find((entry) =>
    entry.ruleId === 'js-route-security-evidence-incomplete').status, 'not_applicable');
  assertReconciled(cleanCoverage);
  const trackedFixture = auditSource(join(ROOT, 'test', 'fixtures', 'audit-app'));
  const trackedFinding = trackedFixture.findings.find((finding) =>
    finding.ruleId === 'tracked-sensitive-env-file');
  assert.equal(trackedFinding.state, 'confirmed');
  assert.equal(trackedFinding.location.path, '.env.production');
  assert.equal(trackedFinding.evidence.contentsRead, false);
  let result = run(clean, 'clean');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.report.findings.length, 0);

  const large = join(temp, 'large-monorepo');
  supported(large);
  for (let index = 0; index < 5005; index += 1) {
    write(join(large, 'ordinary', `file-${String(index).padStart(5, '0')}.txt`), 'fixture\n');
  }
  const deepConfig = join(large, 'apps', 'a', 'b', 'c', 'd', 'e', 'f', 'next.config.mjs');
  write(deepConfig, 'export default { productionBrowserSourceMaps: true };\n');
  const firstLarge = auditSource(large);
  const secondLarge = auditSource(large);
  assert.ok(firstLarge.traversal.filesDiscovered > 5000);
  assert.equal(firstLarge.traversal.stopped, false);
  assert.ok(firstLarge.findings.some((finding) => finding.ruleId === 'production-source-map-enabled'
    && finding.location.path.endsWith('next.config.mjs')));
  assert.deepEqual(firstLarge, secondLarge, 'bounded traversal must be deterministic');
  assertReconciled(sourceCoverage(firstLarge));

  const limited = join(temp, 'limited');
  write(join(limited, '00-first.txt'), 'first\n');
  supported(limited);
  result = run(limited, 'limited', ['--max-files', '1']);
  assert.equal(result.status, 3, result.stderr);
  assert.equal(result.report.scope.traversal.effectiveLimits.maxFiles, 1);
  assert.equal(result.report.scope.traversal.stopped, true);
  assert.ok(result.report.findings.some((finding) => finding.rule.id === 'source-evidence-incomplete'
    && finding.state === 'unknown'));
  assert.ok(result.report.coverage.some((entry) => entry.reasons.some((reason) =>
    reason.code === 'file_limit_reached')));
  assert.match(readFileSync(join(result.out, 'report.md'), 'utf8'), /file_limit_reached/);
  assertReconciled(result.report.coverage);

  const depthLimited = join(temp, 'depth-limited');
  supported(depthLimited);
  write(join(depthLimited, 'a', 'b', 'next.config.mjs'), 'export default { sourcemap: true };\n');
  result = run(depthLimited, 'depth-limited', ['--max-depth', '1']);
  assert.equal(result.status, 3, result.stderr);
  assert.ok(result.report.coverage.some((entry) => entry.reasons.some((reason) =>
    reason.code === 'depth_limit_reached')));

  const malformed = join(temp, 'malformed');
  write(join(malformed, 'package.json'), '{bad json');
  write(join(malformed, 'package-lock.json'), '{}\n');
  result = run(malformed, 'malformed');
  assert.equal(result.status, 3, result.stderr);
  assert.ok(result.report.coverage.find((entry) => entry.ruleId === 'node-inspector-public-bind')
    .reasons.some((reason) => reason.code === 'manifest_parse_error'));

  const pnpmWorkspace = join(temp, 'pnpm-workspace');
  write(join(pnpmWorkspace, 'package.json'), '{"private":true}\n');
  write(join(pnpmWorkspace, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n');
  write(join(pnpmWorkspace, 'pnpm-workspace.yaml'), "packages:\n  - 'apps/*'\n  - '!apps/legacy'\n");
  write(join(pnpmWorkspace, 'apps', 'api', 'package.json'), '{"private":true}\n');
  write(join(pnpmWorkspace, 'apps', 'legacy', 'package.json'), '{"private":true}\n');
  const pnpmAudit = auditSource(pnpmWorkspace);
  assert.deepEqual(pnpmAudit.findings.filter((finding) =>
    finding.ruleId === 'dependency-lockfile-missing').map((finding) => finding.location.path),
  ['apps/legacy/package.json']);

  const malformedPnpm = join(temp, 'malformed-pnpm-workspace');
  write(join(malformedPnpm, 'package.json'), '{"private":true}\n');
  write(join(malformedPnpm, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n');
  write(join(malformedPnpm, 'pnpm-workspace.yaml'), 'packages: [apps/*\n');
  write(join(malformedPnpm, 'apps', 'api', 'package.json'), '{"private":true}\n');
  const malformedPnpmAudit = auditSource(malformedPnpm);
  assert.equal(malformedPnpmAudit.findings.some((finding) =>
    finding.ruleId === 'dependency-lockfile-missing' && finding.location?.path === 'apps/api/package.json'), false);
  assert.ok(malformedPnpmAudit.coverage['dependency-lockfile-missing'].reasons.some((reason) =>
    reason.code === 'pnpm_workspace_parse_error'));
  assert.ok(malformedPnpmAudit.findings.some((finding) =>
    finding.ruleId === 'source-evidence-incomplete' && finding.state === 'unknown'));

  const oversize = join(temp, 'oversize');
  supported(oversize);
  write(join(oversize, 'next.config.mjs'), `export default { sourcemap: true };\n${'x'.repeat(2048)}`);
  result = run(oversize, 'oversize', ['--max-file-bytes', '1024']);
  assert.equal(result.status, 3, result.stderr);
  assert.ok(result.report.coverage.find((entry) => entry.ruleId === 'production-source-map-enabled')
    .reasons.some((reason) => reason.code === 'file_size_limit'));

  const invalidEncoding = join(temp, 'invalid-encoding');
  supported(invalidEncoding);
  write(join(invalidEncoding, 'vite.config.js'), Buffer.from([0xff, 0xfe, 0xfd]));
  result = run(invalidEncoding, 'invalid-encoding');
  assert.equal(result.status, 3, result.stderr);
  assert.ok(result.report.coverage.find((entry) => entry.ruleId === 'production-source-map-enabled')
    .reasons.some((reason) => reason.code === 'unsupported_encoding'));

  const hostileSource = join(temp, 'hostile-source');
  supported(hostileSource);
  write(join(hostileSource, 'package.json'),
    '{"private":true,"dependencies":{"express":"fixture"}}\n');
  write(join(hostileSource, 'src', 'hostile.js'),
    `const options = {\n${'origin: "*",\n'.repeat(4000)}};\n`);
  const hostileStarted = performance.now();
  result = run(hostileSource, 'hostile-source');
  const hostileElapsed = performance.now() - hostileStarted;
  assert.equal(result.status, 3, result.stderr);
  assert.ok(hostileElapsed < 3000, `source operation budget took ${hostileElapsed.toFixed(1)}ms`);
  assert.equal(result.report.scope.traversal.analysis.effectiveLimits.maxOperationsPerFile, 2000000);
  assert.ok(result.report.coverage.find((entry) => entry.ruleId === 'cors-wildcard-with-credentials')
    .reasons.some((reason) => reason.code === 'source_operation_limit'));
  assert.ok(result.report.findings.some((finding) =>
    finding.rule.id === 'source-evidence-incomplete' && finding.state === 'unknown'));
  assert.ok(result.report.findings.some((finding) =>
    finding.rule.id === 'js-route-security-evidence-incomplete' && finding.state === 'unknown'));

  const normalSource = join(temp, 'normal-source');
  supported(normalSource);
  write(join(normalSource, 'src', 'client.js'),
    'const client = { rejectUnauthorized: false };\n');
  const normalAudit = auditSource(normalSource);
  assert.ok(normalAudit.findings.some((finding) => finding.ruleId === 'node-tls-verification-disabled'));
  assert.equal(normalAudit.coverage['node-tls-verification-disabled'].status, 'completed');

  const globalBudget = join(temp, 'global-source-budget');
  supported(globalBudget);
  write(join(globalBudget, 'src', 'a.js'), 'const first = 1;\n');
  write(join(globalBudget, 'src', 'b.js'), 'const second = 2;\n');
  const globalAudit = auditSource(globalBudget, undefined, {
    analysisLimits: {
      maxTokensPerFile: 1000,
      maxOperationsPerFile: 10000,
      maxOperationsTotal: 60,
    },
  });
  assert.ok(globalAudit.integrityIssues.some((issue) =>
    issue.code === 'source_global_operation_limit'));
  assert.equal(globalAudit.traversal.analysis.usage.globalLimitReached, true);

  const unreadable = join(temp, 'unreadable');
  supported(unreadable);
  const unreadableConfig = join(unreadable, 'astro.config.mjs');
  write(unreadableConfig, 'export default { sourcemap: true };\n');
  chmodSync(unreadableConfig, 0o000);
  result = run(unreadable, 'unreadable');
  chmodSync(unreadableConfig, 0o600);
  assert.equal(result.status, 3, result.stderr);
  assert.ok(result.report.coverage.find((entry) => entry.ruleId === 'production-source-map-enabled')
    .reasons.some((reason) => reason.code === 'file_unreadable'));

  const excluded = join(temp, 'excluded');
  supported(excluded);
  write(join(excluded, 'node_modules', 'fixture', 'next.config.mjs'),
    'export default { productionBrowserSourceMaps: true };\n');
  const outside = join(temp, 'outside');
  write(join(outside, 'next.config.mjs'), 'export default { productionBrowserSourceMaps: true };\n');
  symlinkSync(outside, join(excluded, 'linked-outside'));
  const excludedAudit = auditSource(excluded);
  const excludedCoverage = sourceCoverage(excludedAudit);
  assert.equal(excludedAudit.findings.some((finding) =>
    ['production-source-map-enabled', 'source-evidence-incomplete'].includes(finding.ruleId)), false);
  assert.equal(excludedCoverage.find((entry) => entry.ruleId === 'tracked-sensitive-env-file').status,
    'not_applicable');
  assert.ok(excludedCoverage.filter((entry) => ![
    'tracked-sensitive-env-file', 'js-route-security-evidence-incomplete',
  ].includes(entry.ruleId))
    .every((entry) => entry.status === 'completed'));
  assert.equal(excludedCoverage.find((entry) =>
    entry.ruleId === 'js-route-security-evidence-incomplete').status, 'not_applicable');
  assert.ok(excludedCoverage.some((entry) => entry.reasons.some((reason) =>
    reason.code === 'scope_excluded_directory')));
  assert.ok(excludedCoverage.some((entry) => entry.reasons.some((reason) =>
    reason.code === 'symlink_not_followed')));
  assertReconciled(excludedCoverage);

  const unsupported = join(temp, 'unsupported');
  write(join(unsupported, 'README.md'), 'no supported manifest\n');
  result = run(unsupported, 'unsupported');
  assert.equal(result.status, 3, result.stderr);
  assert.ok(result.report.findings.some((finding) => finding.rule.id === 'source-stack-unsupported'));

  result = run(clean, 'invalid-limit', ['--max-depth', '0']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /maxDepth must be an integer/);

  console.log('source coverage ledger ok: bounded traversal, candidate failures, exclusions and exits');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
