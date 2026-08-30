#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import {
  cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-self-audit-'));
const clone = join(temp, 'clone');

function write(path, contents) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
}

function run(name) {
  const output = join(temp, name);
  const result = spawnSync(process.execPath, [
    join(clone, '.github', 'scripts', 'run-self-audit.mjs'), '--out', output,
  ], {
    cwd: clone,
    encoding: 'utf8',
    env: {
      ...process.env,
      SOURCE_DATE_EPOCH: '1788048000',
      NODE_OPTIONS: `--require=${join(ROOT, 'test', 'helpers', 'deny-network.cjs')}`,
    },
  });
  return {
    ...result,
    output,
    report: [0, 1, 3].includes(result.status)
      ? JSON.parse(readFileSync(join(output, 'report.json'), 'utf8')) : null,
  };
}

try {
  mkdirSync(clone);
  for (const path of ['.github', 'rules', 'scripts']) {
    cpSync(join(ROOT, path), join(clone, path), { recursive: true });
  }
  for (const path of ['VERSION', 'package.json', 'package-lock.json']) {
    cpSync(join(ROOT, path), join(clone, path));
  }
  write(join(clone, 'test', 'fixtures', 'intentional.js'),
    'const fixture = { rejectUnauthorized: false };\n');
  write(join(clone, 'examples', 'intentional.js'),
    'const example = { rejectUnauthorized: false };\n');
  write(join(clone, 'docs', 'adoption', 'generated.js'),
    'const adoption = { rejectUnauthorized: false };\n');
  write(join(clone, 'docs', 'releases', 'archived.js'),
    'const release = { rejectUnauthorized: false };\n');

  const clean = run('clean');
  assert.equal(clean.status, 0, clean.stderr || clean.stdout);
  assert.equal(clean.report.scope.networkAccessPerformed, false);
  assert.equal(clean.report.summary.total, 1);
  assert.equal(clean.report.summary.activeTotal, 0);
  assert.equal(clean.report.summary.suppressedTotal, 1);
  assert.equal(clean.report.summary.byState.unknown, 0);
  assert.equal(clean.report.findings[0].disposition.status, 'suppressed');
  assert.equal(clean.report.findings[0].disposition.owner, '@parousia8888');
  assert.equal(clean.report.scope.suppression.diagnostics.length, 0);
  const excluded = new Set(clean.report.coverage.flatMap((entry) => entry.reasons
    .filter((reason) => reason.code === 'scope_excluded_directory')
    .flatMap((reason) => reason.samplePaths)));
  for (const path of ['test', 'examples', 'docs/adoption', 'docs/releases']) {
    assert.ok(excluded.has(path), `${path} must remain an observable file-read exclusion`);
  }
  assert.equal(clean.report.scope.auditBoundary.excludedDirectories.includes('vendor'), false);
  assert.ok(clean.report.coverage.some((entry) => entry.reasons.some((reason) =>
    reason.code === 'generated_or_minified_source'
      && reason.samplePaths.includes('scripts/vendor/js-ts-parser.bundle.mjs'))),
  'the packaged generated parser remains in scope with an explicit detector exclusion');
  for (const name of ['report.md', 'report.html']) {
    assert.match(readFileSync(join(clean.output, name), 'utf8'), /SUPPRESSED/);
  }
  const sarif = JSON.parse(readFileSync(join(clean.output, 'report.sarif'), 'utf8'));
  assert.equal(sarif.runs[0].results[0].suppressions[0].status, 'accepted');
  assert.match(readFileSync(join(clean.output, 'report.junit.xml'), 'utf8'),
    /skipped message="suppressed:/);

  const plantedHigh = join(clone, '.github', 'self-audit-planted-high.js');
  write(plantedHigh, 'const tls = { rejectUnauthorized: false };\n');
  const high = run('high');
  assert.equal(high.status, 1, high.stderr || high.stdout);
  assert.ok(high.report.findings.some((finding) =>
    finding.rule.id === 'node-tls-verification-disabled'
      && finding.location.path === '.github/self-audit-planted-high.js'
      && finding.disposition.status === 'active'),
  'an active HIGH in the repository production scope must fail the self-audit gate');
  rmSync(plantedHigh);

  writeFileSync(join(clone, '.github', 'self-audit-planted-invalid.js'),
    Buffer.from([0xff, 0xfe, 0xfd]));
  const unknown = run('unknown');
  assert.equal(unknown.status, 3, unknown.stderr || unknown.stdout);
  assert.ok(unknown.report.findings.some((finding) => finding.state === 'unknown'));
  assert.equal(unknown.report.findings.filter((finding) =>
    finding.state === 'unknown').every((finding) => finding.disposition.status === 'active'), true);

  console.log('repository self-audit ok: production scope, exact suppression, no-network evidence and gates');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
