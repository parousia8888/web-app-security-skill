#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import {
  cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(ROOT, 'scripts', 'webapp-security.mjs');
const CRAWL = join(ROOT, 'scripts', 'crawl-surface-audit.mjs');
const ACTION = join(ROOT, 'scripts', 'run-action.sh');
const SBOM = join(ROOT, 'scripts', 'generate-sbom.mjs');
const temp = mkdtempSync(join(tmpdir(), 'webapp-security-products-'));

function run(program, args, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(program, args, { cwd: ROOT, ...options, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => resolve({ status: 127, stdout, stderr: `${stderr}${error.message}` }));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

const requests = [];
const server = createServer((req, res) => {
  requests.push(req.url);
  const origin = `http://${req.headers.host}`;
  if (req.url === '/robots.txt') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(`User-agent: *\nAllow: /\nSitemap: ${origin}/sitemap.xml\n`);
  } else if (req.url === '/sitemap.xml') {
    res.writeHead(200, { 'content-type': 'application/xml' });
    res.end('<?xml version="1.0"?><urlset></urlset>');
  } else if (req.url === '/') {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<html><head><link rel="canonical" href="${origin}/"></head><body>${'ok '.repeat(800)}</body></html>`);
  } else if (req.url === '/.env') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('FIXTURE_API_KEY=not-a-real-secret');
  } else {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  }
});

try {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;

  let result = await run(process.execPath, [CRAWL, '--site', origin, '--max-urls', '0', '--matrix', '0', '--delay', '0', '--fail-on', 'never', '--quiet']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(requests.includes('/.env'), false, 'passive crawl must not probe sensitive paths');

  requests.length = 0;
  result = await run(process.execPath, [CRAWL, '--site', origin, '--active-probe', '--max-urls', '0', '--matrix', '0', '--delay', '0', '--fail-on', 'never', '--quiet']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /requires --acknowledge-authorization/);
  assert.equal(requests.length, 0, 'authorization gate must run before network activity');

  result = await run(process.execPath, [CRAWL, '--site', origin, '--active-probe', '--acknowledge-authorization', '--max-urls', '0', '--matrix', '0', '--delay', '0', '--fail-on', 'never', '--quiet']);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(requests.includes('/.env'), true, 'active probe flag must enable sensitive-path checks');

  result = await run('/bin/bash', [ACTION], {
    env: { ...process.env, INPUT_SITE: origin, INPUT_ACKNOWLEDGE_AUTHORIZATION: 'false' },
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /must be true/);

  const actionOut = join(temp, 'action-report');
  result = await run('/bin/bash', [ACTION], {
    env: {
      ...process.env,
      INPUT_SITE: origin,
      INPUT_ACKNOWLEDGE_AUTHORIZATION: 'true',
      INPUT_OUTPUT_DIR: actionOut,
      INPUT_FAIL_ON: 'never',
      INPUT_ACTIVE_PROBE: 'true',
    },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.ok(existsSync(join(actionOut, 'report.json')));
  assert.ok(existsSync(join(actionOut, 'report.md')));
  assert.ok(existsSync(join(actionOut, 'report.sarif')));

  const failingActionOut = join(temp, 'action-failing-report');
  const stepSummary = join(temp, 'step-summary.md');
  result = await run('/bin/bash', [ACTION], {
    env: {
      ...process.env,
      INPUT_SITE: origin,
      INPUT_ACKNOWLEDGE_AUTHORIZATION: 'true',
      INPUT_OUTPUT_DIR: failingActionOut,
      INPUT_FAIL_ON: 'high',
      INPUT_ACTIVE_PROBE: 'true',
      GITHUB_STEP_SUMMARY: stepSummary,
    },
  });
  assert.equal(result.status, 1, 'Action must preserve the audit failure status');
  assert.ok(existsSync(join(failingActionOut, 'report.json')), 'failing Action must retain evidence');
  assert.match(readFileSync(stepSummary, 'utf8'), /Web App Security report/);

  const sourceProject = join(temp, 'action-source-project');
  mkdirSync(sourceProject);
  writeFileSync(join(sourceProject, 'package.json'), '{"name":"action-source","version":"1.0.0"}\n');
  writeFileSync(join(sourceProject, 'package-lock.json'), '{"name":"action-source","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"action-source","version":"1.0.0"}}}\n');
  const sourceActionOut = join(temp, 'action-source-report');
  const sourceStepSummary = join(temp, 'source-step-summary.md');
  result = await run('/bin/bash', [ACTION], {
    env: {
      ...process.env,
      INPUT_MODE: 'source',
      INPUT_PROJECT: sourceProject,
      INPUT_OUTPUT_DIR: sourceActionOut,
      INPUT_FAIL_ON: 'never',
      GITHUB_STEP_SUMMARY: sourceStepSummary,
    },
  });
  assert.equal(result.status, 0, result.stderr);
  const sourceActionReport = JSON.parse(readFileSync(join(sourceActionOut, 'report.json'), 'utf8'));
  assert.deepEqual(sourceActionReport.ruleset.adapters.map((adapter) => adapter.id), ['builtin-source']);
  assert.equal(sourceActionReport.scope.networkAccessPerformed, false);
  assert.ok(existsSync(join(sourceActionOut, 'report.sarif')));
  assert.match(readFileSync(sourceStepSummary, 'utf8'), /# Web App Security report/);

  const demoOut = join(temp, 'demo');
  result = await run(process.execPath, [CLI, 'demo', '--out', demoOut]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /before: suspected HIGH node-child-process-shell-execution/);
  assert.match(result.stdout, /security retest: fixed/);
  assert.match(result.stdout, /functional retest: passed/);
  assert.ok(existsSync(join(demoOut, 'before.json')));
  assert.ok(existsSync(join(demoOut, 'after.json')));
  const demoEvidenceBefore = JSON.parse(readFileSync(join(demoOut, 'before.json'), 'utf8'));
  const demoEvidenceAfter = JSON.parse(readFileSync(join(demoOut, 'after.json'), 'utf8'));
  assert.equal(demoEvidenceBefore.schemaVersion, 3);
  assert.equal(demoEvidenceBefore.mode, 'audit');
  assert.equal(demoEvidenceBefore.summary.byState.suspected, 1);
  assert.equal(demoEvidenceBefore.findings[0].rule.id, 'node-child-process-shell-execution');
  const demoFacts = JSON.parse(readFileSync(join(demoOut, 'demo-result.json'), 'utf8'));
  assert.equal(demoFacts.schemaVersion, 2);
  assert.equal(demoFacts.before.state, 'suspected');
  assert.equal(demoFacts.before.ruleId, 'node-child-process-shell-execution');
  assert.equal(demoEvidenceAfter.mode, 'retest');
  assert.equal(demoEvidenceAfter.summary.byBaseline.fixed, 1);
  assert.equal(demoFacts.securityRetest.baselineState, 'fixed');
  assert.equal(demoFacts.functionalRetest.status, 'passed');
  assert.ok(existsSync(join(demoOut, 'before.html')));
  assert.ok(existsSync(join(demoOut, 'after.sarif')));
  assert.match(readFileSync(join(demoOut, 'summary.md'), 'utf8'), /OS command injection lead \(CWE-78\).*suspected.*fixed.*passed/);
  assert.match(readFileSync(join(demoOut, 'hardening.patch'), 'utf8'), /execFile\('printf'/);
  assert.match(readFileSync(join(demoOut, 'functional-retest.txt'), 'utf8'), /ordinary report export still works/);

  const fakeHome = join(temp, 'home');
  mkdirSync(join(fakeHome, '.codex', 'skills', 'webapp-security-hardening'), { recursive: true });
  writeFileSync(
    join(fakeHome, '.codex', 'skills', 'webapp-security-hardening', 'SKILL.md'),
    '---\nname: webapp-security-hardening\ndescription: legacy\n---\n',
  );
  writeFileSync(join(fakeHome, '.codex', 'skills', 'webapp-security-hardening', 'sentinel'), 'old');
  result = await run(process.execPath, [CLI, 'install', '--target', 'both'], { env: { ...process.env, HOME: fakeHome } });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /require migration/);
  assert.equal(existsSync(join(fakeHome, '.claude', 'skills', 'web-app-security')), false, 'preflight must prevent partial install');

  result = await run(process.execPath, [CLI, 'install', '--target', 'both', '--force'], { env: { ...process.env, HOME: fakeHome } });
  assert.equal(result.status, 0, result.stderr);
  for (const client of ['.claude', '.codex']) {
    const installed = join(fakeHome, client, 'skills', 'web-app-security');
    assert.ok(existsSync(join(installed, 'SKILL.md')));
    assert.equal(existsSync(join(installed, 'README.md')), false, 'installer must copy only the skill payload');
    assert.ok(existsSync(join(installed, 'KNOWN_LIMITATIONS.md')));
    assert.match(readFileSync(join(installed, 'THIRD_PARTY_NOTICES.md'), 'utf8'),
      /@babel\/parser 7\.28\.4/);
    assert.ok(existsSync(join(installed, 'docs', 'capabilities.md')));
    assert.ok(existsSync(join(installed, 'docs', 'security-scope.schema.json')));
    assert.ok(existsSync(join(installed, 'docs', 'finding.schema.json')));
    assert.ok(existsSync(join(installed, 'docs', 'report.schema.json')));
    assert.ok(existsSync(join(installed, 'docs', 'finding-v2.schema.json')));
    assert.ok(existsSync(join(installed, 'docs', 'report-v2.schema.json')));
    assert.ok(existsSync(join(installed, 'docs', 'report-v2-migration.md')));
    assert.ok(existsSync(join(installed, 'docs', 'finding-v3.schema.json')));
    assert.ok(existsSync(join(installed, 'docs', 'report-v3.schema.json')));
    assert.ok(existsSync(join(installed, 'docs', 'report-v3-migration.md')));
    assert.ok(existsSync(join(installed, 'docs', 'adapter-protocol.md')));
    assert.ok(existsSync(join(installed, 'docs', 'alert-policy.md')));
    assert.ok(existsSync(join(installed, 'docs', 'rule-taxonomy.md')));
    assert.ok(existsSync(join(installed, 'docs', 'stable-source-rules.json')));
    assert.ok(existsSync(join(installed, 'docs', 'stable-rule-corpus.json')));
    assert.match(readFileSync(join(installed, 'SKILL.md'), 'utf8'), /^name: web-app-security$/m);
  }
  const codexSkills = join(fakeHome, '.codex', 'skills');
  assert.ok(readdirSync(codexSkills).some((name) => name.startsWith('webapp-security-hardening.backup-')));

  const allHome = join(temp, 'all-home');
  result = await run(process.execPath, [CLI, 'install'], { env: { ...process.env, HOME: allHome } });
  assert.equal(result.status, 0, result.stderr);
  assert.ok(existsSync(join(allHome, '.claude', 'skills', 'web-app-security', 'SKILL.md')));
  assert.ok(existsSync(join(allHome, '.codex', 'skills', 'web-app-security', 'SKILL.md')));
  assert.ok(existsSync(join(allHome, '.local', 'share', 'web-app-security', 'SKILL.md')));
  for (const [surface, installed] of [
    ['claude', join(allHome, '.claude', 'skills', 'web-app-security')],
    ['codex', join(allHome, '.codex', 'skills', 'web-app-security')],
    ['cli', join(allHome, '.local', 'share', 'web-app-security')],
  ]) {
    const marker = JSON.parse(readFileSync(join(installed, '.web-app-security-install.json'), 'utf8'));
    assert.equal(marker.product, 'Web App Security Skill');
    assert.equal(marker.version, readFileSync(join(ROOT, 'VERSION'), 'utf8').trim());
    assert.equal(marker.surface, surface);
  }
  const launcher = join(allHome, '.local', 'bin', 'webapp-security');
  assert.ok(existsSync(launcher));
  result = await run(launcher, ['--help'], { env: { ...process.env, HOME: allHome } });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /webapp-security <command>/);
  assert.match(result.stdout, /route-security\.json/);
  assert.match(result.stdout, /review order, not severity/);
  result = await run(launcher, ['version'], { env: { ...process.env, HOME: allHome } });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), `Web App Security Skill ${readFileSync(join(ROOT, 'VERSION'), 'utf8').trim()}`);
  const installedStartOut = join(temp, 'installed-start');
  const installedProject = join(temp, 'installed-project');
  cpSync(join(ROOT, 'test', 'fixtures', 'next-app'), installedProject, { recursive: true });
  result = await run(launcher, [
    'start', installedProject,
    '--out', installedStartOut, '--run-id', 'installed', '--origin', 'https://example.com/path?token=redacted',
  ], { env: { ...process.env, HOME: allHome, SOURCE_DATE_EPOCH: '0' } });
  assert.equal(result.status, 0, result.stderr);
  const installedScope = JSON.parse(readFileSync(join(installedStartOut, 'installed', 'security-scope.yml'), 'utf8'));
  assert.ok(installedScope.target.frameworks.some((item) => item.name === 'Next.js'));
  assert.equal(installedScope.target.publicOrigins[0].url, 'https://example.com/');
  assert.equal(installedScope.checkModes.remoteActive.status, 'blocked_pending_authorization');
  const installedAuditOut = join(temp, 'installed-audit');
  result = await run(launcher, [
    'audit', join(ROOT, 'test', 'fixtures', 'audit-app'), '--out', installedAuditOut,
    '--name', 'installed', '--fail-on', 'never',
  ], { env: { ...process.env, HOME: allHome, SOURCE_DATE_EPOCH: '0' } });
  assert.equal(result.status, 0, result.stderr);
  const installedReport = JSON.parse(readFileSync(join(installedAuditOut, 'installed.json'), 'utf8'));
  assert.equal(installedReport.schemaVersion, 3);
  assert.equal(installedReport.subject.binding, 'ephemeral');
  assert.equal(JSON.stringify(installedReport).includes(installedAuditOut), false);
  assert.equal(installedReport.summary.byState.confirmed, 2);
  assert.equal(installedReport.summary.byState.suspected, 3);
  assert.deepEqual(installedReport.findings.filter((finding) => finding.state === 'confirmed')
    .map((finding) => finding.rule.id).sort(), [
    'dependency-lockfile-missing',
    'tracked-sensitive-env-file',
  ]);
  assert.ok(existsSync(join(installedAuditOut, 'installed.html')));
  assert.ok(existsSync(join(installedAuditOut, 'installed.sarif')));

  result = await run(launcher, ['upgrade'], { env: { ...process.env, HOME: allHome } });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /upgraded:/);
  const backupRoots = [
    join(allHome, '.claude', 'skills'),
    join(allHome, '.codex', 'skills'),
    join(allHome, '.local', 'share'),
  ];
  const lifecycleBackups = backupRoots.flatMap((directory) =>
    readdirSync(directory).filter((name) => name.includes('.backup-')).map((name) => join(directory, name)));
  assert.ok(lifecycleBackups.length >= 3, 'upgrade must preserve prior Claude, Codex and CLI payloads');
  result = await run(launcher, ['version'], { env: { ...process.env, HOME: allHome } });
  assert.equal(result.status, 0, result.stderr);

  result = await run(launcher, ['uninstall'], { env: { ...process.env, HOME: allHome } });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(existsSync(join(allHome, '.claude', 'skills', 'web-app-security')), false);
  assert.equal(existsSync(join(allHome, '.codex', 'skills', 'web-app-security')), false);
  assert.equal(existsSync(join(allHome, '.local', 'share', 'web-app-security')), false);
  assert.equal(existsSync(launcher), false);
  assert.ok(lifecycleBackups.every((path) => existsSync(path)), 'uninstall must preserve timestamped backups');

  const unknownHome = join(temp, 'unknown-home');
  const unknownInstall = join(unknownHome, '.codex', 'skills', 'web-app-security');
  mkdirSync(unknownInstall, { recursive: true });
  writeFileSync(join(unknownInstall, 'sentinel'), 'unrecognized');
  result = await run(process.execPath, [CLI, 'uninstall', '--target', 'codex'], {
    env: { ...process.env, HOME: unknownHome },
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /refusing to remove unrecognized paths/);
  assert.equal(readFileSync(join(unknownInstall, 'sentinel'), 'utf8'), 'unrecognized');
  result = await run(process.execPath, [CLI, 'install', '--target', 'codex', '--force'], {
    env: { ...process.env, HOME: unknownHome },
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /--force refuses unrecognized paths/);
  assert.equal(readFileSync(join(unknownInstall, 'sentinel'), 'utf8'), 'unrecognized');
  result = await run(process.execPath, [CLI, 'upgrade', '--target', 'codex'], {
    env: { ...process.env, HOME: unknownHome },
  });
  assert.equal(result.status, 2);
  assert.ok(existsSync(unknownInstall), 'upgrade must not replace an unrecognized path');

  const legacyCliHome = join(temp, 'legacy-cli-home');
  const legacyCliRoot = join(legacyCliHome, '.local', 'share', 'webapp-security-hardening');
  const legacyLauncher = join(legacyCliHome, '.local', 'bin', 'webapp-security');
  mkdirSync(join(legacyCliRoot, 'scripts'), { recursive: true });
  mkdirSync(join(legacyCliHome, '.local', 'bin'), { recursive: true });
  writeFileSync(join(legacyCliRoot, 'SKILL.md'), '---\nname: webapp-security-hardening\ndescription: legacy\n---\n');
  writeFileSync(join(legacyCliRoot, 'scripts', 'webapp-security.mjs'), '#!/usr/bin/env node\n');
  symlinkSync(join(legacyCliRoot, 'scripts', 'webapp-security.mjs'), legacyLauncher);
  result = await run(process.execPath, [CLI, 'upgrade', '--target', 'cli'], {
    env: { ...process.env, HOME: legacyCliHome },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.ok(existsSync(join(legacyCliHome, '.local', 'share', 'web-app-security', 'SKILL.md')));
  assert.equal(existsSync(legacyCliRoot), false);
  result = await run(legacyLauncher, ['version'], { env: { ...process.env, HOME: legacyCliHome } });
  assert.equal(result.status, 0, result.stderr);

  const sbomPath = join(temp, 'sbom.spdx.json');
  result = await run(process.execPath, [SBOM, '--out', sbomPath], { env: { ...process.env, SOURCE_DATE_EPOCH: '0' } });
  assert.equal(result.status, 0, result.stderr);
  const sbom = JSON.parse(readFileSync(sbomPath, 'utf8'));
  assert.equal(sbom.spdxVersion, 'SPDX-2.3');
  assert.equal(sbom.creationInfo.created, '1970-01-01T00:00:00.000Z');
  assert.equal(sbom.packages[0].versionInfo, readFileSync(join(ROOT, 'VERSION'), 'utf8').trim());
  assert.equal(sbom.packages[0].name, 'web-app-security-skill');
  const parserPackage = sbom.packages.find((item) => item.name === '@babel/parser');
  assert.equal(parserPackage.versionInfo, '7.28.4');
  assert.equal(parserPackage.licenseDeclared, 'MIT');
  assert.ok(sbom.relationships.some((item) => item.relationshipType === 'CONTAINS'
    && item.relatedSpdxElement === parserPackage.SPDXID));
  assert.match(sbom.documentNamespace, /^https:\/\/github\.com\/parousia8888\/web-app-security-skill\/sbom\//);
  assert.match(sbom.packages[0].downloadLocation, /parousia8888\/web-app-security-skill\/archive\/refs\/tags/);
  assert.match(sbom.packages[0].externalRefs[0].referenceLocator, /^pkg:github\/parousia8888\/web-app-security-skill@v/);

  console.log('✓ product surfaces: passive boundary, Action gate, demo, installer, and SBOM');
} finally {
  server.close();
  rmSync(temp, { recursive: true, force: true });
}
