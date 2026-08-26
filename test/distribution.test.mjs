#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { recordTestOutcome } from './helpers/test-outcome.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-distribution-'));
const version = readFileSync(join(ROOT, 'VERSION'), 'utf8').trim();

function run(program, args, options = {}) {
  const { acceptedStatuses = [0], ...spawnOptions } = options;
  const result = spawnSync(program, args, {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, ...spawnOptions,
  });
  assert.ok(acceptedStatuses.includes(result.status), result.stderr || result.stdout);
  return result;
}

try {
  const packed = run('npm', [
    'pack', '--json', '--ignore-scripts', '--pack-destination', temp,
  ]);
  const packResult = JSON.parse(packed.stdout)[0];
  const paths = packResult.files.map((file) => file.path);
  for (const required of [
    '.claude-plugin/plugin.json', 'SKILL.md', 'VERSION', 'KNOWN_LIMITATIONS.md',
    'THIRD_PARTY_NOTICES.md',
    'scripts/webapp-security.mjs', 'scripts/lib/source-audit.mjs',
    'scripts/vendor/js-ts-parser.bundle.mjs', 'scripts/vendor/js-ts-parser.manifest.json',
    'references/phase-2-api.md', 'rules/opengrep-source.yml', 'docs/report-v3.schema.json',
    'docs/route-security-v1.schema.json', 'docs/route-security-v2.schema.json',
    'docs/reviews/v0.6.0-route-review.json',
    'docs/reviews/v0.6.0-route-review-provenance.json',
    'docs/reviews/v0.7.0-access-control-review.json',
    'docs/regressions/v0.7.0-access-control-real-world-regressions.json',
  ]) assert.ok(paths.includes(required), `packed npm artifact is missing ${required}`);
  for (const forbidden of ['test/', 'docs/assets/', 'docs/adoption/', 'docs/V0.5.']) {
    assert.equal(paths.some((path) => path.startsWith(forbidden)), false,
      `packed npm artifact unexpectedly contains ${forbidden}`);
  }

  const tarball = join(temp, packResult.filename);
  const npmCache = join(temp, 'npm-cache');
  const npx = run('npx', [
    '--yes', '--offline', `--cache=${npmCache}`, `--package=${tarball}`, '--',
    'web-app-security-skill', 'version',
  ]);
  assert.equal(npx.stdout.trim(), `Web App Security Skill ${version}`);

  const project = join(temp, 'project');
  cpSync(join(ROOT, 'test', 'fixtures', 'audit-app'), project, { recursive: true });
  const output = join(temp, 'report');
  run('npx', [
    '--yes', '--offline', `--cache=${npmCache}`, `--package=${tarball}`, '--',
    'web-app-security-skill', 'audit', project, '--out', output, '--fail-on', 'never',
  ], { acceptedStatuses: [0, 3] });
  assert.ok(existsSync(join(output, 'report.json')));
  const report = JSON.parse(readFileSync(join(output, 'report.json'), 'utf8'));
  assert.equal(report.schemaVersion, 3);
  assert.ok(report.findings.length > 0);

  const pluginConfig = join(temp, 'claude-config');
  mkdirSync(pluginConfig);
  const claudeBin = process.env.WEBAPP_SECURITY_CLAUDE_BIN || 'claude';
  const claudeVersion = spawnSync(claudeBin, ['--version'], { encoding: 'utf8' });
  let pluginResult = 'Claude CLI unavailable; plugin install skipped';
  let pluginStatus = 'skipped';
  if (claudeVersion.status === 0) {
    const env = { ...process.env, CLAUDE_CONFIG_DIR: pluginConfig };
    run(claudeBin, ['plugin', 'marketplace', 'add', ROOT, '--scope', 'user'], { env });
    run(claudeBin, ['plugin', 'install', 'web-app-security-skill@web-app-security', '--scope', 'user'], { env });
    const installed = run(claudeBin, ['plugin', 'list', '--json'], { env });
    assert.match(installed.stdout, /web-app-security-skill@web-app-security/);
    pluginResult = 'isolated Claude marketplace install';
    pluginStatus = 'passed';
  }
  recordTestOutcome({
    surfaces: [
      { id: 'npm-package-file-inventory', status: 'passed', reasonCode: null },
      { id: 'offline-npx-audit', status: 'passed', reasonCode: null },
      { id: 'claude-plugin-install', status: pluginStatus,
        reasonCode: pluginStatus === 'skipped' ? 'claude_cli_unavailable' : null },
    ],
  });
  console.log(`distribution ${pluginStatus === 'passed' ? 'ok' : 'partial'}: ${paths.length} npm files, offline npx audit, ${pluginResult}`);
} finally {
  rmSync(temp, { recursive: true, force: true });
}
