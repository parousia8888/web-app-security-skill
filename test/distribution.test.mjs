#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-distribution-'));
const version = readFileSync(join(ROOT, 'VERSION'), 'utf8').trim();

function run(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, ...options,
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
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
    'docs/reviews/v0.6.0-route-review.json', 'docs/reviews/v0.7.0-access-control-review.json',
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
  ]);
  assert.ok(existsSync(join(output, 'report.json')));
  const report = JSON.parse(readFileSync(join(output, 'report.json'), 'utf8'));
  assert.equal(report.schemaVersion, 3);
  assert.ok(report.findings.length > 0);

  const pluginConfig = join(temp, 'claude-config');
  mkdirSync(pluginConfig);
  const claudeVersion = spawnSync('claude', ['--version'], { encoding: 'utf8' });
  let pluginResult = 'Claude CLI unavailable; manifest-only validation';
  if (claudeVersion.status === 0) {
    const env = { ...process.env, CLAUDE_CONFIG_DIR: pluginConfig };
    run('claude', ['plugin', 'marketplace', 'add', ROOT, '--scope', 'user'], { env });
    run('claude', ['plugin', 'install', 'web-app-security-skill@web-app-security', '--scope', 'user'], { env });
    const installed = run('claude', ['plugin', 'list', '--json'], { env });
    assert.match(installed.stdout, /web-app-security-skill@web-app-security/);
    pluginResult = 'isolated Claude marketplace install';
  }
  console.log(`distribution ok: ${paths.length} npm files, offline npx audit, ${pluginResult}`);
} finally {
  rmSync(temp, { recursive: true, force: true });
}
