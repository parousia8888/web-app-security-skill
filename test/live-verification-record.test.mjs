#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SCRIPT = join(ROOT, 'scripts', 'build-live-verification-record.mjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-live-record-'));
try {
  const identity = { version: '0.7.2', sourceCommit: 'a'.repeat(40) };
  const promotion = {
    generatedBy: 'promotion', state: 'live_verified', repository: 'owner/repo',
    ...identity, tag: 'v0.7.2', publishedRelease: { publishedAt: '2026-08-25T00:00:00Z' },
    gates: { localArtifacts: 'verified', publicRelease: 'verified', signedTag: 'verified', provenance: 'verified' },
  };
  const publicState = {
    generatedBy: 'public-state', state: 'live_verified', version: identity.version,
    publishedRelease: { sourceCommit: identity.sourceCommit },
  };
  const packageState = { generatedBy: 'package', state: 'live_verified', ...identity };
  for (const [name, value] of [['promotion', promotion], ['public', publicState], ['package', packageState]]) {
    writeFileSync(join(temp, `${name}.json`), JSON.stringify(value));
  }
  writeFileSync(join(temp, 'installer.log'),
    'verified:    Web App Security Skill 0.7.2\nattestation: verified with GitHub CLI\n');
  const command = [SCRIPT,
    '--promotion', join(temp, 'promotion.json'),
    '--public-state', join(temp, 'public.json'),
    '--package-state', join(temp, 'package.json'),
    '--installer-log', join(temp, 'installer.log'),
    '--out', join(temp, 'record.json')];
  const env = {
    ...process.env,
    WEBAPP_SECURITY_IMMUTABLE_CONSUMER_RESULT: 'success',
    WEBAPP_SECURITY_STABLE_CONSUMER_RESULT: 'success',
  };
  let result = spawnSync(process.execPath, command, { cwd: ROOT, encoding: 'utf8', env });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(readFileSync(join(temp, 'record.json'), 'utf8')).state, 'live_verified');

  result = spawnSync(process.execPath, [...command.slice(0, -1), join(temp, 'rejected.json')], {
    cwd: ROOT, encoding: 'utf8', env: { ...env, WEBAPP_SECURITY_STABLE_CONSUMER_RESULT: 'failure' },
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /consumers must both succeed/);
  console.log('live verification record ok: all public gates required; failed consumer rejected');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
