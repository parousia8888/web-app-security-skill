#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const BUILD = join(ROOT, 'scripts', 'build-release-artifacts.mjs');
const PREPARE = join(ROOT, 'scripts', 'prepare-release-promotion.mjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-release-promotion-'));
const releaseRef = process.env.RELEASE_TEST_REF || 'HEAD';

function run(program, commandArgs, options = {}) {
  const result = spawnSync(program, commandArgs, { cwd: ROOT, encoding: 'utf8', ...options });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout;
}

try {
  const version = run('git', ['show', `${releaseRef}:VERSION`]).trim();
  const missingAssets = spawnSync(process.execPath, [PREPARE, '--version', version], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.equal(missingAssets.status, 2);
  assert.match(missingAssets.stderr, /--assets must be an existing directory/);
  const dist = join(temp, 'dist');
  run(process.execPath, [BUILD, '--ref', releaseRef, '--out', dist]);
  const output = run(process.execPath, [PREPARE, '--version', version, '--assets', dist]);
  const record = JSON.parse(output);
  const expectedNames = [
    'SHA256SUMS',
    `web-app-security-skill-${version}.release.json`,
    `web-app-security-skill-${version}.spdx.json`,
    `web-app-security-skill-${version}.tar.gz`,
  ].sort();
  assert.equal(record.state, 'local_candidate');
  assert.equal(record.version, version);
  assert.equal(record.tag, `v${version}`);
  assert.match(record.sourceCommit, /^[a-f0-9]{40}$/);
  assert.deepEqual(Object.keys(record.assets).sort(), expectedNames);
  assert.deepEqual(record.trustEntry.assets, record.assets);
  assert.equal(record.publishedRelease, null);
  assert.deepEqual(record.gates, {
    localArtifacts: 'verified',
    publicRelease: 'not_requested',
    signedTag: 'not_requested',
    provenance: 'not_requested',
  });

  const archive = join(dist, `web-app-security-skill-${version}.tar.gz`);
  writeFileSync(archive, Buffer.concat([readFileSync(archive), Buffer.from('tampered')]));
  const rejected = spawnSync(process.execPath, [PREPARE, '--version', version, '--assets', dist], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /differs from release manifest|differs from SHA256SUMS/);
  console.log('release promotion ok: exact trust entry generated; tampered candidate rejected');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
