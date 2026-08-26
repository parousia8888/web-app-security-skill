#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
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

  const premature = spawnSync(process.execPath, [
    PREPARE, '--version', version, '--assets', dist, '--live',
  ], { cwd: ROOT, encoding: 'utf8' });
  assert.notEqual(premature.status, 0);
  assert.match(premature.stderr, /signed tag commit differs from release manifest/);

  const state = JSON.parse(readFileSync(join(ROOT, 'docs', 'release-state.json'), 'utf8'));
  const publishedVersion = state.publishedRelease.version;
  const publishedTag = state.publishedRelease.tag;
  const liveDist = join(temp, 'live-dist');
  run(process.execPath, [BUILD, '--ref', publishedTag, '--out', liveDist]);
  const localPublished = JSON.parse(run(process.execPath, [
    PREPARE, '--version', publishedVersion, '--assets', liveDist,
  ]));
  const releaseJson = join(temp, 'release.json');
  const release = {
    tagName: publishedTag,
    url: `https://github.com/parousia8888/web-app-security-skill/releases/tag/${publishedTag}`,
    isDraft: false,
    isPrerelease: false,
    publishedAt: '2026-08-25T00:00:00Z',
    assets: Object.entries(localPublished.assets).map(([name, digest]) => ({
      name, state: 'uploaded', digest: `sha256:${digest}`,
    })),
  };
  writeFileSync(releaseJson, JSON.stringify(release));
  const bin = join(temp, 'bin');
  mkdirSync(bin);
  const gh = join(bin, 'gh');
  writeFileSync(gh, `#!/bin/sh
if [ "$1" = release ] && [ "$2" = view ]; then cat "$GH_RELEASE_JSON"; exit 0; fi
if [ "$1" = attestation ] && [ "$2" = verify ]; then
  [ "\${GH_ATTESTATION_FAIL:-}" = 1 ] && { echo 'attestation unavailable' >&2; exit 1; }
  echo verified
  exit 0
fi
echo "unexpected gh command: $*" >&2
exit 1
`);
  chmodSync(gh, 0o755);
  const liveEnv = {
    ...process.env,
    PATH: `${bin}:${process.env.PATH}`,
    GH_RELEASE_JSON: releaseJson,
  };
  const live = JSON.parse(run(process.execPath, [
    PREPARE, '--version', publishedVersion, '--assets', liveDist, '--live',
  ], { env: liveEnv }));
  assert.equal(live.state, 'live_verified');
  assert.deepEqual(live.gates, {
    localArtifacts: 'verified', publicRelease: 'verified',
    signedTag: 'verified', provenance: 'verified',
  });

  release.assets.push({
    name: `web-app-security-skill-${publishedVersion}.live-verification.json`,
    state: 'uploaded', digest: `sha256:${'f'.repeat(64)}`,
  });
  writeFileSync(releaseJson, JSON.stringify(release));
  const rerun = JSON.parse(run(process.execPath, [
    PREPARE, '--version', publishedVersion, '--assets', liveDist, '--live',
  ], { env: liveEnv }));
  assert.deepEqual(rerun, live);

  const canonicalAsset = release.assets.find((asset) => asset.name === 'SHA256SUMS');
  const canonicalDigest = canonicalAsset.digest;
  canonicalAsset.digest = `sha256:${'0'.repeat(64)}`;
  writeFileSync(releaseJson, JSON.stringify(release));
  const digestMismatch = spawnSync(process.execPath, [
    PREPARE, '--version', publishedVersion, '--assets', liveDist, '--live',
  ], { cwd: ROOT, encoding: 'utf8', env: liveEnv });
  assert.notEqual(digestMismatch.status, 0);
  assert.match(digestMismatch.stderr, /public release digest or state mismatch/);
  canonicalAsset.digest = canonicalDigest;
  writeFileSync(releaseJson, JSON.stringify(release));
  const unavailable = spawnSync(process.execPath, [
    PREPARE, '--version', publishedVersion, '--assets', liveDist, '--live',
  ], { cwd: ROOT, encoding: 'utf8', env: { ...liveEnv, GH_ATTESTATION_FAIL: '1' } });
  assert.notEqual(unavailable.status, 0);
  assert.match(unavailable.stderr, /attestation unavailable/);

  const archive = join(dist, `web-app-security-skill-${version}.tar.gz`);
  writeFileSync(archive, Buffer.concat([readFileSync(archive), Buffer.from('tampered')]));
  const rejected = spawnSync(process.execPath, [PREPARE, '--version', version, '--assets', dist], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /differs from release manifest|differs from SHA256SUMS/);
  console.log('release promotion ok: candidate/live lifecycle, unavailable attestation, public digest and rerun gates');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
