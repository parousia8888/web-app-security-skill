#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const BUILD = join(ROOT, 'scripts', 'build-release-artifacts.mjs');
const VERIFY = join(ROOT, 'scripts', 'verify-release-artifacts.mjs');
const LIFECYCLE = join(ROOT, 'scripts', 'test-release-artifact.mjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-artifacts-'));
const releaseRef = process.env.RELEASE_TEST_REF || 'HEAD';

function run(program, args, options = {}) {
  const result = spawnSync(program, args, { cwd: ROOT, encoding: 'utf8', ...options });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout.trim();
}

function artifactMap(directory) {
  return Object.fromEntries(readdirSync(directory).sort().map((name) => [
    name, readFileSync(join(directory, name)),
  ]));
}

try {
  const version = run('git', ['show', `${releaseRef}:VERSION`]);
  const first = join(temp, 'first');
  const second = join(temp, 'second');
  run(process.execPath, [BUILD, '--ref', releaseRef, '--out', first]);
  run(process.execPath, [BUILD, '--ref', releaseRef, '--out', second]);
  const firstArtifacts = artifactMap(first);
  const secondArtifacts = artifactMap(second);
  assert.deepEqual(Object.keys(firstArtifacts), Object.keys(secondArtifacts));
  for (const name of Object.keys(firstArtifacts)) {
    assert.deepEqual(firstArtifacts[name], secondArtifacts[name], `${name} is not reproducible`);
  }
  const manifest = join(first, `web-app-security-skill-${version}.release.json`);
  const archive = join(first, `web-app-security-skill-${version}.tar.gz`);
  const previous = join(temp, 'previous');
  run(process.execPath, [BUILD, '--ref', 'v0.4.0', '--out', previous]);
  const previousArchive = join(previous, 'web-app-security-skill-0.4.0.tar.gz');
  run(process.execPath, [VERIFY, '--manifest', manifest]);
  run(process.execPath, [LIFECYCLE, '--archive', archive, '--previous-archive', previousArchive]);

  const index = join(temp, 'index');
  const alternateVersion = join(temp, 'VERSION');
  writeFileSync(alternateVersion, '9.8.7\n');
  const gitEnv = { ...process.env, GIT_INDEX_FILE: index };
  run('git', ['read-tree', releaseRef], { env: gitEnv });
  const blob = run('git', ['hash-object', '-w', alternateVersion]);
  run('git', ['update-index', '--add', '--cacheinfo', `100644,${blob},VERSION`], { env: gitEnv });
  const tree = run('git', ['write-tree'], { env: gitEnv });
  const commitEnv = {
    ...process.env,
    GIT_AUTHOR_NAME: 'release artifact test',
    GIT_AUTHOR_EMAIL: 'release-artifact@example.invalid',
    GIT_AUTHOR_DATE: '2000-01-01T00:00:00Z',
    GIT_COMMITTER_NAME: 'release artifact test',
    GIT_COMMITTER_EMAIL: 'release-artifact@example.invalid',
    GIT_COMMITTER_DATE: '2000-01-01T00:00:00Z',
  };
  const syntheticRef = run('git', ['commit-tree', tree], { env: commitEnv, input: 'synthetic release ref\n' });
  const syntheticOut = join(temp, 'synthetic');
  run(process.execPath, [BUILD, '--ref', syntheticRef, '--out', syntheticOut]);
  const syntheticManifest = JSON.parse(readFileSync(
    join(syntheticOut, 'web-app-security-skill-9.8.7.release.json'), 'utf8',
  ));
  const syntheticSbom = JSON.parse(readFileSync(
    join(syntheticOut, 'web-app-security-skill-9.8.7.spdx.json'), 'utf8',
  ));
  assert.equal(syntheticManifest.version, '9.8.7');
  assert.equal(syntheticManifest.sourceCommit, syntheticRef);
  assert.equal(syntheticSbom.packages[0].versionInfo, '9.8.7');
  assert.equal(syntheticSbom.packages.find((item) => item.name === '@babel/parser').versionInfo,
    '7.28.4');
  console.log(`release artifacts ok: reproducible ${version}, v0.4.0 upgrade lifecycle, ref-derived metadata`);
} finally {
  rmSync(temp, { recursive: true, force: true });
}
