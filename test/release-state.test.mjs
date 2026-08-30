#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-release-state-'));
const candidate = join(temp, 'candidate');
const clone = join(temp, 'clone');

function run(program, commandArgs, options = {}) {
  const result = spawnSync(program, commandArgs, { cwd: ROOT, encoding: 'utf8', ...options });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout;
}

try {
  const state = JSON.parse(readFileSync(join(ROOT, 'docs', 'release-state.json'), 'utf8'));
  assert.equal(state.publishedRelease.version, '0.8.0');
  assert.equal(state.stableAction.tag, 'v1');
  assert.equal(state.stableAction.sourceCommit, '119cbcc7f8d327482df8abfa50a4af0b69fcceee');
  assert.deepEqual(state.stableAction.promotion, { state: 'final' });
  assert.equal(state.npmPackage.name, 'web-app-security-skill');
  assert.equal(state.npmPackage.version, '0.8.0');
  assert.equal(state.npmPackage.shasum, '1b45330758998f04eeacf71166ab20310fd1c1e7');
  assert.equal(state.npmPackage.integrity,
    'sha512-zbnRkSZ4bdMgRtXprWSp8uvgMswAGjdZstXbcObLJlOIvjnpbmmSHQzdzWPTTlID3giNFfsDH8hchnomYQfUNQ==');
  assert.equal(state.npmPackage.provenance.predicateType, 'https://slsa.dev/provenance/v1');
  assert.equal(state.verifiedInstaller.defaultVersion, '0.8.0');
  assert.deepEqual(state.verifiedInstaller.trustedVersions,
    ['0.3.0', '0.4.0', '0.5.0', '0.5.1', '0.5.2', '0.5.3', '0.5.4', '0.6.0', '0.7.0', '0.7.1', '0.7.2', '0.7.3', '0.8.0']);
  run(process.execPath, [join(ROOT, 'scripts', 'check-release-state.mjs')]);

  const candidateCommit = run('git', ['rev-parse', 'HEAD']).trim();
  run('git', ['clone', '--quiet', '--no-hardlinks', ROOT, clone]);
  run('git', ['checkout', '--quiet', '--detach', state.publishedRelease.sourceCommit], { cwd: clone });
  writeFileSync(join(clone, 'docs', 'release-state.json'), `${JSON.stringify(state, null, 2)}\n`);
  const publicRecord = join(temp, 'public-state.json');
  run(process.execPath, [
    join(ROOT, 'scripts', 'check-public-release-state.mjs'), '--root', clone, '--out', publicRecord,
  ], { cwd: clone });
  assert.equal(JSON.parse(readFileSync(publicRecord, 'utf8')).stableAction.sourceCommit,
    state.stableAction.sourceCommit);

  const pendingState = structuredClone(state);
  pendingState.stableAction.promotion = {
    state: 'pending',
    version: state.publishedRelease.version,
    expectedSourceCommit: state.publishedRelease.sourceCommit,
    priorTagObject: run('git', ['rev-parse', 'v1^{tag}'], { cwd: clone }).trim(),
  };
  writeFileSync(join(clone, 'docs', 'release-state.json'), `${JSON.stringify(pendingState, null, 2)}\n`);
  const pendingPublic = spawnSync(process.execPath, [
    join(ROOT, 'scripts', 'check-public-release-state.mjs'), '--root', clone,
  ], { cwd: clone, encoding: 'utf8' });
  assert.notEqual(pendingPublic.status, 0);
  assert.match(pendingPublic.stderr, /promotion is pending/);
  const pendingRecord = join(temp, 'pending-public-state.json');
  run(process.execPath, [
    join(ROOT, 'scripts', 'check-public-release-state.mjs'), '--root', clone,
    '--phase', 'pending', '--out', pendingRecord,
  ], { cwd: clone });
  const pendingEvidence = JSON.parse(readFileSync(pendingRecord, 'utf8'));
  assert.equal(pendingEvidence.state, 'promotion_pending_verified');
  assert.equal(pendingEvidence.stableAction.sourceCommit,
    pendingState.stableAction.promotion.expectedSourceCommit);
  writeFileSync(join(clone, 'docs', 'release-state.json'), `${JSON.stringify(state, null, 2)}\n`);

  run('git', ['tag', '-f', 'v1', candidateCommit], { cwd: clone });
  let stale = spawnSync(process.execPath, [join(ROOT, 'scripts', 'check-public-release-state.mjs'), '--root', clone], {
    cwd: clone, encoding: 'utf8',
  });
  assert.notEqual(stale.status, 0);
  assert.match(stale.stderr, /v1 differs from the recorded stable Action source commit/);

  cpSync(ROOT, candidate, {
    recursive: true,
    filter: (source) => !source.split('/').includes('.git'),
  });
  writeFileSync(join(candidate, 'VERSION'), '0.8.1\n');
  const pkgPath = join(candidate, 'package.json');
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
  pkg.version = '0.8.1';
  writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
  const changelogPath = join(candidate, 'CHANGELOG.md');
  const changelog = readFileSync(changelogPath, 'utf8').replace(
    '## [Unreleased]\n',
    '## [Unreleased]\n\n## [0.8.1] — 2026-08-30\n',
  );
  writeFileSync(changelogPath, changelog);
  const release080 = readFileSync(join(candidate, 'docs', 'releases', 'v0.8.0.md'), 'utf8');
  writeFileSync(
    join(candidate, 'docs', 'releases', 'v0.8.1.md'),
    release080.replaceAll('v0.8.0', 'v0.8.1'),
  );

  run(process.execPath, [join(candidate, 'scripts', 'generate-launch-evidence.mjs')], { cwd: candidate });
  run(process.execPath, [join(candidate, 'scripts', 'generate-adoption-assets.mjs')], { cwd: candidate });
  run(process.execPath, [join(candidate, 'scripts', 'check-release-state.mjs')], { cwd: candidate });
  const generated = [
    readFileSync(join(candidate, 'docs', 'launch-evidence.md'), 'utf8'),
    readFileSync(join(candidate, 'docs', 'adoption', 'citations.md'), 'utf8'),
    readFileSync(join(candidate, 'docs', 'adoption', 'share-metadata.json'), 'utf8'),
  ].join('\n');
  assert.match(generated, /v0\.8\.0/);
  assert.doesNotMatch(generated, /releases\/tag\/v0\.8\.1|v0\.8\.1 records a signed tag/);
  console.log('release state ok: candidate version cannot become a published-release claim');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
