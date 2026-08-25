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

function run(program, commandArgs, options = {}) {
  const result = spawnSync(program, commandArgs, { cwd: ROOT, encoding: 'utf8', ...options });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout;
}

try {
  const state = JSON.parse(readFileSync(join(ROOT, 'docs', 'release-state.json'), 'utf8'));
  assert.equal(state.publishedRelease.version, '0.7.2');
  assert.equal(state.stableAction.tag, 'v1');
  assert.equal(state.stableAction.sourceCommit, '2b746b168d767c9b2225a273474e561650b2b6f8');
  assert.equal(state.npmPackage.name, 'web-app-security-skill');
  assert.equal(state.npmPackage.version, '0.7.2');
  assert.equal(state.npmPackage.shasum, '4b57df8c5c1f60317ffbb1dc54302cd86884eb88');
  assert.equal(state.npmPackage.integrity,
    'sha512-KftiDW+ABghvOlH38KU9GumhtL8NC+8Xkw6PmL/sptKvS/9xOsRPNjj6CJBMETwutADXIe09ea9iXAgFXfwRdQ==');
  assert.equal(state.npmPackage.provenance.predicateType, 'https://slsa.dev/provenance/v1');
  assert.equal(state.verifiedInstaller.defaultVersion, '0.7.2');
  assert.deepEqual(state.verifiedInstaller.trustedVersions,
    ['0.3.0', '0.4.0', '0.5.0', '0.5.1', '0.5.2', '0.5.3', '0.5.4', '0.6.0', '0.7.0', '0.7.1', '0.7.2']);
  run(process.execPath, [join(ROOT, 'scripts', 'check-release-state.mjs')]);

  cpSync(ROOT, candidate, {
    recursive: true,
    filter: (source) => !source.split('/').includes('.git'),
  });
  writeFileSync(join(candidate, 'VERSION'), '0.7.3\n');
  const pkgPath = join(candidate, 'package.json');
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
  pkg.version = '0.7.3';
  writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
  const changelogPath = join(candidate, 'CHANGELOG.md');
  const changelog = readFileSync(changelogPath, 'utf8').replace(
    '## [Unreleased]\n',
    '## [Unreleased]\n\n## [0.7.3] — 2026-08-25\n',
  );
  writeFileSync(changelogPath, changelog);
  const release072 = readFileSync(join(candidate, 'docs', 'releases', 'v0.7.2.md'), 'utf8');
  writeFileSync(
    join(candidate, 'docs', 'releases', 'v0.7.3.md'),
    release072.replaceAll('v0.7.2', 'v0.7.3'),
  );

  run(process.execPath, [join(candidate, 'scripts', 'generate-launch-evidence.mjs')], { cwd: candidate });
  run(process.execPath, [join(candidate, 'scripts', 'generate-adoption-assets.mjs')], { cwd: candidate });
  run(process.execPath, [join(candidate, 'scripts', 'check-release-state.mjs')], { cwd: candidate });
  const generated = [
    readFileSync(join(candidate, 'docs', 'launch-evidence.md'), 'utf8'),
    readFileSync(join(candidate, 'docs', 'adoption', 'citations.md'), 'utf8'),
    readFileSync(join(candidate, 'docs', 'adoption', 'share-metadata.json'), 'utf8'),
  ].join('\n');
  assert.match(generated, /v0\.7\.2/);
  assert.doesNotMatch(generated, /releases\/tag\/v0\.7\.3|v0\.7\.3 records a signed tag/);
  console.log('release state ok: candidate version cannot become a published-release claim');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
