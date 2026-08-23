#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { basename, dirname, join, posix, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const args = process.argv.slice(2);
const manifestIndex = args.indexOf('--manifest');
if (manifestIndex === -1 || !args[manifestIndex + 1] || args.length !== 2) {
  console.error('usage: node scripts/verify-release-artifacts.mjs --manifest <release.json>');
  process.exit(2);
}
const manifestPath = resolve(args[manifestIndex + 1]);
const directory = dirname(manifestPath);

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function tarOutput(archive, entry = null) {
  const args = entry ? ['-xOzf', archive, entry] : ['-tzf', archive];
  const result = spawnSync('tar', args, { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}

try {
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.product, 'Web App Security Skill');
  assert.match(manifest.version, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/);
  assert.match(manifest.sourceCommit, /^[a-f0-9]{40}$/);
  assert.equal(manifest.tag, `v${manifest.version}`);
  assert.ok(Number.isInteger(manifest.sourceDateEpoch) && manifest.sourceDateEpoch >= 0);
  const prefix = `web-app-security-skill-${manifest.version}`;
  const archiveName = `${prefix}.tar.gz`;
  const sbomName = `${prefix}.spdx.json`;
  const manifestName = `${prefix}.release.json`;
  assert.deepEqual(Object.keys(manifest.assets).sort(), [archiveName, sbomName].sort());
  for (const [name, evidence] of Object.entries(manifest.assets)) {
    const path = join(directory, name);
    assert.ok(existsSync(path), path);
    assert.equal(sha256(path), evidence.sha256, `${name} differs from release manifest`);
  }
  const checksumText = readFileSync(join(directory, 'SHA256SUMS'), 'utf8');
  const checksumNames = [];
  for (const line of checksumText.trim().split('\n')) {
    const match = /^([a-f0-9]{64})  ([^/]+)$/.exec(line);
    assert.ok(match, `invalid checksum line: ${line}`);
    checksumNames.push(match[2]);
    assert.equal(sha256(join(directory, match[2])), match[1], `${match[2]} differs from SHA256SUMS`);
  }
  assert.deepEqual(checksumNames, [archiveName, manifestName, sbomName].sort());
  assert.equal(new Set(checksumNames).size, checksumNames.length, 'duplicate checksum entry');

  const archivePath = join(directory, archiveName);
  const root = `${prefix}/`;
  const entries = tarOutput(archivePath).trim().split('\n');
  assert.ok(entries.every((entry) => entry.startsWith(root)), 'archive has an unexpected root');
  for (const entry of entries) {
    assert.equal(posix.isAbsolute(entry), false, `archive contains absolute path: ${entry}`);
    assert.equal(entry.split('/').includes('..'), false, `archive contains parent traversal: ${entry}`);
  }
  for (const required of [
    'VERSION', 'SKILL.md', 'action.yml', 'scripts/webapp-security.mjs',
    'scripts/install-verified.mjs', 'scripts/bootstrap-install.sh',
    'THIRD_PARTY_NOTICES.md', 'scripts/vendor/js-ts-parser.bundle.mjs',
    'scripts/vendor/js-ts-parser.manifest.json',
    'docs/assets/demo.gif', 'docs/assets/demo.json',
    `docs/releases/v${manifest.version}.md`,
  ]) assert.ok(entries.includes(`${root}${required}`), `archive is missing ${required}`);
  if (entries.includes(`${root}scripts/lib/source-rule-registry.mjs`)) {
    assert.ok(entries.includes(`${root}docs/stable-source-rules.json`),
      'archive with the source rule registry is missing its stable manifest');
  }
  assert.equal(entries.some((entry) => entry.includes('/.git/')), false);
  assert.equal(tarOutput(archivePath, `${root}VERSION`).trim(), manifest.version);
  const sbom = JSON.parse(readFileSync(join(directory, sbomName), 'utf8'));
  assert.equal(sbom.spdxVersion, 'SPDX-2.3');
  assert.equal(sbom.packages[0].versionInfo, manifest.version);
  assert.equal(sbom.packages.find((item) => item.name === '@babel/parser')?.licenseDeclared, 'MIT');
  assert.equal(sbom.creationInfo.created, new Date(manifest.sourceDateEpoch * 1000).toISOString());
  console.log(`release artifacts verified: ${basename(manifestPath)} (${entries.length} archive entries)`);
} catch (error) {
  console.error(`release artifacts: ${error.message}`);
  process.exit(1);
}
