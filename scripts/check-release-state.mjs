#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateActionPromotionState } from './lib/action-promotion-state.mjs';

const args = process.argv.slice(2);
const rootIndex = args.indexOf('--root');
const ROOT = rootIndex === -1
  ? fileURLToPath(new URL('..', import.meta.url))
  : resolve(args[rootIndex + 1] || '');
if (rootIndex !== -1) args.splice(rootIndex, 2);
if (args.length) {
  console.error('usage: node scripts/check-release-state.mjs [--root <repository>]');
  process.exit(2);
}

const read = (path) => readFileSync(`${ROOT}/${path}`, 'utf8');
const state = JSON.parse(read('docs/release-state.json'));
const currentVersion = read('VERSION').trim();
const semver = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
let failed = false;

function fail(message) {
  console.error(`release state: ${message}`);
  failed = true;
}

function compareVersions(left, right) {
  const parts = (value) => value.split('-', 1)[0].split('.').map(Number);
  const a = parts(left);
  const b = parts(right);
  for (let index = 0; index < 3; index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return 0;
}

if (state.schemaVersion !== 1) fail('schemaVersion must be 1');
if (state.repository !== 'parousia8888/web-app-security-skill') fail('repository identity drifted');
if (!semver.test(currentVersion)) fail('VERSION is not semantic');

const published = state.publishedRelease || {};
if (!semver.test(published.version || '')) fail('published release version is invalid');
if (published.tag !== `v${published.version}`) fail('published release tag and version disagree');
if (!/^[a-f0-9]{40}$/.test(published.sourceCommit || '')) fail('published source commit is invalid');
if (published.evidence !== `docs/releases/v${published.version}.md`
    || !existsSync(`${ROOT}/${published.evidence}`)) {
  fail('published release evidence is missing or misnamed');
}
const expectedUrl = `https://github.com/${state.repository}/releases/tag/${published.tag}`;
if (published.url !== expectedUrl) fail('published release URL disagrees with repository and tag');
if (semver.test(currentVersion) && semver.test(published.version || '')
    && compareVersions(currentVersion, published.version) < 0) {
  fail(`current VERSION ${currentVersion} precedes published release ${published.version}`);
}
if (!existsSync(`${ROOT}/docs/releases/v${currentVersion}.md`)) {
  fail(`current version evidence is missing: docs/releases/v${currentVersion}.md`);
}

const stable = state.stableAction || {};
if (stable.tag !== 'v1' || !/^[a-f0-9]{40}$/.test(stable.sourceCommit || '')) {
  fail('stable Action state is invalid');
}
for (const error of validateActionPromotionState(state)) fail(error);

const npmPackage = state.npmPackage || {};
if (npmPackage.name !== 'web-app-security-skill') fail('npm package identity drifted');
if (!semver.test(npmPackage.version || '') || npmPackage.version !== published.version) {
  fail('npm package version disagrees with the published release');
}
if (npmPackage.url !== `https://www.npmjs.com/package/${npmPackage.name}/v/${npmPackage.version}`) {
  fail('npm package URL disagrees with its identity');
}
if (!/^[a-f0-9]{40}$/.test(npmPackage.shasum || '')) fail('npm package shasum is invalid');
if (!/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(npmPackage.integrity || '')) {
  fail('npm package integrity is invalid');
}
if (npmPackage.provenance?.predicateType !== 'https://slsa.dev/provenance/v1'
    || npmPackage.provenance?.url
      !== `https://registry.npmjs.org/-/npm/v1/attestations/${npmPackage.name}@${npmPackage.version}`) {
  fail('npm package provenance is missing or disagrees with its identity');
}

const installer = state.verifiedInstaller || {};
if (!semver.test(installer.defaultVersion || '')) fail('verified installer default version is invalid');
if (!Array.isArray(installer.trustedVersions) || !installer.trustedVersions.length
    || new Set(installer.trustedVersions).size !== installer.trustedVersions.length
    || !installer.trustedVersions.every((version) => semver.test(version))) {
  fail('verified installer trustedVersions must be unique semantic versions');
}
if (!installer.trustedVersions?.includes(installer.defaultVersion)) {
  fail('verified installer default version is not trusted');
}

const verifier = spawnSync(process.execPath, [`${ROOT}/scripts/install-verified.mjs`, '--print-trust'], {
  cwd: ROOT,
  encoding: 'utf8',
});
if (verifier.status !== 0) fail(verifier.stderr || 'unable to read verifier trust anchors');
else {
  const trust = JSON.parse(verifier.stdout);
  const trustedVersions = Object.keys(trust.releases || {}).sort();
  if (trustedVersions.join('\n') !== [...installer.trustedVersions].sort().join('\n')) {
    fail('release state trustedVersions disagree with install-verified.mjs');
  }
  if (!trust.releases?.[installer.defaultVersion]) fail('verifier does not trust its documented default');
  if (trust.releases?.[published.version]?.sourceCommit !== published.sourceCommit) {
    fail('published release source commit disagrees with verifier trust anchor');
  }
}
const verifierSource = read('scripts/install-verified.mjs');
if (!verifierSource.includes(`take('--version', '${installer.defaultVersion}')`)) {
  fail('verified installer CLI default disagrees with release state');
}

if (existsSync(`${ROOT}/.git`)) {
  const resolved = spawnSync('git', ['rev-parse', `${published.tag}^{}`], { cwd: ROOT, encoding: 'utf8' });
  if (resolved.status !== 0 || resolved.stdout.trim() !== published.sourceCommit) {
    fail(`${published.tag} does not resolve to its recorded source commit`);
  }
}

if (!failed) {
  const relation = currentVersion === published.version ? 'published' : 'candidate';
  console.log(`release state ok: current ${currentVersion} (${relation}), published ${published.version}, npm ${npmPackage.version}, installer ${installer.defaultVersion}, Action ${stable.tag} (${stable.promotion.state})`);
} else process.exit(1);
