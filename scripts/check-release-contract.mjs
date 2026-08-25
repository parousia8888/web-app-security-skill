#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateReleaseTrustLanguage } from './lib/release-trust-boundaries.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (path) => readFileSync(`${ROOT}/${path}`, 'utf8');
const version = read('VERSION').trim();
const workflows = [
  '.github/workflows/ci.yml',
  '.github/workflows/codeql.yml',
  '.github/workflows/release.yml',
  '.github/workflows/action-v1-consumer.yml',
  '.github/workflows/npm-publish.yml',
];
const RELEASE_ACTION_COMMIT = '2b746b168d767c9b2225a273474e561650b2b6f8';
const BOOTSTRAP_COMMIT = '25a37e476720ad8ef221e38c0e2842abf928a1db';
const BOOTSTRAP_SHA256 = 'ce37908a73bd9ffd004ec3c0a4d36dc88e3baa6187bd17df816a454a940bfe63';
const VERIFIER_COMMIT = '87326f11c0aab3901ac5cb0783d9452e607e83c5';
const VERIFIER_SHA256 = '662b7de3d596bb6faf8fac4bf69f325f44c1152c99cbbea5fc25184863b1c6d5';
let failed = false;

function requireText(path, marker) {
  if (!read(path).includes(marker)) {
    console.error(`release contract: ${path} is missing ${JSON.stringify(marker)}`);
    failed = true;
  }
}

for (const path of workflows) {
  for (const match of read(path).matchAll(/^\s*-?\s*uses:\s*["']?([^\s"']+)/gm)) {
    const action = match[1];
    if (action === 'parousia8888/web-app-security-skill@v1'
        && path === '.github/workflows/action-v1-consumer.yml') continue;
    if (!/@[a-f0-9]{40}$/.test(action)) {
      console.error(`release contract: ${path} has a non-immutable third-party Action: ${action}`);
      failed = true;
    }
  }
}

for (const [path, markers] of [
  ['.github/workflows/release.yml', [
    'v[0-9]*.[0-9]*.[0-9]*',
    'scripts/build-release-artifacts.mjs',
    'scripts/verify-release-artifacts.mjs',
    'scripts/test-release-artifact.mjs',
    'scripts/prepare-release-promotion.mjs',
    'diff -u dist/SHA256SUMS dist-rebuild/SHA256SUMS',
    'actions/attest-build-provenance@',
  ]],
  ['.github/workflows/ci.yml', [
    'fetch-depth: 0',
    "node: ['22', '24']",
  ]],
  ['.github/workflows/action-v1-consumer.yml', [
    'workflow_dispatch:',
    'parousia8888/web-app-security-skill@v1',
    `parousia8888/web-app-security-skill@${RELEASE_ACTION_COMMIT}`,
    'route-security.json',
    'acknowledge-authorization: "true"',
    'acknowledge-authorization: "false"',
  ]],
  ['.github/workflows/npm-publish.yml', [
    'workflow_dispatch:',
    'id-token: "write"',
    'npm@11.19.0',
    'npm publish --provenance --access public',
  ]],
  ['README.md', [
    `parousia8888/web-app-security-skill@${RELEASE_ACTION_COMMIT}`,
    BOOTSTRAP_COMMIT, BOOTSTRAP_SHA256,
    'webapp-security version', 'bootstrap-install.sh --mode upgrade', 'webapp-security uninstall',
  ]],
  ['README.zh-CN.md', [
    `parousia8888/web-app-security-skill@${RELEASE_ACTION_COMMIT}`,
    BOOTSTRAP_COMMIT, BOOTSTRAP_SHA256,
    'webapp-security version', 'bootstrap-install.sh --mode upgrade', 'webapp-security uninstall',
  ]],
  ['scripts/bootstrap-install.sh', [
    VERIFIER_COMMIT, VERIFIER_SHA256,
  ]],
  ['docs/verified-installation.md', [BOOTSTRAP_COMMIT, BOOTSTRAP_SHA256, '--from-dir']],
  ['docs/verified-installation.zh-CN.md', [BOOTSTRAP_COMMIT, BOOTSTRAP_SHA256, '--from-dir']],
  ['.github/release-signers', ['syx627511687@gmail.com ssh-ed25519 ']],
  [`docs/releases/v${version}.md`, [`gpg.ssh.allowedSignersFile=.github/release-signers verify-tag v${version}`]],
]) for (const marker of markers) requireText(path, marker);

for (const marker of [
  '| Node.js | 22, 24 | Ubuntu and macOS CI |',
  '| Windows / WSL2 | Not supported |',
]) requireText('docs/compatibility.md', marker);

for (const error of validateReleaseTrustLanguage({
  readme: read('README.md'),
  readmeZh: read('README.zh-CN.md'),
  security: read('SECURITY.md'),
  trust: read('docs/release-trust-boundaries.md'),
})) {
  console.error(`release contract: ${error}`);
  failed = true;
}

if (read('.github/workflows/release.yml').includes('- "v*"')) {
  console.error('release contract: moving major tags must not trigger a versioned release');
  failed = true;
}
for (const readme of ['README.md', 'README.zh-CN.md']) {
  const install = read(readme).split(/^## /m).find((section) => /^(?:Install|安装)\n/.test(section)) || '';
  if (/git clone[^\n]+(?:\.git)?(?:\s|\\\n)+/i.test(install)) {
    console.error(`release contract: ${readme} install section uses a moving clone`);
    failed = true;
  }
}
const verifier = spawnSync('git', ['show', `${VERIFIER_COMMIT}:scripts/install-verified.mjs`], {
  cwd: ROOT,
  encoding: null,
  maxBuffer: 4 * 1024 * 1024,
});
if (verifier.status !== 0) {
  console.error(`release contract: verifier commit cannot be resolved: ${VERIFIER_COMMIT}`);
  failed = true;
} else if (createHash('sha256').update(verifier.stdout).digest('hex') !== VERIFIER_SHA256) {
  console.error('release contract: verifier commit and SHA-256 trust anchor disagree');
  failed = true;
}
if (failed) process.exit(1);
console.log(`release contract ok: ${workflows.length} workflows pinned/gated, lifecycle documented`);
