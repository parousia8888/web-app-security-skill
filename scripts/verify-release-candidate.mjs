#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const REQUIRED_CHECKS = [
  'repository-self-audit',
  'test (ubuntu-latest, 22)',
  'test (ubuntu-latest, 24)',
  'test (macos-latest, 22)',
  'test (macos-latest, 24)',
  'analyze',
];
const SHA1 = /^[a-f0-9]{40}$/;
const SEMVER = /^\d+\.\d+\.\d+$/;
const args = process.argv.slice(2);

function take(name, fallback = null) {
  const index = args.indexOf(name);
  if (index < 0) return fallback;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
  args.splice(index, 2);
  return value;
}

function git(root, commandArgs, label) {
  const result = spawnSync('git', commandArgs, {
    cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`${label}: ${result.stderr?.trim() || result.stdout?.trim() || 'git failed'}`);
  }
  return result.stdout.trim();
}

function readCandidate(root, commit, path) {
  return git(root, ['show', `${commit}:${path}`], `candidate ${path} is unavailable`);
}

function verifyChecks(path, sourceCommit) {
  const document = JSON.parse(readFileSync(path, 'utf8'));
  const runs = Array.isArray(document.check_runs) ? document.check_runs : [];
  const selected = {};
  for (const name of REQUIRED_CHECKS) {
    const matches = runs.filter((run) => run.name === name)
      .sort((left, right) => Number(right.id || 0) - Number(left.id || 0));
    const run = matches[0];
    if (!run) throw new Error(`required hosted check is missing: ${name}`);
    if (run.head_sha !== sourceCommit) throw new Error(`hosted check belongs to another commit: ${name}`);
    if (run.status !== 'completed' || run.conclusion !== 'success') {
      throw new Error(`hosted check is not successful: ${name}`);
    }
    selected[name] = { id: run.id, status: run.status, conclusion: run.conclusion };
  }
  return selected;
}

try {
  const root = resolve(take('--root', fileURLToPath(new URL('..', import.meta.url))));
  const version = take('--version');
  const tag = take('--tag');
  const sourceCommit = take('--source-commit');
  const trustedMainCommit = take('--trusted-main');
  const approvedMainRef = take('--approved-main-ref', 'HEAD');
  const checksArgument = take('--check-runs');
  const outputArgument = take('--out');
  if (args.length) throw new Error(`unknown option ${args[0]}`);
  if (!SEMVER.test(version || '') || tag !== `v${version}`) {
    throw new Error('version and tag must be matching plain SemVer values');
  }
  if (!SHA1.test(sourceCommit || '') || !SHA1.test(trustedMainCommit || '')) {
    throw new Error('source and trusted-main commits must be full SHA-1 values');
  }
  if (!checksArgument || !outputArgument) throw new Error('--check-runs and --out are required');
  const checksPath = resolve(checksArgument);
  const output = resolve(outputArgument);
  if (git(root, ['rev-parse', 'HEAD'], 'trusted main checkout is unavailable') !== trustedMainCommit) {
    throw new Error('trusted checkout HEAD differs from the declared main commit');
  }
  const signerPolicy = resolve(root, '.github/release-signers');
  const signerStat = lstatSync(signerPolicy);
  if (!signerStat.isFile() || signerStat.isSymbolicLink()) {
    throw new Error('trusted signer policy must be a regular file');
  }
  if (git(root, ['cat-file', '-t', `refs/tags/${tag}`], 'candidate tag is unavailable') !== 'tag') {
    throw new Error('candidate tag must be an annotated tag object');
  }
  git(root, ['-c', `gpg.ssh.allowedSignersFile=${signerPolicy}`, 'verify-tag', tag],
    'candidate tag signature is not trusted');
  const peeledCommit = git(root, ['rev-parse', `${tag}^{}`], 'candidate tag cannot be peeled');
  if (peeledCommit !== sourceCommit) throw new Error('candidate tag peels to the wrong source commit');
  if (sourceCommit !== trustedMainCommit) {
    throw new Error('candidate source differs from the trusted main dispatch commit');
  }
  git(root, ['merge-base', '--is-ancestor', sourceCommit, approvedMainRef],
    'candidate source is not reachable from approved main');
  if (git(root, ['rev-parse', approvedMainRef], 'approved main ref is unavailable') !== trustedMainCommit) {
    throw new Error('approved main ref differs from the trusted dispatch commit');
  }
  const candidateVersion = readCandidate(root, sourceCommit, 'VERSION').trim();
  const candidatePackage = JSON.parse(readCandidate(root, sourceCommit, 'package.json'));
  readCandidate(root, sourceCommit, `docs/releases/v${version}.md`);
  if (candidateVersion !== version || candidatePackage.version !== version
      || candidatePackage.name !== 'web-app-security-skill') {
    throw new Error('candidate VERSION, package identity or release version disagrees');
  }
  const checks = verifyChecks(checksPath, sourceCommit);
  const record = {
    schemaVersion: 1,
    generatedBy: 'scripts/verify-release-candidate.mjs',
    state: 'verified',
    repository: 'parousia8888/web-app-security-skill',
    version,
    tag,
    sourceCommit,
    trustedMainCommit,
    signerPolicy: {
      source: `${trustedMainCommit}:.github/release-signers`,
      sha256: createHash('sha256').update(readFileSync(signerPolicy)).digest('hex'),
    },
    checks,
  };
  writeFileSync(output, `${JSON.stringify(record, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  console.log(`release candidate verified: ${sourceCommit}`);
} catch (error) {
  console.error(`release candidate: ${error.message}`);
  process.exit(1);
}
