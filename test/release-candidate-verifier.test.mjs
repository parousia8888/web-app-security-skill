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
const SCRIPT = join(ROOT, 'scripts', 'verify-release-candidate.mjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-release-verifier-'));
const repo = join(temp, 'repository');
const trustedKey = join(temp, 'trusted');
const attackerKey = join(temp, 'attacker');
const version = '0.8.1';
const tag = `v${version}`;

function run(program, commandArgs, options = {}) {
  const result = spawnSync(program, commandArgs, { cwd: repo, encoding: 'utf8', ...options });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout.trim();
}

function attempt(outputName) {
  return spawnSync(process.execPath, [
    SCRIPT, '--root', repo, '--version', version, '--tag', tag,
    '--source-commit', run('git', ['rev-parse', 'HEAD']),
    '--trusted-main', run('git', ['rev-parse', 'HEAD']),
    '--approved-main-ref', 'HEAD', '--check-runs', join(temp, 'checks.json'),
    '--out', join(temp, outputName),
  ], { cwd: repo, encoding: 'utf8' });
}

function sign(name, key, commit = 'HEAD') {
  run('git', ['tag', '-d', name]);
  run('git', [
    '-c', 'gpg.format=ssh', '-c', `user.signingkey=${key}`,
    'tag', '-s', name, commit, '-m', name,
  ]);
}

try {
  mkdirSync(repo);
  run('git', ['init', '--initial-branch=main']);
  run('git', ['config', 'user.name', 'Release Test']);
  run('git', ['config', 'user.email', 'release@example.test']);
  run('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', trustedKey]);
  run('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', attackerKey]);
  mkdirSync(join(repo, '.github'), { recursive: true });
  mkdirSync(join(repo, 'docs', 'releases'), { recursive: true });
  writeFileSync(join(repo, 'VERSION'), `${version}\n`);
  writeFileSync(join(repo, 'package.json'), JSON.stringify({
    name: 'web-app-security-skill', version,
  }));
  writeFileSync(join(repo, 'docs', 'releases', `${tag}.md`), '# candidate\n');
  const trustedPublic = readFileSync(`${trustedKey}.pub`, 'utf8').trim();
  writeFileSync(join(repo, '.github', 'release-signers'),
    `release@example.test ${trustedPublic}\n`);
  run('git', ['add', '.']);
  run('git', ['commit', '-m', 'trusted main']);
  const trustedCommit = run('git', ['rev-parse', 'HEAD']);
  const names = [
    'repository-self-audit', 'test (ubuntu-latest, 22)', 'test (ubuntu-latest, 24)',
    'test (macos-latest, 22)', 'test (macos-latest, 24)', 'analyze',
  ];
  writeFileSync(join(temp, 'checks.json'), JSON.stringify({ check_runs: names.map((name, index) => ({
    id: index + 1, name, head_sha: trustedCommit, status: 'completed', conclusion: 'success',
  })) }));

  run('git', [
    '-c', 'gpg.format=ssh', '-c', `user.signingkey=${trustedKey}`,
    'tag', '-s', tag, '-m', tag,
  ]);
  const accepted = attempt('accepted.json');
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.equal(JSON.parse(readFileSync(join(temp, 'accepted.json'), 'utf8')).sourceCommit,
    trustedCommit);

  run('git', ['tag', '-d', tag]);
  run('git', ['tag', tag]);
  const unsigned = attempt('unsigned.json');
  assert.notEqual(unsigned.status, 0);
  assert.match(unsigned.stderr, /annotated tag object/);

  sign(tag, attackerKey);
  const wrongSigner = attempt('wrong-signer.json');
  assert.notEqual(wrongSigner.status, 0);
  assert.match(wrongSigner.stderr, /signature is not trusted/);

  run('git', ['checkout', '-b', 'attacker-candidate']);
  const attackerPublic = readFileSync(`${attackerKey}.pub`, 'utf8').trim();
  writeFileSync(join(repo, '.github', 'release-signers'),
    `attacker@example.test ${attackerPublic}\n`);
  writeFileSync(join(repo, 'attacker.txt'), 'candidate-owned signer policy\n');
  run('git', ['add', '.']);
  run('git', ['commit', '-m', 'candidate changes signer policy']);
  const attackerCommit = run('git', ['rev-parse', 'HEAD']);
  sign(tag, attackerKey, attackerCommit);
  run('git', ['checkout', 'main']);
  const tagOwnedPolicy = attempt('tag-owned-policy.json');
  assert.notEqual(tagOwnedPolicy.status, 0);
  assert.match(tagOwnedPolicy.stderr, /signature is not trusted/,
    'the candidate-owned signer file must not become the trust root');

  sign(tag, trustedKey, attackerCommit);
  const wrongCommit = attempt('wrong-commit.json');
  assert.notEqual(wrongCommit.status, 0);
  assert.match(wrongCommit.stderr, /wrong source commit/);

  sign(tag, trustedKey, trustedCommit);
  const checks = JSON.parse(readFileSync(join(temp, 'checks.json'), 'utf8'));
  checks.check_runs.find((item) => item.name === 'analyze').conclusion = 'failure';
  writeFileSync(join(temp, 'checks.json'), JSON.stringify(checks));
  const failedCheck = attempt('failed-check.json');
  assert.notEqual(failedCheck.status, 0);
  assert.match(failedCheck.stderr, /hosted check is not successful: analyze/);
  console.log('release candidate verifier ok: trusted main signer, exact commit and hosted checks');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
