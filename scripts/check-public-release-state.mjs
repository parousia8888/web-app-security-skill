#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const args = process.argv.slice(2);
function take(name, fallback = null) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
  args.splice(index, 2);
  return value;
}

function run(root, program, commandArgs) {
  const result = spawnSync(program, commandArgs, { cwd: root, encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(result.stderr?.trim() || result.stdout?.trim()
      || `${program} ${commandArgs.join(' ')} failed`);
  }
  return result.stdout.trim();
}

try {
  const defaultRoot = fileURLToPath(new URL('..', import.meta.url));
  const root = resolve(take('--root', defaultRoot));
  const output = take('--out');
  if (args.length) throw new Error(`unknown option ${args[0]}`);
  const state = JSON.parse(readFileSync(resolve(root, 'docs/release-state.json'), 'utf8'));
  const version = readFileSync(resolve(root, 'VERSION'), 'utf8').trim();
  const published = state.publishedRelease || {};
  const stable = state.stableAction || {};
  if (version !== published.version) {
    throw new Error(`public-state verification requires VERSION ${published.version}, got ${version}`);
  }
  const releaseCommit = run(root, 'git', ['rev-parse', `${published.tag}^{}`]);
  if (releaseCommit !== published.sourceCommit) {
    throw new Error(`${published.tag} differs from the recorded published source commit`);
  }
  const aliasCommit = run(root, 'git', ['rev-parse', `${stable.tag}^{}`]);
  if (aliasCommit !== stable.sourceCommit) {
    throw new Error(`${stable.tag} differs from the recorded stable Action source commit; refresh moving tags with git fetch --force --tags`);
  }
  run(root, 'git', ['merge-base', '--is-ancestor', releaseCommit, 'HEAD']);
  run(root, 'git', ['merge-base', '--is-ancestor', aliasCommit, 'HEAD']);
  const signerPolicy = resolve(root, '.github/release-signers');
  run(root, 'git', ['-c', `gpg.ssh.allowedSignersFile=${signerPolicy}`, 'verify-tag', published.tag]);
  run(root, 'git', ['-c', `gpg.ssh.allowedSignersFile=${signerPolicy}`, 'verify-tag', stable.tag]);
  const record = {
    schemaVersion: 1,
    generatedBy: 'scripts/check-public-release-state.mjs',
    state: 'live_verified',
    repository: state.repository,
    version,
    publishedRelease: {
      tag: published.tag,
      sourceCommit: releaseCommit,
      signature: 'verified',
    },
    stableAction: {
      tag: stable.tag,
      sourceCommit: aliasCommit,
      signature: 'verified',
    },
    headRelation: 'release_and_alias_are_ancestors_of_head',
  };
  const rendered = `${JSON.stringify(record, null, 2)}\n`;
  if (output) writeFileSync(resolve(output), rendered, { flag: 'wx', mode: 0o600 });
  else process.stdout.write(rendered);
} catch (error) {
  console.error(`public release state: ${error.message}`);
  process.exit(1);
}
