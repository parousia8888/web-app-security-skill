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

try {
  const defaultRoot = fileURLToPath(new URL('..', import.meta.url));
  const root = resolve(take('--root', defaultRoot));
  const metadataPath = take('--metadata');
  const output = take('--out');
  if (args.length) throw new Error(`unknown option ${args[0]}`);
  const state = JSON.parse(readFileSync(resolve(root, 'docs/release-state.json'), 'utf8'));
  const expected = state.npmPackage || {};
  let metadata;
  if (metadataPath) metadata = JSON.parse(readFileSync(resolve(metadataPath), 'utf8'));
  else {
    const result = spawnSync('npm', ['view', `${expected.name}@${expected.version}`, '--json'], {
      cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
    });
    if (result.status !== 0) throw new Error(result.stderr?.trim() || 'npm metadata is unavailable');
    metadata = JSON.parse(result.stdout);
  }
  const checks = [
    [metadata.name === expected.name, 'package name mismatch'],
    [metadata.version === expected.version, 'package version mismatch'],
    [metadata.gitHead === state.publishedRelease.sourceCommit, 'npm gitHead differs from the published source commit'],
    [metadata.dist?.shasum === expected.shasum, 'npm shasum mismatch'],
    [metadata.dist?.integrity === expected.integrity, 'npm integrity mismatch'],
    [metadata.dist?.attestations?.url === expected.provenance?.url, 'npm provenance URL mismatch'],
    [metadata.dist?.attestations?.provenance?.predicateType === expected.provenance?.predicateType,
      'npm provenance predicate mismatch'],
  ];
  const failed = checks.find(([condition]) => !condition);
  if (failed) throw new Error(failed[1]);
  const record = {
    schemaVersion: 1,
    generatedBy: 'scripts/check-public-package.mjs',
    state: 'live_verified',
    package: expected.name,
    version: expected.version,
    sourceCommit: metadata.gitHead,
    dist: {
      shasum: metadata.dist.shasum,
      integrity: metadata.dist.integrity,
      provenance: {
        url: metadata.dist.attestations.url,
        predicateType: metadata.dist.attestations.provenance.predicateType,
      },
    },
  };
  const rendered = `${JSON.stringify(record, null, 2)}\n`;
  if (output) writeFileSync(resolve(output), rendered, { flag: 'wx', mode: 0o600 });
  else process.stdout.write(rendered);
} catch (error) {
  console.error(`public npm package: ${error.message}`);
  process.exit(1);
}
