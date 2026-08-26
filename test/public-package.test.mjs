#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SCRIPT = join(ROOT, 'scripts', 'check-public-package.mjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-public-package-'));
try {
  const state = JSON.parse(readFileSync(join(ROOT, 'docs', 'release-state.json'), 'utf8'));
  const expected = state.npmPackage;
  const metadata = {
    name: expected.name,
    version: expected.version,
    gitHead: state.publishedRelease.sourceCommit,
    dist: {
      shasum: expected.shasum,
      integrity: expected.integrity,
      attestations: {
        url: expected.provenance.url,
        provenance: { predicateType: expected.provenance.predicateType },
      },
    },
  };
  const metadataPath = join(temp, 'metadata.json');
  const output = join(temp, 'verified.json');
  writeFileSync(metadataPath, JSON.stringify(metadata));
  let result = spawnSync(process.execPath, [SCRIPT, '--metadata', metadataPath, '--out', output], {
    cwd: ROOT, encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(readFileSync(output, 'utf8')).state, 'live_verified');

  metadata.dist.shasum = '0'.repeat(40);
  writeFileSync(metadataPath, JSON.stringify(metadata));
  result = spawnSync(process.execPath, [SCRIPT, '--metadata', metadataPath], {
    cwd: ROOT, encoding: 'utf8',
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /npm shasum mismatch/);
  console.log('public npm package ok: exact package/provenance identity accepted; digest drift rejected');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
