#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SCRIPT = join(ROOT, 'scripts', 'action-promotion-state.mjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-action-promotion-'));
const statePath = join(temp, 'release-state.json');
const prior = '1'.repeat(40);
const source = '2'.repeat(40);

function run(commandArgs, expected = 0) {
  const result = spawnSync(process.execPath, [SCRIPT, ...commandArgs], {
    cwd: ROOT, encoding: 'utf8',
  });
  assert.equal(result.status, expected, result.stderr || result.stdout);
  return result;
}

try {
  const state = {
    publishedRelease: { version: '0.8.1', sourceCommit: source },
    stableAction: {
      tag: 'v1', sourceCommit: '0'.repeat(40), promotion: { state: 'final' },
    },
  };
  writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`);
  run(['check', '--state', statePath]);
  run([
    'begin', '--state', statePath, '--version', '0.8.1',
    '--expected-source', source, '--prior-tag-object', prior,
  ]);
  let current = JSON.parse(readFileSync(statePath, 'utf8'));
  assert.deepEqual(current.stableAction.promotion, {
    state: 'pending', version: '0.8.1', expectedSourceCommit: source, priorTagObject: prior,
  });
  const duplicate = run([
    'begin', '--state', statePath, '--version', '0.8.1',
    '--expected-source', source, '--prior-tag-object', prior,
  ], 1);
  assert.match(duplicate.stderr, /already pending/);
  const wrong = run([
    'finalize', '--state', statePath, '--source-commit', '3'.repeat(40),
  ], 1);
  assert.match(wrong.stderr, /differs from the pending promotion/);
  assert.equal(JSON.parse(readFileSync(statePath, 'utf8')).stableAction.promotion.state, 'pending');
  run(['finalize', '--state', statePath, '--source-commit', source]);
  current = JSON.parse(readFileSync(statePath, 'utf8'));
  assert.equal(current.stableAction.sourceCommit, source);
  assert.deepEqual(current.stableAction.promotion, { state: 'final' });
  console.log('Action promotion state ok: exact prior lease, pending source and final transition');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
