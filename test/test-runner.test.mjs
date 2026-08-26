#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runTestInventory } from '../scripts/lib/test-runner.mjs';

const temp = mkdtempSync(join(tmpdir(), 'web-app-security-test-runner-'));
try {
  writeFileSync(join(temp, 'pass.mjs'), "console.log('pass');\n");
  writeFileSync(join(temp, 'skip.mjs'), `
    import { writeFileSync } from 'node:fs';
    writeFileSync(process.env.WEBAPP_SECURITY_TEST_OUTCOME_FILE, JSON.stringify({
      schemaVersion: 1, status: 'skipped', reasonCode: 'prerequisite_unavailable',
      surfaces: [{ id: 'external-tool', status: 'skipped', reasonCode: 'tool_unavailable' }]
    }));
  `);
  writeFileSync(join(temp, 'fail.mjs'), "process.exit(1);\n");
  writeFileSync(join(temp, 'later.mjs'), "throw new Error('must not execute');\n");
  writeFileSync(join(temp, 'contradictory.mjs'), `
    import { writeFileSync } from 'node:fs';
    writeFileSync(process.env.WEBAPP_SECURITY_TEST_OUTCOME_FILE, JSON.stringify({
      schemaVersion: 1, status: 'passed',
      surfaces: [{ id: 'failed-surface', status: 'failed' }]
    }));
  `);

  const partial = runTestInventory({
    root: temp, files: ['pass.mjs', 'skip.mjs'], output: 'partial.json', stream: false,
  });
  assert.equal(partial.exitCode, 0);
  assert.equal(partial.record.state, 'partial');
  assert.deepEqual(partial.record.summary.files,
    { passed: 1, failed: 0, skipped: 1, not_run: 0 });
  assert.equal(partial.record.summary.surfaces.skipped, 1);

  const failed = runTestInventory({
    root: temp, files: ['pass.mjs', 'fail.mjs', 'later.mjs'], output: 'failed.json', stream: false,
  });
  assert.equal(failed.exitCode, 1);
  assert.equal(failed.record.state, 'failed');
  assert.deepEqual(failed.record.summary.files,
    { passed: 1, failed: 1, skipped: 0, not_run: 1 });
  assert.equal(failed.record.files[2].reasonCode, 'earlier_test_failed');
  assert.equal(JSON.parse(readFileSync(join(temp, 'failed.json'), 'utf8')).files[2].status, 'not_run');

  const contradictory = runTestInventory({
    root: temp, files: ['contradictory.mjs'], output: 'contradictory.json', stream: false,
  });
  assert.equal(contradictory.exitCode, 1);
  assert.equal(contradictory.record.files[0].reasonCode, 'invalid_outcome_record');
  console.log('test runner ok: pass, skip, failure and later not-run states are machine-visible');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
