#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(ROOT, 'scripts', 'webapp-security.mjs');
const PROJECT = join(ROOT, 'test', 'fixtures', 'audit-app');
const out = mkdtempSync(join(tmpdir(), 'webapp-security-actionable-gate-'));

try {
  const result = spawnSync(process.execPath, [
    CLI, 'audit', PROJECT, '--out', out, '--name', 'report', '--fail-on', 'high',
  ], { cwd: ROOT, encoding: 'utf8', timeout: 30000 });
  assert.equal(result.status, 1, result.stderr || result.stdout);

  const report = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8'));
  const inspector = report.findings.find((finding) => finding.rule.id === 'node-inspector-public-bind');
  assert.ok(inspector, 'fixture must retain the public Node inspector lead');
  assert.equal(inspector.state, 'suspected', 'the gate must not promote source evidence to confirmed');
  assert.equal(inspector.severity, 'high');
  assert.deepEqual(report.policy.gateStates, ['confirmed', 'suspected']);
  assert.equal(report.policy.precedence, 'actionable_threshold_before_incomplete');
} finally {
  rmSync(out, { recursive: true, force: true });
}

console.log('default actionable gate ok: suspected HIGH fails without evidence-state promotion');
