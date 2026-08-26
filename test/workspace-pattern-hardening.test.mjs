#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { auditSource } from '../scripts/lib/source-audit.mjs';

const temp = mkdtempSync(join(tmpdir(), 'web-app-security-workspace-pattern-'));

function write(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, value);
}

function run(name, workspaces, child = 'app/api') {
  const root = join(temp, name);
  write(join(root, 'package.json'), `${JSON.stringify({ private: true, workspaces })}\n`);
  write(join(root, 'package-lock.json'), '{}\n');
  write(join(root, child, 'package.json'), '{"private":true}\n');
  return auditSource(root);
}

try {
  for (const pattern of ['?apps/*', 'app?/*']) {
    const result = run(`false-clean-${pattern.charCodeAt(0)}-${pattern.length}`, [pattern]);
    assert.ok(result.findings.some((finding) => finding.ruleId === 'dependency-lockfile-missing'
      && finding.location.path === 'app/api/package.json'));
  }

  const nonString = run('non-string', [42]);
  assert.equal(nonString.findings.some((finding) => finding.ruleId === 'dependency-lockfile-missing'
    && finding.location.path === 'app/api/package.json'), false);
  assert.ok(nonString.coverage['dependency-lockfile-missing'].reasons.some((reason) =>
    reason.code === 'workspace_pattern_unsupported'));
  assert.ok(nonString.findings.some((finding) => finding.ruleId === 'source-evidence-incomplete'));

  const unsupported = run('unsupported', ['{app,packages}/*']);
  assert.ok(unsupported.coverage['dependency-lockfile-missing'].reasons.some((reason) =>
    reason.code === 'workspace_pattern_unsupported'));

  const recursive = run('recursive', ['packages/**'], 'packages/group/api');
  assert.equal(recursive.findings.some((finding) => finding.ruleId === 'dependency-lockfile-missing'
    && finding.location.path === 'packages/group/api/package.json'), false);

  const question = run('question', ['apps?/api'], 'apps1/api');
  assert.equal(question.findings.some((finding) => finding.ruleId === 'dependency-lockfile-missing'
    && finding.location.path === 'apps1/api/package.json'), false);
} finally {
  rmSync(temp, { recursive: true, force: true });
}

console.log('workspace pattern hardening ok: bounded glob subset and fail-closed unsupported input');
