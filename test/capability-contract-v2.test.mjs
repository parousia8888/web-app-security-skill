#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CHECK = join(ROOT, 'scripts', 'check-product-contract.mjs');
const source = JSON.parse(readFileSync(join(ROOT, 'docs', 'capabilities.json'), 'utf8'));
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-capability-v2-'));

function run(value) {
  const path = join(temp, 'capabilities.json');
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
  return spawnSync(process.execPath, [CHECK, '--source', path], { cwd: ROOT, encoding: 'utf8' });
}

try {
  let result = run(source);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, /11 stable detection, 0 planned detection/);

  const demoAsDetection = structuredClone(source);
  demoAsDetection.capabilities.find((item) => item.id === 'local-before-after-demo').category = 'detection';
  result = run(demoAsDetection);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /cannot count as detection/);

  const rendererAsDetection = structuredClone(source);
  rendererAsDetection.capabilities.find((item) => item.id === 'structured-reports').category = 'detection';
  result = run(rendererAsDetection);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /cannot count as detection/);

  const stableWithoutImplementationEvidence = structuredClone(source);
  const gitleaks = stableWithoutImplementationEvidence.capabilities.find((item) => item.id === 'gitleaks-secret-detection');
  gitleaks.evidence = ['docs/V0.4.0_ENGINEERING_PLAN.md'];
  result = run(stableWithoutImplementationEvidence);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /requires implementation and test evidence/);

  const plannedWithEvidence = structuredClone(source);
  const plannedGitleaks = plannedWithEvidence.capabilities.find((item) => item.id === 'gitleaks-secret-detection');
  plannedGitleaks.maturity = 'planned';
  plannedGitleaks.plannedFor = '0.5.0';
  result = run(plannedWithEvidence);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /planned maturity cannot claim implementation evidence/);

  const plannedWithoutTarget = structuredClone(source);
  const plannedOsv = plannedWithoutTarget.capabilities.find((item) => item.id === 'osv-dependency-detection');
  plannedOsv.maturity = 'planned';
  delete plannedOsv.plannedFor;
  result = run(plannedWithoutTarget);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /planned maturity requires plannedFor/);

  const guidedAsStable = structuredClone(source);
  guidedAsStable.capabilities.find((item) => item.id === 'api-review').maturity = 'stable';
  result = run(guidedAsStable);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /agent-guided methodology must have agent_guided maturity/);

  console.log('capability v2 contract ok: category and maturity cannot inflate detection coverage');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
