#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  validateDocumentContract, validateMarkdownLinks, validatePlanArtifactStatus,
} from '../scripts/lib/document-contract.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
assert.deepEqual(validateDocumentContract(ROOT), []);
const historicalRouteProvenance = JSON.parse(readFileSync(join(
  ROOT, 'docs', 'reviews', 'v0.6.0-route-review-provenance.json'), 'utf8'));
assert.equal(historicalRouteProvenance.lifecycle, 'historical');
assert.equal(historicalRouteProvenance.reproducibility.currentAnalyzerBehavior, 'verification_pending');
assert.equal(historicalRouteProvenance.reproducibility.originalAnalyzerInvocation, 'not_retained');
assert.match(historicalRouteProvenance.artifacts.reviewSemanticIdentity.sha256, /^[a-f0-9]{64}$/);
assert.match(historicalRouteProvenance.refreshContract.policy, /Do not overwrite v0\.6\.0 artifacts/);

const temp = mkdtempSync(join(tmpdir(), 'web-app-security-document-contract-'));
try {
  mkdirSync(join(temp, 'docs'));
  mkdirSync(join(temp, 'scripts'));
  writeFileSync(join(temp, 'scripts', 'shipped.mjs'), 'export {};\n');
  writeFileSync(join(temp, 'docs', 'plan.md'), '# Plan\n\n`test/missing.test.mjs`\n');
  writeFileSync(join(temp, 'README.md'), '[missing](docs/missing.md)\n');
  writeFileSync(join(temp, 'docs', 'plan-artifact-status.json'), `${JSON.stringify({
    schemaVersion: 1,
    plans: [{
      path: 'docs/plan.md',
      artifacts: [{
        plannedPath: 'test/missing.test.mjs', disposition: 'shipped_as',
        rationale: 'Consolidated during implementation.', asBuilt: ['scripts/shipped.mjs'],
      }],
    }],
  }, null, 2)}\n`);
  assert.match(validateMarkdownLinks(temp).join('; '), /links to missing docs\/missing\.md/);
  assert.deepEqual(validatePlanArtifactStatus(temp), []);
  writeFileSync(join(temp, 'docs', 'plan-artifact-status.json'), `${JSON.stringify({
    schemaVersion: 1,
    plans: [{ path: 'docs/plan.md', artifacts: [] }],
  })}\n`);
  assert.match(validatePlanArtifactStatus(temp).join('; '), /without an as-built disposition/);
} finally {
  rmSync(temp, { recursive: true, force: true });
}

console.log('document contract ok: broken links and undeclared plan drift fail closed');
