#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  buildV080AccessEvaluation,
  FROZEN_V080_EVALUATION_SHA256,
  validateV080AccessEvaluation,
} from '../scripts/generate-v080-access-evaluation.mjs';

const evaluation = buildV080AccessEvaluation();
assert.deepEqual(validateV080AccessEvaluation(evaluation), []);
assert.equal(evaluation.ledgerSha256, FROZEN_V080_EVALUATION_SHA256);
assert.equal(evaluation.entries.length, 32);
assert.deepEqual(evaluation.aggregate.dominantMissFamilies, [
  { family: 'selector_origin', count: 8 },
  { family: 'callable_wrapper_reexport', count: 7 },
  { family: 'depth_propagation', count: 6 },
]);
assert.deepEqual(evaluation.targetCalculation, {
  completionRate: 0.7,
  denominator: 4,
  minimumByRate: 3,
  groundedPathFloor: 6,
  effectiveMinimum: 6,
  feasibleWithCurrentBoundary: false,
  pathShortfall: 2,
  completedProjectFloor: 2,
  representedEligibleProjects: ['formbricks', 'vercel-chatbot'],
  requiredProviders: ['drizzle', 'prisma'],
  representedEligibleProviders: ['drizzle', 'prisma'],
  queryConstraintCases: 0,
  postLoadComparisonCases: 3,
  queryConstraintShortfall: 1,
});

const historicalTamper = structuredClone(evaluation);
historicalTamper.entries[0].historical.note = 'rewritten';
assert.ok(validateV080AccessEvaluation(historicalTamper).some((error) => error.includes('rewrote historical assessment')));

const labelTamper = structuredClone(evaluation);
labelTamper.entries[8].eligibleForV080 = true;
assert.ok(validateV080AccessEvaluation(labelTamper).includes('v080-eval-09 eligible disposition is inconsistent'));

const denominatorTamper = structuredClone(evaluation);
denominatorTamper.targetCalculation.denominator += 1;
assert.ok(validateV080AccessEvaluation(denominatorTamper).includes('ledger digest mismatch'));
assert.ok(validateV080AccessEvaluation(denominatorTamper).includes('target calculation changed'));

console.log('v0.8.0 access evaluation ok: 32 historical labels retained; digest and denominator mutations rejected');
