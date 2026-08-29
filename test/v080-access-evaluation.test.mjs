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
assert.equal(evaluation.state, 'owner_approved');
assert.deepEqual(evaluation.ownerDecision.selection, [
  'exact_react_cache_callback_and_proven_omitted_tx',
  'direct_single_element_array_return_mapping',
]);
assert.deepEqual(evaluation.entries.filter((entry) => entry.eligibleForV080).map((entry) => entry.id), [
  'v080-eval-10',
  'v080-eval-11',
  'v080-eval-12',
  'v080-eval-13',
  'v080-eval-14',
  'v080-eval-16',
  'v080-eval-17',
  'v080-eval-19',
  'v080-eval-20',
  'v080-eval-21',
  'v080-eval-22',
  'v080-eval-25',
  'v080-eval-26',
  'v080-eval-28',
]);
assert.deepEqual(evaluation.aggregate.dominantMissFamilies, [
  { family: 'selector_origin', count: 8 },
  { family: 'callable_wrapper_reexport', count: 7 },
  { family: 'depth_propagation', count: 6 },
]);
assert.deepEqual(evaluation.targetCalculation, {
  completionRate: 0.7,
  denominator: 14,
  minimumByRate: 10,
  groundedPathFloor: 6,
  effectiveMinimum: 10,
  feasibleWithCurrentBoundary: true,
  pathShortfall: 0,
  completedProjectFloor: 2,
  representedEligibleProjects: ['formbricks', 'vercel-chatbot'],
  requiredProviders: ['drizzle', 'prisma'],
  representedEligibleProviders: ['drizzle', 'prisma'],
  queryConstraintCases: 2,
  postLoadComparisonCases: 10,
  queryConstraintShortfall: 0,
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
