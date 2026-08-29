#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  validateV080AccessReview, V080_LEDGER_SHA256, V080_TOOL_COMMIT,
} from '../scripts/generate-v080-access-review.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const review = JSON.parse(readFileSync(join(ROOT,
  'docs/reviews/v0.8.0-access-control-review.json')));

assert.deepEqual(validateV080AccessReview(review), []);
assert.equal(review.evaluation.sha256, V080_LEDGER_SHA256);
assert.ok(review.projects.every((project) => project.toolCommit === V080_TOOL_COMMIT));
assert.deepEqual(review.aggregate, {
  projects: 4,
  routes: 173,
  serverActions: 23,
  frozenEntries: 32,
  eligibleEntries: 14,
  completedEligibleEntries: 13,
  partialEligibleEntries: 1,
  completionRate: 0.9286,
  completedChains: 63,
  frozenMatchedCompletedChains: 13,
  additionalCompletedChains: 50,
  completedWithLimitations: 4,
});
assert.deepEqual(review.distributions.byProvider, { drizzle: 21, prisma: 42 });
assert.deepEqual(review.distributions.byCallDepth, { 0: 4, 1: 38, 2: 19, 4: 2 });
assert.deepEqual(review.distributions.byOutcome, {
  authorization_constraint_not_observed: 54,
  authorization_constraint_observed: 7,
  incomplete: 2,
});
assert.equal(review.dispositions.find((item) => item.id === 'v080-eval-26').result,
  'partial_retained');

const changedDenominator = structuredClone(review);
changedDenominator.aggregate.eligibleEntries = 13;
assert.ok(validateV080AccessReview(changedDenominator).includes('eligible denominator mismatch'));

const hiddenExtra = structuredClone(review);
hiddenExtra.completedChainReview.pop();
hiddenExtra.aggregate.completedChains -= 1;
hiddenExtra.aggregate.additionalCompletedChains -= 1;
assert.ok(validateV080AccessReview(hiddenExtra)
  .includes('manually reviewed completed-chain identity changed'));

const clearedLimitation = structuredClone(review);
clearedLimitation.completedChainReview.find((chain) =>
  chain.id === 'access-chain.98d9d78bf52d0e72a1a11094').limitations = [];
assert.ok(validateV080AccessReview(clearedLimitation)
  .includes('access-chain.98d9d78bf52d0e72a1a11094 limitation boundary changed'));

console.log('v0.8.0 access review provenance ok: denominator, chain identities and limitations enforced');
