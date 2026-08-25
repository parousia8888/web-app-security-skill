#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  buildV070AccessReview, projectRecordDigest, routeSemanticDigest,
  validateV070AccessReview,
} from '../scripts/generate-v070-access-review.mjs';

const review = buildV070AccessReview();
assert.deepEqual(validateV070AccessReview(review), []);
assert.deepEqual(review.aggregate, {
  projects: 4, routes: 173, serverActions: 23, manualEntries: 32,
  partialChains: 12, completedChains: 0,
});
assert.equal(review.projects.find((project) => project.id === 'documenso').target, 'apps/docs');

const staleAggregate = structuredClone(review);
staleAggregate.aggregate.routes += 1;
assert.ok(validateV070AccessReview(staleAggregate).includes('project aggregate mismatch'));

const changedProject = structuredClone(review);
changedProject.projects[0].routes += 1;
changedProject.projects[0].recordDigest = projectRecordDigest(changedProject.projects[0]);
assert.ok(validateV070AccessReview(changedProject).includes('project aggregate mismatch'),
  'a changed project record cannot leave the aggregate stale');

const digestTamper = structuredClone(review);
digestTamper.projects[0].reportSha256 = '0'.repeat(64);
assert.ok(validateV070AccessReview(digestTamper).includes('project record digest mismatch'));

const routeDocument = {
  schemaVersion: 2,
  generatedAt: '2026-08-25T00:00:00.000Z',
  subject: { id: 'ephemeral-a', scopeDigest: 'a'.repeat(64) },
  mode: 'audit',
  baseline: null,
  summary: { total: 1 },
  routes: [{ id: 'route.1', path: '/users/:id' }],
};
const sameSemantics = structuredClone(routeDocument);
sameSemantics.generatedAt = '2026-08-26T00:00:00.000Z';
sameSemantics.subject = { id: 'ephemeral-b', scopeDigest: 'b'.repeat(64) };
sameSemantics.mode = 'retest';
sameSemantics.baseline = { source: 'prior' };
assert.equal(routeSemanticDigest(sameSemantics), routeSemanticDigest(routeDocument));
sameSemantics.routes[0].path = '/accounts/:id';
assert.notEqual(routeSemanticDigest(sameSemantics), routeSemanticDigest(routeDocument));

console.log('v0.7.0 access review provenance ok: aggregate, record and semantic digests enforced');
