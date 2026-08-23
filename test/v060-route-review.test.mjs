import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildV060RouteRegressions, buildV060RouteReview, renderV060RouteRegressions,
  renderV060RouteReview, validateV060RouteRegressions, validateV060RouteReview,
} from '../scripts/lib/v060-route-review.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const review = buildV060RouteReview();
assert.deepEqual(validateV060RouteReview(review), []);
assert.deepEqual(review.aggregate, {
  projects: 3,
  reviewedRoutes: 57,
  detectedRoutes: 51,
  missedRoutes: 6,
  extraRecords: 0,
  experimentalBolaMatches: 0,
});
assert.deepEqual(review.projects.map((project) => project.annotations.length), [20, 20, 17]);
assert.ok(review.projects.some((project) => project.analyzerRun.coverage === 'partial'));
assert.ok(review.projects.flatMap((project) => project.annotations)
  .some((entry) => entry.expected.path === '/metrics' && entry.observed.status === 'missed'));
assert.equal(review.promotionDecisions['experimental-prisma-bola'].decision, 'experimental');
const regressions = buildV060RouteRegressions();
assert.deepEqual(validateV060RouteRegressions(regressions), []);
assert.equal(regressions.summary.resolvedRegressions, 6);

const invalid = structuredClone(review);
invalid.projects[0].annotations[0].source.url = 'https://example.invalid/floating/main';
assert.match(validateV060RouteReview(invalid).join('; '), /not fixed-commit linked/);

assert.equal(readFileSync(join(ROOT, 'docs', 'reviews', 'v0.6.0-route-review.json'), 'utf8'),
  `${JSON.stringify(review, null, 2)}\n`);
assert.equal(readFileSync(join(ROOT, 'docs', 'reviews', 'v0.6.0-route-review.md'), 'utf8'),
  renderV060RouteReview(review));
assert.equal(readFileSync(join(ROOT, 'docs', 'regressions', 'v0.6.0-route-real-world-regressions.json'), 'utf8'),
  `${JSON.stringify(regressions, null, 2)}\n`);
assert.equal(readFileSync(join(ROOT, 'docs', 'regressions', 'v0.6.0-route-real-world-regressions.md'), 'utf8'),
  renderV060RouteRegressions(regressions));
console.log('v0.6.0 route review ok: 57 bounded annotations, six visible misses, separate promotions');
