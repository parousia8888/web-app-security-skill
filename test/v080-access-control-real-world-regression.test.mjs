#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runV080RealWorldRegression } from '../scripts/generate-v080-access-review.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const regression = runV080RealWorldRegression();

assert.equal(regression.result.passed, true);
assert.deepEqual(regression.result.operations, [{
  provider: 'prisma',
  resource: 'workspace',
  operation: 'find-unique',
  objectConstraint: 'observed',
}]);
assert.deepEqual(regression.result.limitations, []);
assert.equal(readFileSync(join(ROOT,
  'docs/regressions/v0.8.0-access-control-real-world-regression.json'), 'utf8'),
`${JSON.stringify(regression, null, 2)}\n`);

console.log('v0.8.0 real-world regression ok: exact Vite and Prisma facade evidence retained');
