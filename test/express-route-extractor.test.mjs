import assert from 'node:assert/strict';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { extractExpressRoutes } from '../scripts/lib/frameworks/express-route-extractor.mjs';

const graph = buildJsTsModuleGraph([
  { path: 'src/app.ts', text: `
import express from 'express';
import passport from 'passport';
import router from './router';
const app = express();
app.use(passport.authenticate('jwt'));
app.use('/api', router);
app.get('/health', (_req, res) => res.send('ok'));
const fake = { get() {} }; fake.get('/not-a-route', handler);
` },
  { path: 'src/router.ts', text: `
import express from 'express';
const router = express.Router();
router.patch('/projects/:id', customPolicy, updateProject);
router.all('/push/:token', recordHeartbeat);
router.route('/reports').get(listReports).post(createReport);
router.get(dynamicPath, handler);
export default router;
` },
]);
const result = extractExpressRoutes(graph);
const patch = result.routes.find((route) => route.method === 'PATCH');
assert.equal(patch.path, '/api/projects/:id');
assert.equal(patch.objectAddressed, true);
assert.equal(patch.authentication.state, 'inherited_observed');
assert.equal(patch.authorization.state, 'not_observed');
assert.equal(patch.routeScopedControl.state, 'classified_controls_observed');
assert.ok(patch.routeScopedControl.unclassifiedSignals.some((signal) =>
  signal.origin === 'customPolicy'));
const reportMethods = result.routes.filter((route) => route.path === '/api/reports').map((route) => route.method).sort();
assert.deepEqual(reportMethods, ['GET', 'POST']);
assert.equal(result.routes.find((route) => route.method === 'ALL').stateChanging, true);
assert.equal(result.routes.some((route) => route.path === '/not-a-route'), false);
assert.ok(result.routes.some((route) => route.pathKind === 'dynamic'));
assert.equal(result.coverage.framework, 'express');

const unrelated = extractExpressRoutes(buildJsTsModuleGraph([
  { path: 'src/app.ts', text: `import express from 'express'; const app = express(); app.get('/health', handler);` },
  { path: 'src/worker.ts', text: `import missing from './missing'; export default missing;` },
]));
assert.equal(unrelated.coverage.status, 'completed',
  'an unrelated module resolution gap must not poison route coverage');

console.log('express route extractor ok: mounts, order, route chains, candidates and lookalikes');
