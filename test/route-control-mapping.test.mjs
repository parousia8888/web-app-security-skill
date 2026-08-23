import assert from 'node:assert/strict';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { extractExpressRoutes } from '../scripts/lib/frameworks/express-route-extractor.mjs';
import { controlPrimitiveInventory } from '../scripts/lib/route-control-registry.mjs';
import { prioritizeRoute } from '../scripts/lib/route-security-priority.mjs';
import { controlEvidence, routeRecord } from '../scripts/lib/route-security-model.mjs';

const graph = buildJsTsModuleGraph([{ path: 'src/app.ts', text: `
import express from 'express';
import passport from 'passport';
import { check } from 'express-jwt-permissions';
const app = express();
app.use(passport.authenticate('jwt'));
app.patch('/projects/:id', check('project:write'), customPolicy, update);
app.get('/projects/:id', read);
` }]);
const routes = extractExpressRoutes(graph).routes;
const patch = routes.find((route) => route.method === 'PATCH');
assert.equal(patch.authentication.state, 'inherited_observed');
assert.equal(patch.authorization.state, 'local_observed');
assert.equal(patch.priority.level, 'no_automatic_priority');
const get = routes.find((route) => route.method === 'GET');
assert.equal(get.authorization.state, 'not_observed');
assert.equal(get.priority.level, 'review_next');
assert.ok(get.priority.reasons.includes('object-authorization-unresolved'));

const sensitive = prioritizeRoute(routeRecord({ framework: 'next-app', method: 'DELETE', path: '/files/[id]',
  location: { path: 'src/app/files/[id]/route.ts', line: 1 }, objectAddressed: true,
  authentication: controlEvidence('local_observed'), authorization: controlEvidence('candidate_observed'),
  operations: ['database-mutation'] }));
assert.equal(sensitive.priority.level, 'review_first');
assert.equal(controlPrimitiveInventory().some((item) => item.role === 'authorization'), true);

console.log('route control mapping ok: exact authn/authz separation, candidates and review priority');
