#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createAccessPathBudget } from '../scripts/lib/js-ts-access-path.mjs';
import { callableIndexForGraph } from '../scripts/lib/js-ts-callable-index.mjs';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { analyzeRouteSecurity } from '../scripts/lib/route-security-audit.mjs';
import { validateRouteSecurityDocument } from '../scripts/lib/route-security-contract.mjs';
import { createRouteSecurityDocument } from '../scripts/lib/route-security-model.mjs';

const expressManifest = [{ dependencies: { express: '5.1.0', '@prisma/client': '6.0.0' } }];

function analyze(files, packageManifests = expressManifest) {
  return analyzeRouteSecurity(files, { packageManifests });
}

const unresolved = analyze([{ path: 'src/app.ts', text: `
import express from 'express';
const app = express();
app.get('/projects/:id', missingHandler);
` }]);
assert.equal(unresolved.coverage.find((item) => item.framework === 'express').status, 'completed');
assert.deepEqual(unresolved.accessPathCoverage.counts, {
  discovered: 1, eligible: 1, scanned: 0, skipped: 1, truncated: 0, errors: 1,
});
assert.equal(unresolved.accessPathCoverage.status, 'partial');
assert.ok(unresolved.accessPathCoverage.reasons.some((reason) =>
  reason.code === 'route_handler_unresolved'));
assert.ok(unresolved.routes[0].limitations.includes(
  'route-object-authorization-analysis-incomplete'));

const wrappedNext = analyze([{
  path: 'app/api/projects/[projectId]/route.ts', text: `
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
function withRoute(options) { return options.handler; }
export const GET = withRoute({
  handler: async ({ props }) => {
    const params = await props.params;
    return prisma.project.findUnique({ where: { id: params.projectId } });
  },
});
`,
}], [{ dependencies: { next: '15.0.0', '@prisma/client': '6.0.0' } }]);
const wrappedRoute = wrappedNext.routes.find((route) => route.method === 'GET');
assert.equal(wrappedNext.accessPathCoverage.status, 'completed');
assert.equal(wrappedRoute.accessChains.length, 1);
assert.equal(wrappedRoute.accessChains[0].status, 'completed');
assert.equal(wrappedRoute.accessChains[0].objectSelectors[0].name, 'projectId');
assert.equal(wrappedRoute.accessChains[0].dataOperation.provider, 'prisma');

const inventoryPartial = analyze([{ path: 'src/app.ts', text: `
import express from 'express';
import { PrismaClient } from '@prisma/client';
import { registerRoutes } from './routes.js';
const app = express();
const prisma = new PrismaClient();
app.get('/projects/:id', async (req, res) => res.json(
  await prisma.project.findUnique({ where: { id: req.params.id } })
));
registerRoutes(app);
` }, { path: 'src/routes.js', text: `
export function registerRoutes(receiver) { receiver.post('/jobs', createJob); }
` }]);
assert.equal(inventoryPartial.coverage.find((item) => item.framework === 'express').status,
  'partial');
assert.equal(inventoryPartial.accessPathCoverage.status, 'completed');
assert.deepEqual(inventoryPartial.accessPathCoverage.counts, {
  discovered: 1, eligible: 1, scanned: 1, skipped: 0, truncated: 0, errors: 0,
});

const combined = analyze([
  { path: 'src/z-route.ts', text: `
import express from 'express';
import { PrismaClient } from '@prisma/client';
const app = express();
const prisma = new PrismaClient();
app.get('/orders/:id', async (req, res) => res.json(
  await prisma.order.findUnique({ where: { id: req.params.id } })
));
` },
  { path: 'src/z-action.ts', text: `
"use server";
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export async function updateZ(projectId) {
  return prisma.project.update({ where: { id: projectId }, data: {} });
}
` },
  { path: 'src/a-action.ts', text: `
"use server";
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export async function updateA(projectId) {
  return prisma.project.update({ where: { id: projectId }, data: {} });
}
` },
], [{ dependencies: { express: '5.1.0', next: '15.0.0', '@prisma/client': '6.0.0' } }]);
assert.deepEqual(combined.accessPathCoverage.counts, {
  discovered: 3, eligible: 3, scanned: 3, skipped: 0, truncated: 0, errors: 0,
});
assert.equal(combined.accessPathCoverage.status, 'completed');
const document = createRouteSecurityDocument({
  version: '0.8.0', generatedAt: '1970-01-01T00:00:00.000Z', mode: 'audit',
  subject: { id: 'subject.p9-coverage', scopeDigest: 'a'.repeat(64) },
  routes: combined.routes,
  serverActions: [...combined.serverActions].reverse(),
  coverage: combined.coverage,
  accessPathCoverage: combined.accessPathCoverage,
  applicationControls: combined.applicationControls,
  limitations: combined.limitations,
});
assert.deepEqual(validateRouteSecurityDocument(document), []);
assert.deepEqual(document.serverActions.map((action) => action.name), ['updateA', 'updateZ']);
assert.equal(new Set(document.routes.flatMap((route) => route.accessChains)
  .map((chain) => chain.id)).size,
document.routes.flatMap((route) => route.accessChains).length);

const sharedFiles = [
  { path: 'src/route.ts', text: `
import express from 'express';
import { loadRouteProject } from './route-repository';
const app = express();
app.get('/shared/:id', async (req, res) => res.json(await loadRouteProject(req.params.id)));
` },
  { path: 'src/route-repository.ts', text: `
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export function loadRouteProject(id) {
  return prisma.project.findUnique({ where: { id } });
}
` },
  { path: 'src/action.ts', text: `
"use server";
import { loadActionProject } from './action-repository';
export async function loadProject(projectId) { return loadActionProject(projectId); }
` },
  { path: 'src/action-repository.ts', text: `
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export function loadActionProject(id) {
  return prisma.project.findUnique({ where: { id } });
}
` },
];
const sharedGraph = buildJsTsModuleGraph(sharedFiles);
const sharedContext = {
  budget: createAccessPathBudget(1), callableIndex: callableIndexForGraph(sharedGraph),
};
const budgetedAnalysis = analyzeRouteSecurity(sharedFiles, {
  packageManifests: [{ dependencies: { express: '5.1.0', next: '15.0.0',
    '@prisma/client': '6.0.0' } }],
  accessPathContext: sharedContext,
});
assert.equal(sharedContext.budget.transitions, 1);
assert.equal(budgetedAnalysis.accessPathCoverage.status, 'partial');
assert.ok(budgetedAnalysis.accessPathCoverage.reasons.some((reason) =>
  reason.code === 'transition_budget_reached'));

console.log('route path coverage ok: independent inventory/path states, visible skips and deterministic route/action output');
