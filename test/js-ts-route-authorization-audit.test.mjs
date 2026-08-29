#!/usr/bin/env node
import assert from 'node:assert/strict';
import { extractExpressRoutes } from '../scripts/lib/frameworks/express-route-extractor.mjs';
import { extractNestRoutes } from '../scripts/lib/frameworks/nest-route-extractor.mjs';
import { extractNextAppRoutes } from '../scripts/lib/frameworks/next-app-route-extractor.mjs';
import { auditJsTsRouteAuthorization } from '../scripts/lib/js-ts-route-authorization-audit.mjs';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import {
  SOURCE_RULE_REGISTRY, validateSourceRuleRegistry,
} from '../scripts/lib/source-rule-registry.mjs';

const files = [
  { path: 'src/express.ts', text: `
import express from 'express';
import { PrismaClient as Database } from '@prisma/client';
const app = express();
const db = new Database();
app.get('/projects/:id', async (req, res) => {
  const { id: projectId } = req.params;
  return res.json(await db.project.findUnique({ where: { id: projectId } }));
});
app.get('/owned/:id', async (req, res) => {
  return res.json(await db.project.findFirst({ where: { id: req.params.id, ownerId: req.user.id } }));
});
app.get('/constant/:id', async (_req, res) => res.json(await db.project.findUnique({ where: { id: 'server-owned' } })));
app.get('/delegated/:id', async (req, res) => res.json(await projectService.get(req.params.id)));
app.get('/query-projects', async (req, res) => {
  const { projectId: selected } = req.query;
  return res.json(await db.project.findUnique({ where: { id: selected } }));
});
app.post('/body-projects', async ({ body }, res) => {
  const { projectId: selected } = body;
  return res.json(await db.project.delete({ where: { id: selected } }));
});
app.get('/mixed/:id', async (req, res) => {
  const pathId = req.params.id;
  const selected = req.query.projectId;
  return res.json(await db.project.findUnique({ where: { id: selected } }));
});
` },
  { path: 'src/projects.controller.ts', text: `
import { Body, Controller, Get, Param, Post, Query } from '@nestjs/common';
import { PrismaClient as Database } from '@prisma/client';
@Controller('projects')
class ProjectsController {
  private db = new Database();
  @Get(':id') async one(@Param('id') projectId) {
    return this.db.project.findUnique({ where: { id: projectId } });
  }
  @Get('lookup') async lookup(@Query('projectId') projectId) {
    return this.db.project.findUnique({ where: { id: projectId } });
  }
  @Post('remove') async remove(@Body() dto) {
    return this.db.project.delete({ where: { id: dto.projectId } });
  }
}
` },
  { path: 'src/app/accounts/[accountId]/route.ts', text: `
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export async function DELETE(_request, { params }) {
  const { accountId: selectedId } = await params;
  return Response.json(await prisma.account.delete({ where: { id: selectedId } }));
}
` },
  { path: 'src/app/search/route.ts', text: `
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export async function GET(request) {
  return Response.json(await prisma.project.findUnique({
    where: { id: request.nextUrl.searchParams.get('projectId') },
  }));
}
export async function POST(request) {
  const { projectId: selected } = await request.json();
  return Response.json(await prisma.project.delete({ where: { id: selected } }));
}
` },
  { path: 'src/drizzle.ts', text: `
import { drizzle } from 'drizzle-orm/node-postgres';
export const sqlDb = drizzle({});
` },
  { path: 'src/supabase.ts', text: `
import { createServerClient } from '@supabase/ssr';
export function createClient() { return createServerClient('url', 'key', {}); }
` },
  { path: 'src/access.ts', text: `
import express from 'express';
import { eq, and } from 'drizzle-orm';
import { currentUser } from '@clerk/nextjs/server';
import { sqlDb } from './drizzle';
import { createClient } from './supabase';
const app = express();
app.get('/drizzle-orders/:id', async (req, res) => {
  const user = await currentUser();
  return res.json(await sqlDb.select().from(orders).where(and(
    eq(orders.id, req.params.id), eq(orders.ownerId, user.id),
  )));
});
app.get('/supabase-orders/:id', async (req, res) => {
  const client = await createClient();
  return res.json(await client.from('orders').select('*').eq('id', req.params.id));
});
` },
  { path: 'src/project-repository.ts', text: `
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export function loadProject(id, ownerId) {
  return prisma.project.findFirst({ where: { id, ownerId } });
}
` },
  { path: 'src/hop.ts', text: `
import express from 'express';
import { currentUser } from '@clerk/nextjs/server';
import { loadProject } from './project-repository';
const app = express();
app.get('/hop-projects/:id', async (req, res) => {
  const user = await currentUser();
  return res.json(await loadProject(req.params.id, user.id));
});
` },
];

function runAudit(sourceFiles) {
  const graph = buildJsTsModuleGraph(sourceFiles);
  const routes = [
    ...extractExpressRoutes(graph).routes,
    ...extractNestRoutes(graph).routes,
    ...extractNextAppRoutes(graph).routes,
  ];
  return { graph, routes, result: auditJsTsRouteAuthorization(graph, routes) };
}

const { graph, routes, result } = runAudit(files);
assert.deepEqual(runAudit(files).result, result);
assert.equal(result.coverage.status, 'partial');
const delegated = result.routes.find((route) => route.path === '/delegated/:id');
assert.ok(delegated.limitations.includes('call_target_unresolved'));
assert.equal(delegated.accessChains[0].status, 'partial');
assert.equal(delegated.accessChains[0].reason, 'call_target_unresolved');
assert.ok(result.routes.find((route) => route.path === '/projects/:id' && route.framework === 'nestjs')
  .operations.includes('prisma-find-unique'));
const nestAccess = result.routes.find((route) => route.path === '/projects/:id'
  && route.framework === 'nestjs').accessChains;
assert.equal(nestAccess.length, 1);
assert.equal(nestAccess[0].dataOperation.provider, 'prisma');
assert.equal(nestAccess[0].outcome, 'authorization_constraint_not_observed');
assert.deepEqual(nestAccess[0].objectSelectors.map((selector) => selector.name), ['id']);
const drizzleAccess = result.routes.find((route) => route.path === '/drizzle-orders/:id').accessChains;
assert.equal(drizzleAccess.length, 1);
assert.equal(drizzleAccess[0].dataOperation.provider, 'drizzle');
assert.equal(drizzleAccess[0].identity.provider, 'clerk');
assert.equal(drizzleAccess[0].outcome, 'authorization_constraint_observed');
const supabaseAccess = result.routes.find((route) => route.path === '/supabase-orders/:id').accessChains;
assert.equal(supabaseAccess.length, 1);
assert.equal(supabaseAccess[0].dataOperation.provider, 'supabase');
assert.deepEqual(supabaseAccess[0].authorizationEvidence.map((evidence) => evidence.kind),
  ['external_policy_dependency']);
assert.equal(supabaseAccess[0].outcome, 'external_policy_required');
const hopAccess = result.routes.find((route) => route.path === '/hop-projects/:id').accessChains;
assert.equal(hopAccess.length, 1);
assert.equal(hopAccess[0].callEdges[0].kind, 'local_import');
assert.equal(hopAccess[0].dataOperation.provider, 'prisma');
assert.equal(hopAccess[0].outcome, 'authorization_constraint_observed');
for (const expected of [
  ['/query-projects', 'express-query-field'],
  ['/body-projects', 'express-body-field'],
  ['/projects/lookup', 'nest-query-field'],
  ['/projects/remove', 'nest-body-field'],
  ['/search', 'next-search-param', 'GET'],
  ['/search', 'next-json-field', 'POST'],
]) {
  const [path, kind, method] = expected;
  const route = result.routes.find((item) => item.path === path && (!method || item.method === method));
  assert.ok(route, `missing integrated selector route ${method || '*'} ${path}`);
  assert.equal(route.objectAddressed, true);
  assert.equal(route.accessChains.length, 1);
  assert.equal(route.accessChains[0].objectSelectors[0].kind, kind);
  assert.equal(route.accessChains[0].outcome, 'authorization_constraint_not_observed');
}
const mixed = result.routes.find((route) => route.path === '/mixed/:id');
assert.equal(mixed.accessChains.length, 1);
assert.deepEqual(mixed.accessChains[0].objectSelectors.map((selector) =>
  `${selector.kind}:${selector.name}`), ['express-query-field:projectId']);

const disconnected = runAudit(files.map((file) => file.path === 'src/express.ts'
  ? { ...file, text: file.text.replace('where: { id: projectId }',
    "where: { id: 'server-owned-project' }") } : file)).result;
assert.equal(disconnected.routes.find((route) => route.path === '/projects/:id'
  && route.framework === 'express').accessChains.length, 0);
const ownerConstraintRemoved = runAudit(files.map((file) => file.path === 'src/express.ts'
  ? { ...file, text: file.text.replace('ownerId: req.user.id', 'displayName: req.user.id') } : file)).result;
assert.equal(ownerConstraintRemoved.routes.find((route) =>
  route.path === '/owned/:id').accessChains[0].outcome, 'authorization_constraint_not_observed');

assert.deepEqual(validateSourceRuleRegistry(SOURCE_RULE_REGISTRY), []);

const incompleteGraph = buildJsTsModuleGraph([{ path: 'src/broken.ts', text: 'const broken = "' }]);
const incomplete = auditJsTsRouteAuthorization(incompleteGraph, [{
  ...routes[0], location: { path: 'src/broken.ts', line: 1 },
}]);
assert.equal(incomplete.coverage.status, 'partial');
assert.ok(incomplete.coverage.reasons.some((reason) => reason.code === 'js_ts_ast_parse_error'));

const transformed = runAudit([{ path: 'src/app/transformed/route.ts', text: `
export async function POST(request) {
  const { projectId } = schema.parse(await request.json());
  return Response.json(projectId);
}
` }]).result;
const transformedRoute = transformed.routes.find((route) => route.path === '/transformed');
assert.equal(transformed.coverage.status, 'partial');
assert.equal(transformedRoute.accessChains[0].reason, 'selector_source_unresolved');
assert.equal(transformedRoute.accessChains[0].objectSelectors[0].origin, 'unknown');
assert.ok(transformed.coverage.reasons.some((reason) => reason.code === 'selector_transform_unresolved'));

const dynamic = runAudit([{ path: 'src/dynamic.ts', text: `
import express from 'express';
const app = express();
app.get('/dynamic', async (req, res) => res.json(req.query[req.query.field]));
` }]).result;
const dynamicRoute = dynamic.routes.find((route) => route.path === '/dynamic');
assert.equal(dynamic.coverage.status, 'partial');
assert.equal(dynamicRoute.objectAddressed, true);
assert.equal(dynamicRoute.accessChains[0].status, 'partial');
assert.equal(dynamicRoute.accessChains[0].reason, 'selector_source_unresolved');
assert.ok(dynamic.coverage.reasons.some((reason) => reason.code === 'selector_dynamic_field_unresolved'));

console.log('route authorization audit ok: shared path/query/body selectors, direct Prisma boundary, safe neighbours and fail-closed coverage');
