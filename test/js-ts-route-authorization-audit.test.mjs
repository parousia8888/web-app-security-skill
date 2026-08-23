#!/usr/bin/env node
import assert from 'node:assert/strict';
import { extractExpressRoutes } from '../scripts/lib/frameworks/express-route-extractor.mjs';
import { extractNestRoutes } from '../scripts/lib/frameworks/nest-route-extractor.mjs';
import { extractNextAppRoutes } from '../scripts/lib/frameworks/next-app-route-extractor.mjs';
import { auditJsTsRouteAuthorization } from '../scripts/lib/js-ts-route-authorization-audit.mjs';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import {
  SOURCE_RULE_REGISTRY, sourceRuleExplanation, validateSourceRuleRegistry,
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
` },
  { path: 'src/projects.controller.ts', text: `
import { Controller, Get, Param } from '@nestjs/common';
import { PrismaClient as Database } from '@prisma/client';
@Controller('projects')
class ProjectsController {
  private db = new Database();
  @Get(':id') async one(@Param('id') projectId) {
    return this.db.project.findUnique({ where: { id: projectId } });
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
assert.equal(result.coverage.status, 'completed');
assert.equal(result.findings.length, 3);
assert.deepEqual(new Set(result.findings.map((finding) => finding.evidence.framework)),
  new Set(['express', 'nestjs', 'next-app']));
assert.ok(result.findings.every((finding) => finding.state === 'suspected'));
assert.ok(result.findings.every((finding) => !/confirmed BOLA|authorization is missing/i.test(
  `${finding.title} ${finding.summary} ${finding.remediation}`)));
assert.equal(result.findings.some((finding) => finding.evidence.routePath === '/owned/:id'), false);
assert.equal(result.findings.some((finding) => finding.evidence.routePath === '/constant/:id'), false);
const delegated = result.routes.find((route) => route.path === '/delegated/:id');
assert.ok(delegated.limitations.includes('delegated-object-authorization-unresolved'));
assert.equal(result.findings.some((finding) => finding.evidence.routePath === '/delegated/:id'), false);
assert.ok(result.routes.find((route) => route.path === '/projects/:id' && route.framework === 'nestjs')
  .operations.includes('prisma-find-unique'));

const disconnected = runAudit(files.map((file) => file.path === 'src/express.ts'
  ? { ...file, text: file.text.replace('id: projectId', "id: 'server-owned-project'") } : file)).result;
assert.equal(disconnected.findings.some((finding) => finding.evidence.routePath === '/projects/:id'
  && finding.evidence.framework === 'express'), false);
const ownerConstraintRemoved = runAudit(files.map((file) => file.path === 'src/express.ts'
  ? { ...file, text: file.text.replace('ownerId: req.user.id', 'displayName: req.user.id') } : file)).result;
assert.equal(ownerConstraintRemoved.findings.some((finding) =>
  finding.evidence.routePath === '/owned/:id'), true);

const rule = SOURCE_RULE_REGISTRY.find((entry) => entry.id === 'js-route-object-authorization-review');
assert.equal(rule.maturity, 'experimental');
assert.deepEqual(validateSourceRuleRegistry(SOURCE_RULE_REGISTRY), []);
const explanation = sourceRuleExplanation('builtin-source', rule.id,
  { state: 'suspected', summary: 'fixture', remediation: 'fixture', retest: 'fixture' });
assert.match(explanation.plainLanguage, /caller select a record ID/i);
assert.match(explanation.evidenceBoundary, /does not prove missing authorization/i);
assert.ok(explanation.sideEffects.length && explanation.userDecisions.length);

const incompleteGraph = buildJsTsModuleGraph([{ path: 'src/broken.ts', text: 'const broken = "' }]);
const incomplete = auditJsTsRouteAuthorization(incompleteGraph, [{
  ...routes[0], location: { path: 'src/broken.ts', line: 1 },
}]);
assert.equal(incomplete.coverage.status, 'partial');
assert.equal(incomplete.findings.length, 0);
assert.ok(incomplete.coverage.reasons.some((reason) => reason.code === 'js_ts_ast_parse_error'));

console.log('route authorization audit ok: three frameworks, direct Prisma boundary, safe neighbours and fail-closed coverage');
