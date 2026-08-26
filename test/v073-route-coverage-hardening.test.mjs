#!/usr/bin/env node
import assert from 'node:assert/strict';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { extractExpressRoutes } from '../scripts/lib/frameworks/express-route-extractor.mjs';
import { extractNextAppRoutes } from '../scripts/lib/frameworks/next-app-route-extractor.mjs';
import { analyzeRouteSecurity } from '../scripts/lib/route-security-audit.mjs';
import { createRouteSecurityDocument } from '../scripts/lib/route-security-model.mjs';
import { renderRouteSecurityMarkdown } from '../scripts/lib/route-security-renderer.mjs';
import { auditJsTsRouteAuthorization } from '../scripts/lib/js-ts-route-authorization-audit.mjs';

const digest = 'a'.repeat(64);

const computed = extractExpressRoutes(buildJsTsModuleGraph([{ path: 'src/app.js', text: `
import express from 'express';
const app = express();
const literalMethod = 'get';
const aliasedMethod = literalMethod;
app['post']('/literal/:id', literalHandler);
app[aliasedMethod]('/alias/:id', aliasHandler);
app[route.method]('/dynamic/:id', dynamicHandler);
app?.delete('/optional/:id', optionalHandler);
app[variant].patch('/receiver/:id', receiverHandler);
` }]));
assert.deepEqual(computed.routes.map((route) => [route.method, route.path]), [
  ['POST', '/literal/:id'], ['GET', '/alias/:id'],
]);
assert.equal(computed.coverage.status, 'partial');
assert.deepEqual(new Set(computed.coverage.reasons.map((reason) => reason.code)), new Set([
  'express_computed_route_method_unresolved', 'express_optional_route_registration',
  'express_route_receiver_unresolved',
]));

const computedTypo = extractExpressRoutes(buildJsTsModuleGraph([{ path: 'src/typo.js', text: `
import express from 'express'; const app = express(); app['gett']('/typo', handler);
` }]));
assert.equal(computedTypo.coverage.status, 'partial');
assert.equal(computedTypo.coverage.reasons[0].code, 'express_computed_route_method_unsupported');

const mounted = extractExpressRoutes(buildJsTsModuleGraph([
  { path: 'src/app.js', text: `
import express from 'express';
import passport from 'passport';
import adminRouter from './admin.js';
const app = express();
app.use('/admin', passport.authenticate('jwt'), adminRouter);
` },
  { path: 'src/admin.js', text: `
import express from 'express';
const router = express.Router();
router.delete('/users/:id', removeUser);
export default router;
` },
]));
assert.equal(mounted.coverage.status, 'completed');
assert.equal(mounted.routes[0].path, '/admin/users/:id');
assert.equal(mounted.routes[0].authentication.state, 'inherited_observed');

const ambiguousMount = extractExpressRoutes(buildJsTsModuleGraph([
  { path: 'src/app.js', text: `
import express from 'express'; import a from './a.js'; import b from './b.js';
const app = express(); app.use('/both', a, b);
` },
  { path: 'src/a.js', text: `import express from 'express'; const a=express.Router(); export default a;` },
  { path: 'src/b.js', text: `import express from 'express'; const b=express.Router(); export default b;` },
]));
assert.equal(ambiguousMount.coverage.status, 'partial');
assert.ok(ambiguousMount.coverage.reasons.some((reason) =>
  reason.code === 'express_router_mount_ambiguous'));

const hinted = analyzeRouteSecurity([{ path: 'src/routes.js', text: `
module.exports = function registerRoutes(app) { app.post('/orders/:id', handler); };
` }], { packageManifests: [{ dependencies: { express: '5.1.0' } }] });
const hintedExpress = hinted.coverage.find((item) => item.framework === 'express');
assert.equal(hintedExpress.status, 'partial');
assert.equal(hintedExpress.counts.parsed, 0);
assert.ok(hintedExpress.reasons.some((reason) =>
  reason.code === 'framework_hinted_no_eligible_module'));
assert.equal(hinted.reportCoverage.status, 'unavailable');

const emptyExpress = analyzeRouteSecurity([{ path: 'src/app.js', text: `
import express from 'express'; const app = express(); export default app;
` }], { packageManifests: [{ dependencies: { express: '5.1.0' } }] });
assert.equal(emptyExpress.coverage.find((item) => item.framework === 'express').status, 'completed');

const loggerRoutes = extractExpressRoutes(buildJsTsModuleGraph([{ path: 'src/logger.js', text: `
import express from 'express'; import morgan from 'morgan';
const app = express(); app.use(morgan('dev')); app.delete('/users/:id', removeUser);
` }])).routes;
assert.equal(loggerRoutes[0].routeScopedControl.state, 'unclassified_control_observed');
assert.ok(loggerRoutes[0].priority.reasons.includes('unclassified-route-scoped-control-observed'));
const loggerDocument = createRouteSecurityDocument({ version: '0.7.3', generatedAt: '1970-01-01T00:00:00.000Z',
  subject: { id: 'subject-fixture', scopeDigest: digest }, routes: loggerRoutes,
  coverage: [], applicationControls: [], serverActions: [], limitations: [] });
const loggerMarkdown = renderRouteSecurityMarkdown(loggerDocument);
assert.match(loggerMarkdown, /unclassified_control_observed/);
assert.match(loggerMarkdown, /identify whether each one authenticates, authorizes/);

const prismaGraph = buildJsTsModuleGraph([
  { path: 'src/prisma.ts', text: `
import { PrismaClient as Database } from '@prisma/client';
export const prisma = globalThis.prisma ?? new Database();
` },
  { path: 'src/app.ts', text: `
import express from 'express'; import { prisma } from './prisma';
import { auth } from '@clerk/nextjs/server';
const app = express();
app.get('/projects/:id', async (req, res) => { const identity = await auth(); return res.json(await prisma.project.findFirst({ where: { id: req.params.id, tenantId: identity.orgId } })); });
` },
]);
const prismaRoute = extractExpressRoutes(prismaGraph).routes[0];
const prismaAudit = auditJsTsRouteAuthorization(prismaGraph, [prismaRoute]);
assert.equal(prismaAudit.routes[0].accessChains.length, 1);
assert.equal(prismaAudit.routes[0].accessChains[0].outcome, 'principal_constraint_observed');
assert.equal(prismaAudit.routes[0].accessChains[0].dataOperation.tenantConstraint, 'observed');

const unresolvedPrismaGraph = buildJsTsModuleGraph([{ path: 'src/app.ts', text: `
import express from 'express'; import { PrismaClient } from '@prisma/client';
const app = express(); const prisma = createClient(PrismaClient);
app.get('/projects/:id', async (req, res) => res.json(await prisma.project.findFirst({ where: { id: req.params.id } })));
` }]);
const unresolvedPrisma = auditJsTsRouteAuthorization(unresolvedPrismaGraph,
  extractExpressRoutes(unresolvedPrismaGraph).routes);
assert.equal(unresolvedPrisma.routes[0].accessChains[0].outcome, 'incomplete');
assert.ok(unresolvedPrisma.routes[0].limitations.includes('prisma_client_identity_unresolved'));

const unrelatedPrismaGraph = buildJsTsModuleGraph([{ path: 'src/app.ts', text: `
import express from 'express'; class PrismaClient {};
const app = express(); const prisma = new PrismaClient();
app.get('/projects/:id', async (req, res) => res.json(await prisma.project.findFirst({ where: { id: req.params.id } })));
` }]);
const unrelatedPrisma = auditJsTsRouteAuthorization(unrelatedPrismaGraph,
  extractExpressRoutes(unrelatedPrismaGraph).routes);
assert.equal(unrelatedPrisma.routes[0].accessChains.length, 0);

const nextGraph = buildJsTsModuleGraph([
  { path: 'middleware.ts', text: `
import { clerkMiddleware } from '@clerk/nextjs/server';
export default clerkMiddleware();
export const config = { matcher: ['/admin/:path*', '/api/:path*'] };
` },
  { path: 'app/api/orders/[id]/route.ts', text: `
import { auth } from '@clerk/nextjs/server';
export async function DELETE() { await auth(); await auth.protect(); return Response.json({ ok: true }); }
` },
]);
const next = extractNextAppRoutes(nextGraph);
assert.equal(next.routes[0].authentication.state, 'local_observed');
assert.equal(next.routes[0].authorization.state, 'local_observed');
assert.equal(next.applicationControls.length, 1);
assert.match(next.applicationControls[0].boundary, /\/admin\/\:path\*/);
assert.match(next.applicationControls[0].boundary, /application context only/);

const customNext = extractNextAppRoutes(buildJsTsModuleGraph([
  { path: 'proxy.ts', text: `export function proxy(request) { return customPolicy(request); } export const config = { matcher: dynamicMatcher };` },
  { path: 'app/api/health/route.ts', text: `export function GET() { return Response.json({ ok: true }); }` },
]));
assert.equal(customNext.applicationControls[0].role, 'unknown');
assert.equal(customNext.coverage.status, 'partial');
assert.deepEqual(new Set(customNext.coverage.reasons.map((reason) => reason.code)), new Set([
  'next_application_control_unclassified', 'next_middleware_matcher_unresolved',
]));

console.log('v0.7.3 route hardening ok: truthful coverage, Express shapes, Prisma singleton and Next application context');
