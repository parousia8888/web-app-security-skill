import assert from 'node:assert/strict';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { extractNestRoutes } from '../scripts/lib/frameworks/nest-route-extractor.mjs';

const graph = buildJsTsModuleGraph([{ path: 'src/projects.controller.ts', text: `
import { Controller, Get, Patch, Post, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Public } from './public';
@Controller({ path: 'projects', version: '1' })
@UseGuards(AuthGuard('jwt'))
export class ProjectsController {
  @Get(':id') getOne() {}
  @Patch(':id') @UseGuards(ProjectGuard) update() {}
  @Public() @Post('login') login() {}
}
class Lookalike { Get() {} }
` }]);
const result = extractNestRoutes(graph);
assert.equal(result.routes.length, 3);
const get = result.routes.find((route) => route.method === 'GET');
assert.equal(get.path, '/projects/:id');
assert.equal(get.authentication.state, 'inherited_observed');
const patch = result.routes.find((route) => route.method === 'PATCH');
assert.equal(patch.authentication.state, 'inherited_observed');
assert.equal(patch.routeScopedControl.state, 'classified_controls_observed');
assert.ok(patch.routeScopedControl.unclassifiedSignals.some((signal) =>
  signal.origin === 'ProjectGuard'));
const post = result.routes.find((route) => route.method === 'POST');
assert.ok(post.limitations.includes('public-override-requires-review'));
assert.equal(result.coverage.framework, 'nestjs');
assert.equal(result.coverage.status, 'completed');

const dynamic = extractNestRoutes(buildJsTsModuleGraph([{ path: 'src/dynamic.controller.ts', text: `
import { Controller, Get } from '@nestjs/common';
@Controller(controllerPath())
export class DynamicController { @Get(':id') getOne() {} }
` }]));
assert.equal(dynamic.routes[0].path, null);
assert.equal(dynamic.routes[0].pathKind, 'dynamic');
assert.equal(dynamic.coverage.status, 'partial');
assert.ok(dynamic.coverage.reasons.some((reason) => reason.code === 'nest_dynamic_controller_path'));

const separated = extractNestRoutes(buildJsTsModuleGraph([
  { path: 'src/auth.guard.ts', text: `
import { AuthGuard } from '@nestjs/passport';
export class JwtAuthGuard extends AuthGuard('jwt') {}
` },
  { path: 'src/roles.constants.ts', text: `export const ROLES_KEY = 'roles';` },
  { path: 'src/roles.guard.ts', text: `
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from './roles.constants';
export class RolesGuard {
  constructor(private reflector: Reflector) {}
  canActivate(context) {
    return this.reflector.getAllAndOverride(ROLES_KEY, [context.getHandler(), context.getClass()]);
  }
}
` },
  { path: 'src/rate-limit.guard.ts', text: `
export class RateLimitGuard { canActivate() { return true; } }
` },
  { path: 'src/app.module.ts', text: `
import { APP_GUARD } from '@nestjs/core';
import { RateLimitGuard } from './rate-limit.guard';
export const providers = [{ provide: APP_GUARD, useClass: RateLimitGuard }];
` },
  { path: 'src/audit.controller.ts', text: `
import { Controller, Get, Patch, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from './auth.guard';
import { RolesGuard } from './roles.guard';
@Controller('admin')
export class AuditController {
  @UseGuards(JwtAuthGuard, RolesGuard) @Get('audit') audit() {}
  @Patch('projects/:id') unguardedMutation() {}
}
` },
]));
assert.equal(separated.routes.length, 2);
assert.equal(separated.applicationControls.length, 1);
assert.equal(separated.applicationControls[0].origin, 'RateLimitGuard');
const guarded = separated.routes.find((route) => route.method === 'GET');
assert.equal(guarded.authentication.state, 'local_observed');
assert.equal(guarded.authorization.state, 'candidate_observed');
assert.deepEqual(guarded.authentication.signals.map((signal) => signal.kind),
  ['nest-passport-derived-auth-guard']);
assert.deepEqual(guarded.authorization.signals.map((signal) => signal.kind),
  ['nest-metadata-authorization-guard-candidate']);
assert.notDeepEqual(guarded.authentication.signals, guarded.authorization.signals);
assert.equal(guarded.routeScopedControl.state, 'classified_controls_observed');
const unguarded = separated.routes.find((route) => route.method === 'PATCH');
assert.equal(unguarded.authentication.state, 'not_observed');
assert.equal(unguarded.authorization.state, 'not_observed');
assert.equal(unguarded.routeScopedControl.state, 'no_route_scoped_control_observed');
assert.ok(unguarded.priority.reasons.includes('no-route-scoped-control-observed'));
assert.equal(unguarded.authentication.signals.some((signal) =>
  signal.origin === 'RateLimitGuard'), false);
assert.equal(unguarded.authorization.signals.some((signal) =>
  signal.origin === 'RateLimitGuard'), false);

console.log('nest route extractor ok: decorators, scoped roles, application guards and lookalikes');
