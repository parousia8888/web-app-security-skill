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
assert.equal(patch.authentication.state, 'candidate_observed');
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

console.log('nest route extractor ok: decorators, class/method guards, public override and lookalikes');
