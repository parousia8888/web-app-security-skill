#!/usr/bin/env node
import assert from 'node:assert/strict';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { walkJsTsAst } from '../scripts/lib/js-ts-ast-parser.mjs';
import { extractSelectorEvidence } from '../scripts/lib/js-ts-selector-evidence.mjs';
import { importedBindings } from '../scripts/lib/frameworks/route-extractor-helpers.mjs';

function handlerIn(module, name) {
  let found = null;
  walkJsTsAst(module.ast, (node) => {
    if (found) return;
    if (node.type === 'FunctionDeclaration' && node.id?.name === name) found = node;
    if (['ClassMethod', 'ClassPrivateMethod'].includes(node.type)
        && node.key?.name === name) found = node;
  });
  assert.ok(found, `missing handler ${name}`);
  return found;
}

function extract(path, text, name, options) {
  const graph = buildJsTsModuleGraph([{ path, text }]);
  const module = graph.modules.get(path);
  assert.ok(module?.ast);
  return extractSelectorEvidence({ module, handler: handlerIn(module, name),
    imports: importedBindings(module), ...options });
}

const express = extract('src/express.ts', `
export async function handler(req, res) {
  const requestAlias = req;
  const query = requestAlias.query;
  const { projectId: selectedProject } = query;
  const bodyProject = req.body.projectId;
  const pathProject = req.params.projectId;
  const searchTerm = req.query.term;
  const fixedId = 'server-owned';
  const principalId = req.user.id;
  return [selectedProject, bodyProject, pathProject, searchTerm, fixedId, principalId];
}
`, 'handler', { framework: 'express', routePath: '/projects/:projectId',
  principalAliases: new Set(['req.user.id']) });
assert.deepEqual(express.selectors.map((item) => `${item.kind}:${item.name}`), [
  'express-query-field:projectId',
  'express-body-field:projectId',
  'express-path-param:projectId',
]);
assert.ok(express.objectAliases.has('selectedProject'));
assert.ok(express.objectAliases.has('bodyProject'));
assert.ok(express.objectAliases.has('pathProject'));
assert.equal(express.facts.get('fixedId').origin, 'constant');
assert.equal(express.facts.get('principalId').origin, 'principal_derived');
assert.equal(express.objectAliases.has('fixedId'), false);
assert.equal(express.objectAliases.has('principalId'), false);
assert.equal(express.facts.has('searchTerm'), false);
assert.equal(express.facts.has('id'), false);
assert.deepEqual(express.limitations, []);

const expressDestructured = extract('src/destructured.ts', `
export async function handler({ query, body }, res) {
  const { accountId } = query;
  const { projectId: selected } = body;
  return [accountId, selected];
}
`, 'handler', { framework: 'express', routePath: '/lookup' });
assert.ok(expressDestructured.objectAliases.has('accountId'));
assert.ok(expressDestructured.objectAliases.has('selected'));

const nest = extract('src/controller.ts', `
import { Body as Payload, Controller, Get, Param, Query } from '@nestjs/common';
@Controller('projects')
class ProjectController {
  @Get(':projectId')
  read(@Param('projectId') selected, @Query() query, @Payload() dto) {
    const { accountId } = query;
    const bodyProject = dto.projectId;
    return [selected, accountId, bodyProject];
  }
}
`, 'read', { framework: 'nestjs', routePath: '/projects/:projectId' });
assert.deepEqual(nest.selectors.map((item) => `${item.kind}:${item.name}`).sort(), [
  'nest-body-field:projectId',
  'nest-path-param:projectId',
  'nest-query-field:accountId',
]);
assert.ok(nest.objectAliases.has('selected'));
assert.ok(nest.objectAliases.has('accountId'));
assert.ok(nest.objectAliases.has('bodyProject'));

const nextRoute = extract('src/app/projects/[projectId]/route.ts', `
export async function POST(request, { params }) {
  const { projectId: pathProject } = await params;
  const { searchParams } = new URL(request.url);
  const queryProject = searchParams.get('accountId');
  const body = await request.json();
  const { projectId: bodyProject } = body;
  return [pathProject, queryProject, bodyProject];
}
`, 'POST', { framework: 'next-app', routePath: '/projects/[projectId]' });
assert.deepEqual(nextRoute.selectors.map((item) => `${item.kind}:${item.name}`).sort(), [
  'next-json-field:projectId',
  'next-route-param:projectId',
  'next-search-param:accountId',
]);
assert.ok(nextRoute.objectAliases.has('pathProject'));
assert.ok(nextRoute.objectAliases.has('queryProject'));
assert.ok(nextRoute.objectAliases.has('bodyProject'));

const transformedBody = extract('src/app/transformed/route.ts', `
export async function POST(request) {
  const { projectId } = schema.parse(await request.json());
  return projectId;
}
`, 'POST', { framework: 'next-app', routePath: '/transformed' });
assert.equal(transformedBody.selectors[0].name, 'projectId');
assert.equal(transformedBody.selectors[0].origin, 'unknown');
assert.equal(transformedBody.objectAliases.size, 0);
assert.ok(transformedBody.limitations.some((item) => item.code === 'selector_transform_unresolved'));

const nextDirectSearch = extract('src/app/search/route.ts', `
export async function GET(request) {
  return request.nextUrl.searchParams.get('projectId');
}
`, 'GET', { framework: 'next-app', routePath: '/search' });
assert.equal(nextDirectSearch.selectors[0].kind, 'next-search-param');
assert.equal(nextDirectSearch.objectAliases.size, 0);
assert.equal(nextDirectSearch.objectNodes.size, 1);

const action = extract('src/actions.ts', `
export async function updateProject({ projectId: selected }, formData, unrelated) {
  'use server';
  const account = formData.get('accountId');
  const term = formData.get('term');
  return [selected, account, term, unrelated];
}
`, 'updateProject', { entryKind: 'server-action' });
assert.deepEqual(action.selectors.map((item) => `${item.kind}:${item.name}`).sort(), [
  'action-parameter:projectId',
  'form-data-field:accountId',
]);
assert.ok(action.objectAliases.has('selected'));
assert.ok(action.objectAliases.has('account'));
assert.equal(action.facts.has('term'), false);

const dynamic = extract('src/dynamic.ts', `
export async function handler(req, res) {
  const selected = req.body[req.query.field];
  let projectId = req.query.projectId;
  projectId = 'server-owned';
  return [selected, projectId];
}
`, 'handler', { framework: 'express', routePath: '/dynamic' });
assert.ok(dynamic.selectors.some((item) => item.origin === 'unknown' && item.name === 'unknown'));
assert.equal(dynamic.facts.get('projectId').origin, 'unknown');
assert.equal(dynamic.objectAliases.has('projectId'), false);
assert.deepEqual(new Set(dynamic.limitations.map((item) => item.code)), new Set([
  'selector_dynamic_field_unresolved', 'selector_alias_ambiguous',
]));

const repeatedBody = extract('src/app/repeated/route.ts', `
export async function POST(request) {
  const requestAlias = request;
  const first = await request.json();
  const second = await requestAlias.json();
  return [first.projectId, second.accountId];
}
`, 'POST', { framework: 'next-app', routePath: '/repeated' });
assert.ok(repeatedBody.selectors.every((item) => item.origin === 'unknown'));
assert.equal(repeatedBody.objectAliases.size, 0);
assert.ok(repeatedBody.limitations.some((item) => item.code === 'selector_body_parse_repeated'));

const dynamicNest = extract('src/dynamic-controller.ts', `
import { Controller, Get, Query } from '@nestjs/common';
@Controller('lookup')
class LookupController {
  @Get() read(@Query(fieldName) selected) { return selected; }
}
`, 'read', { framework: 'nestjs', routePath: '/lookup' });
assert.equal(dynamicNest.selectors[0].origin, 'unknown');
assert.ok(dynamicNest.limitations.some((item) => item.code === 'selector_dynamic_field_unresolved'));

const dynamicAction = extract('src/dynamic-action.ts', `
export async function update(formData, fieldName) {
  'use server';
  return formData.get(fieldName);
}
`, 'update', { entryKind: 'server-action' });
assert.equal(dynamicAction.selectors[0].origin, 'unknown');
assert.ok(dynamicAction.limitations.some((item) => item.code === 'selector_dynamic_field_unresolved'));

const benignSlug = extract('src/slug.ts', `
export async function handler(req) { return req.params.slug; }
`, 'handler', { framework: 'express', routePath: '/docs/:slug' });
assert.equal(benignSlug.selectors.length, 0);
assert.equal(benignSlug.objectAliases.size, 0);

const serializedSelectors = JSON.stringify(express.selectors);
assert.equal(serializedSelectors.includes('server-owned'), false);
assert.equal(serializedSelectors.includes('req.query'), false);
assert.equal(serializedSelectors.includes('requestAlias'), false);

console.log('selector evidence ok: shared route/action origins, exact aliases, benign neighbours and fail-closed dynamic shapes');
