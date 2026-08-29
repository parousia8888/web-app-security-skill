import assert from 'node:assert/strict';
import {
  buildJsTsCallableIndex, resolveCallableCall, resolveCallableExport,
} from '../scripts/lib/js-ts-callable-index.mjs';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { walkJsTsAst } from '../scripts/lib/js-ts-ast-parser.mjs';

function functionNode(module, name) {
  let found = null;
  walkJsTsAst(module.ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name === name) found = node;
    if (node.type === 'ClassMethod' && node.key?.name === name) found = node;
  });
  return found;
}

function calls(module, handler) {
  const found = [];
  walkJsTsAst(handler, (node) => {
    if (node.type === 'CallExpression') found.push(node);
  });
  return found;
}

const graph = buildJsTsModuleGraph([
  { path: 'src/direct.ts', text: `
export default function defaultLoad(id) { return id; }
export function namedLoad(id) { return id; }
export class LocalStore {
  load(id) { return id; }
  static staticLoad(id) { return id; }
}
` },
  { path: 'src/barrel-a.ts', text: "export { namedLoad as carriedLoad } from './direct';" },
  { path: 'src/barrel-b.ts', text: "export { carriedLoad as load } from './barrel-a';" },
  { path: 'src/service.ts', text: `
export default class ProjectService { find(id) { return id; } }
` },
  { path: 'src/wrapper.ts', text: 'export function wrap(value) { return value; }' },
  { path: 'src/entry.ts', text: `
import defaultLoad from './direct';
import { load } from './barrel-b';
import { LocalStore } from './direct';
import ProjectService from './service';
import { wrap } from './wrapper';
import { cache as reactCache } from 'react';
const local = (id) => id;
const store = new LocalStore();
export const directVariable = async (id) => id;
export const cached = reactCache(local);
export const cachedInline = reactCache(async (id) => id);
export const wrapped = wrap(local);
export const wrappedObject = wrap({ handler: async (id) => id });
export const unresolvedCache = reactCache(local, local);
function handler(id) {
  defaultLoad(id);
  load(id);
  store.load(id);
  LocalStore.staticLoad(id);
}
class Controller {
  constructor(private service: ProjectService) {}
  route(id) { return this.service.find(id); }
}
` },
], { configFiles: [{ path: 'tsconfig.json', text: '{"compilerOptions":{"paths":{"@/*":["src/*"]}}}' }] });
const index = buildJsTsCallableIndex(graph);
assert.equal(index.coverage.status, 'complete');
assert.equal(resolveCallableExport(index, 'src/entry.ts', 'directVariable').state, 'exact');

const entry = graph.modules.get('src/entry.ts');
const resolvedCalls = calls(entry, functionNode(entry, 'handler')).map((call) =>
  resolveCallableCall(index, entry, functionNode(entry, 'handler'), call));
assert.deepEqual(resolvedCalls.map((result) => result.edgeKind), [
  'local_import', 'local_reexport', 'class_method', 'static_member',
]);
assert.equal(resolvedCalls[1].target.name, 'namedLoad');

const nestCall = calls(entry, functionNode(entry, 'route'))[0];
const nest = resolveCallableCall(index, entry, functionNode(entry, 'route'), nestCall);
assert.equal(nest.state, 'exact');
assert.equal(nest.edgeKind, 'nest_injected_service');
assert.equal(nest.target.name, 'ProjectService.find');

for (const exported of ['cached', 'cachedInline']) {
  const result = resolveCallableExport(index, 'src/entry.ts', exported);
  assert.equal(result.state, 'exact');
  assert.equal(result.specialKind, 'react_cache_callback');
  assert.equal(Object.hasOwn(result, 'authentication'), false);
  assert.equal(Object.hasOwn(result, 'authorization'), false);
}
for (const exported of ['wrapped', 'wrappedObject']) {
  const result = resolveCallableExport(index, 'src/entry.ts', exported);
  assert.equal(result.state, 'exact');
  assert.equal(result.specialKind, 'wrapper_handler');
  assert.equal(result.wrapper.name, 'wrap');
  assert.equal(Object.hasOwn(result, 'authentication'), false);
  assert.equal(Object.hasOwn(result, 'authorization'), false);
}
const invalidCache = resolveCallableExport(index, 'src/entry.ts', 'unresolvedCache');
assert.equal(invalidCache.state, 'incomplete');
assert.equal(invalidCache.limitation, 'react_cache_callback_unresolved');

const aliasGraph = buildJsTsModuleGraph([
  { path: 'app/entry.ts', text: "import { load } from '@/load'; function handler(id) { return load(id); }" },
  { path: 'src/load.ts', text: 'export function load(id) { return id; }' },
], { configFiles: [{ path: 'tsconfig.json', text:
  '{"compilerOptions":{"baseUrl":".","paths":{"@/*":["src/*"]}}}' }] });
const aliasIndex = buildJsTsCallableIndex(aliasGraph);
const aliasModule = aliasGraph.modules.get('app/entry.ts');
const aliasHandler = functionNode(aliasModule, 'handler');
assert.equal(resolveCallableCall(aliasIndex, aliasModule, aliasHandler,
  calls(aliasModule, aliasHandler)[0]).state, 'exact');

const workspaceGraph = buildJsTsModuleGraph([
  { path: 'apps/web/entry.ts', text:
    "import { load } from '@workspace/data/load'; function handler(id) { return load(id); }" },
  { path: 'packages/data/src/load.ts', text: 'export function load(id) { return id; }' },
], { packageManifests: [{ path: 'packages/data/package.json', manifest: {
  name: '@workspace/data', exports: { './*': './src/*.ts' },
} }] });
const workspaceIndex = buildJsTsCallableIndex(workspaceGraph);
const workspaceModule = workspaceGraph.modules.get('apps/web/entry.ts');
const workspaceHandler = functionNode(workspaceModule, 'handler');
assert.equal(resolveCallableCall(workspaceIndex, workspaceModule, workspaceHandler,
  calls(workspaceModule, workspaceHandler)[0]).state, 'exact');

const cycleGraph = buildJsTsModuleGraph([
  { path: 'src/a.ts', text: "export * from './b';" },
  { path: 'src/b.ts', text: "export * from './a';" },
  { path: 'src/entry.ts', text: "import { load } from './a'; function handler(id) { return load(id); }" },
]);
const cycleIndex = buildJsTsCallableIndex(cycleGraph);
const cycleModule = cycleGraph.modules.get('src/entry.ts');
const cycleHandler = functionNode(cycleModule, 'handler');
const cycle = resolveCallableCall(cycleIndex, cycleModule, cycleHandler,
  calls(cycleModule, cycleHandler)[0]);
assert.equal(cycle.state, 'incomplete');
assert.equal(cycle.reason, 'reexport_unresolved');
assert.equal(cycle.limitation, 'callable_reexport_cycle');

const ambiguousGraph = buildJsTsModuleGraph([
  { path: 'src/a.ts', text: 'export function load(id) { return id; }' },
  { path: 'src/b.ts', text: 'export function load(id) { return id; }' },
  { path: 'src/barrel.ts', text: "export * from './a'; export * from './b';" },
  { path: 'src/entry.ts', text: "import { load } from './barrel'; function handler(id) { return load(id); }" },
]);
const ambiguousIndex = buildJsTsCallableIndex(ambiguousGraph);
const ambiguousModule = ambiguousGraph.modules.get('src/entry.ts');
const ambiguousHandler = functionNode(ambiguousModule, 'handler');
const ambiguous = resolveCallableCall(ambiguousIndex, ambiguousModule, ambiguousHandler,
  calls(ambiguousModule, ambiguousHandler)[0]);
assert.equal(ambiguous.state, 'incomplete');
assert.equal(ambiguous.reason, 'call_target_ambiguous');

const depthLimited = buildJsTsCallableIndex(graph, { maxReexportDepth: 0 });
const depthResult = resolveCallableCall(depthLimited, entry, functionNode(entry, 'handler'),
  calls(entry, functionNode(entry, 'handler'))[1]);
assert.equal(depthResult.state, 'incomplete');
assert.equal(depthResult.limitation, 'callable_reexport_depth_limit');

const dynamicGraph = buildJsTsModuleGraph([
  { path: 'src/entry.ts', text: `
function dynamicHandler(service, method, id) { return service[method](id); }
function containerHandler(container, id) { return container.get('service').load(id); }
` },
]);
const dynamicIndex = buildJsTsCallableIndex(dynamicGraph);
const dynamicModule = dynamicGraph.modules.get('src/entry.ts');
for (const name of ['dynamicHandler', 'containerHandler']) {
  const handler = functionNode(dynamicModule, name);
  const result = resolveCallableCall(dynamicIndex, dynamicModule, handler,
    calls(dynamicModule, handler)[0]);
  assert.equal(result.state, 'incomplete');
  assert.equal(result.reason, 'dynamic_dispatch_unresolved');
}

const limited = buildJsTsCallableIndex(graph, { maxCallables: 1 });
assert.equal(limited.coverage.status, 'partial');
assert.ok(limited.coverage.reasons.some((reason) => reason.code === 'callable_index_callable_limit'));
assert.ok(limited.coverage.counts.callables <= 1);

console.log('js/ts callable index ok: imports, re-exports, classes, Nest DI, wrappers, cache and fail-closed limits');
