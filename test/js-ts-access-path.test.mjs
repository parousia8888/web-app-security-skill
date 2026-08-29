import assert from 'node:assert/strict';
import { analyzeAccessPaths, createAccessPathBudget } from '../scripts/lib/js-ts-access-path.mjs';
import { buildJsTsCallableIndex } from '../scripts/lib/js-ts-callable-index.mjs';
import { summarizeCallable } from '../scripts/lib/js-ts-function-summary.mjs';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { walkJsTsAst } from '../scripts/lib/js-ts-ast-parser.mjs';

const files = [
  { path: 'src/db.ts', text: `
import { PrismaClient } from '@prisma/client';
export const prisma = new PrismaClient();
` },
  { path: 'src/repository.ts', text: `
import { prisma } from './db';
export function constrained(id, owner) {
  return prisma.project.findFirst({ where: { id, ownerId: owner } });
}
export function unconstrained(id) {
  return prisma.project.findUnique({ where: { id } });
}
export function objectInput({ projectId, principalId }) {
  return prisma.project.findFirst({ where: { id: projectId, ownerId: principalId } });
}
` },
  { path: 'src/service.ts', text: `
import { constrained, unconstrained, objectInput } from './repository';
export function levelFour(id, principal) { return constrained(id, principal); }
export function levelThree(id, principal) { return levelFour(String(id), principal); }
export function levelTwo(id, principal) { return levelThree(id, principal); }
export function levelOne(id, principal) { return levelTwo(id, principal); }
export function levelZero(id, principal) { return levelOne(id, principal); }
export function unsafe(id) { return unconstrained(id); }
export function objectBridge(id, principal) {
  const input = { projectId: id, principalId: principal };
  return objectInput(input);
}
export function cycleA(id) { return cycleB(id); }
export function cycleB(id) { return cycleA(id); }
export function arrayBridge(id) { return constrained(...[id, 'principal']); }
` },
  { path: 'src/entry.ts', text: `
import { constrained } from './repository';
import { levelFour, levelThree, levelTwo, levelOne, unsafe, objectBridge, cycleA, arrayBridge } from './service';
function zero(objectId, principalId) {
  return localPrisma.project.findFirst({ where: { id: objectId, ownerId: principalId } });
}
function one(objectId, principalId) { return constrained(objectId, principalId); }
function two(objectId, principalId) { return levelFour(objectId, principalId); }
function three(objectId, principalId) { return levelThree(objectId, principalId); }
function four(objectId, principalId) { return levelTwo(objectId, principalId); }
function five(objectId, principalId) { return levelOne(objectId, principalId); }
function noOwner(objectId) { return unsafe(objectId); }
function objectPath(objectId, principalId) { return objectBridge(objectId, principalId); }
function cyclic(objectId) { return cycleA(objectId); }
function arrayPath(objectId) { return arrayBridge(objectId); }
function swappedFacts(objectId, principalId) { return constrained(principalId, objectId); }
function unrelatedRest(objectId) {
  const { ignored, ...rest } = { ignored: true, note: 'not access-control input' };
  return localPrisma.project.findUnique({ where: { id: objectId } });
}
function relevantRest(input) {
  const { objectId, ...rest } = input;
  return localPrisma.project.findUnique({ where: { id: objectId } });
}
` },
];
// The direct fixture needs its own exact Prisma singleton in the entry module.
files[3].text = `import { PrismaClient } from '@prisma/client';\nconst localPrisma = new PrismaClient();\n${files[3].text}`;
const graph = buildJsTsModuleGraph(files);
const index = buildJsTsCallableIndex(graph);
const module = graph.modules.get('src/entry.ts');

function handler(name) {
  let found = null;
  walkJsTsAst(module.ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name === name) found = node;
  });
  return found;
}

function analyze(name, options = {}) {
  return analyzeAccessPaths({
    graph,
    callableIndex: index,
    module,
    handler: handler(name),
    entry: { kind: 'route', id: `route.${name}`, name },
    identity: { state: 'not_observed', provider: null, signals: [], boundary: 'fixture' },
    selectorGroups: [{
      selector: { kind: 'route-parameter', name: 'id', origin: 'request_selected',
        location: { path: module.path, line: 1 } },
      aliases: new Set(['objectId']),
      nodes: new Set(),
    }],
    principalAliases: new Set(['principalId']),
    tenantAliases: new Set(['tenantId']),
    ...options,
  });
}

for (const [name, edges] of [['zero', 0], ['one', 1], ['two', 2], ['three', 3], ['four', 4]]) {
  const result = analyze(name);
  const completed = result.chains.find((chain) => chain.status === 'completed');
  assert.ok(completed, name);
  assert.equal(completed.callEdges.length, edges, name);
  assert.equal(completed.outcome, 'principal_constraint_observed', name);
}
const fifth = analyze('five');
assert.equal(fifth.chains.some((chain) => chain.status === 'completed'), false);
assert.ok(fifth.chains.some((chain) => chain.reason === 'call_depth_limit_reached'));
assert.equal(fifth.chains.find((chain) => chain.reason === 'call_depth_limit_reached').callEdges.length, 4);

const unconstrained = analyze('noOwner');
assert.equal(unconstrained.chains.find((chain) => chain.status === 'completed').outcome,
  'principal_constraint_not_observed');
const objectPath = analyze('objectPath');
assert.equal(objectPath.chains.find((chain) => chain.status === 'completed').outcome,
  'principal_constraint_observed');
assert.equal(objectPath.chains.find((chain) => chain.status === 'completed').callEdges.length, 2);

const cycle = analyze('cyclic');
assert.ok(cycle.chains.some((chain) => chain.reason === 'call_cycle_detected'));
const array = analyze('arrayPath');
assert.ok(array.chains.some((chain) => chain.reason === 'argument_mapping_ambiguous'));
assert.equal(array.chains.some((chain) => chain.status === 'completed'), false);
const swapped = analyze('swappedFacts');
assert.equal(swapped.chains.some((chain) => chain.status === 'completed'), false);
const unrelatedRest = analyze('unrelatedRest');
assert.deepEqual(unrelatedRest.chains.find((chain) => chain.status === 'completed').limitations, [],
  'unrelated object rest must not contaminate an exact tracked path');
const relevantRest = analyze('relevantRest', { selectorGroups: [{
  selector: { kind: 'route-parameter', name: 'id', origin: 'request_selected',
    location: { path: module.path, line: 1 } },
  aliases: new Set(['input.objectId']), nodes: new Set(),
}] });
assert.ok(relevantRest.chains.find((chain) => chain.status === 'completed').limitations
  .includes('destructuring_mapping_ambiguous'),
'rest on a tracked object must retain an explicit evidence limitation');

const stateLimited = analyze('two', { limits: { maxActiveStatesPerEntry: 1 } });
assert.ok(stateLimited.chains.some((chain) => chain.reason === 'call_state_budget_reached'));
const transitionLimited = analyze('two', { budget: createAccessPathBudget(0) });
assert.ok(transitionLimited.chains.some((chain) => chain.reason === 'transition_budget_reached'));

const returnGraph = buildJsTsModuleGraph([{ path: 'src/returns.ts', text: `
function load(id) { return id; }
async function direct(id) { return await load(id); }
async function assigned(id) { const value = await load(id); return value; }
async function single(id) { const [record] = await load(id); return record; }
async function indexed(id) { const record = (await load(id))[0]; return record; }
` }]);
const returnIndex = buildJsTsCallableIndex(returnGraph);
const returnModule = returnGraph.modules.get('src/returns.ts');
function returnHandler(name) {
  let found = null;
  walkJsTsAst(returnModule.ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name === name) found = node;
  });
  return found;
}
const target = (name) => ({ id: `return.${name}`, module: returnModule,
  node: returnHandler(name), name, kind: 'function' });
assert.equal(summarizeCallable(returnIndex, target('direct')).calls[0].resultMapping.kind, 'direct_return');
assert.equal(summarizeCallable(returnIndex, target('assigned')).calls[0].resultMapping.kind, 'identifier');
assert.equal(summarizeCallable(returnIndex, target('single')).calls[0].resultMapping.kind,
  'single_element_array');
assert.equal(summarizeCallable(returnIndex, target('indexed')).calls[0].resultMapping.reason,
  'return_mapping_unresolved');

const repeatA = analyze('objectPath');
const repeatB = analyze('objectPath');
assert.deepEqual(repeatA.chains, repeatB.chains);
assert.deepEqual(repeatA.coverage, repeatB.coverage);

console.log('js/ts access path ok: 0-4 edges, budgets, cycles, typed mappings and return shapes');
