import assert from 'node:assert/strict';
import { analyzeOneHopAccess } from '../scripts/lib/js-ts-one-hop-access.mjs';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { walkJsTsAst } from '../scripts/lib/js-ts-ast-parser.mjs';

const files = [
  { path: 'src/db.ts', text: `
import { PrismaClient } from '@prisma/client';
export const db = new PrismaClient();
` },
  { path: 'src/repository.ts', text: `
import { db } from './db';
export function loadProject(id, userId) {
  return db.project.findFirst({ where: { id, ownerId: userId } });
}
export function secondHop(id) { return loadProject(id, 'unknown'); }
` },
  { path: 'src/service.ts', text: `
import { db } from './db';
export class ProjectService {
  find(id, userId) { return db.project.findFirst({ where: { id, ownerId: userId } }); }
}
` },
  { path: 'src/barrel.ts', text: "export { loadProject as carriedLoad } from './repository';" },
  { path: 'src/default-repository.ts', text: `
import { db } from './db';
export default function defaultLoad(id, userId) {
  return db.project.findFirst({ where: { id, ownerId: userId } });
}
` },
  { path: 'src/entry.ts', text: `
import { loadProject, secondHop } from './repository';
import { carriedLoad } from './barrel';
import defaultLoad from './default-repository';
import { ProjectService } from './service';
import { db } from './db';
function sameFile(id) { return loadProject(id, 'unknown'); }
function sameFileDirect(id, userId) {
  return db.project.findFirst({ where: { id, ownerId: userId } });
}
function importedHandler(objectId, userId) { return loadProject(objectId, userId); }
function reexportedHandler(objectId, userId) { return carriedLoad(objectId, userId); }
function defaultHandler(objectId, userId) { return defaultLoad(objectId, userId); }
function sameFileHandler(objectId) { return sameFile(objectId); }
function sameFileDirectHandler(objectId, userId) { return sameFileDirect(objectId, userId); }
function twoHopHandler(objectId) { return secondHop(objectId); }
function spreadHandler(objectId, userId) { return loadProject(...[objectId, userId]); }
class Controller {
  constructor(private service: ProjectService) {}
  nestHandler(objectId, userId) { return this.service.find(objectId, userId); }
}
function benignHandler(objectId) { return externalClient.load(objectId); }
` },
];

const graph = buildJsTsModuleGraph(files);
const module = graph.modules.get('src/entry.ts');
function handler(name) {
  let found = null;
  walkJsTsAst(module.ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name === name) found = node;
    if (node.type === 'ClassMethod' && node.key?.name === name) found = node;
  });
  return found;
}
function analyze(name) {
  return analyzeOneHopAccess({
    graph, module, handler: handler(name),
    entry: { kind: 'route', id: `route.${name}`, name, module },
    identity: { state: 'not_observed', provider: null, signals: [], boundary: 'fixture' },
    objectAliases: new Set(['objectId']), principalAliases: new Set(['userId']),
    objectSelectors: [{ kind: 'route-parameter', name: 'id', location: { path: module.path, line: 1 } }],
  });
}

const imported = analyze('importedHandler');
assert.equal(imported.length, 1);
assert.equal(imported[0].callEdges[0].kind, 'local_import');
assert.equal(imported[0].entryId, 'route.importedHandler');
assert.equal(imported[0].outcome, 'principal_constraint_observed');
const reexported = analyze('reexportedHandler');
assert.equal(reexported.length, 1);
assert.equal(reexported[0].callEdges[0].kind, 'local_reexport');
assert.equal(reexported[0].outcome, 'principal_constraint_observed');
const defaultImported = analyze('defaultHandler');
assert.equal(defaultImported.length, 1);
assert.equal(defaultImported[0].callEdges[0].kind, 'local_import');
assert.equal(defaultImported[0].outcome, 'principal_constraint_observed');
const sameFile = analyze('sameFileHandler');
assert.equal(sameFile.length, 1);
assert.equal(sameFile[0].status, 'partial');
assert.equal(sameFile[0].reason, 'second_local_call_edge_not_followed');
const sameFileDirect = analyze('sameFileDirectHandler');
assert.equal(sameFileDirect.length, 1);
assert.equal(sameFileDirect[0].status, 'completed');
assert.equal(sameFileDirect[0].outcome, 'principal_constraint_observed');
const twoHop = analyze('twoHopHandler');
assert.equal(twoHop.length, 1);
assert.equal(twoHop[0].status, 'partial');
assert.equal(twoHop[0].reason, 'second_local_call_edge_not_followed');
const spread = analyze('spreadHandler');
assert.equal(spread.length, 1);
assert.equal(spread[0].status, 'partial');
assert.equal(spread[0].reason, 'one_hop_spread_or_rest_ambiguous');
const nest = analyze('nestHandler');
assert.equal(nest.length, 1);
assert.equal(nest[0].callEdges[0].kind, 'nest_injected_service');
assert.equal(nest[0].outcome, 'principal_constraint_observed');
assert.equal(analyze('benignHandler').length, 0);

const aliasGraph = buildJsTsModuleGraph([
  { path: 'app/route.ts', text: `
import { loadProject } from '@/repository';
function aliasHandler(objectId, userId) { return loadProject(objectId, userId); }
` },
  { path: 'repository.ts', text: `
import { PrismaClient } from '@prisma/client';
const db = new PrismaClient();
export function loadProject(id, userId) {
  return db.project.findFirst({ where: { id, ownerId: userId } });
}
` },
], { configFiles: [{ path: 'tsconfig.json', text: '{"compilerOptions":{"paths":{"@/*":["./*"]}}}' }] });
const aliasModule = aliasGraph.modules.get('app/route.ts');
let aliasHandler = null;
walkJsTsAst(aliasModule.ast, (node) => {
  if (node.type === 'FunctionDeclaration' && node.id?.name === 'aliasHandler') aliasHandler = node;
});
const aliasResult = analyzeOneHopAccess({
  graph: aliasGraph, module: aliasModule, handler: aliasHandler,
  entry: { kind: 'route', id: 'route.alias', name: 'aliasHandler', module: aliasModule },
  identity: { state: 'not_observed', provider: null, signals: [], boundary: 'fixture' },
  objectAliases: new Set(['objectId']), principalAliases: new Set(['userId']),
  objectSelectors: [{ kind: 'route-parameter', name: 'id', location: { path: aliasModule.path, line: 1 } }],
});
assert.equal(aliasResult.length, 1);
assert.equal(aliasResult[0].outcome, 'principal_constraint_observed');

console.log('access-control one-hop ok: relative/alias import, same-file stop, Nest injection and benign external call');
