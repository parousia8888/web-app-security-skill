import assert from 'node:assert/strict';
import { analyzeAccessPaths } from '../scripts/lib/js-ts-access-path.mjs';
import { buildJsTsCallableIndex } from '../scripts/lib/js-ts-callable-index.mjs';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { walkJsTsAst } from '../scripts/lib/js-ts-ast-parser.mjs';

const files = [
  { path: 'src/db.ts', text: `
import { drizzle } from 'drizzle-orm/node-postgres';
export const db = drizzle({});
` },
  { path: 'src/repository.ts', text: `
import { eq } from 'drizzle-orm';
import { db } from './db';
export async function loadChat(id) {
  const [selectedChat] = await db.select().from(chat).where(eq(chat.id, id));
  if (!selectedChat) return null;
  return selectedChat;
}
export async function loadDocuments(id) {
  const documents = await db.select().from(document).where(eq(document.id, id));
  return documents;
}
` },
  { path: 'src/entry.ts', text: `
import { eq } from 'drizzle-orm';
import { db } from './db';
import { loadChat, loadDocuments } from './repository';
import { policy } from './missing-policy';

async function direct(objectId, principalId) {
  const chat = await loadChat(objectId);
  if (chat?.userId !== principalId) throw new Error('forbidden');
}
async function strictEquality(objectId, principalId) {
  const chat = await loadChat(objectId);
  return chat.ownerId === principalId;
}
async function singleElement(objectId, principalId) {
  const documents = await loadDocuments(objectId);
  const [document] = documents;
  if (document.userId !== principalId) throw new Error('forbidden');
}
async function directFieldAlias(objectId, principalId) {
  const chat = await loadChat(objectId);
  const owner = chat.ownerId;
  return owner === principalId;
}
function exactOwner(resource, principal) {
  return resource.ownerId === principal;
}
async function exactHelper(objectId, principalId) {
  const chat = await loadChat(objectId);
  return exactOwner(chat, principalId);
}
async function tenantComparison(objectId, tenantId) {
  const chat = await loadChat(objectId);
  return chat.organizationId !== tenantId;
}
async function loggingOnly(objectId, principalId) {
  const chat = await loadChat(objectId);
  console.log(chat.userId === principalId);
  metrics.record(chat, principalId);
  return chat;
}
async function unrelatedEquality(objectId, principalId) {
  const chat = await loadChat(objectId);
  return chat.title === principalId;
}
async function indexed(objectId, principalId) {
  const documents = await loadDocuments(objectId);
  const document = documents[0];
  return document.userId === principalId;
}
async function opaquePolicy(objectId, principalId) {
  const chat = await loadChat(objectId);
  return policy(chat, principalId);
}
async function sameHandler(objectId, principalId) {
  const [chatRecord] = await db.select().from(chat).where(eq(chat.id, objectId));
  return chatRecord.userId !== principalId;
}
` },
];

const graph = buildJsTsModuleGraph(files);
const callableIndex = buildJsTsCallableIndex(graph);
const module = graph.modules.get('src/entry.ts');

function handler(name) {
  let found = null;
  walkJsTsAst(module.ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name === name) found = node;
  });
  assert.ok(found, name);
  return found;
}

function analyze(name, options = {}) {
  return analyzeAccessPaths({
    graph,
    callableIndex,
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

function completed(name) {
  const chain = analyze(name).chains.find((item) => item.status === 'completed');
  assert.ok(chain, name);
  return chain;
}

for (const name of ['direct', 'strictEquality', 'singleElement', 'directFieldAlias',
  'exactHelper', 'tenantComparison', 'sameHandler']) {
  const chain = completed(name);
  assert.equal(chain.outcome, 'principal_constraint_observed', name);
  const comparison = chain.authorizationEvidence.find((item) =>
    item.kind === 'post_load_comparison' && item.state === 'observed');
  assert.ok(comparison, name);
  assert.equal(Object.hasOwn(comparison, 'denialObserved'), false, name);
  assert.match(chain.evidenceBoundary, /does not prove control-flow dominance/);
}

assert.equal(completed('tenantComparison').authorizationEvidence[0].category, 'tenant');
assert.equal(completed('singleElement').authorizationEvidence[0].field, 'userId');
assert.equal(completed('directFieldAlias').authorizationEvidence[0].field, 'ownerId');
assert.equal(completed('exactHelper').authorizationEvidence[0].location.path, 'src/entry.ts');

for (const name of ['loggingOnly', 'unrelatedEquality']) {
  const chain = completed(name);
  assert.equal(chain.outcome, 'principal_constraint_not_observed', name);
  assert.equal(chain.authorizationEvidence, null, name);
}

for (const name of ['indexed', 'opaquePolicy']) {
  const chain = completed(name);
  assert.equal(chain.outcome, 'incomplete', name);
  assert.ok(chain.authorizationEvidence.some((item) =>
    item.kind === 'post_load_comparison' && item.state === 'incomplete'), name);
}
assert.ok(completed('indexed').limitations.includes('return_mapping_unresolved'));
assert.ok(completed('opaquePolicy').limitations.includes('module_resolution_missing'));

console.log('js/ts post-load comparison ok: returns, one-element binding, exact helper and ambiguity');
