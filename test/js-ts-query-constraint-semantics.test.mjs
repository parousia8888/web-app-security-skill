import assert from 'node:assert/strict';
import { analyzeAccessPaths } from '../scripts/lib/js-ts-access-path.mjs';
import { analyzeDataOperations } from '../scripts/lib/js-ts-data-operation-evidence.mjs';
import { buildJsTsCallableIndex } from '../scripts/lib/js-ts-callable-index.mjs';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { walkJsTsAst } from '../scripts/lib/js-ts-ast-parser.mjs';

const files = [
  { path: 'src/prisma.ts', text: `
import { PrismaClient } from '@prisma/client';
export const prisma = new PrismaClient();
` },
  { path: 'src/drizzle.ts', text: `
import { drizzle } from 'drizzle-orm/node-postgres';
export const db = drizzle({});
` },
  { path: 'src/handlers.ts', text: `
import { prisma } from './prisma';
import { db } from './drizzle';
import { eq as equals, and as all, or as either } from 'drizzle-orm';

const getDbClient = (tx?: unknown) => tx ?? prisma;

async function prismaObjectOnly(objectId, userId) {
  return prisma.order.findUnique({ where: { id: objectId } });
}
async function prismaSibling(objectId, userId) {
  return prisma.order.findFirst({ where: { id: objectId, ownerId: userId } });
}
async function prismaAnd(objectId, userId) {
  return prisma.order.findFirst({ where: { AND: [{ id: objectId }, { ownerId: userId }] } });
}
async function prismaOr(objectId, userId) {
  return prisma.order.findFirst({ where: { OR: [
    { id: objectId, ownerId: userId }, { id: objectId },
  ] } });
}
async function prismaNot(objectId, userId) {
  return prisma.order.findFirst({ where: { id: objectId, NOT: { ownerId: userId } } });
}
async function prismaCompound(objectId, userId, organizationId) {
  return prisma.membership.findUnique({ where: {
    userId_organizationId: { userId, organizationId }, id: objectId,
  } });
}
async function prismaSpread(objectId, userId, filters) {
  return prisma.order.findFirst({ where: { id: objectId, ownerId: userId, ...filters } });
}
async function prismaComputed(objectId, userId, field) {
  return prisma.order.findFirst({ where: { id: objectId, [field]: userId } });
}
async function prismaOpaque(objectId, userId) {
  return prisma.order.findFirst({ where: buildWhere(objectId, userId) });
}
async function omittedTx(objectId, userId) {
  return getDbClient().order.findFirst({ where: { id: objectId, ownerId: userId } });
}
async function explicitTx(objectId, userId, tx) {
  return getDbClient(tx).order.findFirst({ where: { id: objectId, ownerId: userId } });
}
async function membershipUncached(objectId, userId, organizationId, tx?: unknown) {
  return getDbClient(tx).membership.findUnique({ where: {
    userId_organizationId: { userId, organizationId }, id: objectId,
  } });
}
async function membershipService(objectId, userId, organizationId) {
  return membershipUncached(objectId, userId, organizationId);
}
async function membershipEntry(objectId, userId, organizationId) {
  return membershipService(objectId, userId, organizationId);
}
async function drizzleAnd(objectId, userId) {
  return db.select().from(orders).where(all(
    equals(orders.id, objectId), equals(userId, orders.ownerId),
  ));
}
async function drizzleOr(objectId, userId) {
  return db.select().from(orders).where(either(
    all(equals(orders.id, objectId), equals(orders.ownerId, userId)),
    equals(orders.id, objectId),
  ));
}
function eq(left, right) { return left === right; }
async function sameNameLocalEq(objectId) {
  return db.select().from(orders).where(eq(orders.id, objectId));
}
async function shadowedDb(objectId) {
  const db = { select() { return { where() {} }; } };
  return db.select().where(objectId);
}
async function shadowedPrisma(objectId) {
  const prisma = { order: { findUnique() {} } };
  return prisma.order.findUnique({ where: { id: objectId } });
}
` },
];

const graph = buildJsTsModuleGraph(files);
const callableIndex = buildJsTsCallableIndex(graph);
const module = graph.modules.get('src/handlers.ts');

function handler(name) {
  let found = null;
  walkJsTsAst(module.ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name === name) found = node;
  });
  assert.ok(found, name);
  return found;
}

function analyze(name) {
  return analyzeDataOperations(graph, module, handler(name), {
    objectAliases: new Set(['objectId']),
    principalAliases: new Set(['userId']),
    tenantAliases: new Set(['organizationId']),
    callableIndex,
  });
}

function operation(name) {
  const output = analyze(name);
  assert.equal(output.operations.length, 1, name);
  return output.operations[0];
}

const objectOnly = operation('prismaObjectOnly');
assert.equal(objectOnly.objectConstraint, 'observed');
assert.equal(objectOnly.principalConstraint, 'not_observed');
assert.equal(objectOnly.authorizationEvidence, null);

const sibling = operation('prismaSibling');
assert.equal(sibling.principalConstraint, 'observed');
assert.deepEqual(sibling.authorizationEvidence.map((item) => [item.category, item.field]),
  [['principal', 'ownerId']]);
assert.equal(sibling.authorizationEvidence[0].location.path, 'src/handlers.ts');

assert.equal(operation('prismaAnd').principalConstraint, 'observed');
assert.equal(operation('prismaOr').principalConstraint, 'not_observed');
assert.equal(operation('prismaNot').principalConstraint, 'not_observed');

const compound = operation('prismaCompound');
assert.equal(compound.principalConstraint, 'observed');
assert.equal(compound.tenantConstraint, 'observed');
assert.deepEqual(compound.authorizationEvidence.map((item) => item.field).sort(),
  ['organizationId', 'userId']);

for (const name of ['prismaSpread', 'prismaComputed', 'prismaOpaque']) {
  const item = operation(name);
  assert.equal(item.objectConstraint, 'incomplete', name);
  assert.equal(item.principalConstraint, 'incomplete', name);
  assert.ok(item.limitations.includes('constraint_expression_unresolved'), name);
}

assert.equal(operation('omittedTx').principalConstraint, 'observed');
const explicitTx = analyze('explicitTx');
assert.equal(explicitTx.operations.length, 0);
assert.deepEqual(explicitTx.incomplete.map((item) => item.code),
  ['prisma_client_identity_unresolved']);

const membershipPath = analyzeAccessPaths({
  graph,
  callableIndex,
  module,
  handler: handler('membershipEntry'),
  entry: { kind: 'route', id: 'route.membership', name: 'membershipEntry' },
  identity: { state: 'not_observed', provider: null, signals: [], boundary: 'fixture' },
  selectorGroups: [{
    selector: { kind: 'route-parameter', name: 'id', origin: 'request_selected',
      location: { path: module.path, line: 1 } },
    aliases: new Set(['objectId']),
    nodes: new Set(),
  }],
  principalAliases: new Set(['userId']),
  tenantAliases: new Set(['organizationId']),
});
const completedMembership = membershipPath.chains.find((item) => item.status === 'completed');
assert.ok(completedMembership);
assert.equal(completedMembership.callEdges.length, 2);
assert.equal(completedMembership.dataOperation.principalConstraint, 'observed');
assert.equal(completedMembership.dataOperation.tenantConstraint, 'observed');

const drizzleAnd = operation('drizzleAnd');
assert.equal(drizzleAnd.objectConstraint, 'observed');
assert.equal(drizzleAnd.principalConstraint, 'observed');
assert.equal(drizzleAnd.authorizationEvidence[0].field, 'ownerId');
assert.equal(operation('drizzleOr').principalConstraint, 'not_observed');

const localEq = operation('sameNameLocalEq');
assert.equal(localEq.objectConstraint, 'incomplete');
assert.equal(localEq.principalConstraint, 'incomplete');
assert.equal(analyze('shadowedDb').operations.length, 0);
const shadowedPrisma = analyze('shadowedPrisma');
assert.equal(shadowedPrisma.operations.length, 0);
assert.deepEqual(shadowedPrisma.incomplete.map((item) => item.code),
  ['prisma_client_identity_unresolved']);

console.log('js/ts query constraints ok: Prisma, Drizzle, exact tx omission and fail-closed predicates');
