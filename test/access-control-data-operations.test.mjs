import assert from 'node:assert/strict';
import { analyzeDataOperations } from '../scripts/lib/js-ts-data-operation-evidence.mjs';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { walkJsTsAst } from '../scripts/lib/js-ts-ast-parser.mjs';

const files = [
  { path: 'src/db.ts', text: `
import { drizzle } from 'drizzle-orm/node-postgres';
export const db = drizzle({});
` },
  { path: 'src/supabase.ts', text: `
import { createServerClient } from '@supabase/ssr';
export function createClient() { return createServerClient('url', 'key', {}); }
` },
  { path: 'src/handlers.ts', text: `
import { PrismaClient } from '@prisma/client';
import { eq, and } from 'drizzle-orm';
import { db } from './db';
import { createClient } from './supabase';
const prisma = new PrismaClient();
async function prismaUnsafe(objectId, userId) {
  return prisma.order.findUnique({ where: { id: objectId } });
}
async function prismaSafe(objectId, userId) {
  return prisma.order.findFirst({ where: { id: objectId, ownerId: userId } });
}
async function drizzleUnsafe(objectId, userId) {
  return db.select().from(orders).where(eq(orders.id, objectId));
}
async function drizzleSafe(objectId, userId) {
  return db.select().from(orders).where(and(eq(orders.id, objectId), eq(orders.ownerId, userId)));
}
async function supabaseUnsafe(objectId, userId) {
  const client = await createClient();
  return client.from('orders').select('*').eq('id', objectId);
}
async function supabaseSafe(objectId, tenantId) {
  const client = await createClient();
  return client.from('orders').update({ status: 'done' }).eq('id', objectId).eq('tenant_id', tenantId);
}
async function supabasePrincipalIsNotTenant(objectId, userId) {
  const client = await createClient();
  return client.from('orders').update({ status: 'done' }).eq('id', objectId).eq('tenant_id', userId);
}
async function benign(objectId) {
  const db = { select() { return { where() {} }; } };
  return db.select().where(objectId);
}
` },
];

const graph = buildJsTsModuleGraph(files);
const module = graph.modules.get('src/handlers.ts');
function handler(name) {
  let found = null;
  walkJsTsAst(module.ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name === name) found = node;
  });
  return found;
}
function operation(name) {
  const result = analyzeDataOperations(graph, module, handler(name), {
    objectAliases: new Set(['objectId']), principalAliases: new Set(['userId']),
    tenantAliases: new Set(['tenantId']),
  });
  assert.equal(result.operations.length, 1, name);
  return result.operations[0];
}

assert.equal(operation('prismaUnsafe').principalConstraint, 'not_observed');
assert.equal(operation('prismaSafe').principalConstraint, 'observed');
assert.equal(operation('drizzleUnsafe').principalConstraint, 'not_observed');
assert.equal(operation('drizzleSafe').principalConstraint, 'observed');
const supabaseUnsafe = operation('supabaseUnsafe');
assert.equal(supabaseUnsafe.principalConstraint, 'not_observed');
assert.equal(supabaseUnsafe.externalPolicy, 'external_policy_required');
const supabaseSafe = operation('supabaseSafe');
assert.equal(supabaseSafe.tenantConstraint, 'observed');
assert.equal(supabaseSafe.externalPolicy, 'external_policy_required');
assert.equal(operation('supabasePrincipalIsNotTenant').tenantConstraint, 'not_observed');
assert.equal(analyzeDataOperations(graph, module, handler('benign'), {
  objectAliases: new Set(['objectId']), principalAliases: new Set(),
}).operations.length, 0);

console.log('access-control data operations ok: Prisma, Drizzle, Supabase constraints and shadowed client');
