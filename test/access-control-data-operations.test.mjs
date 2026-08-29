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

const generatedFacadeFiles = [
  { path: 'apps/web/handler.ts', text: `
import { prisma } from '@workspace/database';
export async function handler(objectId) {
  return prisma.project.findUnique({ where: { id: objectId } });
}
` },
  { path: 'packages/database/src/index.ts', text: "export * from './client';" },
  { path: 'packages/database/src/client.ts', text: `
import { PrismaClient } from './prisma';
const createClient = () => new PrismaClient();
const globalForPrisma = globalThis;
export const prisma = globalForPrisma.prisma ?? createClient();
` },
  { path: 'packages/database/src/prisma.ts', text: `
import { PrismaClient as GeneratedPrismaClient } from '../generated/prisma/client';
import type { PrismaClient as GeneratedPrismaClientType } from '../generated/prisma/client';
export const PrismaClient = GeneratedPrismaClient;
export type PrismaClient = GeneratedPrismaClientType;
` },
];
const generatedOptions = {
  packageManifests: [{ path: 'packages/database/package.json', manifest: {
    name: '@workspace/database', exports: './src/index.ts',
  } }],
  providerFiles: [{ path: 'packages/database/schema/main.prisma', text: `
generator client {
  provider = "prisma-client"
  output = "../generated/prisma"
}
` }],
};
const generatedGraph = buildJsTsModuleGraph(generatedFacadeFiles, generatedOptions);
const generatedModule = generatedGraph.modules.get('apps/web/handler.ts');
let generatedHandler = null;
walkJsTsAst(generatedModule.ast, (node) => {
  if (node.type === 'FunctionDeclaration' && node.id?.name === 'handler') generatedHandler = node;
});
const generatedResult = analyzeDataOperations(generatedGraph, generatedModule, generatedHandler, {
  objectAliases: new Set(['objectId']), principalAliases: new Set(),
});
assert.equal(generatedResult.operations.length, 1);
assert.equal(generatedResult.operations[0].provider, 'prisma');

const missingGeneratorGraph = buildJsTsModuleGraph(generatedFacadeFiles, {
  packageManifests: generatedOptions.packageManifests,
});
const missingGeneratorModule = missingGeneratorGraph.modules.get('apps/web/handler.ts');
let missingGeneratorHandler = null;
walkJsTsAst(missingGeneratorModule.ast, (node) => {
  if (node.type === 'FunctionDeclaration' && node.id?.name === 'handler') missingGeneratorHandler = node;
});
assert.equal(analyzeDataOperations(missingGeneratorGraph, missingGeneratorModule,
  missingGeneratorHandler, { objectAliases: new Set(['objectId']), principalAliases: new Set() })
  .operations.length, 0);

const falseGlobalAliasFiles = generatedFacadeFiles.map((file) => file.path.endsWith('/client.ts')
  ? { ...file, text: file.text.replace('const globalForPrisma = globalThis;', `
const fakeGlobal = { prisma: undefined };
const globalForPrisma = fakeGlobal;`) }
  : file);
const falseGlobalAliasGraph = buildJsTsModuleGraph(falseGlobalAliasFiles, generatedOptions);
const falseGlobalAliasModule = falseGlobalAliasGraph.modules.get('apps/web/handler.ts');
let falseGlobalAliasHandler = null;
walkJsTsAst(falseGlobalAliasModule.ast, (node) => {
  if (node.type === 'FunctionDeclaration' && node.id?.name === 'handler') falseGlobalAliasHandler = node;
});
assert.equal(analyzeDataOperations(falseGlobalAliasGraph, falseGlobalAliasModule,
  falseGlobalAliasHandler, { objectAliases: new Set(['objectId']), principalAliases: new Set() })
  .operations.length, 0);

const shadowedGlobalFiles = generatedFacadeFiles.map((file) => file.path.endsWith('/client.ts')
  ? { ...file, text: file.text.replace('const globalForPrisma = globalThis;', `
const globalThis = { prisma: undefined };
const globalForPrisma = globalThis;`) }
  : file);
const shadowedGlobalGraph = buildJsTsModuleGraph(shadowedGlobalFiles, generatedOptions);
const shadowedGlobalModule = shadowedGlobalGraph.modules.get('apps/web/handler.ts');
let shadowedGlobalHandler = null;
walkJsTsAst(shadowedGlobalModule.ast, (node) => {
  if (node.type === 'FunctionDeclaration' && node.id?.name === 'handler') shadowedGlobalHandler = node;
});
assert.equal(analyzeDataOperations(shadowedGlobalGraph, shadowedGlobalModule,
  shadowedGlobalHandler, { objectAliases: new Set(['objectId']), principalAliases: new Set() })
  .operations.length, 0);

const typeOnlyConstructorFiles = generatedFacadeFiles.map((file) => file.path.endsWith('/prisma.ts')
  ? { ...file, text: `
import type { PrismaClient as GeneratedPrismaClient } from '../generated/prisma/client';
export const PrismaClient = GeneratedPrismaClient;
` }
  : file);
const typeOnlyConstructorGraph = buildJsTsModuleGraph(typeOnlyConstructorFiles, generatedOptions);
const typeOnlyConstructorModule = typeOnlyConstructorGraph.modules.get('apps/web/handler.ts');
let typeOnlyConstructorHandler = null;
walkJsTsAst(typeOnlyConstructorModule.ast, (node) => {
  if (node.type === 'FunctionDeclaration' && node.id?.name === 'handler') {
    typeOnlyConstructorHandler = node;
  }
});
assert.equal(analyzeDataOperations(typeOnlyConstructorGraph, typeOnlyConstructorModule,
  typeOnlyConstructorHandler, { objectAliases: new Set(['objectId']), principalAliases: new Set() })
  .operations.length, 0);

console.log('access-control data operations ok: Prisma, Drizzle, Supabase constraints and shadowed client');
