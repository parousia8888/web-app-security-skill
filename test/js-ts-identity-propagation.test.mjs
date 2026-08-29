import assert from 'node:assert/strict';
import { analyzeAccessPaths } from '../scripts/lib/js-ts-access-path.mjs';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { walkJsTsAst } from '../scripts/lib/js-ts-ast-parser.mjs';

const graph = buildJsTsModuleGraph([
  { path: 'src/db.ts', text: `
import { PrismaClient } from '@prisma/client';
export const prisma = new PrismaClient();
` },
  { path: 'src/identity.ts', text: `
import { getServerSession } from 'next-auth';
export async function currentIdentity() {
  const session = await getServerSession();
  return { userId: String(session.user.id) };
}
` },
  { path: 'src/service.ts', text: `
import { getServerSession } from 'next-auth';
import { auth as clerkAuth } from '@clerk/nextjs/server';
import { prisma } from './db';
export async function fromCallee(id) {
  const session = await getServerSession();
  return prisma.project.findFirst({ where: { id, ownerId: session.user.id } });
}
export async function clerkTenant(id) {
  const { userId, orgId } = await clerkAuth();
  return prisma.project.findFirst({ where: { id, ownerId: userId, organizationId: orgId } });
}
export function constrained(id, owner) {
  return prisma.project.findFirst({ where: { id, ownerId: owner } });
}
export function constrainedObject({ id, ownerId, organizationId }) {
  return prisma.project.findFirst({ where: { id, ownerId, organizationId } });
}
const wrapProvider = (provider) => provider;
export async function unresolvedWrapper(id) {
  const wrapped = wrapProvider(getServerSession);
  const session = await wrapped();
  return prisma.project.findFirst({ where: { id, ownerId: session.user.id } });
}
export async function benignAuthName(id) {
  const auth = () => ({ userId: 'fixture' });
  const user = auth();
  return prisma.project.findFirst({ where: { id, ownerId: user.userId } });
}
` },
  { path: 'src/entry.ts', text: `
import { currentIdentity } from './identity';
import { auth as clerkAuth } from '@clerk/nextjs/server';
import { fromCallee, clerkTenant, constrained, constrainedObject, unresolvedWrapper, benignAuthName } from './service';
export function callee(objectId) { return fromCallee(objectId); }
export function tenant(objectId) { return clerkTenant(objectId); }
export async function returned(objectId) {
  const { userId: principalId } = await currentIdentity();
  return constrained(objectId, principalId);
}
export function alleged(userId) { return constrained(userId, userId); }
export async function objectFacts(objectId) {
  const { userId, orgId } = await clerkAuth();
  return constrainedObject({ id: objectId, ownerId: userId, organizationId: orgId });
}
export function wrapped(objectId) { return unresolvedWrapper(objectId); }
export function benign(objectId) { return benignAuthName(objectId); }
` },
]);

const module = graph.modules.get('src/entry.ts');
function handler(name) {
  let found = null;
  walkJsTsAst(module.ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name === name) found = node;
  });
  return found;
}

function analyze(name, selectorAlias = 'objectId', selectorKind = 'route-parameter') {
  return analyzeAccessPaths({
    graph, module, handler: handler(name),
    entry: { kind: 'route', id: `route.${name}`, name },
    identity: { state: 'not_observed', provider: null, signals: [], boundary: 'fixture' },
    selectorGroups: [{
      selector: { kind: selectorKind, name: selectorAlias, origin: 'request_selected',
        location: { path: module.path, line: 1 } },
      aliases: new Set([selectorAlias]), nodes: new Set(),
    }],
    principalAliases: new Set(), tenantAliases: new Set(),
  });
}

const callee = analyze('callee').chains.find((chain) => chain.status === 'completed');
assert.equal(callee.identity.provider, 'authjs');
assert.equal(callee.dataOperation.principalConstraint, 'observed');

const tenant = analyze('tenant').chains.find((chain) => chain.status === 'completed');
assert.equal(tenant.identity.provider, 'clerk');
assert.equal(tenant.dataOperation.principalConstraint, 'observed');
assert.equal(tenant.dataOperation.tenantConstraint, 'observed');

const returned = analyze('returned').chains.find((chain) => chain.status === 'completed');
assert.equal(returned.identity.provider, 'authjs');
assert.equal(returned.dataOperation.principalConstraint, 'observed');

const alleged = analyze('alleged', 'userId', 'express-body-field')
  .chains.find((chain) => chain.status === 'completed');
assert.equal(alleged.identity.state, 'not_observed');
assert.equal(alleged.dataOperation.principalConstraint, 'not_observed');

const objectFacts = analyze('objectFacts').chains.find((chain) => chain.status === 'completed');
assert.equal(objectFacts.dataOperation.principalConstraint, 'observed');
assert.equal(objectFacts.dataOperation.tenantConstraint, 'observed');

const wrapped = analyze('wrapped');
assert.ok(wrapped.chains.some((chain) => chain.status === 'partial'
  && chain.reason === 'identity_source_unresolved'));
assert.equal(wrapped.chains.find((chain) => chain.status === 'completed')
  .dataOperation.principalConstraint, 'not_observed');

const benign = analyze('benign').chains.find((chain) => chain.status === 'completed');
assert.equal(benign.identity.state, 'not_observed');
assert.equal(benign.dataOperation.principalConstraint, 'not_observed');

console.log('js/ts identity propagation ok: callee, tenant, returned identity and fail-closed wrappers');
