import assert from 'node:assert/strict';
import { extractNextServerActions } from '../scripts/lib/frameworks/next-server-action-extractor.mjs';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { createRouteSecurityDocument } from '../scripts/lib/route-security-model.mjs';
import { validateRouteSecurityDocument } from '../scripts/lib/route-security-contract.mjs';

const files = [
  { path: 'src/supabase.ts', text: `
import { createServerClient } from '@supabase/ssr';
export function createClient() { return createServerClient('url', 'key', {}); }
` },
  { path: 'src/actions.ts', text: `
"use server";
import { PrismaClient } from '@prisma/client';
import { currentUser } from '@clerk/nextjs/server';
const prisma = new PrismaClient();
export async function updateProject(projectId) {
  const user = await currentUser();
  return prisma.project.update({ where: { id: projectId, ownerId: user.id }, data: {} });
}
async function internalHelper(id) { return prisma.project.findUnique({ where: { id } }); }
` },
  { path: 'src/form-action.ts', text: `
import { createClient } from './supabase';
export async function loadOrder(formData) {
  "use server";
  const orderId = formData.get('orderId');
  const client = await createClient();
  return client.from('orders').select('*').eq('id', orderId);
}
async function hidden(id) { "use server"; return id; }
` },
  { path: 'src/reexports.ts', text: `
"use server";
export { updateProject } from './actions';
` },
];

const graph = buildJsTsModuleGraph(files);
const result = extractNextServerActions(graph);
assert.equal(result.serverActions.length, 2);
assert.equal(result.coverage.status, 'partial');
assert.ok(result.coverage.reasons.some((reason) => reason.code === 'next_server_action_reexport_unresolved'));
const update = result.serverActions.find((action) => action.name === 'updateProject');
assert.equal(update.authentication.state, 'local_observed');
assert.equal(update.accessChains.length, 1);
assert.equal(update.accessChains[0].outcome, 'authorization_constraint_observed');
assert.equal(update.accessChains[0].objectSelectors[0].kind, 'action-parameter');
const form = result.serverActions.find((action) => action.name === 'loadOrder');
assert.equal(form.accessChains.length, 1);
assert.equal(form.accessChains[0].outcome, 'external_policy_required');
assert.equal(form.accessChains[0].objectSelectors[0].kind, 'form-data-field');
assert.equal(result.serverActions.some((action) => action.name === 'internalHelper'
  || action.name === 'hidden'), false);

const document = createRouteSecurityDocument({
  version: '0.7.0', subject: { id: 'fixture', scopeDigest: 'a'.repeat(64) },
  routes: [], serverActions: result.serverActions, coverage: [result.coverage],
});
assert.deepEqual(validateRouteSecurityDocument(document), []);

console.log('next server actions ok: module/function directives, object selectors, chains and re-export boundary');
