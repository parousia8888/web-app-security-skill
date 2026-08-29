import assert from 'node:assert/strict';
import {
  analyzeIdentityEvidence, identityProviderSymbolsForHandler,
} from '../scripts/lib/js-ts-identity-evidence.mjs';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { walkJsTsAst } from '../scripts/lib/js-ts-ast-parser.mjs';

const files = [
  { path: 'src/auth.ts', text: `
import NextAuth from 'next-auth';
export const { auth } = NextAuth({ providers: [] });
` },
  { path: 'src/better.ts', text: `
import { betterAuth } from 'better-auth';
export const auth = betterAuth({});
` },
  { path: 'src/supabase.ts', text: `
import { createServerClient } from '@supabase/ssr';
export function createClient() { return createServerClient('url', 'key', {}); }
` },
  { path: 'src/handlers.ts', text: `
import { auth as authjs } from './auth';
import { auth as better } from './better';
import { createClient } from './supabase';
import { auth as clerkAuth, currentUser } from '@clerk/nextjs/server';
import { getServerSession } from 'next-auth';
const wrapProvider = (provider) => provider;
async function authjsHandler() { const session = await authjs(); return session.user.id; }
async function betterHandler(headers) { const session = await better.api.getSession({ headers }); return session.user.id; }
async function clerkHandler() { const { userId, orgId } = await clerkAuth(); const user = await currentUser(); return [userId, orgId, user.id]; }
async function supabaseHandler() { const client = await createClient(); const { data: { user } } = await client.auth.getUser(); return user.id; }
async function benignHandler() { const auth = () => ({ userId: 'fixture' }); return auth(); }
async function wrappedHandler() { const wrapped = wrapProvider(getServerSession); const session = await wrapped(); return session.user.id; }
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

const authjs = analyzeIdentityEvidence(graph, module, handler('authjsHandler'));
assert.equal(authjs.identity.provider, 'authjs');
assert.equal(authjs.identity.state, 'identity_call_observed');
assert.ok(authjs.principalAliases.has('session.user.id'));

const better = analyzeIdentityEvidence(graph, module, handler('betterHandler'));
assert.equal(better.identity.provider, 'better-auth');
assert.equal(better.identity.state, 'session_lookup_observed');
assert.ok(better.principalAliases.has('session.user.id'));

const clerk = analyzeIdentityEvidence(graph, module, handler('clerkHandler'));
assert.equal(clerk.identity.provider, 'clerk');
assert.equal(clerk.identity.state, 'identity_call_observed');
assert.ok(clerk.principalAliases.has('userId'));
assert.ok(clerk.principalAliases.has('user.id'));
assert.ok(clerk.tenantAliases.has('orgId'));
assert.equal(clerk.principalAliases.has('orgId'), false);

const supabase = analyzeIdentityEvidence(graph, module, handler('supabaseHandler'));
assert.equal(supabase.identity.provider, 'supabase');
assert.equal(supabase.identity.state, 'identity_call_observed');
assert.ok(supabase.principalAliases.has('user.id'));

const benign = analyzeIdentityEvidence(graph, module, handler('benignHandler'));
assert.equal(benign.identity.state, 'not_observed');
assert.equal(benign.identity.signals.length, 0);
assert.equal(identityProviderSymbolsForHandler(graph, module, handler('benignHandler')).has('benignHandler'),
    false, 'a handler that calls a local helper is not itself a provider factory');

const wrapped = analyzeIdentityEvidence(graph, module, handler('wrappedHandler'));
assert.equal(wrapped.identity.state, 'incomplete');
assert.deepEqual(wrapped.limitations, ['identity_provider_wrapper_unresolved']);
assert.equal(wrapped.principalAliases.has('session.user.id'), false);

console.log('access-control identity ok: exact providers, one-local-module factories and benign names');
