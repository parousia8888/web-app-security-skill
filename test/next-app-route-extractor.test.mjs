import assert from 'node:assert/strict';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';
import { extractNextAppRoutes } from '../scripts/lib/frameworks/next-app-route-extractor.mjs';

const graph = buildJsTsModuleGraph([
  { path: 'src/app/(admin)/projects/[id]/route.ts', text: `
import { auth as getAuth } from '@clerk/nextjs/server';
export async function GET() { const user = await getAuth(); return Response.json(user); }
const update = async () => Response.json({ ok: true }); export { update as PATCH };
` },
  { path: 'app/blog/[...slug]/route.js', text: 'export const POST = async () => new Response();' },
  { path: 'pages/api/legacy.ts', text: 'export default function handler() {}' },
  { path: 'app/_private/route.ts', text: 'export function GET() {}' },
]);
const result = extractNextAppRoutes(graph);
assert.equal(result.routes.length, 3);
const get = result.routes.find((route) => route.method === 'GET');
assert.equal(get.path, '/projects/[id]');
assert.equal(get.authentication.state, 'local_observed');
assert.equal(get.objectAddressed, true);
assert.ok(result.routes.some((route) => route.path === '/blog/[...slug]' && route.method === 'POST'));
assert.equal(result.routes.some((route) => route.location.path.includes('pages/api')), false);
assert.ok(result.coverage.reasons.some((reason) => reason.code === 'next_private_route_segment'));

const unrelated = extractNextAppRoutes(buildJsTsModuleGraph([
  { path: 'app/api/health/route.ts', text: 'export function GET() { return new Response(); }' },
  { path: 'app/layout.tsx', text: "import missing from './missing'; export default missing;" },
]));
assert.equal(unrelated.coverage.status, 'completed',
  'an unrelated module resolution gap must not poison route coverage');
const reexport = extractNextAppRoutes(buildJsTsModuleGraph([
  { path: 'app/api/auth/route.ts', text: "export { GET, POST } from '@/auth';" },
]));
assert.equal(reexport.routes.length, 0);
assert.equal(reexport.coverage.status, 'partial');
assert.ok(reexport.coverage.reasons.some((reason) =>
  reason.code === 'next_route_handler_export_unresolved'));

console.log('next app route extractor ok: filesystem paths, exports, exact auth and exclusions');
