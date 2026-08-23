import assert from 'node:assert/strict';
import {
  controlEvidence, createRouteSecurityDocument, routeRecord,
} from '../scripts/lib/route-security-model.mjs';
import { validateRouteSecurityDocument } from '../scripts/lib/route-security-contract.mjs';
import { renderRouteSecurityMarkdown } from '../scripts/lib/route-security-renderer.mjs';

const signal = { kind: 'passport-authenticate', origin: 'passport', location: { path: 'src/router.ts', line: 3 } };
const routes = [routeRecord({
  framework: 'express', method: 'PATCH', path: '/projects/:id', pathKind: 'parameterized',
  location: { path: 'src/router.ts', line: 4 }, handler: 'updateProject', objectAddressed: true,
  authentication: controlEvidence('inherited_observed', [signal], 'Passport middleware is registered before this route.'),
  authorization: controlEvidence('candidate_observed', [], 'A custom policy helper is visible but was not resolved.'),
  operations: ['database-mutation'], priority: { level: 'review_first', reasons: ['object-authorization-unresolved'] },
  limitations: ['service-layer-policy-unresolved'],
})];
const document = createRouteSecurityDocument({
  version: '0.6.0', generatedAt: '2026-08-24T00:00:00.000Z', mode: 'audit',
  subject: { id: 'subject.route-fixture', scopeDigest: 'a'.repeat(64) }, routes,
  coverage: [{ framework: 'express', status: 'completed', counts: { discovered: 1, eligible: 1, parsed: 1, incomplete: 0 }, reasons: [] }],
  limitations: ['Static analysis does not prove runtime enforcement.'],
});
assert.deepEqual(validateRouteSecurityDocument(document), []);
assert.equal(document.summary.total, 1);
assert.equal(document.summary.stateChanging, 1);
assert.equal(document.summary.objectAddressed, 1);
assert.equal(document.summary.byAuthentication.inherited_observed, 1);

const markdown = renderRouteSecurityMarkdown(document);
assert.match(markdown, /Review priority orders manual work; it is not vulnerability severity/);
assert.match(markdown, /PATCH `\/projects\/:id`/);
assert.match(markdown, /Authentication: `inherited_observed`/);
assert.doesNotMatch(markdown, /\[object Object\]/);

const invalid = structuredClone(document);
invalid.routes[0].location.path = '/private/project.ts';
assert.ok(validateRouteSecurityDocument(invalid).some((error) => error.includes('location.path')));
const wrongSummary = structuredClone(document);
wrongSummary.summary.total = 0;
assert.ok(validateRouteSecurityDocument(wrongSummary).includes('summary.total differs from routes'));

const empty = createRouteSecurityDocument({
  version: '0.6.0', generatedAt: '2026-08-24T00:00:00.000Z', mode: 'audit',
  subject: { id: 'subject.empty-fixture', scopeDigest: 'b'.repeat(64) }, routes: [], coverage: [], limitations: [],
});
assert.match(renderRouteSecurityMarkdown(empty), /No routes were inventoried/);

console.log('route security contract ok: schema model, summaries, safe paths and golden markdown');
