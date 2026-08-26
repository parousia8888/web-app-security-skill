import assert from 'node:assert/strict';
import {
  controlEvidence, createRouteSecurityDocument, routeRecord, routeScopedControlEvidence,
} from '../scripts/lib/route-security-model.mjs';
import {
  compareRouteSecurityDocuments, routeSecurityRegressions,
} from '../scripts/lib/route-security-baseline.mjs';
import { validateRouteSecurityDocument } from '../scripts/lib/route-security-contract.mjs';
import { renderRouteSecurityMarkdown } from '../scripts/lib/route-security-renderer.mjs';

const signal = { kind: 'passport-authenticate', origin: 'passport', location: { path: 'src/router.ts', line: 3 } };
const routes = [routeRecord({
  framework: 'express', method: 'PATCH', path: '/projects/:id', pathKind: 'parameterized',
  location: { path: 'src/router.ts', line: 4 }, handler: 'updateProject', objectAddressed: true,
  authentication: controlEvidence('inherited_observed', [signal], 'Passport middleware is registered before this route.'),
  authorization: controlEvidence('candidate_observed', [], 'A custom policy helper is visible but was not resolved.'),
  routeScopedControl: routeScopedControlEvidence([signal], []),
  accessChains: [{
    entryKind: 'route', entryId: 'fixture', status: 'completed',
    outcome: 'principal_constraint_observed',
    identity: { state: 'identity_call_observed', provider: 'clerk', signals: [signal],
      boundary: 'An exact identity call was observed.' },
    objectSelectors: [{ kind: 'route-parameter', name: 'id',
      location: { path: 'src/router.ts', line: 4 } }],
    callEdges: [],
    dataOperation: { provider: 'prisma', resource: 'project', operation: 'update',
      location: { path: 'src/router.ts', line: 8 }, objectConstraint: 'observed',
      principalConstraint: 'observed', tenantConstraint: 'not_observed',
      externalPolicy: 'not_applicable' },
    evidenceBoundary: 'Static evidence does not prove runtime enforcement.',
  }],
  operations: ['database-mutation'], priority: { level: 'review_first', reasons: ['object-authorization-unresolved'] },
  limitations: ['service-layer-policy-unresolved'],
})];
const document = createRouteSecurityDocument({
  version: '0.7.0', generatedAt: '2026-08-24T00:00:00.000Z', mode: 'audit',
  subject: { id: 'subject.route-fixture', scopeDigest: 'a'.repeat(64) }, routes,
  applicationControls: [{ framework: 'nestjs', kind: 'nest-global-guard-candidate',
    origin: 'RateLimitGuard', role: 'unclassified', location: { path: 'src/app.module.ts', line: 8 } }],
  coverage: [{ framework: 'express', status: 'completed', counts: { discovered: 1, eligible: 1, parsed: 1, incomplete: 0 }, reasons: [] }],
  limitations: ['Static analysis does not prove runtime enforcement.'],
});
assert.deepEqual(validateRouteSecurityDocument(document), []);
assert.equal(document.schemaVersion, 2);
assert.equal(document.summary.total, 1);
assert.equal(document.summary.stateChanging, 1);
assert.equal(document.summary.objectAddressed, 1);
assert.equal(document.summary.byAuthentication.inherited_observed, 1);
assert.equal(document.summary.applicationControls, 1);
assert.equal(document.summary.byRouteScopedControl.classified_controls_observed, 1);

const markdown = renderRouteSecurityMarkdown(document);
assert.match(markdown, /Review priority orders manual work; it is not vulnerability severity/);
assert.match(markdown, /PATCH `\/projects\/:id`/);
assert.match(markdown, /Authentication: `inherited_observed`/);
assert.equal((markdown.match(/RateLimitGuard/g) || []).length, 1);
assert.match(markdown, /Access-control chain review/);
assert.match(markdown, /principal_constraint_observed/);
assert.doesNotMatch(markdown, /\[object Object\]/);

const hostileRoute = structuredClone(document);
hostileRoute.routes[0].path = '/projects/`id`\n# injected-route-heading';
const hostileMarkdown = renderRouteSecurityMarkdown(hostileRoute);
assert.doesNotMatch(hostileMarkdown, /^# injected-route-heading$/m);
assert.match(hostileMarkdown, /\/projects\/`id`\\n# injected-route-heading/);

const degradedRoute = structuredClone(document.routes[0]);
degradedRoute.accessChains[0].outcome = 'principal_constraint_not_observed';
degradedRoute.accessChains[0].dataOperation.principalConstraint = 'not_observed';
const degradedDocument = createRouteSecurityDocument({
  version: '0.7.0', generatedAt: document.generatedAt, mode: 'retest', subject: document.subject,
  routes: [degradedRoute], applicationControls: document.applicationControls,
  coverage: document.coverage, limitations: document.limitations,
});
const compared = compareRouteSecurityDocuments(degradedDocument, document, 'd'.repeat(64));
assert.equal(compared.routes[0].baseline.reasonCode, 'principal_or_tenant_constraint_disappeared');
assert.equal(routeSecurityRegressions(compared).length, 1);
const degradedMarkdown = renderRouteSecurityMarkdown(compared);
assert.match(degradedMarkdown, /Object-level authorization review \(BOLA\/IDOR\)/);
assert.match(degradedMarkdown, /user-selected record ID reaches a database operation/);
assert.match(degradedMarkdown, /deliberate sharing, administrator, support/);

const invalid = structuredClone(document);
invalid.routes[0].location.path = '/private/project.ts';
assert.ok(validateRouteSecurityDocument(invalid).some((error) => error.includes('location.path')));
const wrongSummary = structuredClone(document);
wrongSummary.summary.total = 0;
assert.ok(validateRouteSecurityDocument(wrongSummary).includes('summary.total differs from routes'));

const empty = createRouteSecurityDocument({
  version: '0.7.0', generatedAt: '2026-08-24T00:00:00.000Z', mode: 'audit',
  subject: { id: 'subject.empty-fixture', scopeDigest: 'b'.repeat(64) }, routes: [], coverage: [], limitations: [],
});
assert.match(renderRouteSecurityMarkdown(empty), /No routes were inventoried/);

const legacy = structuredClone(document);
legacy.schemaVersion = 1;
legacy.analyzer.revision = '1';
delete legacy.applicationControls;
delete legacy.serverActions;
for (const key of ['serverActions', 'byRouteScopedControl', 'applicationControls',
  'byApplicationControlRole']) delete legacy.summary[key];
for (const route of legacy.routes) {
  delete route.routeScopedControl;
  delete route.accessChains;
}
assert.deepEqual(validateRouteSecurityDocument(legacy), []);
const migrated = compareRouteSecurityDocuments(document, legacy, 'c'.repeat(64));
assert.equal(migrated.baseline.compatibility, 'not_comparable');
assert.equal(migrated.baseline.reasonCode, 'route_schema_changed');
assert.ok(migrated.routes.every((route) => route.baseline.reasonCode === 'route_schema_changed'));

console.log('route security contract ok: schema model, summaries, safe paths and golden markdown');
