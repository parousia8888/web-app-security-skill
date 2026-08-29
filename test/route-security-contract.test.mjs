import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  accessChainRecord, controlEvidence, createRouteSecurityDocument, routeRecord,
  routeScopedControlEvidence,
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
  accessPathCoverage: { status: 'completed', counts: { discovered: 1, eligible: 1,
    scanned: 1, skipped: 0, truncated: 0, errors: 0 }, reasons: [] },
  limitations: ['Static analysis does not prove runtime enforcement.'],
});
assert.deepEqual(validateRouteSecurityDocument(document), []);
assert.equal(document.schemaVersion, 3);
assert.equal(document.analyzer.revision, '3');
assert.deepEqual(document.analyzer.analysisLimits, {
  maxLocalCallEdges: 4, maxEmittedChainsPerEntry: 50, maxActiveStatesPerEntry: 512,
  maxExaminedCallSitesPerSummary: 200, maxTotalTransitionsPerAudit: 50_000,
});
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
assert.match(markdown, /Access-path review leads/);
assert.match(markdown, /authorization_constraint_observed/);
assert.doesNotMatch(markdown, /\[object Object\]/);

const hostileRoute = structuredClone(document);
hostileRoute.routes[0].path = '/projects/`id`\n# injected-route-heading';
assert.ok(validateRouteSecurityDocument(hostileRoute)
  .some((error) => error.includes('bounded fields')));
assert.throws(() => renderRouteSecurityMarkdown(hostileRoute), /route security contract failed/);

const degradedRoute = structuredClone(document.routes[0]);
degradedRoute.accessChains[0].outcome = 'authorization_constraint_not_observed';
degradedRoute.accessChains[0].dataOperation.principalConstraint = 'not_observed';
degradedRoute.accessChains[0].authorizationEvidence = [{
  kind: 'none', category: 'none', state: 'not_observed', field: null,
  location: degradedRoute.accessChains[0].dataOperation.location,
}];
const degradedDocument = createRouteSecurityDocument({
  version: '0.7.0', generatedAt: document.generatedAt, mode: 'retest', subject: document.subject,
    routes: [degradedRoute], applicationControls: document.applicationControls,
    coverage: document.coverage, accessPathCoverage: document.accessPathCoverage,
    limitations: document.limitations,
});
const compared = compareRouteSecurityDocuments(degradedDocument, document, 'd'.repeat(64));
assert.equal(compared.routes[0].baseline.reasonCode, 'authorization_evidence_disappeared');
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
delete legacy.analyzer.analysisLimits;
delete legacy.applicationControls;
delete legacy.serverActions;
delete legacy.accessPathCoverage;
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
assert.ok([...migrated.routes, ...migrated.serverActions].every((item) =>
  !['unchanged', 'fixed', 'removed'].includes(item.baseline.state)));

const legacyV2 = structuredClone(document);
legacyV2.schemaVersion = 2;
legacyV2.analyzer.revision = '2';
delete legacyV2.analyzer.analysisLimits;
delete legacyV2.accessPathCoverage;
for (const item of [...legacyV2.routes, ...legacyV2.serverActions]) {
  for (const chain of item.accessChains) {
    chain.outcome = chain.outcome === 'authorization_constraint_observed'
      ? 'principal_constraint_observed'
      : chain.outcome === 'authorization_constraint_not_observed'
        ? 'principal_constraint_not_observed' : chain.outcome;
    for (const selector of chain.objectSelectors) delete selector.origin;
    if (chain.dataOperation) chain.dataOperation.externalPolicy = 'not_applicable';
    delete chain.authorizationEvidence;
    delete chain.reason;
    delete chain.limitations;
  }
}
assert.deepEqual(validateRouteSecurityDocument(legacyV2), []);
const migratedV2 = compareRouteSecurityDocuments(document, legacyV2, 'e'.repeat(64));
assert.equal(migratedV2.baseline.compatibility, 'not_comparable');
assert.equal(migratedV2.baseline.reasonCode, 'route_schema_changed');
assert.ok([...migratedV2.routes, ...migratedV2.serverActions].every((item) =>
  item.baseline.state === 'not_comparable' && item.baseline.reasonCode === 'route_schema_changed'));

const changedLimits = structuredClone(document);
changedLimits.analyzer.analysisLimits.maxActiveStatesPerEntry = 256;
const limitsCompared = compareRouteSecurityDocuments(document, changedLimits, 'f'.repeat(64));
assert.equal(limitsCompared.baseline.compatibility, 'not_comparable');
assert.equal(limitsCompared.baseline.reasonCode, 'route_analysis_limits_changed');

const golden = JSON.parse(readFileSync(new URL(
  './fixtures/route-security-v3-golden.json', import.meta.url), 'utf8'));
assert.deepEqual(validateRouteSecurityDocument(golden), []);
assert.deepEqual(golden.routes[0].accessChains.map((chain) => chain.status),
  ['completed', 'partial', 'not_applicable']);
assert.deepEqual(createRouteSecurityDocument({
  version: golden.tool.version, generatedAt: golden.generatedAt, mode: golden.mode,
  subject: golden.subject, routes: golden.routes, coverage: golden.coverage,
  accessPathCoverage: golden.accessPathCoverage,
  applicationControls: golden.applicationControls, serverActions: golden.serverActions,
  limitations: golden.limitations, baseline: golden.baseline,
}), golden, 'the checked-in v3 golden artifact must match the deterministic document model');

const fingerprintInput = {
  entryKind: 'route', entryId: 'route.fingerprint-fixture', status: 'completed',
  outcome: 'authorization_constraint_observed',
  identity: { state: 'identity_call_observed', provider: 'authjs', signals: [],
    boundary: 'Static identity evidence only.' },
  objectSelectors: [{ kind: 'route-parameter', name: 'id', origin: 'request_selected',
    location: { path: 'src/route.ts', line: 10 } }],
  callEdges: [{ kind: 'local_function', from: 'handler', to: 'repository',
    location: { path: 'src/route.ts', line: 12 } }],
  dataOperation: { provider: 'prisma', resource: 'project', operation: 'find-first',
    location: { path: 'src/repository.ts', line: 20 }, objectConstraint: 'observed',
    principalConstraint: 'observed', tenantConstraint: 'not_observed' },
  authorizationEvidence: [{ kind: 'query_predicate', category: 'principal', state: 'observed',
    field: 'ownerId', location: { path: 'src/repository.ts', line: 20 } }],
};
const stableFingerprint = accessChainRecord(fingerprintInput);
const lineMovedFingerprint = accessChainRecord({
  ...fingerprintInput,
  objectSelectors: fingerprintInput.objectSelectors.map((selector) => ({
    ...selector, location: { ...selector.location, line: 110 },
  })),
  callEdges: fingerprintInput.callEdges.map((edge) => ({
    ...edge, location: { ...edge.location, line: 112 },
  })),
  dataOperation: { ...fingerprintInput.dataOperation,
    location: { ...fingerprintInput.dataOperation.location, line: 120 } },
  authorizationEvidence: fingerprintInput.authorizationEvidence.map((evidence) => ({
    ...evidence, location: { ...evidence.location, line: 120 },
  })),
});
assert.equal(lineMovedFingerprint.fingerprint, stableFingerprint.fingerprint,
  'line movement must not become the access-path identity');
assert.notEqual(accessChainRecord({
  ...fingerprintInput,
  callEdges: [{ ...fingerprintInput.callEdges[0], to: 'alternateRepository' }],
}).fingerprint, stableFingerprint.fingerprint, 'ordered callable identity must affect the fingerprint');
assert.notEqual(accessChainRecord({
  ...fingerprintInput,
  authorizationEvidence: [{ ...fingerprintInput.authorizationEvidence[0], category: 'tenant' }],
}).fingerprint, stableFingerprint.fingerprint,
  'authorization evidence category must affect the fingerprint');
const unrecognizedEvidence = accessChainRecord({
  ...fingerprintInput,
  objectSelectors: [{ ...fingerprintInput.objectSelectors[0], origin: 'runtime-proved' }],
  authorizationEvidence: [{ ...fingerprintInput.authorizationEvidence[0], state: 'enforced' }],
});
assert.equal(unrecognizedEvidence.objectSelectors[0].origin, 'unknown');
assert.equal(unrecognizedEvidence.authorizationEvidence[0].state, 'incomplete');

console.log('route security contract ok: schema model, summaries, safe paths and golden markdown');
