#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  compareRouteSecurityDocuments, readRouteSecurityBaseline, routeSecurityDigest,
  routeSecurityDigestManifest, routeSecurityJson, routeSecurityRegressions,
} from '../scripts/lib/route-security-baseline.mjs';
import { validateRouteSecurityDocument } from '../scripts/lib/route-security-contract.mjs';
import {
  createRouteSecurityDocument, serverActionRecord,
} from '../scripts/lib/route-security-model.mjs';
import { renderRouteSecurityMarkdown } from '../scripts/lib/route-security-renderer.mjs';

const golden = JSON.parse(readFileSync(new URL(
  './fixtures/route-security-v3-golden.json', import.meta.url), 'utf8'));
const observed = golden.routes[0].accessChains[0];

function completedCoverage() {
  return { status: 'completed', counts: { discovered: 1, eligible: 1, scanned: 1,
    skipped: 0, truncated: 0, errors: 0 }, reasons: [] };
}

function documentFor(routes, options = {}) {
  return createRouteSecurityDocument({
    version: golden.tool.version,
    generatedAt: golden.generatedAt,
    mode: options.mode || 'audit',
    subject: golden.subject,
    routes,
    serverActions: options.serverActions || [],
    coverage: golden.coverage,
    accessPathCoverage: options.accessPathCoverage || completedCoverage(),
    applicationControls: [],
    limitations: [],
  });
}

const unconstrained = structuredClone(observed);
unconstrained.id = `access-chain.${'1'.repeat(20)}`;
unconstrained.fingerprint = '1'.repeat(64);
unconstrained.outcome = 'authorization_constraint_not_observed';
unconstrained.dataOperation.principalConstraint = 'not_observed';
unconstrained.authorizationEvidence = [{
  kind: 'none', category: 'none', state: 'not_observed', field: null,
  location: unconstrained.dataOperation.location,
}];

const external = structuredClone(observed);
external.id = `access-chain.${'2'.repeat(20)}`;
external.fingerprint = '2'.repeat(64);
external.outcome = 'external_policy_required';
external.dataOperation.provider = 'supabase';
external.dataOperation.principalConstraint = 'not_applicable';
external.authorizationEvidence = [{
  kind: 'external_policy_dependency', category: 'none', state: 'not_applicable', field: null,
  location: external.dataOperation.location,
}];

const specialRoute = structuredClone(golden.routes[0]);
specialRoute.path = '/projects/`owner`/[id]';
specialRoute.accessChains = [
  observed, unconstrained, external,
  golden.routes[0].accessChains[1], golden.routes[0].accessChains[2],
];
const longActionName = `${'review*action`'.repeat(20)}`.slice(0, 160);
const action = serverActionRecord({
  name: longActionName,
  location: { path: 'src/actions/review.ts', line: 9 },
  accessChains: [external],
});
const renderedDocument = documentFor([specialRoute], { serverActions: [action],
  accessPathCoverage: { ...completedCoverage(), counts: { ...completedCoverage().counts,
    discovered: 2, eligible: 2, scanned: 2 } } });
assert.deepEqual(validateRouteSecurityDocument(renderedDocument), []);
const markdown = renderRouteSecurityMarkdown(renderedDocument);
for (const phrase of [
  'Bounded object-authorization constraint observed',
  'Object-level authorization review (BOLA/IDOR)',
  'External row-level security (RLS) dependency review',
  'Incomplete static access-control chain',
  'No supported object operation on this bounded path',
  'Ordered local calls',
  'Non-owner check',
  'Change risks',
]) assert.match(markdown, new RegExp(phrase.replace(/[()\/]/g, '\\$&')));
assert.match(markdown, /`completed` means the supported path analysis finished; it does not mean the route is safe/);
assert.doesNotMatch(markdown, /\/Users\/|const prisma|source snippet/i);
assert.match(markdown, /``\/projects\/`owner`\/\[id\]``/);
assert.ok(markdown.includes(longActionName));
const positions = [
  'Object-level authorization review (BOLA/IDOR)',
  'External row-level security (RLS) dependency review',
  'Incomplete static access-control chain',
  '## Route-scoped control review',
  'Bounded object-authorization constraint observed',
  '## Routes',
].map((value) => markdown.indexOf(value));
assert.ok(positions.every((position) => position >= 0));
assert.deepEqual([...positions].sort((left, right) => left - right), positions,
  'Markdown review queues must preserve the P10 high-signal order');

const removedEvidenceRoute = structuredClone(golden.routes[0]);
removedEvidenceRoute.accessChains = [];
removedEvidenceRoute.operations = [];
removedEvidenceRoute.limitations = [];
const removedEvidence = documentFor([removedEvidenceRoute], { mode: 'retest' });
const compared = compareRouteSecurityDocuments(
  removedEvidence, golden, 'b'.repeat(64),
);
assert.equal(compared.baseline.compatibility, 'compatible');
assert.equal(compared.routes[0].baseline.state, 'changed');
assert.equal(compared.routes[0].baseline.reasonCode, 'authorization_evidence_disappeared');
assert.equal(routeSecurityRegressions(compared).length, 1);

const incompleteRoute = structuredClone(removedEvidenceRoute);
incompleteRoute.limitations = ['route-object-authorization-analysis-incomplete'];
const incompleteCoverage = {
  status: 'partial',
  counts: { discovered: 1, eligible: 1, scanned: 0, skipped: 1, truncated: 0, errors: 1 },
  reasons: [{ code: 'route_handler_unresolved', count: 1,
    samplePaths: [incompleteRoute.location.path] }],
};
const incomplete = documentFor([incompleteRoute], {
  mode: 'retest', accessPathCoverage: incompleteCoverage,
});
const unretested = compareRouteSecurityDocuments(incomplete, golden, 'c'.repeat(64));
assert.equal(unretested.routes[0].baseline.state, 'unretested');
assert.equal(unretested.routes[0].baseline.reasonCode, 'current_access_path_coverage_incomplete');
assert.equal(unretested.accessPathCoverage.status, 'partial');
assert.equal(routeSecurityRegressions(unretested).length, 0);

const completedDigest = routeSecurityDigest(routeSecurityJson(removedEvidence));
const partialDigest = routeSecurityDigest(routeSecurityJson(incomplete));
assert.notEqual(partialDigest, completedDigest,
  'access-path coverage state must participate in the immutable JSON digest');

const hostile = structuredClone(renderedDocument);
hostile.serverActions[0].name = 'unsafe\nheading';
assert.throws(() => renderRouteSecurityMarkdown(hostile), /route security contract failed/);

const baselineDirectory = mkdtempSync(join(tmpdir(), 'route-v3-digest-'));
try {
  const json = routeSecurityJson(golden);
  const baselineMarkdown = renderRouteSecurityMarkdown(golden);
  writeFileSync(join(baselineDirectory, 'route-security.json'), json);
  writeFileSync(join(baselineDirectory, 'route-security.md'), baselineMarkdown);
  writeFileSync(join(baselineDirectory, 'route-security.sha256'),
    `${routeSecurityDigest(json)}  route-security.json\n`);
  assert.equal(readRouteSecurityBaseline(join(baselineDirectory, 'report.json')).sourceDigest,
    routeSecurityDigest(json), 'historical JSON-only sidecars must remain readable');
  writeFileSync(join(baselineDirectory, 'route-security.sha256'),
    routeSecurityDigestManifest(json, baselineMarkdown));
  assert.equal(readRouteSecurityBaseline(join(baselineDirectory, 'report.json')).sourceDigest,
    routeSecurityDigest(json));
  writeFileSync(join(baselineDirectory, 'route-security.md'), `${baselineMarkdown}tampered\n`);
  assert.throws(() => readRouteSecurityBaseline(join(baselineDirectory, 'report.json')),
    /Markdown does not match/);
} finally {
  rmSync(baselineDirectory, { recursive: true, force: true });
}

console.log('route v3 renderer/baseline ok: five outcomes, ordered traces, escaping, digest and fail-closed retest');
