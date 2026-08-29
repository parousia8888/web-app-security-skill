#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { validateRepairRecord } from './lib/repair-record.mjs';
import { V2_DOMAINS, validateFindingV2, validateReportV2 } from './lib/report-v2-contract.mjs';
import { validateFindingV3, validateReportV3 } from './lib/report-v3-contract.mjs';
import { validateRouteSecurityDocument } from './lib/route-security-contract.mjs';
import { createRouteSecurityDocument } from './lib/route-security-model.mjs';
import { createFindingV2 } from './lib/evidence-v2.mjs';
import { upgradeFindingV2 } from './lib/evidence-v3.mjs';
import { sourceRule, sourceRuleset } from './lib/source-rules.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const DOCS = join(ROOT, 'docs');
const RAW_BASE = 'https://raw.githubusercontent.com/parousia8888/web-app-security-skill/main/';

function schemaFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return schemaFiles(path);
    return entry.name.endsWith('.schema.json') ? [path] : [];
  });
}

const schemas = schemaFiles(DOCS).sort().map((path) => {
  const schema = JSON.parse(readFileSync(path, 'utf8'));
  const repositoryPath = relative(ROOT, path).replaceAll('\\', '/');
  assert.equal(schema.$id, `${RAW_BASE}${repositoryPath}`,
    `${repositoryPath} must use a fetchable raw-content $id`);
  return { path, repositoryPath, schema };
});

const ajv = new Ajv2020({
  allErrors: true, allowUnionTypes: true, strict: true, strictTypes: false,
  strictRequired: false, $data: false,
});
addFormats(ajv);
for (const { schema } of schemas) ajv.addSchema(schema);
const compiled = new Map(schemas.map(({ repositoryPath, schema }) => {
  const validate = ajv.getSchema(schema.$id);
  assert.equal(typeof validate, 'function', `${repositoryPath} did not compile`);
  return [repositoryPath, validate];
}));

const zeroSeverity = () => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
const zeroState = () => ({ confirmed: 0, suspected: 0, unknown: 0, not_applicable: 0 });
const zeroBaseline = () => ({ new: 0, unchanged: 0, regressed: 0, fixed: 0, unretested: 0, not_comparable: 0 });
const zeroDomain = () => ({
  total: 0,
  byState: Object.fromEntries(['confirmed', 'suspected', 'unknown', 'not_applicable']
    .map((state) => [state, { total: 0, bySeverity: zeroSeverity() }])),
});

function emptyReport(schemaVersion) {
  return {
    schemaVersion,
    tool: { name: 'Web App Security Skill', version: '0.7.2' },
    generatedAt: '2026-08-25T00:00:00.000Z', mode: 'audit',
    subject: {
      id: 'project-0123456789abcdef0123456789abcdef', binding: 'ephemeral',
      scopeDigest: 'a'.repeat(64), localPathIncluded: false,
    },
    ruleset: { digest: 'b'.repeat(64), fingerprintVersion: 2, adapters: [] },
    scope: {},
    policy: {
      thresholds: V2_DOMAINS.map((domain) => ({ domain, failOn: 'never' })),
      gateStates: ['confirmed', 'suspected'], precedence: 'actionable_threshold_before_incomplete',
    },
    coverage: [],
    summary: {
      total: 0, byDomain: Object.fromEntries(V2_DOMAINS.map((domain) => [domain, zeroDomain()])),
      bySeverity: zeroSeverity(), byState: zeroState(), byBaseline: zeroBaseline(),
    },
    findings: [], limitations: ['Curated schema-contract fixture.'], baseline: null, migration: null,
  };
}

const ruleset = sourceRuleset();
const findingV2 = createFindingV2({
  ruleset, adapterId: 'builtin-source', rule: sourceRule('dependency-lockfile-missing'),
  title: 'Missing lockfile', severity: 'low', state: 'confirmed', summary: 'No lockfile was found.',
  evidence: { subject: 'package.json' }, remediation: 'Commit the applicable lockfile.',
  retest: 'Run the source audit again.',
});
const findingV3 = upgradeFindingV2(findingV2);
const routeV2 = createRouteSecurityDocument({
  version: '0.7.2', generatedAt: '2026-08-25T00:00:00.000Z', mode: 'audit',
  subject: { id: 'project-0123456789abcdef0123456789abcdef', scopeDigest: 'c'.repeat(64) },
  routes: [], coverage: [], limitations: ['Curated schema-contract fixture.'],
});
routeV2.schemaVersion = 2;
routeV2.analyzer.revision = '2';
delete routeV2.analyzer.analysisLimits;
const routeV3 = createRouteSecurityDocument({
  version: '0.8.0', generatedAt: '2026-08-29T00:00:00.000Z', mode: 'audit',
  subject: { id: 'project-0123456789abcdef0123456789abcdef', scopeDigest: 'd'.repeat(64) },
  routes: [], coverage: [], limitations: ['Curated schema-contract fixture.'],
});
const routeV3Golden = JSON.parse(readFileSync(join(ROOT,
  'test/fixtures/route-security-v3-golden.json'), 'utf8'));
const routeV3Invalid = JSON.parse(readFileSync(join(ROOT,
  'test/fixtures/route-security-v3-invalid.json'), 'utf8'));

function check(label, schemaPath, manualValidator, value, expected) {
  const schemaValidator = compiled.get(schemaPath);
  const schemaValid = schemaValidator(value);
  let manualErrors;
  assert.doesNotThrow(() => { manualErrors = manualValidator(value); },
    `${label} handwritten validator threw`);
  assert.ok(Array.isArray(manualErrors), `${label} handwritten validator must return an array`);
  assert.equal(schemaValid, expected,
    `${label} JSON Schema result differed: ${ajv.errorsText(schemaValidator.errors)}`);
  assert.equal(manualErrors.length === 0, expected,
    `${label} handwritten result differed: ${manualErrors.join('; ')}`);
}

const reportV2 = emptyReport(2);
const reportV3 = emptyReport(3);
check('report v2 positive', 'docs/report-v2.schema.json', validateReportV2, reportV2, true);
check('report v2 extra property', 'docs/report-v2.schema.json', validateReportV2,
  { ...reportV2, unexpected: true }, false);
check('report v3 positive', 'docs/report-v3.schema.json', validateReportV3, reportV3, true);
check('report v3 extra property', 'docs/report-v3.schema.json', validateReportV3,
  { ...reportV3, unexpected: true }, false);
check('finding v2 positive', 'docs/finding-v2.schema.json', validateFindingV2, findingV2, true);
check('finding v2 extra property', 'docs/finding-v2.schema.json', validateFindingV2,
  { ...findingV2, unexpected: true }, false);
check('finding v3 positive', 'docs/finding-v3.schema.json', validateFindingV3, findingV3, true);
check('finding v3 v1 shape', 'docs/finding-v3.schema.json', validateFindingV3,
  { schemaVersion: 1, id: 'legacy.finding' }, false);
check('route v2 positive', 'docs/route-security-v2.schema.json', validateRouteSecurityDocument,
  routeV2, true);
check('route v2 extra property', 'docs/route-security-v2.schema.json', validateRouteSecurityDocument,
  { ...routeV2, unexpected: true }, false);
check('route v3 positive', 'docs/route-security-v3.schema.json', validateRouteSecurityDocument,
  routeV3, true);
check('route v3 golden path states', 'docs/route-security-v3.schema.json',
  validateRouteSecurityDocument, routeV3Golden, true);
check('route v3 extra property', 'docs/route-security-v3.schema.json', validateRouteSecurityDocument,
  { ...routeV3, unexpected: true }, false);

function setPath(root, path, value) {
  const segments = path.split('.');
  let cursor = root;
  for (const segment of segments.slice(0, -1)) cursor = cursor[Number.isNaN(Number(segment)) ? segment : Number(segment)];
  cursor[segments.at(-1)] = value;
}

for (const fixture of routeV3Invalid) {
  const invalid = structuredClone(routeV3Golden);
  let value = fixture.mutation.value;
  if (value === 'repeat_first_edge_five_times') {
    value = Array.from({ length: 5 }, () => structuredClone(
      routeV3Golden.routes[0].accessChains[1].callEdges[0]));
  } else if (value === 'repeat_x_121') value = 'x'.repeat(121);
  setPath(invalid, fixture.mutation.path, value);
  check(`route v3 invalid ${fixture.id}`, 'docs/route-security-v3.schema.json',
    validateRouteSecurityDocument, invalid, false);
}

const totalValidators = [
  validateFindingV2, validateFindingV3, validateReportV2, validateReportV3,
  validateRouteSecurityDocument, validateRepairRecord,
];
for (const value of [null, true, 1, 'text', [], {}]) {
  for (const validator of totalValidators) {
    let errors;
    assert.doesNotThrow(() => { errors = validator(value); },
      `${validator.name} threw for JSON value ${JSON.stringify(value)}`);
    assert.ok(Array.isArray(errors) && errors.length > 0,
      `${validator.name} must reject JSON value ${JSON.stringify(value)} with errors`);
  }
}

console.log(`JSON Schema contracts ok: ${schemas.length} schemas compiled; ${13 + routeV3Invalid.length} overlap cases agreed`);
