#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  scopeDigest, sourceAuditBoundary, validatePersistedScope,
} from '../scripts/lib/project-identity.mjs';
import { runOsv } from '../scripts/lib/external-adapters.mjs';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const temp = mkdtempSync(join(tmpdir(), 'web-app-security-scope-target-'));

function scope(projectRoot) {
  const auditBoundary = sourceAuditBoundary();
  return {
    schemaVersion: 2,
    generatedBy: { product: 'Web App Security Skill', version: '0.7.3-test' },
    subject: {
      id: `project-${'a'.repeat(32)}`, binding: 'persisted',
      scopeDigest: scopeDigest(auditBoundary), localPathIncluded: false,
    },
    auditBoundary,
    target: {
      projectRoot, frameworks: [{ name: 'Express', root: '.' }],
      packageManagers: [{ name: 'npm', root: '.' }], manifests: ['package.json'],
      lockfiles: ['package-lock.json'], deploymentSurfaces: [], configSurfaces: [],
    },
  };
}

function schemaScope(projectRoot) {
  const value = scope(projectRoot);
  value.generatedAt = '2026-08-26T00:00:00.000Z';
  value.run = { id: 'schema-fixture', directory: '.webapp-security/runs/schema-fixture' };
  Object.assign(value.target, {
    discoveryStatus: 'supported', layout: 'single-root', publicOrigins: [],
  });
  value.authorization = { status: 'pending', basis: '', proof: '', note: '' };
  value.checkModes = { source: true, local: true, remotePassive: false, remoteActive: false };
  value.discoveryEvidence = {
    examinedFiles: [], networkAccessPerformed: false, secretFilesRead: false, warnings: [], unknowns: [],
  };
  value.exclusions = [];
  return value;
}

try {
  const project = join(temp, 'project');
  const outside = join(temp, 'outside');
  mkdirSync(project);
  mkdirSync(outside);
  writeFileSync(join(project, 'package.json'), '{}\n');
  writeFileSync(join(project, 'package-lock.json'), '{}\n');
  writeFileSync(join(outside, 'outside.lock'), '{}\n');
  assert.equal(validatePersistedScope(scope(project)).target.projectRoot, project);

  const ajv = new Ajv2020({ strict: true, strictTypes: false, strictRequired: false });
  addFormats(ajv);
  const validateSchema = ajv.compile(JSON.parse(readFileSync(
    new URL('../docs/security-scope.schema.json', import.meta.url), 'utf8')));
  assert.equal(validateSchema(schemaScope(project)), true, ajv.errorsText(validateSchema.errors));
  for (const [field, value] of [
    ['projectRoot', '../relative'], ['lockfiles', '../escape.lock'],
    ['lockfiles', '/etc/passwd'], ['lockfiles', 'nested/./lockfile'],
  ]) {
    const hostile = schemaScope(project);
    if (field === 'projectRoot') hostile.target.projectRoot = value;
    else hostile.target.lockfiles = [value];
    assert.equal(validateSchema(hostile), false, `${field} ${value} must fail the public schema`);
  }

  for (const value of ['/etc/passwd', '../escape.lock', 'nested/../../escape.lock', 'bad\nname']) {
    const hostile = scope(project);
    hostile.target.lockfiles = [value];
    assert.throws(() => validatePersistedScope(hostile), /invalid lockfiles/);
  }
  const hostileRoot = scope(project);
  hostileRoot.target.projectRoot = '../relative';
  assert.throws(() => validatePersistedScope(hostileRoot), /invalid projectRoot/);
  const hostileFramework = scope(project);
  hostileFramework.target.frameworks[0].root = '../outside';
  assert.throws(() => validatePersistedScope(hostileFramework), /invalid frameworks root/);

  const fakeOsv = join(temp, 'fake-osv.mjs');
  writeFileSync(fakeOsv, `#!/usr/bin/env node
if (process.argv[2] === '--version') console.log('osv-scanner version: 2.5.0');
else console.log('{"results":[]}');
`);
  chmodSync(fakeOsv, 0o755);
  symlinkSync(join(outside, 'outside.lock'), join(project, 'linked.lock'));
  const escaped = runOsv(project, ['linked.lock'], { binary: fakeOsv, timeoutSeconds: 1 });
  assert.equal(escaped.coverage[0].status, 'unavailable');
  assert.equal(escaped.findings[0].evidence.reasonCode, 'adapter_input_path_unsafe');
  const missing = runOsv(project, ['missing.lock'], { binary: fakeOsv, timeoutSeconds: 1 });
  assert.equal(missing.findings[0].evidence.reasonCode, 'adapter_input_path_unavailable');
  const clean = runOsv(project, ['package-lock.json'], { binary: fakeOsv, timeoutSeconds: 1 });
  assert.equal(clean.coverage[0].status, 'completed');
} finally {
  rmSync(temp, { recursive: true, force: true });
}

console.log('scope target validation ok: canonical paths and OSV realpath containment');
