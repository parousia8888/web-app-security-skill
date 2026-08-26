#!/usr/bin/env node
import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  scopeDigest, sourceAuditBoundary, validatePersistedScope,
} from '../scripts/lib/project-identity.mjs';
import { runOsv } from '../scripts/lib/external-adapters.mjs';

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

try {
  const project = join(temp, 'project');
  const outside = join(temp, 'outside');
  mkdirSync(project);
  mkdirSync(outside);
  writeFileSync(join(project, 'package.json'), '{}\n');
  writeFileSync(join(project, 'package-lock.json'), '{}\n');
  writeFileSync(join(outside, 'outside.lock'), '{}\n');
  assert.equal(validatePersistedScope(scope(project)).target.projectRoot, project);

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
