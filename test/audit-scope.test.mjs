#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  compileAuditScope, DEFAULT_EXCLUDED_DIRECTORIES,
} from '../scripts/lib/audit-scope.mjs';

const temp = mkdtempSync(join(tmpdir(), 'web-app-security-scope-'));
try {
  mkdirSync(join(temp, 'apps', 'web', 'src'), { recursive: true });
  mkdirSync(join(temp, 'apps', 'web', 'private'), { recursive: true });
  writeFileSync(join(temp, 'package.json'), '{}\n');
  writeFileSync(join(temp, 'package-lock.json'), '{}\n');
  writeFileSync(join(temp, 'apps', 'web', 'src', 'app.js'), 'export default true;\n');
  const policy = compileAuditScope(temp, {
    version: 2,
    sourceRoots: ['apps/web'],
    excludedDirectories: ['private'],
  });
  assert.equal(policy.includes('apps/web/src/app.js'), true);
  assert.equal(policy.includes('apps/web/private/secret.js'), false);
  assert.equal(policy.classify('apps/web/private/secret.js').reason, 'scope_excluded_directory');
  assert.equal(policy.includes('package.json'), false);
  assert.deepEqual(policy.governingInputs(['package.json'], ['package-lock.json']), [
    { path: 'package-lock.json', mode: 'governing_input' },
    { path: 'package.json', mode: 'governing_input' },
  ]);
  assert.ok(policy.excludedDirectoryNames.includes('.git'));
  assert.ok(policy.excludedDirectoryNames.includes('.webapp-security'));
  assert.equal(policy.scopeDigest.length, 64);
  assert.equal(policy.restricted, true);

  const defaultPolicy = compileAuditScope(temp, {
    version: 2,
    sourceRoots: ['.'],
    excludedDirectories: [...DEFAULT_EXCLUDED_DIRECTORIES],
  });
  assert.equal(defaultPolicy.restricted, false);
  assert.equal(defaultPolicy.classify('.git/config').reason, 'scope_excluded_directory');

  assert.throws(() => compileAuditScope(temp, {
    sourceRoots: ['apps/web', 'apps/web'], excludedDirectories: [],
  }), /sourceRoots contains duplicates/);
  assert.throws(() => compileAuditScope(temp, {
    sourceRoots: ['../outside'], excludedDirectories: [],
  }), /source root is invalid/);
  assert.throws(() => compileAuditScope(temp, {
    sourceRoots: ['missing'], excludedDirectories: [],
  }), /source root is unavailable/);
  assert.throws(() => compileAuditScope(temp, {
    sourceRoots: ['apps/web'], excludedDirectories: ['nested/private'],
  }), /excluded directory must be a basename/);
  symlinkSync(join(temp, 'apps', 'web'), join(temp, 'linked-root'));
  assert.throws(() => compileAuditScope(temp, {
    sourceRoots: ['linked-root'], excludedDirectories: [],
  }), /source root is unavailable/);
} finally {
  rmSync(temp, { recursive: true, force: true });
}

console.log('audit scope ok: roots, exclusions, governing inputs, containment and digest are canonical');
