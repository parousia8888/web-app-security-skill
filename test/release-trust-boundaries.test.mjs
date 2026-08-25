#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { validateReleaseTrustLanguage } from '../scripts/lib/release-trust-boundaries.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (path) => readFileSync(`${ROOT}/${path}`, 'utf8');
const documents = {
  readme: read('README.md'),
  readmeZh: read('README.zh-CN.md'),
  security: read('SECURITY.md'),
  trust: read('docs/release-trust-boundaries.md'),
};
assert.deepEqual(validateReleaseTrustLanguage(documents), []);

const stale = structuredClone(documents);
stale.readme = stale.readme.replace('verify-tag v0.7.2', 'verify-tag v0.6.0');
assert.ok(validateReleaseTrustLanguage(stale).includes('README tag verification example is stale'));

const conflated = structuredClone(documents);
conflated.trust = conflated.trust.replace('does not independently prove GitHub account ownership',
  'proves GitHub account ownership');
assert.ok(validateReleaseTrustLanguage(conflated)
  .some((error) => error.includes('does not independently prove GitHub account ownership')));

console.log('release trust boundaries ok: local signer, GitHub and npm signals remain separate');
