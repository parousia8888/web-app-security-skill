#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (path) => readFileSync(`${ROOT}/${path}`, 'utf8');
const release = read('.github/workflows/release.yml');
const ci = read('.github/workflows/ci.yml');
const consumer = read('.github/workflows/action-v1-consumer.yml');
const verifier = read('scripts/verify-release-candidate.mjs');

assert.match(release, /workflow_dispatch:/,
  'release publication must be manually dispatched from trusted main');
assert.match(release, /version:\s*\n[\s\S]*tag:/,
  'manual dispatch names the version and immutable tag explicitly');
assert.doesNotMatch(release, /push:\s*\n\s*tags:/,
  'an unverified tag push cannot obtain publication permissions');
assert.match(release, /if:\s*["']?github\.ref == 'refs\/heads\/main'/,
  'release execution is restricted to the trusted main branch');
assert.match(release, /verify-and-build:/);
assert.match(release, /publish:/);
assert.match(release, /post-publish-verify:/);
assert.doesNotMatch(release, /^permissions:\s*\n\s+contents:\s*["']?write/m,
  'write permissions must not be granted at workflow scope');
assert.match(release, /environment:\s*["']?release["']?/,
  'write-capable publication uses the protected release environment');
assert.match(release, /scripts\/verify-release-candidate\.mjs/,
  'candidate tags use the main-sourced verifier before dependencies or publication');
assert.ok(release.indexOf('scripts/verify-release-candidate.mjs')
  < release.indexOf('npm ci --ignore-scripts'),
  'candidate trust verification must precede dependency installation');
assert.match(release, /actions\/download-artifact@[a-f0-9]{40}/,
  'publication consumes the verified read-only artifact bundle');
const verifyJob = release.slice(release.indexOf('  verify-and-build:'), release.indexOf('  publish:'));
const publishJob = release.slice(release.indexOf('  publish:'), release.indexOf('  post-publish-verify:'));
const postJob = release.slice(release.indexOf('  post-publish-verify:'));
assert.doesNotMatch(verifyJob, /contents:\s*["']?write/);
assert.doesNotMatch(verifyJob, /id-token:\s*["']?write|attestations:\s*["']?write/);
assert.match(publishJob, /contents:\s*["']?write/);
assert.match(publishJob, /id-token:\s*["']?write/);
assert.match(publishJob, /attestations:\s*["']?write/);
assert.match(publishJob, /needs:\s*\[verify-and-build\]/);
assert.doesNotMatch(postJob, /contents:\s*["']?write/);
assert.match(verifier, /gpg\.ssh\.allowedSignersFile/,
  'the verifier performs cryptographic tag verification');
assert.match(verifier, /\.github\/release-signers/,
  'the signer allowlist is sourced from the trusted checkout');

assert.match(ci, /branches:\s*\[main\]/,
  'generic CI is branch-scoped and does not run during moving-tag promotion');
assert.doesNotMatch(ci, /^on:\s*\[push, pull_request\]/m);
assert.match(consumer, /group:\s*["']action-v1-promotion["']/);
assert.match(consumer, /cancel-in-progress:\s*false/);
assert.match(consumer, /- ["']promotion["']/);
assert.match(consumer, /promotion-run-id:/);
assert.match(consumer, /check-public-release-state\.mjs --phase pending/);
assert.match(consumer, /check-public-release-state\.mjs --phase final/);
assert.match(consumer, /gh run download ["']\$PROMOTION_RUN_ID["']/);
const promotionJob = consumer.slice(consumer.indexOf('  promotion-verification:'),
  consumer.indexOf('  final-state-verification:'));
const finalJob = consumer.slice(consumer.indexOf('  final-state-verification:'));
assert.doesNotMatch(promotionJob, /contents:\s*["']?write/,
  'pending consumer evidence is read-only');
assert.match(finalJob, /environment:\s*["']?release["']?/,
  'the final Release asset write is environment-bound');
assert.match(finalJob, /contents:\s*["']?write/);

console.log('v0.8.1 release workflow contract ok: trusted-main verification precedes isolated publication');
