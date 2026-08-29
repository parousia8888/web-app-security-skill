#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (path) => readFileSync(join(ROOT, path), 'utf8');
const json = (path) => JSON.parse(read(path));
const version = read('VERSION').trim();
const pkg = json('package.json');
const plugin = json('.claude-plugin/plugin.json');
const marketplace = json('.claude-plugin/marketplace.json');

assert.equal(pkg.name, 'web-app-security-skill');
assert.equal(pkg.version, version);
assert.equal(pkg.private, false);
assert.equal(pkg.bin['web-app-security-skill'], 'scripts/webapp-security.mjs');
assert.equal(pkg.bin['webapp-security'], 'scripts/webapp-security.mjs');
for (const entry of [
  'SKILL.md', 'VERSION', 'KNOWN_LIMITATIONS.md', 'THIRD_PARTY_NOTICES.md',
  'scripts', 'references', 'rules',
  'docs/release-trust-boundaries.md',
  'docs/conformance/rule-contract-conformance.json',
  'docs/conformance/rule-contract-conformance.md',
  'docs/regressions/v0.5.4-real-world-regressions.json',
  'docs/regressions/v0.5.4-real-world-regressions.md',
  'docs/regressions/v0.6.0-route-real-world-regressions.json',
  'docs/regressions/v0.6.0-route-real-world-regressions.md',
  'docs/regressions/v0.7.0-access-control-real-world-regressions.json',
  'docs/regressions/v0.7.0-access-control-real-world-regressions.md',
  'docs/reviews/v0.6.0-route-review.json',
  'docs/reviews/v0.6.0-route-review.md',
  'docs/reviews/v0.6.0-route-review-provenance.json',
  'docs/reviews/v0.6.0-route-review-provenance.md',
  'docs/reviews/v0.7.0-access-control-review.json',
  'docs/reviews/v0.7.0-access-control-review.md',
  'docs/route-security-v1.schema.json',
  'docs/route-security-v2.schema.json',
  'docs/route-security-v3.schema.json',
]) {
  assert.ok(pkg.files.includes(entry), `npm files is missing ${entry}`);
}
const parserManifest = json('scripts/vendor/js-ts-parser.manifest.json');
assert.equal(parserManifest.component, '@babel/parser');
assert.equal(parserManifest.license, 'MIT');
assert.match(read('THIRD_PARTY_NOTICES.md'), /@babel\/parser 7\.28\.4/);
for (const forbidden of ['test', 'docs/assets', 'docs/adoption']) {
  assert.ok(!pkg.files.includes(forbidden), `npm files must not include ${forbidden}`);
}

assert.equal(plugin.name, 'web-app-security-skill');
assert.equal(plugin.version, version);
assert.equal(plugin.license, 'MIT');
assert.match(read('SKILL.md'), /^---\nname: web-app-security\n/m);
assert.equal(marketplace.name, 'web-app-security');
assert.equal(marketplace.metadata.version, version);
assert.equal(marketplace.plugins.length, 1);
assert.equal(marketplace.plugins[0].name, plugin.name);
assert.equal(marketplace.plugins[0].version, version);
assert.equal(marketplace.plugins[0].source, './');

const limitations = read('KNOWN_LIMITATIONS.md');
for (const heading of [
  '# Known limitations', '## Built-in detection', '## Incremental audit',
  '## Route-security review',
  '## External adapters and runtime evidence', '## Recurring expected matches',
  '## Resolved regressions',
]) assert.ok(limitations.includes(heading), `known limitations is missing ${heading}`);
assert.match(limitations, /does not establish that a\nWeb application is secure/);

console.log(`distribution contract ok: npm and Claude plugin ${version}, current limits published`);
