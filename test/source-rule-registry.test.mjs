#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  CHECKOV_RULES, DEEP_PROFILE_ADAPTERS, GITLEAKS_RULES, OPENGREP_RULES, OSV_RULES,
  resolveAdapterSelection,
} from '../scripts/lib/adapter-definitions.mjs';
import {
  SOURCE_RULE_REGISTRY, registrySemanticDigest, runtimeRule, stableSourceRuleManifest,
  validateSourceRuleRegistry,
} from '../scripts/lib/source-rule-registry.mjs';
import { SOURCE_RULES, sourceRuleset } from '../scripts/lib/source-rules.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const clone = () => structuredClone(SOURCE_RULE_REGISTRY);

assert.deepEqual(validateSourceRuleRegistry(SOURCE_RULE_REGISTRY, { root: ROOT }), []);
const manifest = stableSourceRuleManifest();
assert.deepEqual(manifest.counts, {
  stableTotal: 44, builtInRisk: 25, builtInIntegrity: 3, externalRisk: 16,
});
assert.deepEqual(manifest.rules.map((rule) => rule.id),
  [...manifest.rules.map((rule) => rule.id)].sort());
assert.deepEqual(JSON.parse(readFileSync(`${ROOT}/docs/stable-source-rules.json`, 'utf8')), manifest);

const runtime = SOURCE_RULE_REGISTRY.filter((rule) =>
  rule.adapter.type === 'built_in' && rule.maturity === 'stable').map(runtimeRule);
assert.deepEqual(SOURCE_RULES, runtime);
assert.deepEqual(CHECKOV_RULES,
  SOURCE_RULE_REGISTRY.filter((rule) => rule.adapter.id === 'checkov').map(runtimeRule));
assert.deepEqual(GITLEAKS_RULES,
  SOURCE_RULE_REGISTRY.filter((rule) => rule.adapter.id === 'gitleaks').map(runtimeRule));
assert.deepEqual(OPENGREP_RULES,
  SOURCE_RULE_REGISTRY.filter((rule) => rule.adapter.id === 'opengrep').map(runtimeRule));
assert.deepEqual(OSV_RULES,
  SOURCE_RULE_REGISTRY.filter((rule) => rule.adapter.id === 'osv').map(runtimeRule));
assert.deepEqual(resolveAdapterSelection([], 'deep'), DEEP_PROFILE_ADAPTERS);
assert.throws(() => resolveAdapterSelection(['builtin'], 'deep'), /cannot be combined/);
assert.throws(() => resolveAdapterSelection([], 'wide'), /unsupported profile/);
assert.equal(sourceRuleset(['builtin', 'checkov', 'gitleaks', 'opengrep', 'osv']).digest,
  'e86cb3c7764e097e74fef80b52e7ae9c4aa25af275fbbae695854818524d15a3');

const docsOnly = clone();
docsOnly[0].plainLanguage = 'Documentation-only wording changed.';
assert.equal(registrySemanticDigest(docsOnly), manifest.semanticDigest);
const semantic = clone();
semantic[0].detection.workspaceAware = false;
assert.notEqual(registrySemanticDigest(semantic), manifest.semanticDigest);

const experimental = clone();
experimental.push({
  ...structuredClone(experimental[0]), id: 'experimental-fixture-rule', maturity: 'experimental',
  fixtures: structuredClone(experimental[0].fixtures),
});
assert.equal(validateSourceRuleRegistry(experimental, { root: ROOT }).length, 0);
assert.equal(stableSourceRuleManifest(experimental).counts.stableTotal, 44);

for (const mutate of [
  (registry) => { registry[1].id = registry[0].id; },
  (registry) => { registry[0].family = 'unknown_family'; },
  (registry) => { registry[0].standards = [{ id: 'OWASP-latest', url: 'https://example.com' }]; },
  (registry) => { registry[0].plainLanguage = ''; },
  (registry) => { registry[0].fixtures.negative = []; },
  (registry) => { registry[0].fixtures.positive[0].path = 'test/fixtures/does-not-exist'; },
]) {
  const invalid = clone();
  mutate(invalid);
  assert.ok(validateSourceRuleRegistry(invalid, { root: ROOT }).length > 0);
}

console.log('source rule registry ok: metadata, counts, fixtures, semantic digest and runtime identity');
