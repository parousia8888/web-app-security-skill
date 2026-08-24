#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditSource } from '../scripts/lib/source-audit.mjs';
import {
  classifyPythonSource, inspectPythonSource, PYTHON_DEFERRED_CANDIDATES,
  PYTHON_SOURCE_RULE_IDS, tokenizePython,
} from '../scripts/lib/python-source-audit.mjs';
import { sourceRuleExplanation } from '../scripts/lib/source-rule-registry.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const vulnerablePath = 'test/fixtures/python-rules/vulnerable.py';
const safePath = 'test/fixtures/python-rules/safe.py';
const vulnerableText = readFileSync(join(ROOT, vulnerablePath), 'utf8');
const safeText = readFileSync(join(ROOT, safePath), 'utf8');

const vulnerable = inspectPythonSource('src/vulnerable.py', vulnerableText);
assert.equal(vulnerable.error, null);
assert.deepEqual(new Set(vulnerable.findings.map((finding) => finding.ruleId)),
  new Set(PYTHON_SOURCE_RULE_IDS));
assert.deepEqual(inspectPythonSource('src/safe.py', safeText).findings, []);
assert.equal(PYTHON_DEFERRED_CANDIDATES.length, 5);
assert.ok(PYTHON_DEFERRED_CANDIDATES.every((candidate) =>
  candidate.id && candidate.reason && !PYTHON_SOURCE_RULE_IDS.includes(candidate.id)));
for (const ruleId of PYTHON_SOURCE_RULE_IDS) {
  const finding = vulnerable.findings.find((item) => item.ruleId === ruleId);
  assert.ok(finding, ruleId);
  assert.equal(finding.state, 'suspected', ruleId);
  const explanation = sourceRuleExplanation('builtin-source', ruleId, finding);
  assert.ok(explanation.technicalTerm.length > 3, ruleId);
  assert.ok(explanation.plainLanguage.length > 20, ruleId);
  assert.ok(explanation.consequence.length > 20, ruleId);
  assert.ok(explanation.evidenceBoundary.length > 20, ruleId);
  assert.ok(explanation.sideEffects.length, ruleId);
  assert.ok(explanation.securityRetest.length > 20, ruleId);
  assert.ok(explanation.functionalRetest.length > 20, ruleId);
  assert.ok(explanation.rollback.length > 20, ruleId);
  assert.ok(explanation.userDecisions.length, ruleId);
}

const secrets = vulnerable.findings.filter((finding) =>
  finding.ruleId === 'python-hardcoded-framework-secret');
assert.ok(secrets.length >= 1);
for (const secret of secrets) {
  assert.equal(secret.evidence.literalRedacted, true);
  assert.deepEqual(Object.keys(secret.evidence).sort(),
    ['construct', 'line', 'literalLengthBand', 'literalRedacted', 'subject'].sort());
}
assert.doesNotMatch(JSON.stringify(vulnerable), /fixture-python-secret-never-deploy/);

const unrelatedSettings = inspectPythonSource('src/constants.py', `
  SESSION_COOKIE_SECURE = False
  WTF_CSRF_ENABLED = False
`);
assert.deepEqual(unrelatedSettings.findings, []);
const djangoProtections = inspectPythonSource('project/settings.py', `
  SESSION_COOKIE_SECURE = False
  SESSION_COOKIE_HTTPONLY = False
  CSRF_COOKIE_SECURE = False
`);
assert.equal(djangoProtections.findings.filter((finding) =>
  finding.ruleId === 'python-insecure-session-cookie-settings').length, 3);

const masked = inspectPythonSource('src/masked.py', String.raw`
  # eval(user); requests.get(url, verify=False)
  a = "eval(user); subprocess.run(user, shell=True)"
  b = '''yaml.load(payload); app.run(debug=True)'''
`);
assert.equal(masked.error, null);
assert.deepEqual(masked.findings, []);

const aliases = inspectPythonSource('src/aliases.py', `
  import httpx as client
  from pickle import loads as restore
  from yaml import load as parse
  from yaml import SafeLoader
  client.AsyncClient(
    verify=False,
  )
  restore(data)
  parse(data, Loader=SafeLoader)
`);
assert.deepEqual(new Set(aliases.findings.map((finding) => finding.ruleId)),
  new Set(['python-tls-verification-disabled', 'python-unsafe-deserialization']));
const yamlWithoutLoader = inspectPythonSource('src/legacy_yaml.py', `
  import yaml
  yaml.load(payload)
`);
assert.deepEqual(yamlWithoutLoader.findings, []);
const yamlLoaderAliases = inspectPythonSource('src/yaml_aliases.py', `
  from yaml import load as parse, SafeLoader as Safe, UnsafeLoader as Unsafe
  parse(first, Loader=Safe)
  parse(second, Loader=Unsafe)
`);
assert.deepEqual(yamlLoaderAliases.findings.map((finding) => finding.ruleId),
  ['python-unsafe-yaml-load']);
const genericSecret = inspectPythonSource('src/constants.py', `
  SECRET_KEY = "non-framework-constant-value"
`);
assert.deepEqual(genericSecret.findings, []);
const repeatedPythonSink = inspectPythonSource('src/repeated.py', `
  eval(first)
  eval(second)
`);
assert.equal(repeatedPythonSink.findings.length, 2);
assert.equal(new Set(repeatedPythonSink.findings.map((finding) => finding.evidence.subject)).size, 2);

const flaskCors = inspectPythonSource('src/flask_app.py', `
  from flask import Flask
  from flask_cors import CORS as CrossOrigin
  app = Flask(__name__)
  CrossOrigin(app, origins="*", supports_credentials=True)
`);
assert.deepEqual(flaskCors.findings.map((finding) => finding.ruleId),
  ['python-cors-wildcard-with-credentials']);

const django = inspectPythonSource('project/settings.py', `
  DEBUG = True
  SECRET_KEY = "fixture-django-secret-never-deploy"
  CORS_ALLOW_ALL_ORIGINS = True
  CORS_ALLOW_CREDENTIALS = True
`);
assert.deepEqual(new Set(django.findings.map((finding) => finding.ruleId)), new Set([
  'python-framework-debug-enabled', 'python-hardcoded-framework-secret',
  'python-cors-wildcard-with-credentials',
]));
assert.doesNotMatch(JSON.stringify(django), /fixture-django-secret-never-deploy/);

assert.equal(classifyPythonSource('src/app.py').eligible, true);
assert.deepEqual(classifyPythonSource('tests/test_app.py'),
  { eligible: false, reason: 'test_or_fixture_source' });
assert.deepEqual(classifyPythonSource('app/migrations/0001.py'),
  { eligible: false, reason: 'generated_or_migration_source' });
assert.deepEqual(classifyPythonSource('README.md'),
  { eligible: false, reason: 'unsupported_python_extension' });
assert.equal(tokenizePython('value = "unterminated').error.code, 'unterminated_python_string');
assert.equal(tokenizePython('run(\n').error.code, 'unbalanced_python_delimiter');
const operationLimited = inspectPythonSource('src/operation_limit.py',
  'import requests\nrequests.get("https://example.test", verify=False)\n', {
    analysisLimits: { maxOperationsPerFile: 12 },
  });
assert.equal(operationLimited.error.code, 'source_operation_limit');
assert.deepEqual(operationLimited.findings, []);
const rawRegex = String.raw`import re
_FM_TITLE = re.compile(r'^title:\s*["\']?(.+?)["\']?\s*$', re.MULTILINE)
`;
assert.equal(tokenizePython(rawRegex).error, null);
assert.deepEqual(inspectPythonSource('src/frontmatter.py', rawRegex).findings, []);

const temp = mkdtempSync(join(tmpdir(), 'webapp-security-python-'));
const write = (path, contents) => {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
};
try {
  write(join(temp, 'pyproject.toml'), '[project]\nname = "fixture"\nversion = "0"\n');
  write(join(temp, 'uv.lock'), 'version = 1\n');
  write(join(temp, 'src', 'app.py'), vulnerableText);
  write(join(temp, 'tests', 'test_ignored.py'), 'eval(untrusted)\n');
  write(join(temp, 'app', 'migrations', '0001.py'), 'eval(untrusted)\n');
  const audit = auditSource(temp);
  assert.deepEqual(new Set(audit.findings.filter((finding) =>
    PYTHON_SOURCE_RULE_IDS.includes(finding.ruleId)).map((finding) => finding.ruleId)),
  new Set(PYTHON_SOURCE_RULE_IDS));
  assert.equal(audit.findings.some((finding) => finding.location?.path.includes('test_ignored')
    || finding.location?.path.includes('migrations')), false);
  for (const ruleId of PYTHON_SOURCE_RULE_IDS) {
    assert.equal(audit.coverage[ruleId].status, 'completed', ruleId);
    assert.ok(audit.coverage[ruleId].reasons.some((reason) =>
      ['test_or_fixture_source', 'generated_or_migration_source'].includes(reason.code)), ruleId);
  }

  write(join(temp, 'src', 'broken.py'), 'value = "unterminated');
  const incomplete = auditSource(temp);
  assert.ok(incomplete.findings.some((finding) =>
    finding.ruleId === 'source-evidence-incomplete' && finding.state === 'unknown'));
  for (const ruleId of PYTHON_SOURCE_RULE_IDS) {
    assert.equal(incomplete.coverage[ruleId].status, 'partial', ruleId);
    assert.ok(incomplete.coverage[ruleId].reasons.some((reason) =>
      reason.code === 'unterminated_python_string'), ruleId);
  }
} finally {
  rmSync(temp, { recursive: true, force: true });
}

console.log('python source audit ok: 10 stable leads, aliases, safe neighbours, redaction and coverage');
