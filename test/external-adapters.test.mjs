#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  parseCheckovJson, parseGitleaksJson, parseOpengrepJson, parseOsvJson, runCheckov, runGitleaks,
  runOpengrep, runOsv,
} from '../scripts/lib/external-adapters.mjs';
import { createFindingV2 } from '../scripts/lib/evidence-v2.mjs';
import { sanitizeEvidence } from '../scripts/lib/evidence-writer.mjs';
import { sourceRuleForAdapter, sourceRuleset } from '../scripts/lib/source-rules.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(ROOT, 'scripts', 'webapp-security.mjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-adapters-'));
const project = join(temp, 'project');
const secret = 'M6_EXTERNAL_SECRET_SENTINEL';
mkdirSync(project);
mkdirSync(join(project, '.git'));
writeFileSync(join(project, 'package.json'), '{"name":"fixture","version":"1.0.0"}\n');
writeFileSync(join(project, 'package-lock.json'), '{"name":"fixture","version":"1.0.0","lockfileVersion":3,"packages":{}}\n');
writeFileSync(join(project, 'config.txt'), 'fixture\n');
writeFileSync(join(project, 'Dockerfile'), 'FROM node:22-alpine\nUSER root\nCMD ["node", "server.js"]\n');
mkdirSync(join(project, '.github', 'workflows'), { recursive: true });
writeFileSync(join(project, '.github', 'workflows', 'ci.yml'), 'name: fixture\non: push\npermissions: write-all\n');
mkdirSync(join(project, 'nested'));
writeFileSync(join(project, 'nested', 'Dockerfile'), 'FROM alpine\nUSER root\n');

const fakeCheckov = join(temp, 'fake-checkov.mjs');
writeFileSync(fakeCheckov, `#!/usr/bin/env node
import { dirname, join } from 'node:path';
import { mkdirSync, writeFileSync } from 'node:fs';
const args = process.argv.slice(2);
const mode = process.env.FAKE_CHECKOV_MODE || 'clean';
const state = join(process.env.HOME, 'Library', 'Caches', 'checkov', 'update_checker_cache.json');
mkdirSync(dirname(state), { recursive: true });
writeFileSync(state, '${secret}');
writeFileSync(join(process.env.TMPDIR, '.lark_cache_fixture.tmp'), '${secret}');
if (args[0] === '--version') {
  console.log(mode === 'version-drift' ? '3.3.8' : '3.3.9');
  process.exit(0);
}
const fileFlag = args.indexOf('-f');
const frameworkFlag = args.indexOf('--framework');
const scannedFiles = fileFlag >= 0 && frameworkFlag > fileFlag
  ? args.slice(fileFlag + 1, frameworkFlag)
  : [];
if (args.includes('-d') || scannedFiles.join(',') !== 'Dockerfile,.github/workflows/ci.yml') {
  process.exit(2);
}
const check = (check_id, file_path, file_line_range) => ({
  check_id, file_path, file_line_range, code_block: [[1, '${secret}']], resource: '${secret}',
});
const docker = {
  check_type: 'dockerfile',
  summary: { checkov_version: '3.3.9', parsing_errors: mode === 'scan-errors' ? 1 : 0 },
  results: { passed_checks: [], failed_checks: [], skipped_checks: [] },
};
const workflow = {
  check_type: 'github_actions',
  summary: { checkov_version: '3.3.9', parsing_errors: 0 },
  results: { passed_checks: [], failed_checks: [], skipped_checks: [] },
};
const root = check('CKV_DOCKER_8', '/Dockerfile', [2, 2]);
const health = check('CKV_DOCKER_2', '/Dockerfile', [1, 3]);
const permissions = check('CKV2_GHA_1', '/.github/workflows/ci.yml', [3, 3]);
if (mode === 'finding' || mode === 'duplicate') {
  docker.results.failed_checks = mode === 'duplicate' ? [root, root, health] : [root, health];
  workflow.results.failed_checks = [permissions];
} else if (mode === 'escape') {
  docker.results.failed_checks = [check('CKV_DOCKER_8', '/../escape', [1, 1]), health];
  workflow.results.passed_checks = [permissions];
} else if (mode === 'unknown-rule') {
  docker.results.failed_checks = [check('CKV_DOCKER_99', '/Dockerfile', [1, 1])];
  workflow.results.passed_checks = [permissions];
} else if (mode === 'incomplete') {
  docker.results.passed_checks = [root];
  workflow.results.passed_checks = [permissions];
} else if (mode === 'suppressed') {
  docker.results.passed_checks = [health];
  docker.results.skipped_checks = [root];
  workflow.results.passed_checks = [permissions];
} else {
  docker.results.passed_checks = [root, health];
  workflow.results.passed_checks = [permissions];
}
if (mode === 'timeout') setTimeout(() => {}, 5000);
else if (mode === 'output-limit') process.stdout.write('x'.repeat(17 * 1024 * 1024));
else if (mode === 'internal') { console.error('${secret} raw stderr'); process.exit(2); }
else if (mode === 'malformed') { console.log('{bad'); process.exit(1); }
else if (mode === 'inconsistent') { console.log(JSON.stringify([docker, workflow])); process.exit(1); }
else {
  console.error('${secret} raw stderr');
  console.log(JSON.stringify([docker, workflow]));
  process.exit(['finding', 'duplicate', 'escape', 'unknown-rule'].includes(mode) ? 1 : 0);
}
`);
chmodSync(fakeCheckov, 0o755);

const fakeGitleaks = join(temp, 'fake-gitleaks.mjs');
writeFileSync(fakeGitleaks, `#!/usr/bin/env node
const [command] = process.argv.slice(2);
const mode = process.env.FAKE_GITLEAKS_MODE || 'clean';
if (command === 'version') {
  console.log(mode === 'version-drift' ? '8.29.0' : '8.30.1');
  process.exit(0);
}
if (mode === 'timeout') { setTimeout(() => {}, 5000); }
else if (mode === 'internal') { console.error('${secret} raw stderr'); process.exit(2); }
else if (mode === 'malformed') { console.log('{bad'); process.exit(1); }
else if (mode === 'inconsistent') { console.log('[]'); process.exit(1); }
else if (mode === 'history-duplicates' && command === 'git') {
  console.log(JSON.stringify([
    { RuleID: 'generic-api-key', StartLine: 2, File: 'config.txt', Fingerprint: 'first-history-fingerprint', Commit: 'a'.repeat(40) },
    { RuleID: 'generic-api-key', StartLine: 2, File: 'config.txt', Fingerprint: 'second-history-fingerprint', Commit: 'b'.repeat(40) },
  ]));
  process.exit(1);
}
else if (mode === 'finding') {
  console.error('${secret} raw stderr');
  console.log(JSON.stringify([{
    RuleID: 'github-pat', StartLine: 2, File: 'config.txt', Fingerprint: 'fixture-fingerprint',
    Secret: '${secret}', Match: '${secret}', Email: '${secret}@example.invalid', Commit: 'a'.repeat(40),
  }]));
  process.exit(1);
} else { console.log('[]'); process.exit(0); }
`);
chmodSync(fakeGitleaks, 0o755);

const fakeOsv = join(temp, 'fake-osv.mjs');
writeFileSync(fakeOsv, `#!/usr/bin/env node
const args = process.argv.slice(2);
const mode = process.env.FAKE_OSV_MODE || 'clean';
if (args[0] === '--version') {
  console.log('osv-scanner version: ' + (mode === 'version-drift' ? '2.4.0' : '2.5.0'));
  process.exit(0);
}
if (mode === 'timeout') { setTimeout(() => {}, 5000); }
else if (mode === 'internal') { console.error('${secret} raw stderr'); process.exit(2); }
else if (mode === 'malformed') { console.log('{bad'); process.exit(1); }
else if (mode === 'inconsistent') { console.log('{"results":[]}'); process.exit(1); }
else if (mode === 'finding' || mode === 'no-severity') {
  console.error('${secret} raw stderr');
  const group = { ids: ['GHSA-fixture-0001'], aliases: ['CVE-2099-0001'] };
  if (mode === 'finding') group.max_severity = '9.9';
  console.log(JSON.stringify({ results: [{
    source: { path: args[args.indexOf('--lockfile') + 1], type: 'lockfile' },
    packages: [{
      package: { name: 'fixture-package', version: '1.0.0', ecosystem: 'npm' },
      groups: [group],
      vulnerabilities: [{ id: 'GHSA-fixture-0001', database_specific: { severity: 'CRITICAL', secret: '${secret}' } }],
    }],
  }] }));
  process.exit(1);
} else { console.log('{"results":[]}'); process.exit(0); }
`);
chmodSync(fakeOsv, 0o755);

const fakeOpengrep = join(temp, 'fake-opengrep.mjs');
writeFileSync(fakeOpengrep, `#!/usr/bin/env node
import { dirname, join } from 'node:path';
import { mkdirSync, writeFileSync } from 'node:fs';
const args = process.argv.slice(2);
const mode = process.env.FAKE_OPENGREP_MODE || 'clean';
const logFile = process.env.SEMGREP_LOG_FILE || join(process.env.HOME, '.opengrep', 'semgrep.log');
mkdirSync(dirname(logFile), { recursive: true });
writeFileSync(logFile, '${secret} ' + process.cwd());
if (args[0] === '--version') {
  console.log(mode === 'version-drift' ? '1.26.0' : '1.27.0');
  process.exit(0);
}
const root = process.cwd();
const clean = { version: '1.27.0', results: [], errors: [], paths: { scanned: ['config.txt'] } };
if (mode === 'timeout') { setTimeout(() => {}, 5000); }
else if (mode === 'output-limit') { process.stdout.write('x'.repeat(17 * 1024 * 1024)); }
else if (mode === 'internal') { console.error('${secret} raw stderr'); process.exit(2); }
else if (mode === 'malformed') { console.log('{bad'); process.exit(1); }
else if (mode === 'inconsistent') { console.log(JSON.stringify(clean)); process.exit(1); }
else if (mode === 'scan-errors') { clean.errors.push({ message: '${secret}' }); console.log(JSON.stringify(clean)); }
else if (mode === 'finding' || mode === 'escape') {
  const path = mode === 'escape' ? '../escape.js' : 'config.txt';
  const item = {
    check_id: 'webapp-security.javascript.request-to-command', path,
    start: { line: 2, col: 3 }, end: { line: 2, col: 20 },
    extra: { engine_kind: 'OSS', lines: '${secret}', metavars: { value: '${secret}' } },
  };
  clean.results = [item, item];
  console.error('${secret} raw stderr');
  console.log(JSON.stringify(clean));
  process.exit(1);
} else { console.log(JSON.stringify(clean)); }
`);
chmodSync(fakeOpengrep, 0o755);

function withEnv(values, callback) {
  const prior = Object.fromEntries(Object.keys(values).map((key) => [key, process.env[key]]));
  Object.assign(process.env, values);
  try { return callback(); } finally {
    for (const [key, value] of Object.entries(prior)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
}

function cli(args, env = {}) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 10000,
    env: { ...process.env, ...env, SOURCE_DATE_EPOCH: '0' },
  });
}

try {
  const cleanCheckov = JSON.stringify([
    {
      check_type: 'dockerfile', summary: { checkov_version: '3.3.9', parsing_errors: 0 },
      results: {
        passed_checks: [
          { check_id: 'CKV_DOCKER_8', file_path: '/Dockerfile' },
          { check_id: 'CKV_DOCKER_2', file_path: '/Dockerfile' },
        ],
        failed_checks: [], skipped_checks: [],
      },
    },
    {
      check_type: 'github_actions', summary: { checkov_version: '3.3.9', parsing_errors: 0 },
      results: {
        passed_checks: [{ check_id: 'CKV2_GHA_1', file_path: '/.github/workflows/ci.yml' }],
        failed_checks: [], skipped_checks: [],
      },
    },
  ]);
  assert.deepEqual(parseCheckovJson(cleanCheckov, project).findings, []);
  assert.throws(() => parseCheckovJson('{bad', project), /malformed_json/);
  let result = withEnv({ FAKE_CHECKOV_MODE: 'finding' }, () => runCheckov(project, {
    binary: fakeCheckov, timeoutSeconds: 1,
  }));
  assert.deepEqual(result.findings.map((finding) => finding.ruleId), [
    'checkov-dockerfile-healthcheck-missing',
    'checkov-dockerfile-root-user',
    'checkov-github-actions-write-all',
  ]);
  assert.ok(result.findings.every((finding) => finding.state === 'suspected'));
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.ok(result.coverage.every((entry) => entry.status === 'completed'));
  result = withEnv({ FAKE_CHECKOV_MODE: 'duplicate' }, () => runCheckov(project, {
    binary: fakeCheckov, timeoutSeconds: 1,
  }));
  assert.equal(result.findings.length, 3, 'duplicate Checkov results must be stable and deduplicated');
  for (const [mode, reason] of [
    ['malformed', 'adapter_malformed_json'], ['inconsistent', 'adapter_inconsistent_exit'],
    ['scan-errors', 'adapter_scan_errors'], ['escape', 'adapter_unsafe_path'],
    ['unknown-rule', 'adapter_unknown_rule'], ['incomplete', 'adapter_incomplete_framework_evidence'],
    ['internal', 'adapter_internal_error'], ['timeout', 'adapter_timeout'],
    ['output-limit', 'adapter_output_limit'],
  ]) {
    result = withEnv({ FAKE_CHECKOV_MODE: mode }, () => runCheckov(project, {
      binary: fakeCheckov, timeoutSeconds: mode === 'output-limit' ? 10 : 1,
    }));
    assert.ok(result.coverage.every((entry) => entry.status === 'unavailable'), `${mode}: ${JSON.stringify(result)}`);
    assert.ok(result.findings.every((finding) => finding.state === 'unknown'));
    assert.ok(result.findings.every((finding) => finding.evidence.reasonCode === reason),
      `${mode}: expected ${reason}: ${JSON.stringify(result)}`);
  }
  result = withEnv({ FAKE_CHECKOV_MODE: 'suppressed' }, () => runCheckov(project, {
    binary: fakeCheckov, timeoutSeconds: 1,
  }));
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].evidence.reasonCode, 'adapter_rule_suppressed');
  assert.equal(result.coverage.find((entry) => entry.ruleId === 'checkov-dockerfile-root-user').status, 'unavailable');
  assert.ok(result.coverage.filter((entry) => entry.ruleId !== 'checkov-dockerfile-root-user')
    .every((entry) => entry.status === 'completed'));
  result = withEnv({ FAKE_CHECKOV_MODE: 'version-drift' }, () => runCheckov(project, {
    binary: fakeCheckov, timeoutSeconds: 1,
  }));
  assert.equal(result.identity.status, 'unsupported_version');
  result = runCheckov(project, { binary: join(temp, 'missing-checkov'), timeoutSeconds: 1 });
  assert.ok(result.findings.every((finding) => finding.evidence.reasonCode === 'adapter_missing'));
  const checkovHome = join(temp, 'checkov-home');
  const userCache = join(checkovHome, 'Library', 'Caches', 'checkov', 'update_checker_cache.json');
  mkdirSync(dirname(userCache), { recursive: true });
  writeFileSync(userCache, 'owner cache\n');
  withEnv({ FAKE_CHECKOV_MODE: 'clean', HOME: checkovHome }, () => runCheckov(project, {
    binary: fakeCheckov, timeoutSeconds: 1,
  }));
  assert.equal(readFileSync(userCache, 'utf8'), 'owner cache\n', 'Checkov must not write state to the user cache');
  const noDeployment = join(temp, 'no-deployment');
  mkdirSync(noDeployment);
  result = runCheckov(noDeployment, { binary: join(temp, 'missing-checkov'), timeoutSeconds: 1 });
  assert.equal(result.identity.status, 'not_applicable');
  assert.equal(result.findings.length, 0);
  assert.ok(result.coverage.every((entry) => entry.status === 'not_applicable'));

  assert.deepEqual(parseGitleaksJson('[]', project, 'working-tree'), []);
  assert.throws(() => parseGitleaksJson('{bad', project, 'working-tree'), /malformed_json/);
  assert.throws(() => parseGitleaksJson('[{"RuleID":"x","StartLine":1,"File":"../escape"}]', project, 'working-tree'), /unsafe_path/);
  const parsedSecret = parseGitleaksJson(JSON.stringify([{
    RuleID: 'github-pat', StartLine: 2, File: 'config.txt', Fingerprint: 'fixture',
    Secret: secret, Match: secret, Email: `${secret}@example.invalid`, Commit: 'b'.repeat(40),
  }]), project, 'history');
  assert.equal(parsedSecret.length, 1);
  assert.equal(JSON.stringify(parsedSecret).includes(secret), false);
  assert.equal(parsedSecret[0].evidence.externalRuleId, 'github-pat');
  const deduplicatedSecrets = parseGitleaksJson(JSON.stringify([
    { RuleID: 'github-pat', StartLine: 2, File: 'config.txt', Fingerprint: 'same' },
    { RuleID: 'github-pat', StartLine: 2, File: 'config.txt', Fingerprint: 'same' },
    { RuleID: 'github-pat', StartLine: 2, File: 'config.txt', Fingerprint: 'different' },
  ]), project, 'history');
  assert.equal(deduplicatedSecrets.length, 2);
  assert.notEqual(deduplicatedSecrets[0].evidence.subject, deduplicatedSecrets[1].evidence.subject);

  const ruleset = sourceRuleset(['builtin', 'gitleaks']);
  const gitleaksRule = sourceRuleForAdapter('gitleaks', 'gitleaks-committed-secret', ['builtin', 'gitleaks']);
  let numericDigestFinding = null;
  for (let index = 0; index < 10000 && !numericDigestFinding; index += 1) {
    const candidate = createFindingV2({
      ruleset, adapterId: 'gitleaks', rule: gitleaksRule, title: 'lead', severity: 'high',
      state: 'suspected', summary: 'lead', evidence: { subject: `numeric-id-${index}` },
      remediation: 'review', retest: 'rerun',
    });
    if (/\d{12}$/.test(candidate.fingerprint.slice(0, 12))) numericDigestFinding = candidate;
  }
  assert.ok(numericDigestFinding, 'fixture must find a numeric fingerprint prefix');
  assert.match(numericDigestFinding.id, /-f\d{12}$/);
  assert.equal(sanitizeEvidence(numericDigestFinding).id, numericDigestFinding.id,
    'finding ID must not be rewritten as an AWS account number');

  result = withEnv({ FAKE_GITLEAKS_MODE: 'clean' }, () => runGitleaks(project, {
    binary: fakeGitleaks, timeoutSeconds: 1,
  }));
  assert.ok(result.coverage.every((entry) => entry.status === 'completed'));
  assert.equal(result.findings.length, 0);

  for (const [mode, reason] of [
    ['malformed', 'adapter_malformed_json'], ['inconsistent', 'adapter_inconsistent_exit'],
    ['internal', 'adapter_internal_error'], ['timeout', 'adapter_timeout'],
  ]) {
    result = withEnv({ FAKE_GITLEAKS_MODE: mode }, () => runGitleaks(project, {
      binary: fakeGitleaks, timeoutSeconds: 1,
    }));
    assert.ok(result.coverage.every((entry) => entry.status === 'unavailable'));
    assert.ok(result.findings.every((finding) => finding.state === 'unknown'));
    assert.ok(result.findings.every((finding) => finding.evidence.reasonCode === reason),
      `${mode}: expected ${reason}: ${JSON.stringify(result)}`);
  }
  result = withEnv({ FAKE_GITLEAKS_MODE: 'version-drift' }, () => runGitleaks(project, {
    binary: fakeGitleaks, timeoutSeconds: 1,
  }));
  assert.equal(result.identity.status, 'unsupported_version');
  assert.ok(result.findings.every((finding) => finding.state === 'unknown'));

  result = withEnv({ FAKE_GITLEAKS_MODE: 'history-duplicates' }, () => runGitleaks(project, {
    binary: fakeGitleaks, timeoutSeconds: 1,
  }));
  const historical = result.findings.filter((finding) => finding.ruleId === 'gitleaks-committed-secret');
  assert.equal(historical.length, 2);
  assert.equal(new Set(historical.map((finding) => finding.evidence.subject)).size, 2);
  assert.equal(new Set(historical.map((finding) => sanitizeEvidence(finding.evidence).subject)).size, 2,
    'sanitization must not collapse distinct Gitleaks history identities');

  const nonGit = join(temp, 'non-git');
  mkdirSync(nonGit);
  result = runGitleaks(nonGit, { binary: join(temp, 'missing-gitleaks'), timeoutSeconds: 1 });
  assert.equal(result.coverage.find((entry) => entry.ruleId === 'gitleaks-committed-secret').status, 'not_applicable');
  assert.equal(result.coverage.find((entry) => entry.ruleId === 'gitleaks-working-tree-secret').status, 'unavailable');

  assert.deepEqual(parseOsvJson('{"results":[]}', project), []);
  assert.throws(() => parseOsvJson('{bad', project), /malformed_json/);
  const conflicting = withEnv({ FAKE_OSV_MODE: 'finding' }, () => runOsv(project, ['package-lock.json'], {
    binary: fakeOsv, timeoutSeconds: 1,
  }));
  const missingSeverity = withEnv({ FAKE_OSV_MODE: 'no-severity' }, () => runOsv(project, ['package-lock.json'], {
    binary: fakeOsv, timeoutSeconds: 1,
  }));
  assert.equal(conflicting.findings[0].severity, 'info');
  assert.equal(conflicting.findings[0].state, 'suspected');
  assert.equal(missingSeverity.findings[0].severity, 'info');
  assert.equal(conflicting.findings[0].evidence.upstreamMaxSeverity, '9.9', JSON.stringify(conflicting));
  assert.equal(missingSeverity.findings[0].evidence.upstreamMaxSeverity, null);
  assert.equal(JSON.stringify(conflicting).includes(secret), false);

  for (const [mode, reason] of [
    ['malformed', 'adapter_malformed_json'], ['inconsistent', 'adapter_inconsistent_exit'],
    ['internal', 'adapter_internal_error'], ['timeout', 'adapter_timeout'],
  ]) {
    result = withEnv({ FAKE_OSV_MODE: mode }, () => runOsv(project, ['package-lock.json'], {
      binary: fakeOsv, timeoutSeconds: 1,
    }));
    assert.equal(result.coverage[0].status, 'unavailable');
    assert.equal(result.findings[0].state, 'unknown');
    assert.equal(result.findings[0].evidence.reasonCode, reason);
  }
  result = runOsv(project, [], { binary: join(temp, 'missing-osv'), timeoutSeconds: 1 });
  assert.equal(result.coverage[0].status, 'not_applicable');
  assert.equal(result.findings.length, 0);
  result = runOsv(project, ['package-lock.json'], { binary: join(temp, 'missing-osv'), timeoutSeconds: 1 });
  assert.equal(result.coverage[0].status, 'unavailable');
  assert.equal(result.findings[0].state, 'unknown');

  const opengrepClean = JSON.stringify({
    version: '1.27.0', results: [], errors: [], paths: { scanned: [join(project, 'config.txt')] },
  });
  assert.deepEqual(parseOpengrepJson(opengrepClean, project), []);
  const redirectFinding = parseOpengrepJson(JSON.stringify({
    version: '1.27.0', errors: [], paths: { scanned: [join(project, 'source.js')] }, results: [{
      check_id: 'webapp-security.javascript.request-to-redirect', path: join(project, 'source.js'),
      start: { line: 4, col: 3 }, extra: { engine_kind: 'OSS' },
    }],
  }), project)[0];
  assert.equal(redirectFinding.ruleId, 'opengrep-js-request-redirect-flow');
  assert.equal(redirectFinding.severity, 'medium');
  assert.match(redirectFinding.title, /redirect/i);
  assert.match(redirectFinding.remediation, /local relative paths|approved destination/i);
  assert.throws(() => parseOpengrepJson('{bad', project), /malformed_json/);
  assert.throws(() => parseOpengrepJson(JSON.stringify({
    version: '1.27.0', results: [], errors: [], paths: { scanned: ['../escape.js'] },
  }), project), /unsafe_path/);
  assert.throws(() => parseOpengrepJson(JSON.stringify({
    version: '1.27.0', errors: [], paths: { scanned: [] }, results: [{
      check_id: 'webapp-security.javascript.request-to-command', path: '../escape.js',
      start: { line: 1, col: 1 }, extra: { engine_kind: 'OSS' },
    }],
  }), project), /unsafe_path/);
  result = withEnv({ FAKE_OPENGREP_MODE: 'finding' }, () => runOpengrep(project, {
    binary: fakeOpengrep, timeoutSeconds: 1,
  }));
  assert.equal(result.findings.length, 1, `duplicate external results must be normalized: ${JSON.stringify(result)}`);
  assert.equal(result.findings[0].state, 'suspected');
  assert.equal(result.findings[0].evidence.externalRuleId, 'webapp-security.javascript.request-to-command');
  assert.equal(result.findings[0].evidence.rulesetSha256.length, 64);
  assert.equal(JSON.stringify(result).includes(secret), false);
  const opengrepHome = join(temp, 'opengrep-home');
  const userLog = join(opengrepHome, '.opengrep', 'semgrep.log');
  mkdirSync(join(opengrepHome, '.opengrep'), { recursive: true });
  writeFileSync(userLog, 'owner log\n');
  result = withEnv({ FAKE_OPENGREP_MODE: 'finding', HOME: opengrepHome }, () => runOpengrep(project, {
    binary: fakeOpengrep, timeoutSeconds: 1,
  }));
  assert.equal(result.findings.length, 1);
  assert.equal(readFileSync(userLog, 'utf8'), 'owner log\n', 'Opengrep must not write scan evidence to the user log');
  for (const [mode, reason] of [
    ['malformed', 'adapter_malformed_json'], ['inconsistent', 'adapter_inconsistent_exit'],
    ['scan-errors', 'adapter_scan_errors'], ['escape', 'adapter_unsafe_path'],
    ['internal', 'adapter_internal_error'], ['timeout', 'adapter_timeout'],
    ['output-limit', 'adapter_output_limit'],
  ]) {
    result = withEnv({ FAKE_OPENGREP_MODE: mode }, () => runOpengrep(project, {
      binary: fakeOpengrep, timeoutSeconds: mode === 'output-limit' ? 10 : 1,
    }));
    assert.ok(result.coverage.every((entry) => entry.status === 'unavailable'), `${mode}: ${JSON.stringify(result)}`);
    assert.ok(result.findings.every((finding) => finding.state === 'unknown'));
    assert.ok(result.findings.every((finding) => finding.evidence.reasonCode === reason),
      `${mode}: expected ${reason}: ${JSON.stringify(result)}`);
  }
  result = withEnv({ FAKE_OPENGREP_MODE: 'version-drift' }, () => runOpengrep(project, {
    binary: fakeOpengrep, timeoutSeconds: 1,
  }));
  assert.equal(result.identity.status, 'unsupported_version');
  result = runOpengrep(project, { binary: join(temp, 'missing-opengrep'), timeoutSeconds: 1 });
  assert.ok(result.findings.every((finding) => finding.state === 'unknown'));
  result = runOpengrep(project, {
    binary: fakeOpengrep, timeoutSeconds: 1, rulesPath: join(temp, 'missing-rules.yml'),
  });
  assert.ok(result.findings.every((finding) => finding.evidence.reasonCode === 'adapter_ruleset_unavailable'));
  result = runOpengrep(project, {
    binary: fakeOpengrep, timeoutSeconds: 1,
    rulesPath: join(ROOT, 'rules', 'opengrep-source.yml'), rulesetSha256: '0'.repeat(64),
  });
  assert.ok(result.findings.every((finding) => finding.evidence.reasonCode === 'adapter_ruleset_digest_mismatch'));

  const gateDir = join(temp, 'gate');
  result = cli(['audit', project, '--out', gateDir, '--adapter', 'all'], {
    WEBAPP_SECURITY_CHECKOV_BIN: fakeCheckov,
    WEBAPP_SECURITY_GITLEAKS_BIN: fakeGitleaks,
    WEBAPP_SECURITY_OPENGREP_BIN: fakeOpengrep,
    WEBAPP_SECURITY_OSV_SCANNER_BIN: fakeOsv,
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /requires --acknowledge-alert-policy/);
  assert.equal(existsSync(gateDir), false);

  const reportDir = join(temp, 'report');
  result = cli(['audit', project, '--out', reportDir, '--adapter', 'all', '--fail-on', 'never'], {
    WEBAPP_SECURITY_CHECKOV_BIN: fakeCheckov,
    WEBAPP_SECURITY_GITLEAKS_BIN: fakeGitleaks,
    WEBAPP_SECURITY_OPENGREP_BIN: fakeOpengrep,
    WEBAPP_SECURITY_OSV_SCANNER_BIN: fakeOsv,
    FAKE_GITLEAKS_MODE: 'finding',
    FAKE_CHECKOV_MODE: 'finding',
    FAKE_OPENGREP_MODE: 'finding',
    FAKE_OSV_MODE: 'finding',
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const report = JSON.parse(readFileSync(join(reportDir, 'report.json'), 'utf8'));
  assert.deepEqual(report.ruleset.adapters.map((adapter) => adapter.id), ['builtin-source', 'checkov', 'gitleaks', 'opengrep', 'osv']);
  assert.ok(report.findings.some((finding) => finding.rule.id === 'checkov-github-actions-write-all'));
  assert.ok(report.findings.some((finding) => finding.rule.id === 'gitleaks-committed-secret'));
  assert.ok(report.findings.some((finding) => finding.rule.id === 'osv-known-vulnerability'));
  assert.ok(report.findings.some((finding) => finding.rule.id === 'opengrep-js-request-command-flow'));
  assert.ok(report.findings.filter((finding) => ['gitleaks-committed-secret', 'gitleaks-working-tree-secret', 'osv-known-vulnerability'].includes(finding.rule.id))
    .every((finding) => finding.state === 'suspected'));
  assert.ok(report.findings.every((finding) => /-f[a-f0-9]{12}$/.test(finding.id)));
  assert.equal(report.findings.find((finding) => finding.rule.id === 'osv-known-vulnerability').severity, 'info');
  assert.equal(report.scope.networkAccessPerformed, true);
  for (const name of readdirSync(reportDir)) {
    assert.equal(readFileSync(join(reportDir, name), 'utf8').includes(secret), false, `${name} persisted raw adapter output`);
  }
  for (const name of ['report.md', 'report.html', 'report.sarif', 'report.junit.xml']) {
    const output = readFileSync(join(reportDir, name), 'utf8');
    assert.match(output, /gitleaks/);
    assert.match(output, /8\.30\.1/);
    assert.match(output, /osv/);
    assert.match(output, /2\.5\.0/);
    assert.match(output, /opengrep/);
    assert.match(output, /1\.27\.0/);
    assert.match(output, /checkov/);
    assert.match(output, /3\.3\.9/);
    assert.match(output, /coverage|Coverage/);
  }

  const deepDir = join(temp, 'deep-profile');
  result = cli(['audit', project, '--out', deepDir, '--profile', 'deep', '--fail-on', 'never'], {
    WEBAPP_SECURITY_CHECKOV_BIN: join(temp, 'missing-checkov'),
    WEBAPP_SECURITY_GITLEAKS_BIN: join(temp, 'missing-gitleaks'),
    WEBAPP_SECURITY_OPENGREP_BIN: join(temp, 'missing-opengrep'),
    WEBAPP_SECURITY_OSV_SCANNER_BIN: join(temp, 'missing-osv'),
  });
  assert.equal(result.status, 3, result.stderr || result.stdout);
  const deepReport = JSON.parse(readFileSync(join(deepDir, 'report.json'), 'utf8'));
  assert.deepEqual(deepReport.scope.auditBoundary.adapters,
    ['builtin', 'checkov', 'gitleaks', 'opengrep', 'osv']);
  assert.equal(deepReport.scope.networkAccessPerformed, false);
  const deepExternal = deepReport.findings.filter((finding) => finding.adapter.id !== 'builtin-source');
  assert.equal(deepExternal.length, 16);
  assert.ok(deepExternal.every((finding) => finding.state === 'unknown'));
  assert.ok(deepExternal.every((finding) => /doctor/.test(finding.explanation.proposal.summary)));
  const conflictDir = join(temp, 'deep-conflict');
  result = cli(['audit', project, '--out', conflictDir, '--profile', 'deep', '--adapter', 'builtin']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /cannot be combined/);
  assert.equal(existsSync(conflictDir), false);
  const unknownProfileDir = join(temp, 'unknown-profile');
  result = cli(['audit', project, '--out', unknownProfileDir, '--profile', 'wide']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /unsupported profile/);
  assert.equal(existsSync(unknownProfileDir), false);

  result = cli(['doctor', project, '--adapter', 'all', '--json'], {
    WEBAPP_SECURITY_CHECKOV_BIN: join(temp, 'missing-checkov'),
    WEBAPP_SECURITY_GITLEAKS_BIN: join(temp, 'missing-gitleaks'),
    WEBAPP_SECURITY_OPENGREP_BIN: join(temp, 'missing-opengrep'),
    WEBAPP_SECURITY_OSV_SCANNER_BIN: join(temp, 'missing-osv'),
  });
  assert.equal(result.status, 3);
  const doctor = JSON.parse(result.stdout);
  assert.equal(doctor.downloadsPerformed, false);
  assert.ok(doctor.adapters.filter((adapter) => adapter.id !== 'builtin').every((adapter) => adapter.status === 'missing'));
  assert.ok(doctor.adapters.filter((adapter) => adapter.id !== 'builtin').every((adapter) => /will not download/.test(adapter.guidance)));

  console.log('external adapters ok: identity, failure states, redaction, severity boundary, reports, doctor and gate acknowledgement');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
