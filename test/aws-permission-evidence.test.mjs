#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SCRIPT = join(ROOT, 'scripts', 'aws-exposure-audit.sh');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-aws-'));
const bin = join(temp, 'bin');
mkdirSync(bin);
const fake = join(bin, 'aws');
copyFileSync(join(ROOT, 'test', 'fixtures', 'aws', 'fake-aws.sh'), fake);
chmodSync(fake, 0o755);
const secret = 'FIXTURE_SECRET_MUST_NOT_APPEAR';

function run(mode, extraArgs = [], env = {}) {
  return spawnSync('/bin/bash', [SCRIPT, '--region', 'us-east-1', ...extraArgs], {
    cwd: ROOT,
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${bin}:${dirname(process.execPath)}:/usr/bin:/bin`,
      AWS_FIXTURE_MODE: mode,
      AWS_SECRET_ACCESS_KEY: secret,
      AWS_SESSION_TOKEN: secret,
      ...env,
    },
  });
}

try {
  const nested = run('nested-denial');
  assert.equal(nested.status, 3, nested.stderr || nested.stdout);
  assert.match(nested.stdout, /aws-iam-user-mfa.*unavailable/i);
  assert.match(nested.stdout, /aws-cloudtrail-logging.*unavailable/i);
  assert.doesNotMatch(nested.stdout, /IAM user has no MFA device/i);
  assert.doesNotMatch(nested.stdout, /CloudTrail is not currently logging/i);
  assert.doesNotMatch(`${nested.stdout}\n${nested.stderr}`, new RegExp(secret));

  const top = run('top-denial');
  assert.equal(top.status, 3, top.stderr || top.stdout);
  assert.match(top.stdout, /aws-caller-identity.*unavailable/i);
  assert.match(top.stdout, /caller identity unavailable; check was not run/i);
  assert.doesNotMatch(top.stdout, /root account has no MFA/i);
  assert.doesNotMatch(`${top.stdout}\n${top.stderr}`, new RegExp(secret));

  const missing = run('nested-denial', [], { WEBAPP_SECURITY_AWS_BIN: 'webapp-security-missing-aws' });
  assert.equal(missing.status, 3, missing.stderr || missing.stdout);
  assert.match(missing.stdout, /aws-cli-capability.*unavailable/i);
  assert.match(missing.stdout, /AWS CLI is unavailable/i);

  const malformed = run('malformed');
  assert.equal(malformed.status, 3, malformed.stderr || malformed.stdout);
  assert.match(malformed.stdout, /aws-root-mfa.*unavailable/i);
  assert.match(malformed.stdout, /get-account-summary returned malformed JSON/i);
  assert.doesNotMatch(malformed.stdout, /root account has MFA enabled/i);

  const mixed = run('mixed-high-unknown');
  assert.equal(mixed.status, 1, mixed.stderr || mixed.stdout);
  assert.match(mixed.stdout, /root account has no MFA/i);
  assert.match(mixed.stdout, /aws-iam-user-mfa.*unavailable/i);

  const out = join(temp, 'reports');
  const written = run('nested-denial', ['--out', out, '--report-name', 'aws-fixture']);
  assert.equal(written.status, 3, written.stderr || written.stdout);
  const report = JSON.parse(readFileSync(join(out, 'aws-fixture.json'), 'utf8'));
  const observations = JSON.parse(readFileSync(join(out, 'aws-fixture.observations.json'), 'utf8'));
  assert.equal(report.schemaVersion, 2);
  assert.equal(report.ruleset.adapters[0].id, 'builtin-aws-exposure');
  assert.equal(report.policy.precedence, 'actionable_threshold_before_incomplete');
  assert.deepEqual(report.policy.gateStates, ['confirmed', 'suspected']);
  assert.ok(report.coverage.some((entry) => entry.status === 'unavailable'));
  assert.ok(report.findings.some((finding) => finding.state === 'unknown'));
  assert.equal(observations.accountDigest.length, 64);
  assert.doesNotMatch(JSON.stringify(observations), /123456789012|fixture-user|fixture-trail/);
  assert.equal(statSync(out).mode & 0o777, 0o700);
  for (const name of ['aws-fixture.json', 'aws-fixture.md', 'aws-fixture.html', 'aws-fixture.sarif', 'aws-fixture.junit.xml', 'aws-fixture.sha256', 'aws-fixture.observations.json']) {
    assert.equal(statSync(join(out, name)).mode & 0o777, 0o600, `${name} must be private`);
  }

  const duplicateOut = join(temp, 'duplicate-reports');
  const duplicate = run('duplicate-sg', ['--out', duplicateOut, '--report-name', 'duplicate-sg']);
  assert.equal(duplicate.status, 1, duplicate.stderr || duplicate.stdout);
  const duplicateReport = JSON.parse(readFileSync(join(duplicateOut, 'duplicate-sg.json'), 'utf8'));
  assert.equal(duplicateReport.findings.filter((finding) =>
    finding.rule.id === 'aws-security-group-sensitive-exposure').length, 1);

  console.log('AWS v2 evidence ok: denial, malformed input, precedence, redaction, dedupe and private output');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
