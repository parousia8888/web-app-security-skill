#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createFindingV2, createReportV2, initializeFindingsV2, writeReportBundleV2,
} from '../scripts/lib/evidence-v2.mjs';
import { sanitizeEvidence, writeAtomicEvidenceBundle } from '../scripts/lib/evidence-writer.mjs';
import { sourceCoverage, sourceRule, sourceRuleset } from '../scripts/lib/source-rules.mjs';

const temp = mkdtempSync(join(tmpdir(), 'web-app-security-writer-'));
const secret = 'M5_UNIQUE_SECRET_SENTINEL';
const privateKey = `-----BEGIN PRIVATE KEY-----\n${secret}\n-----END PRIVATE KEY-----`;

try {
  const output = join(temp, 'private-output');
  const sanitized = sanitizeEvidence({
    authorization: `Bearer ${secret}`,
    cookie: `session=${secret}`,
    email: `owner-${secret}@example.invalid`,
    accountId: '123456789012',
    message: `token=${secret}\u0000<script>alert(1)</script>${'x'.repeat(5000)}`,
    privateKey,
    nestedHeaders: { authorization: { value: `Bearer ${secret}` } },
    credentialObjects: {
      authorization: { scheme: 'Bearer', credentials: secret },
      cookie: { name: 'session', value: secret },
    },
    nestedTokens: [{ token: [secret, { value: secret }] }],
    diagnostic: `scanner failed while reading /Users/${secret}/project/src/app.js`,
    route: {
      authorization: {
        state: 'candidate_observed', signals: ['route-guard'], boundary: 'Static evidence only.',
      },
    },
    list: Array.from({ length: 250 }, (_, index) => `${index}`),
  });
  const files = writeAtomicEvidenceBundle(output, [
    { key: 'json', name: 'report.json', content: `${JSON.stringify(sanitized, null, 2)}\n` },
    { key: 'html', name: 'report.html', content: '<p>&lt;script&gt;escaped&lt;/script&gt;</p>\n' },
    { key: 'junit', name: 'report.junit.xml', content: '<?xml version="1.0"?><testsuite/>\n' },
  ]);
  assert.equal(statSync(output).mode & 0o777, 0o700);
  for (const path of Object.values(files)) assert.equal(statSync(path).mode & 0o777, 0o600);
  const serialized = Object.values(files).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.doesNotMatch(serialized, new RegExp(secret));
  assert.doesNotMatch(serialized, /BEGIN PRIVATE KEY|owner-/);
  assert.doesNotMatch(serialized, /\/Users\//);
  assert.match(serialized, /REDACTED/);
  assert.equal(sanitized.route.authorization.state, 'candidate_observed',
    'authorization evidence models must not be mistaken for credential values');
  assert.equal(sanitized.list.length, 200);
  assert.ok(sanitized.message.length < 4200);
  assert.doesNotMatch(sanitized.message, /\u0000/);

  const ruleset = sourceRuleset();
  const coverage = sourceCoverage([], {
    'dependency-lockfile-missing': { status: 'completed' },
  });
  const finding = createFindingV2({
    ruleset,
    adapterId: 'builtin-source',
    rule: sourceRule('dependency-lockfile-missing'),
    title: 'Missing lockfile <script>alert(1)</script>',
    severity: 'low',
    state: 'confirmed',
    summary: `Authorization: Bearer ${secret}\n<script>alert(1)</script>`,
    evidence: {
      subject: 'lockfile', token: secret, email: `${secret}@example.invalid`,
      headers: { authorization: { value: `Bearer ${secret}` } },
      nested: [{ token: [secret, { value: secret }] }],
      diagnostic: `failed at /home/${secret}/project/src/server.js`,
    },
    remediation: `Remove cookie: session=${secret}`,
    retest: `password=${secret}`,
  });
  const report = createReportV2({
    version: '0.3.0',
    generatedAt: '1970-01-01T00:00:00.000Z',
    mode: 'audit',
    subject: {
      id: 'project-0123456789abcdef0123456789abcdef', binding: 'ephemeral',
      scopeDigest: 'a'.repeat(64), localPathIncluded: false,
    },
    ruleset,
    scope: { auditBoundary: { version: 1 }, checkModes: ['fixture'], networkAccessPerformed: false },
    coverage,
    findings: initializeFindingsV2([finding], coverage),
    limitations: [`cookie: session=${secret}`],
  });
  const renderedOutput = join(temp, 'rendered-output');
  const renderedFiles = writeReportBundleV2(report, renderedOutput, 'report', { additionalFiles: [{
    name: 'report.observations.json',
    json: { authorization: `Bearer ${secret}`, error: '<error>unavailable</error>' },
  }] });
  const rendered = Object.values(renderedFiles).map((path) => readFileSync(path, 'utf8')).join('\n');
  assert.doesNotMatch(rendered, new RegExp(secret));
  assert.doesNotMatch(rendered, /\/(?:Users|home|private)\//);
  JSON.parse(readFileSync(renderedFiles.json, 'utf8'));
  JSON.parse(readFileSync(renderedFiles.sarif, 'utf8'));
  JSON.parse(readFileSync(renderedFiles['report.observations.json'], 'utf8'));
  assert.match(readFileSync(renderedFiles.html, 'utf8'), /&lt;script&gt;/);
  assert.match(readFileSync(renderedFiles.junit, 'utf8'), /&lt;script&gt;/);

  const existing = join(temp, 'existing');
  mkdirSync(existing, { mode: 0o700 });
  writeFileSync(join(existing, 'report.json'), 'previous\n', { mode: 0o600 });
  assert.throws(() => writeAtomicEvidenceBundle(existing, [
    { name: 'report.json', content: 'replacement\n' },
    { name: 'report.md', content: 'new\n' },
  ]), /refusing to overwrite existing evidence/);
  assert.equal(readFileSync(join(existing, 'report.json'), 'utf8'), 'previous\n');
  assert.deepEqual(readdirSync(existing), ['report.json']);

  const symlinkTarget = join(temp, 'outside');
  mkdirSync(symlinkTarget);
  const symlinkOutput = join(temp, 'symlink-output');
  symlinkSync(symlinkTarget, symlinkOutput);
  assert.throws(() => writeAtomicEvidenceBundle(symlinkOutput, [
    { name: 'report.json', content: '{}\n' },
  ]), /symlink evidence directory/);
  assert.deepEqual(readdirSync(symlinkTarget), []);

  const symlinkFileOutput = join(temp, 'symlink-file');
  mkdirSync(symlinkFileOutput);
  symlinkSync(join(temp, 'missing-target'), join(symlinkFileOutput, 'report.json'));
  assert.throws(() => writeAtomicEvidenceBundle(symlinkFileOutput, [
    { name: 'report.json', content: '{}\n' },
  ]), /refusing to overwrite existing evidence/);

  const renderFailure = join(temp, 'render-failure');
  assert.throws(() => writeAtomicEvidenceBundle(renderFailure, [
    { name: 'report.json', content: '{}\n' },
    { name: 'report.sarif', content: '{bad', validate: (bytes) => JSON.parse(bytes.toString('utf8')) },
  ]));
  assert.ok(!existsSync(renderFailure) || readdirSync(renderFailure).length === 0);

  const interrupted = join(temp, 'interrupted');
  assert.throws(() => writeAtomicEvidenceBundle(interrupted, [
    { name: 'report.json', content: '{}\n' },
    { name: 'report.md', content: '# report\n' },
  ], { afterCommit: (_name, count) => { if (count === 1) throw new Error('simulated interruption'); } }),
  /simulated interruption/);
  assert.deepEqual(readdirSync(interrupted), []);

  assert.throws(() => writeAtomicEvidenceBundle(join(temp, 'escape'), [
    { name: '../report.json', content: '{}\n' },
  ]), /escapes the output directory/);

  console.log('evidence writer ok: all renderers private, bounded, sanitized, atomic, non-overwriting and symlink-safe');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
