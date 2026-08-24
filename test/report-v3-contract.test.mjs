#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  assertComparableBaselineV3, compareFindingsV3, createFindingV3, createReportV3, exitCodeV3,
  initializeFindingsV3, renderHtmlV3, renderJunitV3, renderMarkdownV3, renderSarifV3,
  validateRuntimeReportV3, writeReportBundleV3,
} from '../scripts/lib/evidence-v3.mjs';
import { createFindingV2, createReportV2, initializeFindingsV2 } from '../scripts/lib/evidence-v2.mjs';
import { validateExplanationV3 } from '../scripts/lib/report-v3-contract.mjs';
import { sha256 } from '../scripts/lib/report-v2-contract.mjs';
import { createRulesetV2 } from '../scripts/lib/ruleset-v2.mjs';

const ADAPTER = { id: 'fixture-source', version: '1.0.0', maturity: 'stable' };
const RULES = [
  { id: 'unsafe-cookie', revision: '1', domain: 'security_exposure', severity: 'high' },
  { id: 'scanner-unavailable', revision: '1', domain: 'evidence_integrity', severity: 'high' },
];
const ruleset = createRulesetV2([{ ...ADAPTER, rules: RULES }]);
const subject = {
  id: 'project-0123456789abcdef', binding: 'persisted',
  scopeDigest: sha256('v3-fixture-scope'), localPathIncluded: false,
};

function coverage(rule, status = 'completed') {
  return {
    id: `fixture-${rule.id}`, adapterId: ADAPTER.id, ruleId: rule.id, ruleRevision: rule.revision,
    status,
    counts: { discovered: 1, eligible: 1, scanned: status === 'completed' ? 1 : 0,
      excluded: 0, skipped: 0, truncated: 0, errors: status === 'completed' ? 0 : 1 },
    reasons: status === 'completed' ? [] : [{ code: 'tool_unavailable', count: 1, samplePaths: [] }],
  };
}

const cookieExplanation = {
  technicalTerm: 'Missing HttpOnly cookie attribute',
  plainLanguage: 'The browser may allow page scripts to read the login cookie.',
  consequence: 'If an attacker can run script in the page, they may be able to steal the session and use the account.',
  evidenceBoundary: 'The fixture proves the cookie option is absent in source. It does not prove an XSS path or a deployed response.',
  standards: [
    { id: 'CWE-1004', url: 'https://cwe.mitre.org/data/definitions/1004.html' },
    { id: 'OWASP-TOP10-2025-A07', url: 'https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/' },
  ],
  proposal: { status: 'review_required', summary: 'Enable HttpOnly after confirming the frontend does not read this cookie.' },
  alternatives: ['Move browser-readable state to a separate non-session value.'],
  sideEffects: ['Login or refresh can fail if existing browser code reads the session cookie.'],
  securityRetest: 'Confirm browser script cannot read the session cookie.',
  functionalRetest: 'Run login, session refresh and logout journeys.',
  rollback: 'Revert the cookie option if login or refresh fails, then remove the browser dependency before retrying.',
  userDecisions: ['Confirm whether frontend code intentionally reads the session cookie.'],
};

const cookie = createFindingV3({
  ruleset, adapterId: ADAPTER.id, rule: RULES[0], title: 'Session cookie may be readable by scripts',
  severity: 'high', state: 'suspected', summary: 'The fixture omits HttpOnly.',
  location: { path: 'src/session.ts', line: 7 },
  evidence: { subject: 'src/session.ts:7:cookie_options', construct: 'cookie_options', observed: '<script>' },
  remediation: 'Enable HttpOnly after reviewing browser dependencies.', retest: 'Repeat the cookie check.',
  explanation: cookieExplanation,
});
const unknown = createFindingV3({
  ruleset, adapterId: ADAPTER.id, rule: RULES[1], title: 'Source scanner evidence unavailable',
  severity: 'high', state: 'unknown', summary: 'The required scanner did not run.',
  evidence: { subject: 'scanner', reasonCode: 'tool_unavailable' },
  remediation: 'Install the pinned local scanner and rerun.', retest: 'Rerun the same scanner check.',
});
const ledger = [coverage(RULES[0]), coverage(RULES[1], 'unavailable')];
const report = createReportV3({
  version: '0.5.0-dev', generatedAt: '1970-01-01T00:00:00.000Z', mode: 'audit', subject,
  ruleset, scope: { checkModes: ['fixture'], networkAccessPerformed: false }, coverage: ledger,
  findings: initializeFindingsV3([cookie, unknown], ledger), limitations: ['Controlled fixture only.'],
});

assert.deepEqual(validateRuntimeReportV3(report), []);
assert.equal(report.schemaVersion, 3);
assert.deepEqual(report.policy.gateStates, ['confirmed', 'suspected']);
assert.equal(exitCodeV3(report), 1, 'actionable suspected HIGH takes precedence over incomplete evidence');
assert.equal(validateExplanationV3(cookieExplanation).length, 0);

const changedWords = createFindingV3({
  ruleset, adapterId: ADAPTER.id, rule: RULES[0], title: cookie.title, severity: 'high', state: 'suspected',
  summary: cookie.summary, location: cookie.location, evidence: cookie.evidence,
  remediation: cookie.remediation, retest: cookie.retest,
  explanation: { ...cookieExplanation, plainLanguage: 'Updated wording with identical evidence identity.' },
});
assert.equal(changedWords.fingerprint, cookie.fingerprint, 'explanation wording must not change finding identity');

for (const invalid of [
  { ...cookieExplanation, plainLanguage: '' },
  { ...cookieExplanation, sideEffects: [] },
  { ...cookieExplanation, standards: [{ id: 'ASVS-latest', url: 'https://example.com' }] },
  { ...cookieExplanation, proposal: { status: 'apply_now', summary: 'Unsafe.' } },
]) assert.ok(validateExplanationV3(invalid).length > 0);

const markdown = renderMarkdownV3(report);
const technical = renderMarkdownV3(report, { technical: true });
const html = renderHtmlV3(report);
const sarif = renderSarifV3(report);
const junit = renderJunitV3(report);
for (const output of [JSON.stringify(report), markdown, html, sarif, junit]) {
  for (const marker of ['Missing HttpOnly cookie attribute', 'suspected', 'fixture-source', '1.0.0']) {
    assert.ok(output.includes(marker));
  }
}
assert.doesNotMatch(markdown, /"observed":"<script>"/, 'beginner Markdown omits raw evidence JSON');
assert.match(markdown,
  /security_exposure: total=1; suspected=1 \(high=1\)/,
  'Markdown renders numeric v3 state and severity summaries');
assert.match(markdown,
  /evidence_integrity: total=1; unknown=1 \(high=1\)/,
  'Markdown omits empty evidence states from each domain');
assert.doesNotMatch(markdown, /\[object Object\]/);
assert.match(technical, /Technical evidence/);
assert.match(technical, /&lt;script&gt;|<script>/);
assert.doesNotMatch(html, /<script>/, 'HTML escapes evidence and explanation content');
assert.match(html, /security_exposure: total=1; suspected=1 \(high=1\)/);
assert.doesNotMatch(html, /\[object Object\]/);
assert.match(html, /What could happen/);
assert.match(sarif, /Possible side effects/);
assert.match(junit, /technicalTerm/);

const v2Finding = createFindingV2({
  ruleset, adapterId: ADAPTER.id, rule: RULES[0], title: cookie.title, severity: cookie.severity,
  state: cookie.state, summary: cookie.summary, location: cookie.location, evidence: cookie.evidence,
  remediation: cookie.remediation, retest: cookie.retest,
});
const v2 = createReportV2({
  version: '0.4.0', generatedAt: '1970-01-01T00:00:00.000Z', mode: 'audit', subject,
  ruleset, scope: { checkModes: ['fixture'], networkAccessPerformed: false }, coverage: ledger,
  findings: initializeFindingsV2([v2Finding], ledger), limitations: ['v2 fixture.'],
});
const legacyReport = structuredClone(report);
legacyReport.policy = {
  thresholds: structuredClone(report.policy.thresholds),
  precedence: 'confirmed_threshold_before_incomplete',
};
assert.deepEqual(validateRuntimeReportV3(legacyReport), [], 'legacy confirmed-only policy remains valid');
assert.equal(exitCodeV3(legacyReport), 3,
  'legacy policy without gateStates ignores suspected threshold leads and preserves incomplete evidence');
const rawV2 = Buffer.from(`${JSON.stringify(v2, null, 2)}\n`);
const compatible = assertComparableBaselineV3(subject, v2, rawV2);
assert.equal(compatible.sourceSchemaVersion, 2);
const compared = compareFindingsV3([cookie], [ledger[0]], v2, ruleset,
  () => cookieExplanation);
assert.equal(compared[0].baseline.state, 'unchanged');
assert.equal(compared[0].schemaVersion, 3);
const movedCookie = createFindingV3({
  ruleset, adapterId: ADAPTER.id, rule: RULES[0], title: cookie.title, severity: cookie.severity,
  state: cookie.state, summary: cookie.summary, location: { path: 'src/moved-session.ts', line: 11 },
  evidence: { subject: 'src/moved-session.ts:11:cookie_options', construct: 'cookie_options', observed: '<script>' },
  remediation: cookie.remediation, retest: cookie.retest, explanation: cookieExplanation,
});
const moved = compareFindingsV3([movedCookie], [ledger[0]], v2, ruleset,
  () => cookieExplanation);
assert.equal(moved.length, 1);
assert.equal(moved[0].location.path, 'src/moved-session.ts');
assert.equal(moved[0].baseline.state, 'unchanged');
assert.equal(moved[0].baseline.reasonCode, 'condition_moved');
assert.equal(moved[0].baseline.priorFingerprint, cookie.fingerprint);

const secondV2Finding = createFindingV2({
  ruleset, adapterId: ADAPTER.id, rule: RULES[0], title: cookie.title, severity: cookie.severity,
  state: cookie.state, summary: cookie.summary, location: { path: 'src/second-session.ts', line: 9 },
  evidence: { subject: 'src/second-session.ts:9:cookie_options', construct: 'cookie_options', observed: '<script>' },
  remediation: cookie.remediation, retest: cookie.retest,
});
const ambiguousBaseline = createReportV2({
  version: '0.4.0', generatedAt: '1970-01-01T00:00:00.000Z', mode: 'audit', subject,
  ruleset, scope: { checkModes: ['fixture'], networkAccessPerformed: false }, coverage: ledger,
  findings: initializeFindingsV2([v2Finding, secondV2Finding], ledger), limitations: ['v2 fixture.'],
});
const secondMovedCookie = createFindingV3({
  ruleset, adapterId: ADAPTER.id, rule: RULES[0], title: cookie.title, severity: cookie.severity,
  state: cookie.state, summary: cookie.summary, location: { path: 'src/second-moved-session.ts', line: 13 },
  evidence: { subject: 'src/second-moved-session.ts:13:cookie_options', construct: 'cookie_options', observed: '<script>' },
  remediation: cookie.remediation, retest: cookie.retest, explanation: cookieExplanation,
});
const ambiguous = compareFindingsV3([movedCookie, secondMovedCookie], ledger,
  ambiguousBaseline, ruleset, () => cookieExplanation);
assert.equal(ambiguous.filter((finding) => finding.baseline.state === 'new').length, 2);
assert.equal(ambiguous.filter((finding) => finding.baseline.state === 'fixed').length, 2);
assert.throws(() => assertComparableBaselineV3({ ...subject, id: 'project-fedcba9876543210' }, v2, rawV2), /does not match/);

const temp = mkdtempSync(join(tmpdir(), 'web-app-security-v3-'));
try {
  const files = writeReportBundleV3(report, temp);
  assert.equal(JSON.parse(readFileSync(files.json, 'utf8')).schemaVersion, 3);
  for (const path of Object.values(files)) assert.ok(readFileSync(path).length > 0);
} finally {
  rmSync(temp, { recursive: true, force: true });
}

console.log('report v3 contract ok: explanations, renderers, fingerprint stability and v2 baseline compatibility');
