#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditSource } from '../scripts/lib/source-audit.mjs';
import {
  classifyJsTsSource, inspectJsTsSource, JS_TS_DEFERRED_CANDIDATES, JS_TS_SOURCE_RULE_IDS,
  tokenizeJsTs,
} from '../scripts/lib/js-ts-source-audit.mjs';
import { sourceRuleExplanation } from '../scripts/lib/source-rule-registry.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const vulnerablePath = 'test/fixtures/js-ts-rules/vulnerable.tsx';
const safePath = 'test/fixtures/js-ts-rules/safe.tsx';
const vulnerableText = readFileSync(join(ROOT, vulnerablePath), 'utf8');
const safeText = readFileSync(join(ROOT, safePath), 'utf8');

const vulnerable = inspectJsTsSource(vulnerablePath, vulnerableText);
assert.equal(vulnerable.error, null);
assert.deepEqual(new Set(vulnerable.findings.map((finding) => finding.ruleId)),
  new Set(JS_TS_SOURCE_RULE_IDS));
assert.equal(inspectJsTsSource(safePath, safeText).findings.length, 0);
assert.equal(JS_TS_DEFERRED_CANDIDATES.length, 7);
assert.ok(JS_TS_DEFERRED_CANDIDATES.every((candidate) =>
  candidate.id && candidate.reason && !JS_TS_SOURCE_RULE_IDS.includes(candidate.id)));
for (const ruleId of JS_TS_SOURCE_RULE_IDS) {
  assert.ok(vulnerable.findings.some((finding) => finding.ruleId === ruleId), ruleId);
  const explanation = sourceRuleExplanation('builtin-source', ruleId,
    { state: 'suspected', summary: 'fixture', remediation: 'fixture', retest: 'fixture' });
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

const secret = vulnerable.findings.find((finding) => finding.ruleId === 'hardcoded-auth-secret');
assert.equal(secret.evidence.literalRedacted, true);
assert.deepEqual(Object.keys(secret.evidence).sort(),
  ['construct', 'line', 'literalLengthBand', 'literalRedacted', 'subject'].sort());
assert.doesNotMatch(JSON.stringify(secret), /fixture-value-never-use-12345/);
const sessionSecret = vulnerable.findings.find((finding) => finding.ruleId === 'js-inline-session-secret');
assert.equal(sessionSecret.evidence.literalRedacted, true);
assert.deepEqual(Object.keys(sessionSecret.evidence).sort(),
  ['construct', 'line', 'literalLengthBand', 'literalRedacted', 'subject'].sort());
assert.doesNotMatch(JSON.stringify(sessionSecret), /fixture-session-secret-never-deploy/);

const unrelatedOptions = inspectJsTsSource('src/options.ts', `
  const options = {
    secret: 'ordinary-fixed-text-not-a-session-key',
    cookie: { httpOnly: false, secure: false },
  };
`);
assert.deepEqual(unrelatedOptions.findings, []);

const masked = inspectJsTsSource('src/masked.ts', String.raw`
  // eval(user); document.body.innerHTML = user;
  const a = "eval(user); rejectUnauthorized: false";
  const b = /document\.write\(user\)/;
  const c = ` + '`dangerouslySetInnerHTML={{ __html: user }}`' + `;
`);
assert.equal(masked.error, null);
assert.deepEqual(masked.findings, []);
const comparisonString = inspectJsTsSource('src/comparison.ts',
  'const compared = input === "eval(user); document.body.innerHTML = user";\n');
assert.equal(comparisonString.error, null);
assert.deepEqual(comparisonString.findings, []);
const templateSecret = inspectJsTsSource('src/template.ts',
  'const jwtSecret = `prefix-${process.env.SECRET}`;\n');
assert.equal(templateSecret.error, null);
assert.deepEqual(templateSecret.findings, []);
const nestedTemplate = inspectJsTsSource('src/ssr.ts',
  'const html = `${`</b>`}</div>`;\n');
assert.equal(nestedTemplate.error, null);
assert.deepEqual(nestedTemplate.findings, []);
const jsxTemplate = inspectJsTsSource('src/ssr.tsx',
  'const Page = ({ value }) => <div>{`${`</b>`}${value}`}</div>;\n');
assert.equal(jsxTemplate.error, null);
assert.deepEqual(jsxTemplate.findings, []);
const expressionFinding = inspectJsTsSource('src/template-expression.ts',
  'const result = `${eval(userInput)}`;\n');
assert.equal(expressionFinding.error, null);
assert.deepEqual(expressionFinding.findings.map((finding) => finding.ruleId),
  ['js-dynamic-code-execution']);
const jsxText = inspectJsTsSource('src/page.tsx', `
  export function Page() {
    return <main>Don't treat a user's apostrophe, "quote", or skills/*.yaml glob as source code.</main>;
  }
`);
assert.equal(jsxText.error, null);
assert.deepEqual(jsxText.findings, []);
const nestedJsxText = inspectJsTsSource('src/nested.tsx', `
  export const Page = ({ visible, value }) => (
    <main>{visible ? <span data-value={value}>src/*.tsx</span> : null}</main>
  );
`);
assert.equal(nestedJsxText.error, null);
assert.deepEqual(nestedJsxText.findings, []);

const multiline = inspectJsTsSource('src/multiline.ts', `
  import { spawn as launch } from 'child_process';
  launch(
    'tool',
    ['fixture'],
    {
      shell:
        true,
    },
  );
  const cors = {
    credentials: true,
    origin:
      '*',
  };
`);
assert.deepEqual(new Set(multiline.findings.map((finding) => finding.ruleId)),
  new Set(['node-child-process-shell-execution', 'cors-wildcard-with-credentials']));
const nestedCors = inspectJsTsSource('src/cors.ts', `
  export const options = { nested: { origin: '*' }, credentials: true };
`);
assert.deepEqual(nestedCors.findings, []);
const repeatedJsSink = inspectJsTsSource('src/repeated.ts', `
  element.innerHTML = first;
  element.innerHTML = second;
`);
assert.equal(repeatedJsSink.findings.length, 2);
assert.equal(new Set(repeatedJsSink.findings.map((finding) => finding.evidence.subject)).size, 2);

assert.equal(classifyJsTsSource('src/client.ts').eligible, true);
assert.deepEqual(classifyJsTsSource('src/client.min.js'),
  { eligible: false, reason: 'generated_or_minified_source' });
assert.deepEqual(classifyJsTsSource('src/component.test.tsx'),
  { eligible: false, reason: 'test_or_fixture_source' });
assert.deepEqual(classifyJsTsSource('README.md'),
  { eligible: false, reason: 'unsupported_js_ts_extension' });
assert.equal(tokenizeJsTs('const x = "unterminated').error.code, 'unterminated_string_literal');
assert.equal(tokenizeJsTs('const x = `unterminated').error.code, 'unterminated_string_literal');
assert.equal(tokenizeJsTs('/* unterminated').error.code, 'unterminated_block_comment');
const tokenLimited = inspectJsTsSource('src/token-limit.ts', 'const first = 1; const second = 2;\n', {
  analysisLimits: { maxTokensPerFile: 4 },
});
assert.equal(tokenLimited.error.code, 'source_token_limit');
assert.deepEqual(tokenLimited.findings, []);

const temp = mkdtempSync(join(tmpdir(), 'webapp-security-js-ts-'));
const write = (path, contents) => {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, contents);
};
try {
  write(join(temp, 'package.json'), '{"private":true}\n');
  write(join(temp, 'package-lock.json'), '{"lockfileVersion":3}\n');
  write(join(temp, 'src', 'app.tsx'), vulnerableText);
  write(join(temp, 'src', 'ignored.min.js'), 'eval(untrusted);\n');
  write(join(temp, 'src', 'generated', 'ignored.ts'), 'eval(untrusted);\n');
  const audit = auditSource(temp);
  assert.deepEqual(new Set(audit.findings.filter((finding) =>
    JS_TS_SOURCE_RULE_IDS.includes(finding.ruleId)).map((finding) => finding.ruleId)),
  new Set(JS_TS_SOURCE_RULE_IDS));
  assert.equal(audit.findings.some((finding) => finding.location?.path.includes('ignored')), false);
  for (const ruleId of JS_TS_SOURCE_RULE_IDS) {
    assert.equal(audit.coverage[ruleId].status, 'completed', ruleId);
    assert.ok(audit.coverage[ruleId].reasons.some((reason) =>
      reason.code === 'generated_or_minified_source'), ruleId);
  }

  write(join(temp, 'src', 'broken.ts'), 'const value = "unterminated');
  const incomplete = auditSource(temp);
  assert.ok(incomplete.findings.some((finding) =>
    finding.ruleId === 'source-evidence-incomplete' && finding.state === 'unknown'));
  for (const ruleId of JS_TS_SOURCE_RULE_IDS) {
    assert.equal(incomplete.coverage[ruleId].status, 'partial', ruleId);
    assert.ok(incomplete.coverage[ruleId].reasons.some((reason) =>
      reason.code === 'unterminated_string_literal'), ruleId);
  }
} finally {
  rmSync(temp, { recursive: true, force: true });
}

console.log('js/ts source audit ok: 10 stable leads, safe neighbours, masking, redaction and coverage');
