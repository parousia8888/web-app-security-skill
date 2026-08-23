#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { auditSource } from '../scripts/lib/source-audit.mjs';
import { inspectJsTsSource } from '../scripts/lib/js-ts-source-audit.mjs';
import { inspectPythonSource } from '../scripts/lib/python-source-audit.mjs';
import {
  readStableRuleCorpus, validateCorpusObservations, validateStableRuleCorpus,
} from '../scripts/lib/rule-corpus.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const corpus = readStableRuleCorpus(join(ROOT, 'docs', 'stable-rule-corpus.json'));
assert.deepEqual(validateStableRuleCorpus(corpus, undefined, { root: ROOT }), []);

const positive = new Map();
const add = (findings) => {
  for (const finding of findings) positive.set(finding.ruleId, finding.state);
};
add(inspectJsTsSource('src/vulnerable.tsx', readFileSync(
  join(ROOT, 'test', 'fixtures', 'js-ts-rules', 'vulnerable.tsx'), 'utf8')).findings);
add(inspectPythonSource('src/vulnerable.py', readFileSync(
  join(ROOT, 'test', 'fixtures', 'python-rules', 'vulnerable.py'), 'utf8')).findings);
add(auditSource(join(ROOT, 'test', 'fixtures', 'audit-app')).findings);

const temp = mkdtempSync(join(tmpdir(), 'web-app-security-corpus-'));
try {
  const incomplete = join(temp, 'incomplete');
  mkdirSync(join(incomplete, 'src'), { recursive: true });
  writeFileSync(join(incomplete, 'package.json'), '{"private":true}\n');
  writeFileSync(join(incomplete, 'package-lock.json'), '{"lockfileVersion":3}\n');
  writeFileSync(join(incomplete, 'src', 'broken.ts'), 'const value = "unterminated');
  add(auditSource(incomplete).findings);
  const unsupported = join(temp, 'unsupported');
  mkdirSync(unsupported);
  writeFileSync(join(unsupported, 'README.txt'), 'no supported manifest\n');
  add(auditSource(unsupported).findings);

  const safeJs = inspectJsTsSource('src/safe.tsx', readFileSync(
    join(ROOT, 'test', 'fixtures', 'js-ts-rules', 'safe.tsx'), 'utf8')).findings;
  const safePython = inspectPythonSource('src/safe.py', readFileSync(
    join(ROOT, 'test', 'fixtures', 'python-rules', 'safe.py'), 'utf8')).findings;
  const safeSource = auditSource(join(ROOT, 'test', 'fixtures', 'next-app')).findings;
  const safeIds = [...safeJs, ...safePython, ...safeSource].map((finding) => finding.ruleId);
  const observations = corpus.rules.filter((rule) => rule.adapterType === 'built_in').map((rule) => ({
    ruleId: rule.ruleId,
    positiveState: positive.get(rule.ruleId),
    negativeFindingCount: safeIds.filter((ruleId) => ruleId === rule.ruleId).length,
  }));
  assert.deepEqual(validateCorpusObservations(corpus, observations, { adapterType: 'built_in' }), []);

  for (const rule of corpus.rules.filter((item) => item.adapterType === 'built_in')) {
    const mutated = observations.filter((observation) => observation.ruleId !== rule.ruleId);
    assert.match(validateCorpusObservations(corpus, mutated, { adapterType: 'built_in' }).join('; '),
      new RegExp(`missing positive/negative observation ${rule.ruleId.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
  }
  console.log('stable rule corpus ok: 27 built-in observations and 27 planted missing-observation failures');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
