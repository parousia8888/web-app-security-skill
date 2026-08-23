#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildRuleContractConformance, collectRuleContractObservations, renderRuleContractMarkdown,
  validateRuleContractConformance,
} from '../scripts/lib/rule-contract-conformance.mjs';
import { readStableRuleCorpus } from '../scripts/lib/rule-corpus.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const corpus = readStableRuleCorpus(join(ROOT, 'docs', 'stable-rule-corpus.json'));
const observations = collectRuleContractObservations(ROOT);
const conformance = buildRuleContractConformance(corpus, observations);
assert.deepEqual(validateRuleContractConformance(conformance), []);
assert.deepEqual(conformance.summary.risk, {
  contracts: 25, positivePassed: 25, positiveFailed: 0,
  negativePassed: 25, negativeFailed: 0, stateMismatches: 0,
});
assert.equal(conformance.summary.evidenceIntegrity.positivePassed, 2);
assert.equal(conformance.summary.evidenceIntegrity.negativeFailed, 0);

const missingPositive = buildRuleContractConformance(corpus, observations.slice(1));
assert.equal(missingPositive.summary.combined.positiveFailed, 1);
assert.match(validateRuleContractConformance(missingPositive).join('; '), /planted positive failed/);
const unexpectedNegative = structuredClone(observations);
unexpectedNegative[0].negativeFindingCount = 1;
const failedNegative = buildRuleContractConformance(corpus, unexpectedNegative);
assert.equal(failedNegative.summary.combined.negativeFailed, 1);
assert.match(validateRuleContractConformance(failedNegative).join('; '), /planted negative produced a finding/);

const unexpectedState = structuredClone(observations);
unexpectedState[0].positiveStates = ['confirmed'];
const stateMismatch = buildRuleContractConformance(corpus, unexpectedState);
assert.equal(stateMismatch.summary.combined.stateMismatches, 1);
assert.match(validateRuleContractConformance(stateMismatch).join('; '), /unexpected evidence state/);

assert.equal(readFileSync(join(ROOT, 'docs', 'conformance', 'v0.5.4-rule-contract-conformance.json'), 'utf8'),
  `${JSON.stringify(conformance, null, 2)}\n`);
assert.equal(readFileSync(join(ROOT, 'docs', 'conformance', 'v0.5.4-rule-contract-conformance.md'), 'utf8'),
  renderRuleContractMarkdown(conformance));
console.log('rule-contract conformance ok: 27 contracts, committed bytes and planted failure gates');
