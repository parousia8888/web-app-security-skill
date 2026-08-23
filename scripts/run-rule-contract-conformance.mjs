#!/usr/bin/env node
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildRuleContractConformance, collectRuleContractObservations, renderRuleContractMarkdown,
  validateRuleContractConformance,
} from './lib/rule-contract-conformance.mjs';
import { readStableRuleCorpus, validateStableRuleCorpus } from './lib/rule-corpus.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const JSON_OUTPUT = join(ROOT, 'docs', 'conformance', 'v0.6.0-rule-contract-conformance.json');
const MARKDOWN_OUTPUT = join(ROOT, 'docs', 'conformance', 'v0.6.0-rule-contract-conformance.md');
const check = process.argv.includes('--check');
if (process.argv.slice(2).some((argument) => argument !== '--check')) {
  console.error('usage: node scripts/run-rule-contract-conformance.mjs [--check]');
  process.exit(2);
}

const corpus = readStableRuleCorpus(join(ROOT, 'docs', 'stable-rule-corpus.json'));
const corpusErrors = validateStableRuleCorpus(corpus, undefined, { root: ROOT });
if (corpusErrors.length) {
  console.error(`stable rule corpus is invalid:\n${corpusErrors.map((error) => `- ${error}`).join('\n')}`);
  process.exit(1);
}
const conformance = buildRuleContractConformance(corpus, collectRuleContractObservations(ROOT));
const errors = validateRuleContractConformance(conformance);
if (errors.length) {
  console.error(`rule-contract conformance failed:\n${errors.map((error) => `- ${error}`).join('\n')}`);
  process.exit(1);
}
const outputs = [
  [JSON_OUTPUT, `${JSON.stringify(conformance, null, 2)}\n`],
  [MARKDOWN_OUTPUT, renderRuleContractMarkdown(conformance)],
];
if (check) {
  const stale = outputs.filter(([path, content]) => !existsSync(path) || readFileSync(path, 'utf8') !== content);
  if (stale.length) {
    console.error('rule-contract conformance is stale; run npm run conformance:rules');
    process.exit(1);
  }
  console.log('rule-contract conformance current: 25 risk + 3 evidence-integrity contracts');
} else {
  for (const [path, content] of outputs) writeFileSync(path, content);
  console.log(`${JSON_OUTPUT}\n${MARKDOWN_OUTPUT}`);
}
