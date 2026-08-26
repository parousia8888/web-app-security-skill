#!/usr/bin/env node
import { fileURLToPath } from 'node:url';
import { validateDocumentContract } from './lib/document-contract.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const errors = validateDocumentContract(ROOT);
if (errors.length) {
  console.error(`document contract failed:\n${errors.map((error) => `- ${error}`).join('\n')}`);
  process.exit(1);
}
console.log('document contract ok: relative Markdown links and declared plan deviations resolve');
