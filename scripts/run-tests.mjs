#!/usr/bin/env node
import { readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runTestInventory } from './lib/test-runner.mjs';

const args = process.argv.slice(2);
function take(name, fallback) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
  args.splice(index, 2);
  return value;
}

try {
  const defaultRoot = fileURLToPath(new URL('..', import.meta.url));
  const root = resolve(take('--root', defaultRoot));
  const output = take('--out', 'test-results/test-outcomes.json');
  if (args.length) throw new Error(`unknown option ${args[0]}`);
  const files = readdirSync(resolve(root, 'test'))
    .filter((name) => name.endsWith('.test.mjs'))
    .sort()
    .map((name) => `test/${name}`);
  const result = runTestInventory({ root, files, output });
  const { files: fileCounts, surfaces } = result.record.summary;
  console.log(`test inventory ${result.record.state}: files passed=${fileCounts.passed} failed=${fileCounts.failed} skipped=${fileCounts.skipped} not_run=${fileCounts.not_run}; surfaces passed=${surfaces.passed} failed=${surfaces.failed} skipped=${surfaces.skipped} not_run=${surfaces.not_run}`);
  console.log(`test inventory: ${result.output}`);
  process.exit(result.exitCode);
} catch (error) {
  console.error(`test runner: ${error.message}`);
  process.exit(2);
}
