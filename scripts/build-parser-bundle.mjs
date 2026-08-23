#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build, version as esbuildVersion } from 'esbuild';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ENTRY = resolve(ROOT, 'scripts/vendor/js-ts-parser.entry.mjs');
const OUTPUT = resolve(ROOT, 'scripts/vendor/js-ts-parser.bundle.mjs');
const MANIFEST = resolve(ROOT, 'scripts/vendor/js-ts-parser.manifest.json');
const check = process.argv.slice(2).includes('--check');
if (process.argv.length > (check ? 3 : 2)) {
  console.error('usage: node scripts/build-parser-bundle.mjs [--check]');
  process.exit(2);
}

const parserPackage = JSON.parse(readFileSync(
  resolve(ROOT, 'node_modules/@babel/parser/package.json'), 'utf8'));
const lock = JSON.parse(readFileSync(resolve(ROOT, 'package-lock.json'), 'utf8'));
const lockedParser = lock.packages?.['node_modules/@babel/parser'];
if (!lockedParser || lockedParser.version !== parserPackage.version || !lockedParser.integrity) {
  throw new Error('package-lock parser metadata is missing or inconsistent');
}
if (parserPackage.license !== 'MIT') throw new Error('parser license is no longer MIT');

const result = await build({
  entryPoints: [ENTRY],
  bundle: true,
  format: 'esm',
  platform: 'node',
  target: 'node22',
  minify: true,
  sourcemap: false,
  legalComments: 'eof',
  write: false,
  banner: { js: '/* Generated parser runtime; see THIRD_PARTY_NOTICES.md. */' },
});
const bytes = result.outputFiles[0].contents;
const sha256 = createHash('sha256').update(bytes).digest('hex');
const manifest = `${JSON.stringify({
  schemaVersion: 1,
  component: '@babel/parser',
  version: parserPackage.version,
  license: parserPackage.license,
  npmIntegrity: lockedParser.integrity,
  generator: `esbuild@${esbuildVersion}`,
  target: 'node22',
  output: 'scripts/vendor/js-ts-parser.bundle.mjs',
  sha256,
}, null, 2)}\n`;

function same(path, expected) {
  try {
    return Buffer.compare(readFileSync(path), Buffer.from(expected)) === 0;
  } catch {
    return false;
  }
}

if (check) {
  const stale = [];
  if (!same(OUTPUT, bytes)) stale.push(OUTPUT);
  if (!same(MANIFEST, manifest)) stale.push(MANIFEST);
  if (stale.length) {
    console.error(`generated parser artifacts are stale: ${stale.map((item) => item.slice(ROOT.length + 1)).join(', ')}`);
    process.exit(1);
  }
  console.log(`parser bundle current: sha256:${sha256}`);
} else {
  writeFileSync(OUTPUT, bytes);
  writeFileSync(MANIFEST, manifest);
  console.log(`parser bundle: ${OUTPUT.slice(dirname(ROOT).length + 1)}`);
  console.log(`sha256:       ${sha256}`);
}
