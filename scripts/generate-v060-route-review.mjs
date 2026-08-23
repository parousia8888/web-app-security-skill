#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  buildV060RouteRegressions, buildV060RouteReview, renderV060RouteRegressions,
  renderV060RouteReview, validateV060RouteRegressions, validateV060RouteReview,
} from './lib/v060-route-review.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const OUTPUT_DIR = join(ROOT, 'docs', 'reviews');
const JSON_OUTPUT = join(OUTPUT_DIR, 'v0.6.0-route-review.json');
const MARKDOWN_OUTPUT = join(OUTPUT_DIR, 'v0.6.0-route-review.md');
const REGRESSION_JSON = join(ROOT, 'docs', 'regressions', 'v0.6.0-route-real-world-regressions.json');
const REGRESSION_MARKDOWN = join(ROOT, 'docs', 'regressions', 'v0.6.0-route-real-world-regressions.md');
const check = process.argv.includes('--check');
if (process.argv.slice(2).some((argument) => argument !== '--check')) {
  console.error('usage: node scripts/generate-v060-route-review.mjs [--check]');
  process.exit(2);
}

const review = buildV060RouteReview();
const regressions = buildV060RouteRegressions();
const errors = [...validateV060RouteReview(review), ...validateV060RouteRegressions(regressions)];
if (errors.length) {
  console.error(`v0.6.0 route review invalid:\n${errors.map((error) => `- ${error}`).join('\n')}`);
  process.exit(1);
}
const outputs = [
  [JSON_OUTPUT, `${JSON.stringify(review, null, 2)}\n`],
  [MARKDOWN_OUTPUT, renderV060RouteReview(review)],
  [REGRESSION_JSON, `${JSON.stringify(regressions, null, 2)}\n`],
  [REGRESSION_MARKDOWN, renderV060RouteRegressions(regressions)],
];
if (check) {
  const stale = outputs.filter(([path, content]) => !existsSync(path) || readFileSync(path, 'utf8') !== content);
  if (stale.length) {
    console.error('v0.6.0 route review is stale; run node scripts/generate-v060-route-review.mjs');
    process.exit(1);
  }
  console.log('v0.6.0 route review current: 57 routes, 6 explicit misses, Prisma remains experimental');
} else {
  mkdirSync(OUTPUT_DIR, { recursive: true });
  mkdirSync(join(ROOT, 'docs', 'regressions'), { recursive: true });
  for (const [path, content] of outputs) writeFileSync(path, content);
  console.log(`${JSON_OUTPUT}\n${MARKDOWN_OUTPUT}`);
}
