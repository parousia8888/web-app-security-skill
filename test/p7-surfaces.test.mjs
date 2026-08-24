#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

for (const [script, expected] of [
  ['generate-launch-evidence.mjs', /11 stable detection, 0 planned detection, 5 journeys, 5 studies/],
  ['check-p7-surfaces.mjs', /tutorials, agent lifecycle, 29 capabilities, 5 journeys, 5 studies/],
]) {
  const args = [join(ROOT, 'scripts', script)];
  if (script.startsWith('generate-')) args.push('--check');
  const result = spawnSync(process.execPath, args, { cwd: ROOT, encoding: 'utf8', timeout: 30000 });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.match(result.stdout, expected);
}

const evidence = readFileSync(join(ROOT, 'docs', 'launch-evidence.md'), 'utf8');
const metadata = JSON.parse(readFileSync(join(ROOT, 'docs', 'github-metadata.json'), 'utf8'));
const releaseState = JSON.parse(readFileSync(join(ROOT, 'docs', 'release-state.json'), 'utf8'));
assert.equal(metadata.discussions.status, 'enabled');
assert.equal(metadata.discussions.url,
  'https://github.com/parousia8888/web-app-security-skill/discussions');
assert.match(evidence, /OS command injection lead \(CWE-78\); SUSPECTED HIGH -> security fixed; functional passed/);
assert.match(evidence, /43 findings across 5 fixed commits -> 11 useful leads; 27 expected benign; 1 unknown; 4 confirmed facts/);
assert.doesNotMatch(evidence, /2 security HIGH|11 discoverability HIGH|13\s+(?:high|HIGH)/);
assert.ok(evidence.includes(`releases/tag/${releaseState.publishedRelease.tag}`));
assert.doesNotMatch(evidence, /img\.shields\.io\/github\/(?:stars|forks)|star target/i);
assert.deepEqual(
  Object.fromEntries(metadata.roadmapIssues.map((issue) => [issue.number, issue.state])),
  { 1: 'closed', 2: 'closed', 3: 'open', 4: 'open', 5: 'closed', 6: 'open', 7: 'open' },
);
console.log('P7 evidence ok: structured counts, local demo, tutorial and metadata contract');
