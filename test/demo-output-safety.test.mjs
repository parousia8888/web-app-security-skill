#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const DEMO = join(ROOT, 'scripts', 'demo.mjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-demo-safety-'));

function run(args, cwd = ROOT) {
  return spawnSync(process.execPath, [DEMO, ...args], {
    cwd, encoding: 'utf8', timeout: 30000,
    env: { ...process.env, SOURCE_DATE_EPOCH: '0' },
  });
}

try {
  const missingValue = run(['--out']);
  assert.equal(missingValue.status, 2);
  assert.match(missingValue.stderr, /usage: webapp-security demo/);

  const unowned = join(temp, 'unowned');
  mkdirSync(unowned);
  const sentinel = join(unowned, 'must-survive.txt');
  writeFileSync(sentinel, 'owned by the caller\n');
  const refused = run(['--out', unowned]);
  assert.notEqual(refused.status, 0);
  assert.match(refused.stderr, /pre-existing unowned demo output directory/);
  assert.equal(readFileSync(sentinel, 'utf8'), 'owned by the caller\n',
    'the regression must catch the former recursive deletion primitive');

  const outside = join(temp, 'outside');
  const link = join(temp, 'linked-output');
  mkdirSync(outside);
  writeFileSync(join(outside, 'must-survive.txt'), 'outside\n');
  symlinkSync(outside, link);
  const linked = run(['--out', link]);
  assert.notEqual(linked.status, 0);
  assert.match(linked.stderr, /symlink demo output directory/);
  assert.equal(readFileSync(join(outside, 'must-survive.txt'), 'utf8'), 'outside\n');

  const owned = join(temp, 'owned');
  const first = run(['--out', owned]);
  assert.equal(first.status, 0, first.stderr || first.stdout);
  const callerFile = join(owned, 'caller-note.txt');
  writeFileSync(callerFile, 'preserve me\n');
  const second = run(['--out', owned]);
  assert.equal(second.status, 0, second.stderr || second.stdout);
  assert.equal(readFileSync(callerFile, 'utf8'), 'preserve me\n',
    'reruns may remove only known demo-owned children');
  assert.ok(existsSync(join(owned, '.web-app-security-demo-owner.json')));
  assert.ok(existsSync(join(owned, 'demo-result.json')));

  const protectedPath = run(['--out', ROOT]);
  assert.notEqual(protectedPath.status, 0);
  assert.match(protectedPath.stderr, /protected demo output directory/);

  console.log('demo output safety ok: owned reruns, unowned and protected paths refused');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
