#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const image = readFileSync(join(ROOT, 'docs', 'assets', 'social-preview.png'));
const metadata = JSON.parse(readFileSync(join(ROOT, 'docs', 'assets', 'social-preview.json'), 'utf8'));
const result = spawnSync(process.execPath, [join(ROOT, 'scripts', 'generate-social-preview.mjs'), '--check'], {
  cwd: ROOT,
  encoding: 'utf8',
});

assert.equal(result.status, 0, result.stderr || result.stdout);
assert.deepEqual([...image.subarray(0, 8)], [137, 80, 78, 71, 13, 10, 26, 10]);
assert.equal(image.readUInt32BE(16), 1280);
assert.equal(image.readUInt32BE(20), 640);
assert.equal(metadata.width, 1280);
assert.equal(metadata.height, 640);
assert.equal(metadata.bytes, image.length);
assert.equal(metadata.sha256, createHash('sha256').update(image).digest('hex'));
assert.equal(metadata.command, 'npx --yes web-app-security-skill@0.7.0 audit . --fail-on never');
assert.equal(metadata.liveUpload, 'external_validation_pending');
assert.ok(image.length < 250_000, `social preview is unexpectedly large: ${image.length}`);
console.log(`social preview ok: deterministic 1280x640 PNG, ${image.length} bytes`);
