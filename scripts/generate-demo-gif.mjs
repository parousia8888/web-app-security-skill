#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createCanvas, drawText, encodeGif, fillRect } from './lib/deterministic-gif.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const OUTPUT = join(ROOT, 'docs', 'assets', 'demo.gif');
const METADATA = join(ROOT, 'docs', 'assets', 'demo.json');
const WIDTH = 840;
const HEIGHT = 472;
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-demo-gif-'));
const demoOutput = join(temp, 'demo-output');

function frame(title, subtitle, lines, { accent = 5, delay = 180 } = {}) {
  const canvas = createCanvas(WIDTH, HEIGHT);
  fillRect(canvas, 0, 0, WIDTH, 10, accent);
  fillRect(canvas, 0, 10, WIDTH, 46, 7);
  drawText(canvas, 'WEB APP SECURITY SKILL', 24, 25, { color: 1, scale: 2 });
  drawText(canvas, title, 34, 88, { color: accent, scale: 3 });
  drawText(canvas, subtitle, 36, 126, { color: 6, scale: 2 });
  fillRect(canvas, 34, 164, WIDTH - 68, 2, 7);
  lines.forEach((line, index) => drawText(canvas, line.text, 42, 194 + index * 42, {
    color: line.color ?? 1, scale: line.scale ?? 2,
  }));
  drawText(canvas, 'OWNED LOCAL SOURCE / NO NETWORK', 36, 444, { color: 6, scale: 1 });
  return { pixels: canvas.pixels, delay };
}

try {
  const demo = spawnSync(process.execPath, [join(ROOT, 'scripts', 'demo.mjs'), '--out', demoOutput], {
    cwd: ROOT, encoding: 'utf8', timeout: 30000, env: { ...process.env, SOURCE_DATE_EPOCH: '0' },
  });
  if (demo.status !== 0) throw new Error(demo.stderr || demo.stdout || 'demo failed');
  const facts = JSON.parse(readFileSync(join(demoOutput, 'demo-result.json'), 'utf8'));
  const frames = [
    frame('SOURCE AUDIT', 'INTENTIONALLY VULNERABLE NODE.JS FIXTURE', [
      { text: '$ NPM RUN DEMO -- --OUT ./DEMO-OUTPUT', color: 5 },
      { text: 'LOCAL SOURCE ONLY / NO NETWORK', color: 1 },
      { text: 'V3 REPORTS GENERATED FROM THE REAL CLI', color: 6 },
    ], { accent: 5, delay: 150 }),
    frame('FOUND / REVIEW', 'OS COMMAND INJECTION LEAD (CWE-78)', [
      { text: 'STATE: SUSPECTED / SEVERITY: HIGH', color: 4 },
      { text: 'SHELL TREATS SPECIAL CHARACTERS AS COMMANDS', color: 1 },
      { text: 'INPUT FLOW AND REACHABILITY NOT PROVED', color: 6 },
    ], { accent: 4, delay: 230 }),
    frame('PROPOSAL', 'USE EXECFILE WITH SEPARATE ARGUMENTS', [
      { text: '- EXEC(SHELL COMMAND STRING)', color: 2 },
      { text: '+ EXECFILE(PROGRAM, ARGUMENTS)', color: 3 },
      { text: 'SIDE EFFECT: QUOTING / PLATFORM MAY CHANGE', color: 4 },
      { text: 'REVIEW BEFORE APPLYING', color: 6 },
    ], { accent: 5, delay: 230 }),
    frame('SECURITY RETEST', 'FIXED IN THE COMPATIBLE SOURCE BASELINE', [
      { text: 'THE SAME RULE NO LONGER REPRODUCES', color: 3 },
      { text: 'THIS DOES NOT CLAIM A PRIOR EXPLOIT', color: 6 },
      { text: 'BEFORE.JSON + PATCH + AFTER.JSON', color: 1 },
    ], { accent: 3, delay: 230 }),
    frame('FUNCTIONAL RETEST', 'ORDINARY REPORT EXPORT STILL PASSES', [
      { text: 'SECURITY AND PRODUCT TESTS ARE SEPARATE', color: 1 },
      { text: 'ROLL BACK IF VALID EXPORTS REGRESS', color: 4 },
      { text: 'READ DOCS/DEMO-EVIDENCE.MD', color: 5 },
    ], { accent: 3, delay: 260 }),
  ];
  const gif = encodeGif({ width: WIDTH, height: HEIGHT, frames });
  const digest = createHash('sha256').update(gif).digest('hex');
  const metadata = `${JSON.stringify({
    schemaVersion: 3, generator: 'scripts/generate-demo-gif.mjs',
    sources: ['scripts/demo.mjs', 'demo-result.json', 'hardening.patch', 'functional-retest.txt'],
    width: WIDTH, height: HEIGHT, frames: frames.length,
    durationMilliseconds: frames.reduce((sum, item) => sum + item.delay * 10, 0),
    bytes: gif.length, sha256: digest, result: facts,
    boundary: 'owned-local-source-fixture-no-network',
  }, null, 2)}\n`;
  if (process.argv.includes('--check')) {
    if (!existsSync(OUTPUT) || !readFileSync(OUTPUT).equals(gif)) throw new Error('demo GIF is stale; run node scripts/generate-demo-gif.mjs');
    if (!existsSync(METADATA) || readFileSync(METADATA, 'utf8') !== metadata) throw new Error('demo GIF metadata is stale; run node scripts/generate-demo-gif.mjs');
    console.log(`demo GIF current: ${frames.length} frames, ${gif.length} bytes, sha256 ${digest}`);
  } else {
    mkdirSync(join(ROOT, 'docs', 'assets'), { recursive: true });
    writeFileSync(OUTPUT, gif);
    writeFileSync(METADATA, metadata);
    console.log(`${OUTPUT}\n${METADATA}\n${gif.length} bytes\nsha256 ${digest}`);
  }
} finally {
  rmSync(temp, { recursive: true, force: true });
}
