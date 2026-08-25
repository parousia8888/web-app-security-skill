#!/usr/bin/env node
import {
  cpSync, lstatSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, isAbsolute, join, parse, relative, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const args = process.argv.slice(2);
const outIndex = args.indexOf('--out');
if (outIndex !== -1 && (!args[outIndex + 1] || args[outIndex + 1].startsWith('-'))) {
  console.error('usage: webapp-security demo [--out <owned-output-directory>]');
  process.exit(2);
}
const out = resolve(outIndex === -1 ? join(ROOT, 'demo-output') : args[outIndex + 1]);
const epoch = process.env.SOURCE_DATE_EPOCH || '0';
const env = { ...process.env, SOURCE_DATE_EPOCH: epoch };
const project = join(out, 'owned-source-fixture');
const runs = join(out, 'runs');
const OWNER_FILE = '.web-app-security-demo-owner.json';
const OWNER = { schemaVersion: 1, product: 'Web App Security Skill', purpose: 'owned-demo-output' };
const OWNED_CHILDREN = [
  'owned-source-fixture', 'runs', 'before-evidence', 'after-evidence', 'hardening.patch',
  'functional-retest.txt', 'before.json', 'before.md', 'before.html', 'after.json', 'after.md',
  'after.sarif', 'demo-result.json', 'summary.md',
];

function pathExists(path) {
  try { lstatSync(path); return true; } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

function canonicalCandidate(path) {
  if (pathExists(path)) return realpathSync(path);
  const tail = [];
  let cursor = path;
  while (!pathExists(cursor)) {
    const parent = dirname(cursor);
    if (parent === cursor) break;
    tail.unshift(cursor.slice(parent.length + (parent.endsWith('/') ? 0 : 1)));
    cursor = parent;
  }
  return resolve(realpathSync(cursor), ...tail);
}

function containsPath(parent, child) {
  const relationship = relative(parent, child);
  return relationship === '' || (!relationship.startsWith('..') && !isAbsolute(relationship));
}

function assertSafeOutput(path) {
  if (pathExists(path) && lstatSync(path).isSymbolicLink()) {
    throw new Error('refusing symlink demo output directory');
  }
  const candidate = canonicalCandidate(path);
  const protectedPaths = [parse(candidate).root, homedir(), process.cwd(), ROOT]
    .map((item) => canonicalCandidate(resolve(item)));
  if (protectedPaths.some((protectedPath) => containsPath(candidate, protectedPath))) {
    throw new Error('refusing protected demo output directory');
  }
}

function prepareOwnedOutput(path) {
  assertSafeOutput(path);
  const marker = join(path, OWNER_FILE);
  if (pathExists(path)) {
    if (!lstatSync(path).isDirectory()) throw new Error('demo output is not a directory');
    if (!pathExists(marker) || lstatSync(marker).isSymbolicLink()) {
      throw new Error('refusing pre-existing unowned demo output directory');
    }
    let owner;
    try { owner = JSON.parse(readFileSync(marker, 'utf8')); } catch {
      throw new Error('refusing demo output with an invalid ownership marker');
    }
    if (JSON.stringify(owner) !== JSON.stringify(OWNER)) {
      throw new Error('refusing demo output with an invalid ownership marker');
    }
    for (const child of OWNED_CHILDREN) rmSync(join(path, child), { recursive: true, force: true });
    return;
  }
  mkdirSync(path, { recursive: true, mode: 0o700 });
  writeFileSync(marker, `${JSON.stringify(OWNER, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
}

function run(commandArgs, options = {}) {
  const result = spawnSync(process.execPath, commandArgs, {
    cwd: options.cwd || ROOT, env, encoding: 'utf8', timeout: 30000,
  });
  if (result.status !== (options.expected ?? 0)) {
    throw new Error(result.stderr || result.stdout || `command exited ${result.status}`);
  }
  return result;
}

prepareOwnedOutput(out);
cpSync(join(ROOT, 'examples', 'insecure-demo'), project, { recursive: true });

run([join(ROOT, 'scripts', 'webapp-security.mjs'), 'start', project, '--out', runs, '--run-id', 'before']);
run([join(ROOT, 'scripts', 'webapp-security.mjs'), 'audit', join(runs, 'before'),
  '--out', join(out, 'before-evidence'), '--name', 'report', '--fail-on', 'never']);
const beforePath = join(out, 'before-evidence', 'report.json');
const before = JSON.parse(readFileSync(beforePath, 'utf8'));
const finding = before.findings.find((item) => item.rule.id === 'node-child-process-shell-execution');
if (!finding || finding.state !== 'suspected') throw new Error('demo command-execution lead is missing');

const vulnerable = readFileSync(join(project, 'src', 'export-report.mjs'), 'utf8');
const hardened = `import { execFile } from 'node:child_process';

export function exportReport(title) {
  return new Promise((resolve, reject) => {
    execFile('printf', ['%s\\n', title], (error, stdout) => {
      if (error) reject(error);
      else resolve(stdout);
    });
  });
}
`;
writeFileSync(join(project, 'src', 'export-report.mjs'), hardened);
const patch = `--- a/src/export-report.mjs
+++ b/src/export-report.mjs
@@
-import { exec } from 'node:child_process';
+import { execFile } from 'node:child_process';
@@
-    exec(\`printf '%s\\\\n' "\${title}"\`, (error, stdout) => {
+    execFile('printf', ['%s\\\\n', title], (error, stdout) => {
`;
if (!vulnerable.includes('exec(`printf')) throw new Error('demo fixture drifted');
writeFileSync(join(out, 'hardening.patch'), patch);

run([join(ROOT, 'scripts', 'webapp-security.mjs'), 'start', project, '--out', runs, '--run-id', 'after']);
run([join(ROOT, 'scripts', 'webapp-security.mjs'), 'retest', join(runs, 'after'),
  '--out', join(out, 'after-evidence'), '--name', 'report', '--baseline', beforePath, '--fail-on', 'never']);
const after = JSON.parse(readFileSync(join(out, 'after-evidence', 'report.json'), 'utf8'));
const fixed = after.findings.find((item) => item.id === finding.id);
if (fixed?.baseline.state !== 'fixed') throw new Error('demo security retest did not record fixed');
const functional = run([join(project, 'test-functional.mjs')], { cwd: project });
writeFileSync(join(out, 'functional-retest.txt'), functional.stdout);

for (const [source, target] of [
  [beforePath, 'before.json'], [join(out, 'before-evidence', 'report.md'), 'before.md'],
  [join(out, 'before-evidence', 'report.html'), 'before.html'],
  [join(out, 'after-evidence', 'report.json'), 'after.json'],
  [join(out, 'after-evidence', 'report.md'), 'after.md'],
  [join(out, 'after-evidence', 'report.sarif'), 'after.sarif'],
]) cpSync(source, join(out, target));

const facts = {
  schemaVersion: 2,
  generator: 'scripts/demo.mjs',
  boundary: 'owned-local-source-fixture-no-network',
  input: 'examples/insecure-demo/src/export-report.mjs',
  before: {
    findingId: finding.id, ruleId: finding.rule.id, state: finding.state,
    severity: finding.severity, technicalTerm: finding.explanation.technicalTerm,
    plainLanguage: finding.explanation.plainLanguage,
    consequence: finding.explanation.consequence,
    evidenceBoundary: finding.explanation.evidenceBoundary,
  },
  proposal: {
    status: finding.explanation.proposal.status,
    summary: finding.explanation.proposal.summary,
    sideEffects: finding.explanation.sideEffects,
  },
  securityRetest: { status: 'passed', baselineState: fixed.baseline.state },
  functionalRetest: { status: 'passed', evidence: functional.stdout.trim() },
};
writeFileSync(join(out, 'demo-result.json'), `${JSON.stringify(facts, null, 2)}\n`);
writeFileSync(join(out, 'summary.md'), `# Demo result

| Input | Finding | Evidence state | Proposal | Security retest | Functional retest |
|---|---|---|---|---|---|
| owned local source fixture | ${facts.before.technicalTerm} | ${facts.before.state} | replace shell command with argument-separated execFile | ${facts.securityRetest.baselineState} | ${facts.functionalRetest.status} |

The source lead is not claimed as a confirmed exploit. The patch is review evidence; the compatible
source retest and the separate product behavior test are recorded independently.
`);
console.log(`Demo complete in ${out}
before: suspected HIGH ${facts.before.ruleId}
proposal: review shell-free argument handling and side effects
security retest: ${facts.securityRetest.baselineState}
functional retest: ${facts.functionalRetest.status}`);
