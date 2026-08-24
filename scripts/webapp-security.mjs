#!/usr/bin/env node
import {
  cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync,
  renameSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SKILL_ID = 'web-app-security';
const LEGACY_SKILL_ID = 'webapp-security-hardening';
const VERSION = readFileSync(join(ROOT, 'VERSION'), 'utf8').trim();
const INSTALL_MARKER = '.web-app-security-install.json';
const argv = process.argv.slice(2);
const command = argv.shift();

function usage(code = 0) {
  console.log(`webapp-security <command> [options]

Commands:
  start <project> [options]    Discover stack and create a versioned, network-free scope
  audit <project|run>          Run source checks plus supported route/control review evidence
  explain <id> --report <json> Explain one finding from a structured report
  repair-plan <id> [options]   Create a review-only repair workflow record
  repair-validate <json>       Validate approval, application, retest and rollback state
  retest <project|run>         Rerun source checks against a required baseline
  doctor [project]             Report adapter versions/prerequisites without downloads
  migrate-report <v1-report>   Bind historical v1 evidence as non-comparable v2 lineage
  rebind <project>             Explicitly bind a moved/cloned project to a reviewed subject
  demo                         Run the deterministic local before/after demo
  crawl <crawl options>        Audit a public crawl boundary
  verify-crawler <options>     Verify a crawler IP and claimed user agent
  verify-edge <options>        Verify headers, redirects, TLS, and optional rate limiting
  aws <aws audit options>      Run the read-only AWS posture inventory
  install [options]            Install for Claude Code, Codex, and/or the CLI
  upgrade [options]            Replace recognized installs from this release payload
  uninstall [options]          Remove recognized installs while preserving prior backups
  version                      Print the release version

Lifecycle options:
  --target claude|codex|cli|both|all
                               Default: all; both means Claude Code + Codex
Install only:
  --force                      Replace existing paths after making backups

Built-in JS/TS audits may also write route-security.json and route-security.md. Route priority is
review order, not severity; a control not observed in source is not a confirmed vulnerability.
`);
  process.exit(code);
}

function run(program, args) {
  const child = spawn(program, args, { stdio: 'inherit' });
  child.on('error', (error) => { console.error(error.message); process.exit(2); });
  child.on('exit', (code, signal) => process.exit(signal ? 1 : (code ?? 1)));
}

function pathExists(path) {
  try { lstatSync(path); return true; } catch { return false; }
}

function lifecycleOptions({ allowForce = false } = {}) {
  const args = [...argv];
  const targetIndex = args.indexOf('--target');
  let target = 'all';
  if (targetIndex !== -1) {
    if (!args[targetIndex + 1] || args[targetIndex + 1].startsWith('--')) {
      console.error('error: --target requires a value');
      process.exit(2);
    }
    target = args[targetIndex + 1];
    args.splice(targetIndex, 2);
  }
  const forceIndex = args.indexOf('--force');
  const force = forceIndex !== -1;
  if (force) args.splice(forceIndex, 1);
  if (force && !allowForce) {
    console.error('error: --force is only valid for install');
    process.exit(2);
  }
  if (args.length) {
    console.error(`error: unknown lifecycle option ${args[0]}`);
    process.exit(2);
  }
  if (!['claude', 'codex', 'cli', 'both', 'all'].includes(target)) {
    console.error('error: --target must be claude, codex, cli, both, or all');
    process.exit(2);
  }
  return { target, force };
}

function installSpecs(target) {
  const installs = [];
  if (['claude', 'both', 'all'].includes(target)) installs.push({
    surface: 'claude',
    destination: join(homedir(), '.claude', 'skills', SKILL_ID),
    legacy: join(homedir(), '.claude', 'skills', LEGACY_SKILL_ID),
  });
  if (['codex', 'both', 'all'].includes(target)) installs.push({
    surface: 'codex',
    destination: join(homedir(), '.codex', 'skills', SKILL_ID),
    legacy: join(homedir(), '.codex', 'skills', LEGACY_SKILL_ID),
  });
  if (['cli', 'all'].includes(target)) installs.push({
    surface: 'cli',
    destination: join(homedir(), '.local', 'share', SKILL_ID),
    legacy: join(homedir(), '.local', 'share', LEGACY_SKILL_ID),
    launcher: join(homedir(), '.local', 'bin', 'webapp-security'),
  });
  return installs;
}

function recognizedInstall(path) {
  if (!pathExists(path) || lstatSync(path).isSymbolicLink()) return false;
  try {
    const markerPath = join(path, INSTALL_MARKER);
    if (existsSync(markerPath)) {
      const marker = JSON.parse(readFileSync(markerPath, 'utf8'));
      return marker.schemaVersion === 1 && marker.product === 'Web App Security Skill'
        && [SKILL_ID, LEGACY_SKILL_ID].includes(marker.skillId);
    }
    return /^name:\s+(?:web-app-security|webapp-security-hardening)\s*$/m
      .test(readFileSync(join(path, 'SKILL.md'), 'utf8'));
  } catch {
    return false;
  }
}

function launcherTargetsInstall(launcher, destinations) {
  if (!pathExists(launcher)) return false;
  try {
    if (!lstatSync(launcher).isSymbolicLink()) return false;
    const target = resolve(dirname(launcher), readlinkSync(launcher));
    return destinations.some((destination) =>
      target === join(destination, 'scripts', 'webapp-security.mjs'));
  } catch {
    return false;
  }
}

const include = [
  'SKILL.md', 'VERSION', 'LICENSE', 'KNOWN_LIMITATIONS.md', 'THIRD_PARTY_NOTICES.md',
  '.claude-plugin', 'agents', 'assets', 'examples', 'references', 'rules', 'scripts',
  'docs/capabilities.json', 'docs/capabilities.md', 'docs/security-scope.schema.json',
  'docs/finding.schema.json', 'docs/report.schema.json', 'docs/finding-v2.schema.json',
  'docs/report-v2.schema.json', 'docs/report-v2-migration.md', 'docs/finding-v3.schema.json',
  'docs/report-v3.schema.json', 'docs/report-v3-migration.md',
  'docs/repair-record.schema.json',
  'docs/adapter-protocol.md', 'docs/alert-policy.md', 'docs/rule-taxonomy.md',
  'docs/stable-source-rules.json', 'docs/stable-rule-corpus.json',
  'docs/conformance/v0.6.0-rule-contract-conformance.json',
  'docs/conformance/v0.6.0-rule-contract-conformance.md',
  'docs/regressions/v0.5.4-real-world-regressions.json',
  'docs/regressions/v0.5.4-real-world-regressions.md',
  'docs/regressions/v0.6.0-route-real-world-regressions.json',
  'docs/regressions/v0.6.0-route-real-world-regressions.md',
  'docs/regressions/v0.7.0-access-control-real-world-regressions.json',
  'docs/regressions/v0.7.0-access-control-real-world-regressions.md',
  'docs/reviews/v0.6.0-route-review.json',
  'docs/reviews/v0.6.0-route-review.md',
  'docs/reviews/v0.7.0-access-control-review.json',
  'docs/reviews/v0.7.0-access-control-review.md',
  'docs/route-security-v1.schema.json',
  'docs/route-security-v2.schema.json',
];

function stagePayload(spec) {
  mkdirSync(dirname(spec.destination), { recursive: true });
  const stageRoot = mkdtempSync(join(dirname(spec.destination), '.webapp-security-install-'));
  const staged = join(stageRoot, basename(spec.destination));
  mkdirSync(staged);
  for (const entry of include) {
    const source = join(ROOT, entry);
    const target = join(staged, entry);
    if (!existsSync(source)) continue;
    mkdirSync(dirname(target), { recursive: true });
    cpSync(source, target, { recursive: true });
  }
  writeFileSync(join(staged, INSTALL_MARKER), `${JSON.stringify({
    schemaVersion: 1,
    product: 'Web App Security Skill',
    skillId: SKILL_ID,
    version: VERSION,
    surface: spec.surface,
  }, null, 2)}\n`, { mode: 0o600 });
  return { ...spec, stageRoot, staged };
}

function backupName(path) {
  const base = `${path}.backup-${new Date().toISOString().replace(/[:.]/g, '-')}`;
  let candidate = base;
  let suffix = 1;
  while (pathExists(candidate)) {
    candidate = `${base}-${suffix}`;
    suffix += 1;
  }
  return candidate;
}

function installOrUpgrade(mode) {
  const { target, force } = lifecycleOptions({ allowForce: mode === 'install' });
  const installs = installSpecs(target);
  const conflicts = installs.flatMap(({ destination, legacy, launcher }) =>
    [destination, legacy, launcher].filter((path) => path && pathExists(path)));
  if (mode === 'install' && conflicts.length && !force) {
    const legacyFound = conflicts.some((item) => item.endsWith(`/${LEGACY_SKILL_ID}`));
    console.error(`error: existing install${conflicts.length === 1 ? '' : 's'}:\n${conflicts.map((item) => `  ${item}`).join('\n')}\n${legacyFound ? `legacy ${LEGACY_SKILL_ID} installs require migration; ` : ''}re-run with --force to back up and replace`);
    process.exit(2);
  }
  if (mode === 'install' && conflicts.length && force) {
    const invalid = [];
    for (const spec of installs) {
      const payloads = [spec.destination, spec.legacy].filter((path) => pathExists(path));
      const recognizedPayloads = payloads.filter(recognizedInstall);
      invalid.push(...payloads.filter((path) => !recognizedInstall(path)));
      if (spec.launcher && pathExists(spec.launcher)
          && (!recognizedPayloads.length
            || !launcherTargetsInstall(spec.launcher, recognizedPayloads))) invalid.push(spec.launcher);
    }
    if (invalid.length) {
      console.error(`error: --force refuses unrecognized paths:\n${invalid.map((path) => `  ${path}`).join('\n')}`);
      process.exit(2);
    }
  }
  if (mode === 'upgrade') {
    const invalid = [];
    let found = 0;
    for (const spec of installs) {
      const current = pathExists(spec.destination);
      const legacy = pathExists(spec.legacy);
      if (current) {
        if (!recognizedInstall(spec.destination)) invalid.push(spec.destination);
        else found += 1;
      }
      if (legacy) {
        if (!recognizedInstall(spec.legacy)) invalid.push(spec.legacy);
        else found += 1;
      }
      if (spec.launcher && pathExists(spec.launcher)
          && !launcherTargetsInstall(spec.launcher, [spec.destination, spec.legacy])) invalid.push(spec.launcher);
    }
    if (invalid.length || !found) {
      const detail = invalid.length
        ? `\n${invalid.map((path) => `  ${path}`).join('\n')}`
        : '';
      console.error(`error: upgrade requires at least one recognized selected install and refuses unrecognized paths${detail}`);
      process.exit(2);
    }
  }

  const stagedInstalls = installs.map(stagePayload);
  const installed = [];
  try {
    for (const spec of stagedInstalls) {
      const existingPaths = [spec.destination, spec.legacy, spec.launcher]
        .filter((path) => path && pathExists(path));
      if (mode === 'upgrade' && !existingPaths.length) continue;
      const backups = [];
      try {
        for (const existing of existingPaths) {
          const backup = backupName(existing);
          renameSync(existing, backup);
          backups.push({ backup, original: existing });
        }
        renameSync(spec.staged, spec.destination);
        if (spec.launcher) {
          mkdirSync(dirname(spec.launcher), { recursive: true });
          symlinkSync(join(spec.destination, 'scripts', 'webapp-security.mjs'), spec.launcher);
        }
        installed.push({ spec, backups });
        console.log(`${mode === 'upgrade' ? 'upgraded' : 'installed'}: ${spec.destination}`);
        for (const { backup } of backups) console.log(`backup:    ${backup}`);
      } catch (error) {
        rmSync(spec.destination, { recursive: true, force: true });
        if (spec.launcher) rmSync(spec.launcher, { force: true });
        for (const { backup, original } of backups.reverse()) {
          if (!pathExists(original)) renameSync(backup, original);
        }
        throw error;
      }
    }
  } catch (error) {
    for (const { spec, backups } of installed.reverse()) {
      rmSync(spec.destination, { recursive: true, force: true });
      if (spec.launcher) rmSync(spec.launcher, { force: true });
      for (const { backup, original } of backups.reverse()) {
        if (!pathExists(original)) renameSync(backup, original);
      }
    }
    throw error;
  } finally {
    for (const { stageRoot } of stagedInstalls) rmSync(stageRoot, { recursive: true, force: true });
  }
}

function uninstall() {
  const { target } = lifecycleOptions();
  const installs = installSpecs(target);
  const invalid = [];
  const removable = [];
  for (const spec of installs) {
    for (const path of [spec.destination, spec.legacy]) {
      if (!pathExists(path)) continue;
      if (!recognizedInstall(path)) invalid.push(path);
      else removable.push(path);
    }
    if (spec.launcher && pathExists(spec.launcher)) {
      if (!launcherTargetsInstall(spec.launcher, [spec.destination, spec.legacy])) invalid.push(spec.launcher);
      else removable.push(spec.launcher);
    }
  }
  if (invalid.length) {
    console.error(`error: refusing to remove unrecognized paths:\n${invalid.map((path) => `  ${path}`).join('\n')}`);
    process.exit(2);
  }
  if (!removable.length) {
    console.error('error: no recognized selected installs were found');
    process.exit(2);
  }
  const staged = [];
  try {
    for (const path of removable) {
      const temporary = `${path}.uninstall-${process.pid}`;
      renameSync(path, temporary);
      staged.push({ path, temporary });
    }
  } catch (error) {
    for (const { path, temporary } of staged.reverse()) {
      if (!pathExists(path)) renameSync(temporary, path);
    }
    throw error;
  }
  for (const { path, temporary } of staged) {
    rmSync(temporary, { recursive: true, force: true });
    console.log(`uninstalled: ${path}`);
  }
}

switch (command) {
  case 'start': run(process.execPath, [join(ROOT, 'scripts', 'project-start.mjs'), ...argv]); break;
  case 'audit': run(process.execPath, [join(ROOT, 'scripts', 'project-audit.mjs'), 'audit', ...argv]); break;
  case 'explain': run(process.execPath, [join(ROOT, 'scripts', 'explain-finding.mjs'), ...argv]); break;
  case 'repair-plan': run(process.execPath, [join(ROOT, 'scripts', 'repair-plan.mjs'), 'create', ...argv]); break;
  case 'repair-validate': run(process.execPath, [join(ROOT, 'scripts', 'repair-plan.mjs'), 'validate', ...argv]); break;
  case 'retest': run(process.execPath, [join(ROOT, 'scripts', 'project-audit.mjs'), 'retest', ...argv]); break;
  case 'doctor': run(process.execPath, [join(ROOT, 'scripts', 'adapter-doctor.mjs'), ...argv]); break;
  case 'migrate-report': run(process.execPath, [join(ROOT, 'scripts', 'migrate-report.mjs'), ...argv]); break;
  case 'rebind': run(process.execPath, [join(ROOT, 'scripts', 'rebind-project.mjs'), ...argv]); break;
  case 'demo': run(process.execPath, [join(ROOT, 'scripts', 'demo.mjs'), ...argv]); break;
  case 'crawl': run(process.execPath, [join(ROOT, 'scripts', 'crawl-surface-audit.mjs'), ...argv]); break;
  case 'verify-crawler': run(process.execPath, [join(ROOT, 'scripts', 'verify-crawler-ip.mjs'), ...argv]); break;
  case 'verify-edge': run('/bin/bash', [join(ROOT, 'scripts', 'verify-hardening.sh'), ...argv]); break;
  case 'aws': run('/bin/bash', [join(ROOT, 'scripts', 'aws-exposure-audit.sh'), ...argv]); break;
  case 'install': installOrUpgrade('install'); break;
  case 'upgrade': installOrUpgrade('upgrade'); break;
  case 'uninstall': uninstall(); break;
  case 'version':
    if (argv.length) { console.error(`error: unknown version option ${argv[0]}`); process.exit(2); }
    console.log(`Web App Security Skill ${VERSION}`);
    break;
  case '-h': case '--help': case undefined: usage(command ? 0 : 2); break;
  default: console.error(`error: unknown command ${JSON.stringify(command)}`); usage(2);
}
