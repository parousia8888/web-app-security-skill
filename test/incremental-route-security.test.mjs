#!/usr/bin/env node
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(ROOT, 'scripts', 'webapp-security.mjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-route-diff-'));
const project = join(temp, 'project');

function run(program, args, cwd = ROOT, expected = 0) {
  const result = spawnSync(program, args, { cwd, encoding: 'utf8' });
  assert.equal(result.status, expected, `${program} ${args.join(' ')}\n${result.stdout}\n${result.stderr}`);
  return result;
}

function git(...args) {
  return run('git', args, project).stdout.trim();
}

function write(path, content) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

function audit(name, options) {
  const out = join(temp, name);
  run(process.execPath, [CLI, 'audit', project, '--out', out, '--fail-on', 'never', ...options]);
  return JSON.parse(readFileSync(join(out, 'route-security.json'), 'utf8'));
}

function assertContext(document, mode) {
  assert.equal(document.routes.length, 1, `${mode} must show only the changed router route`);
  const route = document.routes[0];
  assert.equal(route.path, '/api/projects/:id');
  assert.equal(route.authentication.state, 'inherited_observed');
  assert.ok(route.authentication.signals.some((signal) =>
    signal.location.path === 'src/app.ts' && signal.origin === 'passport:authenticate'));
  assert.match(document.limitations.join('\n'), new RegExp(`This ${mode} artifact filters route records`));
}

try {
  mkdirSync(project, { recursive: true });
  git('init', '-q');
  git('config', 'user.name', 'Route Diff Fixture');
  git('config', 'user.email', 'route-diff@example.invalid');
  write(join(project, 'package.json'), `${JSON.stringify({
    private: true, dependencies: { express: '5.1.0', passport: '0.7.0' },
  })}\n`);
  write(join(project, 'package-lock.json'), '{"lockfileVersion":3}\n');
  write(join(project, 'src', 'app.ts'), `
import express from 'express';
import passport from 'passport';
import router from './router';
const app = express();
app.use(passport.authenticate('jwt'));
app.use('/api', router);
`);
  write(join(project, 'src', 'router.ts'), `
import express from 'express';
const router = express.Router();
export default router;
`);
  git('add', '.');
  git('commit', '-qm', 'fixture baseline');

  write(join(project, 'src', 'router.ts'), `
import express from 'express';
const router = express.Router();
router.patch('/projects/:id', updateProject);
export default router;
`);
  assertContext(audit('since-report', ['--since', 'HEAD']), 'since');

  git('add', 'src/router.ts');
  assertContext(audit('staged-report', ['--staged']), 'staged');

  console.log('incremental route security ok: since/staged filtering retains unchanged mount and auth context');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
