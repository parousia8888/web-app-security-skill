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
  assert.equal(route.accessChains[0].status, 'completed');
  assert.equal(route.accessChains[0].callEdges[0].to, 'loadProject');
  assert.equal(route.accessChains[0].dataOperation.location.path, 'src/project-service.ts');
  assert.equal(document.serverActions.length, 0,
    `${mode} must filter unchanged Server Actions after whole-project analysis`);
  assert.deepEqual(document.accessPathCoverage.counts, {
    discovered: 2, eligible: 2, scanned: 2, skipped: 0, truncated: 0, errors: 0,
  });
  assert.match(document.limitations.join('\n'),
    new RegExp(`This ${mode} artifact filters route and Server Action records`));
}

try {
  mkdirSync(project, { recursive: true });
  git('init', '-q');
  git('config', 'user.name', 'Route Diff Fixture');
  git('config', 'user.email', 'route-diff@example.invalid');
  write(join(project, 'package.json'), `${JSON.stringify({
    private: true, dependencies: { express: '5.1.0', passport: '0.7.0', next: '15.0.0',
      '@prisma/client': '6.0.0' },
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
import { loadProject } from './project-service';
const router = express.Router();
export default router;
`);
  write(join(project, 'src', 'project-service.ts'), `
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export function loadProject(id) {
  return prisma.project.findUnique({ where: { id } });
}
`);
  write(join(project, 'src', 'unchanged-action.ts'), `
"use server";
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
export async function loadAction(projectId) {
  return prisma.project.findUnique({ where: { id: projectId } });
}
`);
  git('add', '.');
  git('commit', '-qm', 'fixture baseline');

  write(join(project, 'src', 'router.ts'), `
import express from 'express';
import { loadProject } from './project-service';
const router = express.Router();
router.patch('/projects/:id', async (req, res) => res.json(await loadProject(req.params.id)));
export default router;
`);
  assertContext(audit('since-report', ['--since', 'HEAD']), 'since');

  git('add', 'src/router.ts');
  assertContext(audit('staged-report', ['--staged']), 'staged');

  console.log('incremental route security ok: since/staged filtering retains unchanged mount and auth context');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
