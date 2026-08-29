#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateRouteSecurityDocument } from '../scripts/lib/route-security-contract.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(ROOT, 'scripts', 'webapp-security.mjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-route-integration-'));

function write(path, content) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}

function project(name, source) {
  const root = join(temp, name);
  mkdirSync(root, { recursive: true });
  write(join(root, 'package.json'), `${JSON.stringify({
    private: true, dependencies: { express: '5.1.0', passport: '0.7.0' },
  })}\n`);
  write(join(root, 'package-lock.json'), '{"lockfileVersion":3}\n');
  write(join(root, 'src', 'app.ts'), source);
  return root;
}

function run(args, expected, env = process.env) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    cwd: ROOT, encoding: 'utf8', env: { ...env, SOURCE_DATE_EPOCH: '0' },
  });
  assert.equal(result.status, expected, `${args.join(' ')}\n${result.stdout}\n${result.stderr}`);
  return result;
}

function loadRoute(directory) {
  const path = join(directory, 'route-security.json');
  const raw = readFileSync(path);
  const document = JSON.parse(raw);
  assert.deepEqual(validateRouteSecurityDocument(document), []);
  const expectedDigest = createHash('sha256').update(raw).digest('hex');
  assert.equal(readFileSync(join(directory, 'route-security.sha256'), 'utf8'),
    `${expectedDigest}  route-security.json\n`);
  return document;
}

function start(projectRoot, runRoot, runId) {
  const result = run(['start', projectRoot, '--out', runRoot, '--run-id', runId], 0);
  assert.match(result.stdout, /scope:/);
  return join(runRoot, runId);
}

try {
  const normal = project('normal', `
import express from 'express';
import passport from 'passport';
const app = express();
app.patch('/projects/:id', passport.authenticate('jwt'), updateProject);
function updateProject(_req, res) { return res.sendStatus(204); }
`);
  const normalOut = join(temp, 'normal-report');
  let result = run(['audit', normal, '--out', normalOut, '--fail-on', 'never'], 0);
  assert.match(result.stdout, /routes:\s+.*route-security\.md \(1 records\)/);
  const normalRoute = loadRoute(normalOut);
  assert.equal(normalRoute.routes[0].path, '/projects/:id');
  assert.equal(normalRoute.routes[0].authentication.state, 'local_observed');
  assert.equal(normalRoute.coverage.find((entry) => entry.framework === 'express').status, 'completed');
  const normalReport = JSON.parse(readFileSync(join(normalOut, 'report.json'), 'utf8'));
  assert.equal(normalReport.coverage.find((entry) =>
    entry.ruleId === 'js-route-security-evidence-incomplete').status, 'completed');
  for (const name of ['route-security.json', 'route-security.md', 'route-security.sha256']) {
    assert.equal(statSync(join(normalOut, name)).mode & 0o077, 0, `${name} must be private`);
  }

  const pathIncomplete = project('path-incomplete', `
import express from 'express';
const app = express();
app.get('/projects/:id', missingHandler);
`);
  const pathIncompleteOut = join(temp, 'path-incomplete-report');
  run(['audit', pathIncomplete, '--out', pathIncompleteOut, '--fail-on', 'never'], 3);
  const pathIncompleteRoute = loadRoute(pathIncompleteOut);
  assert.equal(pathIncompleteRoute.coverage.find((entry) => entry.framework === 'express').status,
    'completed');
  assert.equal(pathIncompleteRoute.accessPathCoverage.status, 'partial');
  assert.equal(pathIncompleteRoute.accessPathCoverage.counts.skipped, 1);
  const pathIncompleteReport = JSON.parse(readFileSync(
    join(pathIncompleteOut, 'report.json'), 'utf8'));
  assert.ok(pathIncompleteReport.findings.some((finding) =>
    finding.rule.id === 'js-route-security-evidence-incomplete' && finding.state === 'unknown'));

  const malformed = project('malformed', `
import express from 'express';
const app = express();
app.get('/broken', (req, res) => {
`);
  const malformedOut = join(temp, 'malformed-report');
  run(['audit', malformed, '--out', malformedOut, '--fail-on', 'never'], 3);
  const malformedReport = JSON.parse(readFileSync(join(malformedOut, 'report.json'), 'utf8'));
  assert.ok(malformedReport.findings.some((finding) =>
    finding.rule.id === 'js-route-security-evidence-incomplete' && finding.state === 'unknown'));
  assert.equal(loadRoute(malformedOut).coverage.find((entry) => entry.framework === 'express').status,
    'partial');

  const commonJs = project('commonjs-direct', `
const express = require('express');
const app = express();
app.use('/api', require('./routes'));
`);
  write(join(commonJs, 'src', 'routes.js'), `
const router = require('express').Router();
router.get('/orders/:id', showOrder);
function showOrder(_req, res) { return res.sendStatus(200); }
module.exports = router;
`);
  const commonJsOut = join(temp, 'commonjs-direct-report');
  run(['audit', commonJs, '--out', commonJsOut, '--fail-on', 'never'], 0);
  const commonJsRoutes = loadRoute(commonJsOut);
  assert.deepEqual(commonJsRoutes.routes.map((route) => route.path), ['/api/orders/:id']);
  assert.equal(commonJsRoutes.coverage.find((entry) => entry.framework === 'express').status,
    'completed');

  const registration = project('registration-function', `
import express from 'express';
import { registerRoutes } from './routes.js';
const app = express();
registerRoutes(app);
`);
  write(join(registration, 'src', 'routes.js'), `
export function registerRoutes(receiver) { receiver.post('/jobs', createJob); }
`);
  const registrationOut = join(temp, 'registration-function-report');
  run(['audit', registration, '--out', registrationOut, '--fail-on', 'never'], 3);
  const registrationReport = JSON.parse(readFileSync(join(registrationOut, 'report.json'), 'utf8'));
  assert.ok(registrationReport.findings.some((finding) =>
    finding.rule.id === 'js-route-security-evidence-incomplete' && finding.state === 'unknown'));
  const registrationRoutes = loadRoute(registrationOut);
  const registrationCoverage = registrationRoutes.coverage.find((entry) =>
    entry.framework === 'express');
  assert.equal(registrationCoverage.status, 'partial');
  assert.deepEqual(registrationCoverage.reasons.map((reason) => reason.code),
    ['express_registration_function_unresolved']);

  const externalOut = join(temp, 'external-report');
  const emptyPath = join(temp, 'empty-path');
  mkdirSync(emptyPath);
  run(['audit', normal, '--out', externalOut, '--adapter', 'osv', '--fail-on', 'never'], 3,
    { ...process.env, PATH: emptyPath });
  assert.equal(existsSync(join(externalOut, 'report.json')), true);
  assert.equal(existsSync(join(externalOut, 'route-security.json')), false);
  assert.equal(existsSync(join(externalOut, 'route-security.md')), false);

  const lifecycle = project('lifecycle', `
import express from 'express';
import passport from 'passport';
const app = express();
app.get('/same', sameHandler);
app.patch('/changed/:id', passport.authenticate('jwt'), changedHandler);
app.delete('/removed/:id', removedHandler);
function sameHandler(_req, res) { return res.sendStatus(200); }
function changedHandler(_req, res) { return res.sendStatus(204); }
function removedHandler(_req, res) { return res.sendStatus(204); }
`);
  const runs = join(temp, 'lifecycle-runs');
  const baselineDir = start(lifecycle, runs, 'baseline');
  run(['audit', baselineDir, '--name', 'baseline', '--fail-on', 'never'], 0);
  const baselinePath = join(baselineDir, 'baseline.json');
  write(join(lifecycle, 'src', 'app.ts'), `
import express from 'express';
const app = express();
app.get('/same', sameHandler);
app.patch('/changed/:id', changedHandler);
app.post('/added', addedHandler);
function sameHandler(_req, res) { return res.sendStatus(200); }
function changedHandler(_req, res) { return res.sendStatus(204); }
function addedHandler(_req, res) { return res.sendStatus(201); }
`);
  const changedDir = start(lifecycle, runs, 'changed');
  run(['retest', changedDir, '--name', 'changed', '--baseline', baselinePath,
    '--fail-on', 'never', '--fail-on-route-regression'], 1);
  const compared = loadRoute(changedDir);
  const states = Object.fromEntries(compared.routes.map((route) => [route.path, route.baseline.state]));
  assert.deepEqual(states, {
    '/added': 'added', '/changed/:id': 'changed', '/removed/:id': 'removed', '/same': 'unchanged',
  });
  assert.equal(compared.baseline.compatibility, 'compatible');
  assert.equal(compared.routes.find((route) => route.path === '/changed/:id').baseline.reasonCode,
    'classified_authentication_disappeared');

  write(join(lifecycle, 'src', 'broken.ts'), 'export const broken = `unterminated;\n');
  const incompleteDir = start(lifecycle, runs, 'incomplete');
  run(['retest', incompleteDir, '--name', 'incomplete', '--baseline', baselinePath,
    '--fail-on', 'never'], 3);
  const incomplete = loadRoute(incompleteDir);
  assert.ok(incomplete.routes.some((route) => route.path === '/same'
    && route.baseline.state === 'unretested'));
  assert.ok(incomplete.routes.some((route) => route.path === '/removed/:id'
    && route.baseline.state === 'unretested'));

  console.log('route security integration ok: artifact, private write, fail-closed, adapter isolation and baseline states');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
