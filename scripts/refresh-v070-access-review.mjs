#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import {
  V070_PROJECT_SPECS, V070_TOOL_COMMIT, routeSemanticDigest,
} from './generate-v070-access-review.mjs';

const args = process.argv.slice(2);
const acknowledge = args.includes('--acknowledge-network');
if (acknowledge) args.splice(args.indexOf('--acknowledge-network'), 1);
const outIndex = args.indexOf('--out');
const outValue = outIndex >= 0 ? args[outIndex + 1] : null;
if (outIndex >= 0) args.splice(outIndex, 2);
if (!acknowledge || !outValue || args.length) {
  console.error('usage: node scripts/refresh-v070-access-review.mjs --acknowledge-network --out <new-directory>');
  process.exit(2);
}

const outputRoot = resolve(outValue);
if (existsSync(outputRoot)) {
  console.error(`refusing existing output directory: ${outputRoot}`);
  process.exit(2);
}
mkdirSync(outputRoot, { recursive: true });

function run(command, commandArgs, options = {}) {
  console.log(`running ${command} ${commandArgs.join(' ')}`);
  return execFileSync(command, commandArgs, { stdio: 'inherit', ...options });
}

function checkout(repository, commit, directory) {
  mkdirSync(directory, { recursive: true });
  run('git', ['init', '--quiet', directory]);
  run('git', ['-C', directory, 'remote', 'add', 'origin',
    `https://github.com/${repository}.git`]);
  run('git', ['-C', directory, 'fetch', '--quiet', '--depth=1', 'origin', commit]);
  run('git', ['-C', directory, 'checkout', '--quiet', '--detach', 'FETCH_HEAD']);
  const actual = execFileSync('git', ['-C', directory, 'rev-parse', 'HEAD'],
    { encoding: 'utf8' }).trim();
  if (actual !== commit) throw new Error(`${repository} checkout mismatch: ${actual}`);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function summarizeRouteDocument(document) {
  const chains = [...document.routes, ...document.serverActions]
    .flatMap((entry) => entry.accessChains || []);
  const applicable = document.coverage.filter((item) => item.status !== 'not_applicable');
  const routeCoverage = applicable.some((item) => item.status === 'partial') ? 'partial' : 'completed';
  const coverageReasons = applicable.flatMap((item) => item.reasons.map((reason) => ({
    framework: item.framework, code: reason.code, count: reason.count,
  })));
  return {
    routes: document.routes.length,
    serverActions: document.serverActions.length,
    routeCoverage,
    coverageReasons,
    partialChains: chains.filter((chain) => chain.status === 'partial').length,
    completedChains: chains.filter((chain) => chain.status === 'completed').length,
  };
}

const toolDirectory = `${outputRoot}/tool`;
checkout('parousia8888/web-app-security-skill', V070_TOOL_COMMIT, toolDirectory);
run('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], { cwd: toolDirectory });

const projects = [];
for (const expected of V070_PROJECT_SPECS) {
  const checkoutDirectory = `${outputRoot}/${expected.id}`;
  const reportDirectory = `${outputRoot}/reports/${expected.id}`;
  checkout(expected.repository, expected.commit, checkoutDirectory);
  const audit = spawnSync(process.execPath, [
    `${toolDirectory}/scripts/webapp-security.mjs`, 'audit', expected.target,
    '--out', reportDirectory, '--fail-on', 'never',
  ], {
    cwd: checkoutDirectory,
    env: { ...process.env, SOURCE_DATE_EPOCH: '0' },
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  if (![0, 3].includes(audit.status)) {
    process.stderr.write(audit.stderr || '');
    throw new Error(`${expected.id} audit exited ${audit.status}`);
  }
  process.stdout.write(audit.stdout || '');
  process.stderr.write(audit.stderr || '');
  const reportBytes = readFileSync(`${reportDirectory}/report.json`);
  const routeBytes = readFileSync(`${reportDirectory}/route-security.json`);
  const routeDocument = JSON.parse(routeBytes);
  const actual = {
    id: expected.id,
    repository: expected.repository,
    commit: expected.commit,
    target: expected.target,
    toolCommit: V070_TOOL_COMMIT,
    command: expected.target === '.'
      ? 'SOURCE_DATE_EPOCH=0 node {tool}/scripts/webapp-security.mjs audit . --out {output} --fail-on never'
      : `SOURCE_DATE_EPOCH=0 node {tool}/scripts/webapp-security.mjs audit ${expected.target} --out {output} --fail-on never`,
    reproducedAt: new Date().toISOString(),
    reportSha256: sha256(reportBytes),
    routeReportSha256: sha256(routeBytes),
    routeSemanticSha256: routeSemanticDigest(routeDocument),
    ...summarizeRouteDocument(routeDocument),
  };
  actual.comparison = {
    reportSha256: actual.reportSha256 === expected.reportSha256,
    routeReportSha256: actual.routeReportSha256 === expected.routeReportSha256,
    routeSemanticSha256: actual.routeSemanticSha256 === expected.routeSemanticSha256,
    countsAndCoverage: ['routes', 'serverActions', 'routeCoverage', 'coverageReasons',
      'partialChains', 'completedChains']
      .every((key) => JSON.stringify(actual[key]) === JSON.stringify(expected[key])),
  };
  projects.push(actual);
}

const result = {
  schemaVersion: 1,
  boundary: 'Explicit network reproduction at fixed commits. Target dependencies and applications were not executed. Raw report hashes may differ because subject identity is ephemeral; compare the route semantic hash and recorded counts.',
  projects,
};
const resultPath = `${outputRoot}/v0.7.0-access-review-refresh.json`;
writeFileSync(resultPath, `${JSON.stringify(result, null, 2)}\n`);
console.log(resultPath);
