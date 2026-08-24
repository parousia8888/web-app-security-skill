#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { failsThresholdV2, hasIncompleteEvidenceV2, validateRuntimeReportV2 } from '../scripts/lib/evidence-v2.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SCRIPT = join(ROOT, 'scripts', 'crawl-surface-audit.mjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-crawl-v2-'));

function run(site, name, extra = []) {
  const out = join(temp, name);
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [
      SCRIPT, '--site', site, '--out', out, '--report-name', 'report',
      '--max-urls', '1', '--matrix', '1', '--delay', '0', '--timeout', '100', '--quiet',
      '--allow-private-network',
      ...extra,
    ], { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (status) => resolve({
      status,
      stdout,
      stderr,
      report: JSON.parse(readFileSync(join(out, 'report.json'), 'utf8')),
      observations: JSON.parse(readFileSync(join(out, 'report.observations.json'), 'utf8')),
    }));
  });
}

const server = createServer((req, res) => {
  const origin = `http://${req.headers.host}`;
  if (req.url === '/robots.txt') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(`User-agent: *\nAllow: /\nSitemap: ${origin}/sitemap.xml\n`);
  } else if (req.url === '/sitemap.xml') {
    res.writeHead(200, { 'content-type': 'application/xml' });
    res.end(`<?xml version="1.0"?><urlset><url><loc>${origin}/slow</loc></url></urlset>`);
  } else if (req.url === '/slow') {
    setTimeout(() => {
      if (!res.destroyed) {
        res.writeHead(200, { 'content-type': 'text/html' });
        res.end('<html><head><link rel="canonical" href="/slow"></head><body>slow</body></html>');
      }
    }, 500);
  } else if (req.url === '/.env') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('FIXTURE_API_KEY=not-a-real-secret');
  } else if (req.url === '/llms.txt') {
    res.writeHead(404);
    res.end();
  } else {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<html><head><link rel="canonical" href="${origin}/"></head><body>${'fixture '.repeat(500)}</body></html>`);
  }
});

try {
  const unreachable = await run('http://127.0.0.1:9', 'unreachable', ['--fail-on', 'high']);
  assert.equal(unreachable.status, 3, unreachable.stderr);
  assert.deepEqual(validateRuntimeReportV2(unreachable.report), []);
  assert.equal(unreachable.report.findings.some((finding) => finding.state === 'confirmed'), false);
  for (const forbidden of ['robots-missing', 'sitemap-empty', 'baseline-fetch-failed']) {
    assert.equal(unreachable.report.findings.some((finding) => finding.rule.id === forbidden), false, forbidden);
  }
  assert.equal(failsThresholdV2(unreachable.report), false);
  assert.equal(hasIncompleteEvidenceV2(unreachable.report), true);

  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;

  const partial = await run(origin, 'partial', ['--fail-on', 'never']);
  assert.equal(partial.status, 3, partial.stderr);
  assert.ok(partial.report.findings.some((finding) => finding.rule.id === 'sitemap-url-fetch-unknown' && finding.state === 'unknown'));
  assert.equal(partial.report.coverage.find((entry) => entry.ruleId === 'sitemap-url-fetch-unknown').status, 'unavailable');

  const mixed = await run(origin, 'mixed', [
    '--active-probe', '--acknowledge-authorization', '--fail-on', 'high',
  ]);
  assert.equal(mixed.status, 1, mixed.stderr);
  assert.equal(failsThresholdV2(mixed.report), true);
  assert.equal(hasIncompleteEvidenceV2(mixed.report), true);
  assert.ok(mixed.report.findings.some((finding) =>
    finding.domain === 'security_exposure' && finding.severity === 'high' && finding.state === 'confirmed'));
  assert.ok(mixed.report.findings.some((finding) => finding.state === 'unknown'));

  console.log('crawl v2 evidence ok: unreachable, partial timeout and confirmed-before-unknown precedence');
} finally {
  server.close();
  rmSync(temp, { recursive: true, force: true });
}
