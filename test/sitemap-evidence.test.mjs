#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SCRIPT = join(ROOT, 'scripts', 'crawl-surface-audit.mjs');
const FIXTURES = join(ROOT, 'test', 'fixtures', 'sitemaps');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-sitemap-'));
const requests = [];
const externalRequests = [];
let selected = 'escaped.xml';

const external = createServer((req, res) => {
  externalRequests.push(req.url);
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end('http://example.invalid/invented');
});
const server = createServer((req, res) => {
  requests.push(req.url);
  const origin = `http://${req.headers.host}`;
  const externalOrigin = `http://127.0.0.1:${external.address().port}`;
  if (req.url === '/robots.txt') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(`User-agent: *\nAllow: /\nSitemap: ${origin}/sitemap.xml\n`);
    return;
  }
  if (req.url === '/sitemap.xml') {
    const xml = readFileSync(join(FIXTURES, selected), 'utf8')
      .replaceAll('{{ORIGIN}}', origin)
      .replaceAll('{{EXTERNAL}}', externalOrigin);
    res.writeHead(200, { 'content-type': 'application/xml' });
    res.end(xml);
    return;
  }
  if (req.url === '/llms.txt') {
    res.writeHead(404);
    res.end();
    return;
  }
  res.writeHead(200, { 'content-type': 'text/html' });
  res.end(`<html><head><link rel="canonical" href="${origin}${req.url}"></head><body>${'fixture '.repeat(400)}</body></html>`);
});

function run(origin, name) {
  selected = name;
  requests.length = 0;
  const out = join(temp, name.replace('.xml', ''));
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [
      SCRIPT, '--site', origin, '--out', out, '--report-name', 'report', '--max-urls', '10',
      '--matrix', '0', '--delay', '0', '--fail-on', 'never', '--quiet', '--allow-private-network',
    ], { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (status) => resolve({ status, stdout, stderr, out }));
  });
}

try {
  external.listen(0, '127.0.0.1');
  server.listen(0, '127.0.0.1');
  await Promise.all([once(external, 'listening'), once(server, 'listening')]);
  const origin = `http://127.0.0.1:${server.address().port}`;

  for (const [fixture, expectedRequest] of [
    ['escaped.xml', '/escaped?one=1&two=2'],
    ['numeric.xml', '/numeric?one=1&two=2'],
    ['cdata.xml', '/cdata?one=1&two=2'],
  ]) {
    const result = await run(origin, fixture);
    assert.equal(result.status, 0, `${fixture}: ${result.stderr}\n${result.stdout}`);
    assert.ok(requests.includes(expectedRequest), `${fixture}: ${requests.join(', ')}`);
    const report = JSON.parse(readFileSync(join(result.out, 'report.json'), 'utf8'));
    const observations = JSON.parse(readFileSync(join(result.out, 'report.observations.json'), 'utf8'));
    assert.equal(report.schemaVersion, 2);
    assert.equal(observations.sitemapUrlCount, 1);
    assert.equal(observations.sitemaps[0].parseState, 'confirmed');
  }

  for (const [fixture, expected] of [
    ['malformed.xml', /malformed|mismatched|unclosed/i],
    ['external-declaration.xml', /DOCTYPE|external|declaration/i],
    ['external-url.xml', /outside the audited origin/i],
    ['external-index.xml', /outside the audited origin/i],
  ]) {
    const result = await run(origin, fixture);
    assert.equal(result.status, 3, `${fixture}: ${result.stderr}\n${result.stdout}`);
    assert.ok(existsSync(join(result.out, 'report.json')));
    const report = JSON.parse(readFileSync(join(result.out, 'report.json'), 'utf8'));
    const observations = JSON.parse(readFileSync(join(result.out, 'report.observations.json'), 'utf8'));
    assert.equal(observations.sitemaps[0].parseState, 'unknown');
    const finding = report.findings.find((item) => item.rule.id === 'sitemap-parse-unknown');
    assert.equal(finding?.state, 'unknown');
    assert.match(finding?.summary || '', expected);
    assert.equal(observations.sampledUrls.length, 0);
  }

  assert.deepEqual(externalRequests, [], 'external entity target must never be requested');
  console.log('✓ sitemap evidence: entities and CDATA normalize; malformed/external declarations fail unknown without off-fixture requests');
} finally {
  server.close();
  external.close();
  rmSync(temp, { recursive: true, force: true });
}
