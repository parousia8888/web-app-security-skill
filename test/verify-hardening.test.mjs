#!/usr/bin/env node
import http from 'node:http';
import https from 'node:https';
import { readFileSync, statSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const SCRIPT = join(ROOT, 'scripts', 'verify-hardening.sh');
const temp = await mkdtemp(join(tmpdir(), 'hardening-fixture-'));

function command(program, args, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(program, args, { ...options, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

let failed = 0;
function check(name, condition, detail = '') {
  if (!condition) {
    failed++;
    console.error(`x ${name}${detail ? `\n  ${detail}` : ''}`);
  }
}

const key = join(temp, 'key.pem');
const cert = join(temp, 'cert.pem');
const openssl = await command('openssl', [
  'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
  '-keyout', key, '-out', cert, '-days', '1',
  '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
]);
check('openssl fixture certificate generated', openssl.code === 0, openssl.stderr);

const headers = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
};

const secure = https.createServer({
  key: await readFile(key), cert: await readFile(cert), minVersion: 'TLSv1.2',
}, (req, res) => {
  res.writeHead(req.url === '/.env' ? 429 : 200, headers);
  res.end('ok');
});
secure.listen(0, '127.0.0.1');
await once(secure, 'listening');
const secureSite = `https://localhost:${secure.address().port}`;

const redirect = http.createServer((req, res) => {
  res.writeHead(308, { location: `${secureSite}${req.url}` });
  res.end();
});
redirect.listen(0, '127.0.0.1');
await once(redirect, 'listening');
const httpSite = `http://localhost:${redirect.address().port}`;

const reportDir = join(temp, 'edge-report');
const consoleSecret = 'M5_CONSOLE_SECRET_SENTINEL';
const fixtureTrustEnv = { ...process.env };
delete fixtureTrustEnv.CURL_CA_BUNDLE;
delete fixtureTrustEnv.SSL_CERT_FILE;
const passive = await command('/bin/bash', [
  SCRIPT, '--site', secureSite, '--http-site', httpSite, '--n', '1',
  '--cacert', cert,
  '--content-path', `/?token=${consoleSecret}`,
  '--out', reportDir, '--report-name', 'edge-fixture',
], {
  env: fixtureTrustEnv,
});
check('passive hardening verification succeeds', passive.code === 0, passive.stdout + passive.stderr);
check('passive mode skips burst', /skipped; pass --active-rate-limit/.test(passive.stdout));
check('TLS 1.2 is tested', /TLS 1\.2 handshake succeeds/.test(passive.stdout));
check('TLS 1.0 is rejected', /TLS 1\.0 handshake rejected/.test(passive.stdout));
check('certificate chain is validated', /certificate chain and hostname validate/.test(passive.stdout));
const report = JSON.parse(readFileSync(join(reportDir, 'edge-fixture.json'), 'utf8'));
const observations = JSON.parse(readFileSync(join(reportDir, 'edge-fixture.observations.json'), 'utf8'));
check('edge output uses report v2', report.schemaVersion === 2 && report.ruleset.adapters[0]?.id === 'builtin-edge');
check('edge conclusions keep raw observations separate', observations.schemaVersion === 1 && Array.isArray(observations.observations));
check('edge report directory is private', (statSync(reportDir).mode & 0o777) === 0o700);
check('edge console redacts URL query secrets', !`${passive.stdout}${passive.stderr}`.includes(consoleSecret));
for (const name of ['edge-fixture.json', 'edge-fixture.md', 'edge-fixture.html', 'edge-fixture.sarif', 'edge-fixture.junit.xml', 'edge-fixture.sha256', 'edge-fixture.observations.json']) {
  check(`${name} is private`, (statSync(join(reportDir, name)).mode & 0o777) === 0o600);
  check(`${name} redacts URL query secrets`, !readFileSync(join(reportDir, name), 'utf8').includes(consoleSecret));
}

const active = await command('/bin/bash', [
  SCRIPT, '--site', secureSite, '--http-site', httpSite, '--active-rate-limit', '--acknowledge-authorization', '--n', '1',
  '--cacert', cert,
], { env: fixtureTrustEnv });
check('active rate-limit verification succeeds', active.code === 0, active.stdout + active.stderr);
check('probe throttling is observed', /probe class is being throttled/.test(active.stdout));
check('content availability is observed', /content class remained available/.test(active.stdout));

for (const value of ['0', 'nope', '101']) {
  const invalid = await command('/bin/bash', [SCRIPT, '--site', 'http://127.0.0.1:1', '--n', value]);
  check(`--n ${value} exits 2`, invalid.code === 2, invalid.stdout + invalid.stderr);
}

const noAck = await command('/bin/bash', [SCRIPT, '--site', secureSite, '--active-rate-limit', '--n', '1']);
check('active rate-limit requires authorization acknowledgement', noAck.code === 2 && /requires --acknowledge-authorization/.test(noAck.stderr));

const badCa = await command('/bin/bash', [SCRIPT, '--site', secureSite, '--cacert', join(temp, 'missing-ca.pem')]);
check('unreadable explicit CA is rejected', badCa.code === 2 && /--cacert must be a readable file/.test(badCa.stderr));

const unreachable = await command('/bin/bash', [SCRIPT, '--site', 'http://127.0.0.1:1', '--active-rate-limit', '--acknowledge-authorization', '--n', '1']);
check('network failure exits 3', unreachable.code === 3, unreachable.stdout + unreachable.stderr);
check('network failure is not called crawler-safe', !/content class remained available/.test(unreachable.stdout));

const missingCurl = await command('/bin/bash', [SCRIPT, '--site', secureSite], {
  env: { ...process.env, WEBAPP_SECURITY_CURL_BIN: 'webapp-security-missing-curl' },
});
check('missing curl exits 3', missingCurl.code === 3, missingCurl.stdout + missingCurl.stderr);
check('missing curl is explicit unknown evidence', /edge-curl-capability.*unavailable/.test(missingCurl.stdout));

secure.close();
redirect.close();
await rm(temp, { recursive: true, force: true });

if (failed) process.exit(1);
console.log('ok verify-hardening: v2 bundle, passive/active, TLS, redirect, certificate, network failure, and CLI bounds');
