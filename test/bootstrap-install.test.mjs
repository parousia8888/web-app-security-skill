#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const BOOTSTRAP = join(ROOT, 'scripts', 'bootstrap-install.sh');
const installer = readFileSync(join(ROOT, 'scripts', 'install-verified.mjs'));
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-bootstrap-test-'));
const executed = join(temp, 'unverified-code-executed');
const malicious = Buffer.from(`import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(executed)}, 'bad');\n`);
const requests = [];

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function run(args, env) {
  return new Promise((resolve) => {
    const child = spawn('/bin/sh', [BOOTSTRAP, ...args], {
      cwd: ROOT,
      env: { ...process.env, TMPDIR: temp, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

const server = createServer((request, response) => {
  requests.push(request.url);
  const body = request.url === '/valid' ? installer : malicious;
  response.writeHead(200, { 'content-type': 'application/javascript', 'content-length': body.length });
  response.end(body);
});

try {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;
  const common = {
    WEB_APP_SECURITY_ALLOW_TEST_HTTP: '1',
    WEB_APP_SECURITY_INSTALLER_SHA256: sha256(installer),
  };

  let result = await run(['--print-trust'], {
    ...common,
    WEB_APP_SECURITY_INSTALLER_URL: `${origin}/valid`,
  });
  assert.equal(result.status, 0, result.stderr);
  const trust = JSON.parse(result.stdout);
  assert.equal(trust.repository, 'parousia8888/web-app-security-skill');
  assert.ok(trust.releases['0.3.0']);
  assert.ok(trust.releases['0.4.0']);
  assert.ok(trust.releases['0.5.0']);
  assert.ok(trust.releases['0.5.1']);
  assert.ok(trust.releases['0.5.2']);
  assert.ok(trust.releases['0.5.3']);
  assert.ok(trust.releases['0.5.4']);
  assert.ok(trust.releases['0.6.0']);
  assert.ok(trust.releases['0.7.0']);
  assert.ok(trust.releases['0.7.1']);
  assert.ok(trust.releases['0.7.2']);
  assert.ok(trust.releases['0.7.3']);
  assert.ok(trust.releases['0.8.0']);

  result = await run([], {
    ...common,
    WEB_APP_SECURITY_INSTALLER_URL: `${origin}/malicious`,
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /pinned verifier SHA-256 mismatch/);
  assert.equal(existsSync(executed), false, 'digest-mismatched verifier must never execute');

  const before = requests.length;
  result = await run([], {
    WEB_APP_SECURITY_INSTALLER_URL: `${origin}/valid`,
    WEB_APP_SECURITY_INSTALLER_SHA256: sha256(installer),
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /loopback HTTP requires/);
  assert.equal(requests.length, before, 'URL policy must reject before download');

  result = await run([], {
    WEB_APP_SECURITY_INSTALLER_URL: `${origin}/valid`,
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /overrides must be provided together/);

  const leftovers = readFileSync(BOOTSTRAP, 'utf8').match(/web-app-security-bootstrap\.XXXXXX/g);
  assert.equal(leftovers?.length, 1, 'bootstrap should use one private temporary directory');
  console.log('bootstrap install ok: pinned verifier executes, mismatched bytes and insecure URL reject first');
} finally {
  server.close();
  rmSync(temp, { recursive: true, force: true });
}
