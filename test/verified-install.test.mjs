#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { createServer } from 'node:http';
import {
  cpSync, existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const INSTALL = join(ROOT, 'scripts', 'install-verified.mjs');
const BUILD = join(ROOT, 'scripts', 'build-release-artifacts.mjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-verified-test-'));
const releaseRef = process.env.RELEASE_TEST_REF || 'HEAD';
const versionResult = spawnSync('git', ['show', `${releaseRef}:VERSION`], {
  cwd: ROOT, encoding: 'utf8',
});
assert.equal(versionResult.status, 0, versionResult.stderr);
const version = versionResult.stdout.trim();
const prefix = `web-app-security-skill-${version}`;
const names = {
  archive: `${prefix}.tar.gz`,
  manifest: `${prefix}.release.json`,
  sbom: `${prefix}.spdx.json`,
  sums: 'SHA256SUMS',
};

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function runSync(program, commandArgs, options = {}) {
  const result = spawnSync(program, commandArgs, { cwd: ROOT, encoding: 'utf8', ...options });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout.trim();
}

function run(program, commandArgs, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(program, commandArgs, {
      cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], ...options,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', (error) => resolve({ status: 127, stdout, stderr: `${stderr}${error.message}` }));
    child.on('close', (status) => resolve({ status, stdout, stderr }));
  });
}

function octal(buffer, offset, length, value) {
  const text = value.toString(8).padStart(length - 1, '0');
  buffer.write(text, offset, length - 1, 'ascii');
  buffer[offset + length - 1] = 0;
}

function unsafeTar() {
  const content = Buffer.from('escaped\n');
  const header = Buffer.alloc(512);
  header.write(`${prefix}/../../escape`, 0, 100, 'ascii');
  octal(header, 100, 8, 0o644);
  octal(header, 108, 8, 0);
  octal(header, 116, 8, 0);
  octal(header, 124, 12, content.length);
  octal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = '0'.charCodeAt(0);
  header.write('ustar\0', 257, 6, 'binary');
  header.write('00', 263, 2, 'ascii');
  const sum = header.reduce((total, byte) => total + byte, 0);
  header.write(sum.toString(8).padStart(6, '0'), 148, 6, 'ascii');
  header[154] = 0;
  header[155] = 0x20;
  const padding = Buffer.alloc((512 - (content.length % 512)) % 512);
  return gzipSync(Buffer.concat([header, content, padding, Buffer.alloc(1024)]), { level: 9, mtime: 0 });
}

function assetsFrom(directory) {
  return Object.fromEntries(Object.values(names).map((name) => [name, readFileSync(join(directory, name))]));
}

function trustFor(assets, sourceCommit) {
  return {
    schemaVersion: 1,
    repository: 'parousia8888/web-app-security-skill',
    releases: {
      [version]: {
        tag: `v${version}`,
        sourceCommit,
        assets: Object.fromEntries(Object.entries(assets).map(([name, data]) => [name, sha256(data)])),
      },
    },
  };
}

function rewriteSums(assets) {
  const listed = [names.archive, names.manifest, names.sbom].sort();
  assets[names.sums] = Buffer.from(`${listed.map((name) => `${sha256(assets[name])}  ${name}`).join('\n')}\n`);
}

function variant(base, mutate) {
  const assets = Object.fromEntries(Object.entries(base).map(([name, data]) => [name, Buffer.from(data)]));
  mutate(assets);
  return assets;
}

const requests = [];
const cases = new Map();
const redirectServer = createServer((request, response) => {
  response.writeHead(200, { 'content-type': 'application/octet-stream' });
  response.end('unexpected cross-origin data');
});
const server = createServer((request, response) => {
  requests.push(request.url);
  const [, caseName, ...rest] = request.url.split('/');
  const name = rest.join('/');
  if (caseName === 'redirect') {
    const destination = `http://127.0.0.1:${redirectServer.address().port}/${name}`;
    response.writeHead(302, { location: destination });
    response.end();
    return;
  }
  const data = cases.get(caseName)?.[name];
  if (!data) {
    response.writeHead(404);
    response.end('not found');
    return;
  }
  response.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': data.length });
  response.end(data);
});

function installerArgs(origin, caseName, trustPath, extra = []) {
  return [INSTALL, '--version', version, '--base-url', `${origin}/${caseName}`,
    '--trust-file', trustPath, '--allow-test-http', '--attestation', 'skip', ...extra];
}

try {
  const dist = join(temp, 'dist');
  const sourceCommit = runSync('git', ['rev-parse', `${releaseRef}^{commit}`]);
  runSync(process.execPath, [BUILD, '--ref', releaseRef, '--out', dist]);
  const base = assetsFrom(dist);
  cases.set('valid', base);

  const tampered = variant(base, (assets) => {
    assets[names.archive] = Buffer.concat([assets[names.archive], Buffer.from('tampered')]);
  });
  cases.set('tampered', tampered);

  const mismatch = variant(base, (assets) => {
    const manifest = JSON.parse(assets[names.manifest].toString('utf8'));
    manifest.tag = 'v9.9.9';
    assets[names.manifest] = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
    rewriteSums(assets);
  });
  cases.set('mismatch', mismatch);

  const duplicate = variant(base, (assets) => {
    assets[names.sums] = Buffer.concat([
      assets[names.sums],
      Buffer.from(`${sha256(assets[names.archive])}  ${names.archive}\n`),
    ]);
  });
  cases.set('duplicate', duplicate);

  const traversal = variant(base, (assets) => {
    assets[names.archive] = unsafeTar();
    const manifest = JSON.parse(assets[names.manifest].toString('utf8'));
    manifest.assets[names.archive].sha256 = sha256(assets[names.archive]);
    assets[names.manifest] = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
    rewriteSums(assets);
  });
  cases.set('traversal', traversal);

  server.listen(0, '127.0.0.1');
  redirectServer.listen(0, '127.0.0.1');
  await Promise.all([once(server, 'listening'), once(redirectServer, 'listening')]);
  const origin = `http://127.0.0.1:${server.address().port}`;

  const baseTrust = join(temp, 'base-trust.json');
  writeFileSync(baseTrust, `${JSON.stringify(trustFor(base, sourceCommit), null, 2)}\n`);
  const home = join(temp, 'home');
  let result = await run(process.execPath, installerArgs(origin, 'valid', baseTrust), {
    env: { ...process.env, HOME: home },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /verified:\s+Web App Security Skill/);
  const launcher = join(home, '.local', 'bin', 'webapp-security');
  assert.ok(existsSync(launcher));
  result = await run(launcher, ['version'], { env: { ...process.env, HOME: home } });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), `Web App Security Skill ${version}`);
  const runOut = join(temp, 'first-run');
  const firstProject = join(temp, 'first-project');
  cpSync(join(ROOT, 'test', 'fixtures', 'audit-app'), firstProject, { recursive: true });
  result = await run(launcher, ['start', firstProject, '--out', runOut,
    '--run-id', 'verified'], { env: { ...process.env, HOME: home, SOURCE_DATE_EPOCH: '0' } });
  assert.equal(result.status, 0, result.stderr);
  const scope = join(runOut, 'verified');
  result = await run(launcher, ['audit', scope, '--name', 'before', '--fail-on', 'never'], {
    env: { ...process.env, HOME: home, SOURCE_DATE_EPOCH: '0' },
  });
  assert.equal(result.status, 0, result.stderr);
  result = await run(launcher, ['retest', scope, '--out', join(temp, 'retest'), '--name', 'after',
    '--baseline', join(scope, 'before.json'), '--fail-on', 'never'], {
    env: { ...process.env, HOME: home, SOURCE_DATE_EPOCH: '0' },
  });
  assert.equal(result.status, 0, result.stderr);
  result = await run(launcher, ['uninstall'], { env: { ...process.env, HOME: home } });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(existsSync(launcher), false);

  const offlineHome = join(temp, 'offline-home');
  const beforeOffline = requests.length;
  result = await run(process.execPath, [INSTALL, '--version', version, '--from-dir', dist,
    '--trust-file', baseTrust, '--attestation', 'skip', '--target', 'cli'], {
    env: { ...process.env, HOME: offlineHome },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(requests.length, beforeOffline, 'offline install must not make an HTTP request');
  assert.ok(existsSync(join(offlineHome, '.local', 'bin', 'webapp-security')));

  const rejectedHome = join(temp, 'rejected-home');
  result = await run(process.execPath, installerArgs(origin, 'tampered', baseTrust, ['--target', 'cli']), {
    env: { ...process.env, HOME: rejectedHome },
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /trusted SHA-256/);
  assert.equal(existsSync(join(rejectedHome, '.local')), false);

  for (const [caseName, expected] of [
    ['mismatch', /manifest identity/],
    ['duplicate', /duplicate checksum entry/],
    ['traversal', /archive path traversal|tar:/],
  ]) {
    const trustPath = join(temp, `${caseName}-trust.json`);
    writeFileSync(trustPath, `${JSON.stringify(trustFor(cases.get(caseName), sourceCommit), null, 2)}\n`);
    result = await run(process.execPath, installerArgs(origin, caseName, trustPath, ['--target', 'cli']), {
      env: { ...process.env, HOME: join(temp, `${caseName}-home`) },
    });
    assert.equal(result.status, 2, `${caseName} unexpectedly passed`);
    assert.match(result.stderr, expected);
  }

  result = await run(process.execPath, installerArgs(origin, 'redirect', baseTrust, ['--target', 'cli']), {
    env: { ...process.env, HOME: join(temp, 'redirect-home') },
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /cross-origin redirect/);

  const partialHome = join(temp, 'partial-home');
  const unknown = join(partialHome, '.codex', 'skills', 'web-app-security');
  mkdirSync(unknown, { recursive: true });
  writeFileSync(join(unknown, 'sentinel'), 'keep');
  result = await run(process.execPath, installerArgs(origin, 'valid', baseTrust, ['--force']), {
    env: { ...process.env, HOME: partialHome },
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /verified payload install failed/);
  assert.equal(readFileSync(join(unknown, 'sentinel'), 'utf8'), 'keep');
  assert.equal(existsSync(join(partialHome, '.claude', 'skills', 'web-app-security')), false);
  assert.equal(existsSync(join(partialHome, '.local', 'share', 'web-app-security')), false);

  const printed = JSON.parse(runSync(process.execPath, [INSTALL, '--print-trust']));
  assert.equal(printed.repository, 'parousia8888/web-app-security-skill');
  assert.ok(printed.releases['0.3.0']);
  assert.ok(printed.releases['0.4.0']);
  assert.ok(printed.releases['0.5.0']);
  assert.ok(printed.releases['0.5.1']);
  assert.ok(printed.releases['0.5.2']);
  assert.ok(printed.releases['0.5.3']);
  assert.ok(printed.releases['0.5.4']);
  console.log('verified install ok: pinned assets, clean lifecycle, offline path, tamper and redirect rejection');
} finally {
  server.close();
  redirectServer.close();
  rmSync(temp, { recursive: true, force: true });
}
