#!/usr/bin/env node
import { createHash } from 'node:crypto';
import {
  existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, posix, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const REPOSITORY = 'parousia8888/web-app-security-skill';
const PRODUCT = 'Web App Security Skill';
const MAX_REDIRECTS = 5;
const MAX_ASSET_BYTES = 64 * 1024 * 1024;
const MAX_METADATA_BYTES = 1024 * 1024;
const TRUST = Object.freeze({
  schemaVersion: 1,
  repository: REPOSITORY,
  releases: {
    '0.3.0': {
      tag: 'v0.3.0',
      sourceCommit: 'd7df9fa6efd466c3eb13768c3b9ad259d2636e04',
      assets: {
        SHA256SUMS: '472d7552ad4e5bc54dc0982798a0b59cc5114efb8292e105502f533c64e44d46',
        'web-app-security-skill-0.3.0.release.json': '045b3ab3130b34c6eb4ee6111472dc5e936f7f84fa853c02763daafdf3599eb4',
        'web-app-security-skill-0.3.0.spdx.json': '6b2abe6e8974255f24e150db3733f3dc2366a641fdb315c9179a7a2aa51c3f19',
        'web-app-security-skill-0.3.0.tar.gz': '1964253e9057b802fd4ef61eeda9059c230daa8cf066b2b556fa0cbdf4d7bda2',
      },
    },
    '0.4.0': {
      tag: 'v0.4.0',
      sourceCommit: 'ace0e8a5ed983f553000270f709d70b5de484e28',
      assets: {
        SHA256SUMS: '46ac1d460c4da35b834a195fea2b8488e5d83d184400c853ffe6e3d7f76243bf',
        'web-app-security-skill-0.4.0.release.json': '2a9082833e9efd501d4928278ef0fb2efd728f85abe8499fbab64ce21ac093db',
        'web-app-security-skill-0.4.0.spdx.json': '55295fe4ed37bc4daf403e11dc4a2191dd3623dc648149eae7dd671eb0e861bb',
        'web-app-security-skill-0.4.0.tar.gz': '0d82c840d1d80d163cf29fc244429e555047c2a14c7c262f1433bd01d83aac48',
      },
    },
    '0.5.0': {
      tag: 'v0.5.0',
      sourceCommit: '778a7ba73588cdab1d9df281ab362f4fe0925189',
      assets: {
        SHA256SUMS: '58b9fdffac7ea9bbced3fef4f0075a7d3d7d08894ace541a08b5c7cc8c9c1605',
        'web-app-security-skill-0.5.0.release.json': '412dae8fd0547872ac1e1859c04afbac7358be0f6f61e380f2771673c899da3f',
        'web-app-security-skill-0.5.0.spdx.json': 'babd853267495ce00d1c72a80ca0eb955280f36f5fe777c8b2ac489ec3b34ad3',
        'web-app-security-skill-0.5.0.tar.gz': '5e56875fbec78e8546c006eca77ce4ea081b3bb658480362ee994905fca049bb',
      },
    },
    '0.5.1': {
      tag: 'v0.5.1',
      sourceCommit: 'a9b9575e7a31b118930d49eea05e043a513a5aa3',
      assets: {
        SHA256SUMS: '69347cc2e7bf3f062f43a32b1f43393fb2f505781b89095a51e71ec068b820b4',
        'web-app-security-skill-0.5.1.release.json': 'becf15ed70ff22f172ba5cb120cf707c340461626e33c91a3e67f4fed291fed0',
        'web-app-security-skill-0.5.1.spdx.json': '7383dc15a06539cc82831b0b4b3b53676ed8a26ebd1373a8688eda0924e2b182',
        'web-app-security-skill-0.5.1.tar.gz': 'bda8a612cb32ec019e0b001a0e14de7d70dfb96f34e9f0fc98ea61b4d51c884b',
      },
    },
    '0.5.2': {
      tag: 'v0.5.2',
      sourceCommit: '010ef34c2e87b12b7f1e2502c0260074d131dd01',
      assets: {
        SHA256SUMS: 'bbb57225211644c1956f5a4020a35cd9c5f002d358b846b84d23c5ef4e3a431a',
        'web-app-security-skill-0.5.2.release.json': 'b2911a22a3891a4ac3694013c7e562709902fbf928d2d4910dfc0de9905e279c',
        'web-app-security-skill-0.5.2.spdx.json': '5b9a24198c84f0f53ddbd488aec1545e00a41a7fa3a49aa13ced859d9b0d331f',
        'web-app-security-skill-0.5.2.tar.gz': 'f2fbf560d378a571daba8faa8b826acc801a1c013afcc74b9ba9a8b83a395aa4',
      },
    },
    '0.5.3': {
      tag: 'v0.5.3',
      sourceCommit: '621e0bc2ad044f9390fa9d567bf4b9fca138a959',
      assets: {
        SHA256SUMS: '80a4ab13d6ebf7e5e360f79b3c3f6ef420a4dfb1c5b5f32fe9bfc1714289728b',
        'web-app-security-skill-0.5.3.release.json': 'e53a2d975011ef18186c77f375fc35642163ec623f5bad29b5ece0d73d73ce7f',
        'web-app-security-skill-0.5.3.spdx.json': '1d7a6e9c3f91ebc101230b6111cf54dd7b8641b80c7aa34878183a231ba95e88',
        'web-app-security-skill-0.5.3.tar.gz': '3a7f835bac662e0d99145edbb9f802c32759b5db2d59bf0d6277026302641282',
      },
    },
    '0.5.4': {
      tag: 'v0.5.4',
      sourceCommit: 'd9ee538089ac813dcd454d10b45f14b958c1ec19',
      assets: {
        SHA256SUMS: 'cbd7d771f81cee065989dc386fef239fc65d2d0966b1ca23fb5c8b9f94bdce12',
        'web-app-security-skill-0.5.4.release.json': 'f50d8b974666694ccaebdb583127cc62471536943b028f7057919cf47b4529c1',
        'web-app-security-skill-0.5.4.spdx.json': 'cfa209b59004ce29bbf808eadc37b1fbb8bfd8eb162e462c29661e8d18a592e1',
        'web-app-security-skill-0.5.4.tar.gz': '00742dfe4d0118e8361380314c4fe01ed4e3924db1015d080b882bd3841431a5',
      },
    },
    '0.6.0': {
      tag: 'v0.6.0',
      sourceCommit: '7521e0699eefe26d23a7972fbee6fb37b46fdfe2',
      assets: {
        SHA256SUMS: '40daac6af415136e37e28aa15724bdfb8dd3fc3050691c3a66dbeba7b2e2093d',
        'web-app-security-skill-0.6.0.release.json': '0e89c158688e3211eb02fb9fa54c7d7f452300f30b5906c4fe44f7d46e4a2140',
        'web-app-security-skill-0.6.0.spdx.json': '092fa41f2af42a3da5cdb88769c0d101fb659e3eb080de61351630594ad57a9b',
        'web-app-security-skill-0.6.0.tar.gz': '65da7ce8f88f7ece030e671973235e1ae3c318c2b49cb8d1f53382714191a26c',
      },
    },
    '0.7.0': {
      tag: 'v0.7.0',
      sourceCommit: 'bfed608b5d1abe56b6b34b09f0c6ef59f17eab4a',
      assets: {
        SHA256SUMS: 'f40a58952a221f677c9bc76b923b0f4ebd3a3dfe34b16bfb8ced885cb46aaa47',
        'web-app-security-skill-0.7.0.release.json': 'f707c4cceafc4864917fd47de525c522117b53c9a5724eb6a4e80e57cbbe5e37',
        'web-app-security-skill-0.7.0.spdx.json': '3e0c80aee8a093a3d04fa950d6e78a604c81958a4b7f984ab78cbd97276f0bf4',
        'web-app-security-skill-0.7.0.tar.gz': 'c5fa68b48e3c4a00ccc9c55fbd7a375eb1adddf9e7e8b7398f5e14a93974aa78',
      },
    },
    '0.7.1': {
      tag: 'v0.7.1',
      sourceCommit: '2b746b168d767c9b2225a273474e561650b2b6f8',
      assets: {
        SHA256SUMS: '4fd672781c26a9f39c67a0c3c9576e83d25a6032ba01b1ad6dbd8f2a6f8bafde',
        'web-app-security-skill-0.7.1.release.json': '59ef38bbb6d00873f2c57211db36dd3c2a128c80295c024ff988d2fee67f40a0',
        'web-app-security-skill-0.7.1.spdx.json': 'a97313fbf775f08cddef608b15743d26ea1255e44b192a184a677d8cc0f38725',
        'web-app-security-skill-0.7.1.tar.gz': '8df18745da238a418539d153d68c4fc395cd86c2e9131abbbd2fb9bf0cdfe381',
      },
    },
  },
});

const args = process.argv.slice(2);

function usage(code, message) {
  if (message) console.error(`error: ${message}`);
  console.log(`node install-verified.mjs [options]

Downloads and verifies one explicit Web App Security Skill release before invoking its installer.

Options:
  --version <semver>             Trusted release to install (default: 0.7.1)
  --target <surface>             claude, codex, cli, both, or all (default: all)
  --mode <install|upgrade>       Lifecycle operation (default: install)
  --force                        Back up and replace recognized installs (install only)
  --from-dir <directory>         Verify already-downloaded assets without network access
  --base-url <url>               Release asset directory (advanced; HTTPS required)
  --trust-file <json>            Explicit local trust anchors (advanced)
  --attestation <auto|required|skip>
                                 GitHub attestation policy (default: auto)
  --allow-test-http              Allow loopback HTTP fixtures only
  --print-trust                  Print built-in trust anchors and exit
`);
  process.exit(code);
}

function take(name, fallback = null) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  if (!args[index + 1] || args[index + 1].startsWith('--')) usage(2, `${name} requires a value`);
  return args.splice(index, 2)[1];
}

function flag(name) {
  const index = args.indexOf(name);
  if (index === -1) return false;
  args.splice(index, 1);
  return true;
}

function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

function loadTrust(path) {
  const value = path ? JSON.parse(readFileSync(resolve(path), 'utf8')) : TRUST;
  if (value.schemaVersion !== 1 || value.repository !== REPOSITORY
      || !value.releases || typeof value.releases !== 'object') {
    throw new Error('trust data has an invalid product or schema');
  }
  return value;
}

function assertDigest(label, value) {
  if (!/^[a-f0-9]{64}$/.test(value || '')) throw new Error(`${label} is not a SHA-256 digest`);
}

function assertSafeUrl(value, allowTestHttp) {
  const url = new URL(value);
  if (url.username || url.password) throw new Error('asset URL must not contain credentials');
  if (url.protocol === 'https:') return url;
  const loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
  if (allowTestHttp && url.protocol === 'http:' && loopback) return url;
  throw new Error('asset URL must use HTTPS (loopback HTTP is test-only)');
}

function redirectAllowed(from, to, official, allowTestHttp) {
  assertSafeUrl(to.href, allowTestHttp);
  if (from.origin === to.origin) return true;
  if (!official) return false;
  return [
    'github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com',
    'github-releases.githubusercontent.com',
  ].includes(to.hostname);
}

async function download(urlValue, limit, { official, allowTestHttp }) {
  let url = assertSafeUrl(urlValue, allowTestHttp);
  for (let redirects = 0; redirects <= MAX_REDIRECTS; redirects += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    try {
      const response = await fetch(url, {
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'user-agent': 'web-app-security-skill-verified-installer' },
      });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get('location');
        if (!location) throw new Error(`redirect from ${url.origin} has no location`);
        const next = new URL(location, url);
        if (!redirectAllowed(url, next, official, allowTestHttp)) {
          throw new Error(`refusing cross-origin redirect from ${url.origin} to ${next.origin}`);
        }
        url = next;
        continue;
      }
      if (!response.ok) throw new Error(`download failed with HTTP ${response.status}: ${url.pathname}`);
      const declared = Number(response.headers.get('content-length'));
      if (Number.isFinite(declared) && declared > limit) throw new Error(`asset exceeds ${limit} bytes`);
      if (!response.body) throw new Error('download response has no body');
      const reader = response.body.getReader();
      const chunks = [];
      let length = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        length += value.byteLength;
        if (length > limit) {
          await reader.cancel();
          throw new Error(`asset exceeds ${limit} bytes`);
        }
        chunks.push(Buffer.from(value));
      }
      return Buffer.concat(chunks, length);
    } finally {
      clearTimeout(timeout);
    }
  }
  throw new Error(`more than ${MAX_REDIRECTS} redirects`);
}

function run(program, commandArgs, options = {}) {
  const result = spawnSync(program, commandArgs, {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(result.stderr?.trim() || result.stdout?.trim()
      || `${program} ${commandArgs.join(' ')} failed`);
  }
  return result.stdout;
}

function validateChecksums(text, expectedAssets, files) {
  const entries = new Map();
  for (const line of text.trim().split('\n')) {
    const match = /^([a-f0-9]{64})  ([^/\\]+)$/.exec(line);
    if (!match) throw new Error(`invalid checksum line: ${JSON.stringify(line)}`);
    if (entries.has(match[2])) throw new Error(`duplicate checksum entry: ${match[2]}`);
    entries.set(match[2], match[1]);
  }
  const listed = [...entries.keys()].sort();
  const required = expectedAssets.filter((name) => name !== 'SHA256SUMS').sort();
  if (JSON.stringify(listed) !== JSON.stringify(required)) {
    throw new Error('checksum asset set does not match the trusted release');
  }
  for (const [name, digest] of entries) {
    if (sha256(files.get(name)) !== digest) throw new Error(`${name} differs from SHA256SUMS`);
  }
}

function validateManifest(manifest, release, version, files) {
  if (manifest.schemaVersion !== 1 || manifest.product !== PRODUCT
      || manifest.repository !== REPOSITORY || manifest.version !== version
      || manifest.tag !== release.tag || manifest.sourceCommit !== release.sourceCommit) {
    throw new Error('release manifest identity, tag, version, or source commit mismatch');
  }
  const archiveName = `web-app-security-skill-${version}.tar.gz`;
  const sbomName = `web-app-security-skill-${version}.spdx.json`;
  const keys = Object.keys(manifest.assets || {}).sort();
  if (JSON.stringify(keys) !== JSON.stringify([archiveName, sbomName].sort())) {
    throw new Error('release manifest asset set mismatch');
  }
  for (const name of keys) {
    assertDigest(`manifest digest for ${name}`, manifest.assets[name]?.sha256);
    if (sha256(files.get(name)) !== manifest.assets[name].sha256) {
      throw new Error(`${name} differs from the release manifest`);
    }
  }
}

function validateSbom(sbom, version) {
  if (sbom.spdxVersion !== 'SPDX-2.3' || sbom.packages?.[0]?.name !== 'web-app-security-skill'
      || sbom.packages?.[0]?.versionInfo !== version) {
    throw new Error('SBOM identity or version mismatch');
  }
  const parser = sbom.packages.find((item) => item.name === '@babel/parser');
  if (!parser || parser.licenseDeclared !== 'MIT'
      || !sbom.relationships?.some((item) => item.relationshipType === 'CONTAINS'
        && item.relatedSpdxElement === parser.SPDXID)) {
    throw new Error('SBOM bundled parser component is missing or invalid');
  }
}

function inspectArchive(archive, version, work) {
  const listing = run('tar', ['-tzf', archive]).trim().split('\n').filter(Boolean);
  const root = `web-app-security-skill-${version}/`;
  if (!listing.length || !listing.every((entry) => entry.startsWith(root))) {
    throw new Error('archive has an unexpected or non-unique root');
  }
  if (new Set(listing).size !== listing.length) throw new Error('archive contains duplicate entries');
  for (const entry of listing) {
    if (posix.isAbsolute(entry) || entry.includes('\\')
        || entry.split('/').includes('..') || posix.normalize(entry) !== entry) {
      throw new Error(`archive path traversal or ambiguity: ${entry}`);
    }
  }
  const verbose = run('tar', ['-tvzf', archive]).trim().split('\n').filter(Boolean);
  if (verbose.some((line) => !['-', 'd'].includes(line[0]))) {
    throw new Error('archive links or special files are not allowed');
  }
  const required = [
    'VERSION', 'SKILL.md', 'THIRD_PARTY_NOTICES.md', 'scripts/webapp-security.mjs',
    'scripts/vendor/js-ts-parser.bundle.mjs', 'scripts/vendor/js-ts-parser.manifest.json',
  ];
  for (const name of required) {
    if (!listing.includes(`${root}${name}`)) throw new Error(`archive is missing ${name}`);
  }
  const extract = join(work, 'extracted');
  mkdirSync(extract, { mode: 0o700 });
  run('tar', ['-xzf', archive, '-C', extract]);
  const releaseRoot = join(extract, root.slice(0, -1));
  if (!existsSync(releaseRoot) || !lstatSync(releaseRoot).isDirectory()) {
    throw new Error('extracted release root is invalid');
  }
  if (readFileSync(join(releaseRoot, 'VERSION'), 'utf8').trim() !== version) {
    throw new Error('archive VERSION does not match the selected release');
  }
  return releaseRoot;
}

function verifyAttestation(policy, archive, official) {
  if (policy === 'skip') return 'skipped by explicit option';
  const available = spawnSync('gh', ['--version'], { encoding: 'utf8' }).status === 0;
  if (!available) {
    if (policy === 'required') throw new Error('gh is required for attestation verification');
    return 'not run (gh is unavailable)';
  }
  const authenticated = spawnSync('gh', ['auth', 'status'], { encoding: 'utf8' }).status === 0;
  if (!authenticated) {
    if (policy === 'required') throw new Error('gh authentication is required for attestation verification');
    return 'not run (gh is not authenticated)';
  }
  if (!official && policy === 'auto') return 'not run for a custom asset origin';
  run('gh', ['attestation', 'verify', archive, '--repo', REPOSITORY]);
  return 'verified with GitHub CLI';
}

async function main() {
  if (flag('--print-trust')) {
    if (args.length) usage(2, '--print-trust cannot be combined with other options');
    process.stdout.write(`${JSON.stringify(TRUST, null, 2)}\n`);
    return;
  }
  if (flag('-h') || flag('--help')) usage(0);
  const version = take('--version', '0.7.1');
  const target = take('--target', 'all');
  const mode = take('--mode', 'install');
  const fromDir = take('--from-dir');
  const baseArg = take('--base-url');
  const trustFile = take('--trust-file');
  const attestation = take('--attestation', 'auto');
  const force = flag('--force');
  const allowTestHttp = flag('--allow-test-http');
  if (args.length) usage(2, `unknown option ${args[0]}`);
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) usage(2, '--version is invalid');
  if (!['claude', 'codex', 'cli', 'both', 'all'].includes(target)) usage(2, '--target is invalid');
  if (!['install', 'upgrade'].includes(mode)) usage(2, '--mode must be install or upgrade');
  if (!['auto', 'required', 'skip'].includes(attestation)) usage(2, '--attestation is invalid');
  if (force && mode !== 'install') usage(2, '--force is only valid with install mode');
  if (fromDir && baseArg) usage(2, '--from-dir and --base-url are mutually exclusive');

  const trust = loadTrust(trustFile);
  const release = trust.releases[version];
  if (!release) throw new Error(`version ${version} is absent from the selected trust data`);
  if (release.tag !== `v${version}` || !/^[a-f0-9]{40}$/.test(release.sourceCommit || '')) {
    throw new Error('release trust anchor has an invalid tag or source commit');
  }
  const expectedNames = [
    'SHA256SUMS',
    `web-app-security-skill-${version}.release.json`,
    `web-app-security-skill-${version}.spdx.json`,
    `web-app-security-skill-${version}.tar.gz`,
  ].sort();
  if (JSON.stringify(Object.keys(release.assets || {}).sort()) !== JSON.stringify(expectedNames)) {
    throw new Error('release trust anchor has an unexpected asset set');
  }
  for (const [name, digest] of Object.entries(release.assets)) assertDigest(`trusted digest for ${name}`, digest);

  const defaultBase = `https://github.com/${REPOSITORY}/releases/download/${release.tag}`;
  const base = (baseArg || defaultBase).replace(/\/+$/, '');
  const official = !fromDir && base === defaultBase;
  if (!fromDir) assertSafeUrl(base, allowTestHttp);
  const work = mkdtempSync(join(tmpdir(), 'web-app-security-verified-'));
  try {
    const files = new Map();
    for (const name of expectedNames) {
      let data;
      if (fromDir) {
        const path = join(resolve(fromDir), name);
        if (!existsSync(path) || !lstatSync(path).isFile()) throw new Error(`missing offline asset: ${name}`);
        data = readFileSync(path);
      } else {
        const limit = name.endsWith('.tar.gz') ? MAX_ASSET_BYTES : MAX_METADATA_BYTES;
        data = await download(`${base}/${name}`, limit, { official, allowTestHttp });
      }
      if (sha256(data) !== release.assets[name]) throw new Error(`${name} differs from the trusted SHA-256`);
      files.set(name, data);
      writeFileSync(join(work, name), data, { mode: 0o600 });
    }
    validateChecksums(files.get('SHA256SUMS').toString('utf8'), expectedNames, files);
    const manifestName = `web-app-security-skill-${version}.release.json`;
    const sbomName = `web-app-security-skill-${version}.spdx.json`;
    const archiveName = `web-app-security-skill-${version}.tar.gz`;
    validateManifest(JSON.parse(files.get(manifestName).toString('utf8')), release, version, files);
    validateSbom(JSON.parse(files.get(sbomName).toString('utf8')), version);
    const archivePath = join(work, archiveName);
    const releaseRoot = inspectArchive(archivePath, version, work);
    const attestationResult = verifyAttestation(attestation, archivePath, official);
    console.log(`verified:    ${PRODUCT} ${version}`);
    console.log(`commit:      ${release.sourceCommit}`);
    console.log(`archive:     sha256:${release.assets[archiveName]}`);
    console.log(`attestation: ${attestationResult}`);
    const lifecycle = [join(releaseRoot, 'scripts', 'webapp-security.mjs'), mode, '--target', target];
    if (force) lifecycle.push('--force');
    const result = spawnSync(process.execPath, lifecycle, { stdio: 'inherit' });
    if (result.status !== 0) throw new Error(`verified payload ${mode} failed with status ${result.status}`);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(`error: ${error.message}`);
  process.exit(2);
});
