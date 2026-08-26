#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const REPOSITORY = 'parousia8888/web-app-security-skill';
const args = process.argv.slice(2);

function usage(code, message) {
  if (message) console.error(`error: ${message}`);
  console.log(`node scripts/prepare-release-promotion.mjs --version <semver> --assets <directory> [options]

Verify release assets and emit the exact published-release/trust data needed after publication.

Options:
  --version <semver>       Explicit release version
  --assets <directory>     Directory containing the four release assets
  --live                   Require and verify the public GitHub release, signed tag, and provenance
  --out <file>             Write JSON to a file instead of stdout
`);
  process.exit(code);
}

function take(name) {
  const index = args.indexOf(name);
  if (index === -1) return null;
  if (!args[index + 1] || args[index + 1].startsWith('--')) usage(2, `${name} requires a value`);
  return args.splice(index, 2)[1];
}

function flag(name) {
  const index = args.indexOf(name);
  if (index === -1) return false;
  args.splice(index, 1);
  return true;
}

function run(program, commandArgs, options = {}) {
  const result = spawnSync(program, commandArgs, {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    ...options,
  });
  if (result.status !== 0) {
    throw new Error(result.stderr?.trim() || result.stdout?.trim()
      || `${program} ${commandArgs.join(' ')} failed`);
  }
  return result.stdout.trim();
}

function resolveSignedTagCommit(tag) {
  const result = spawnSync('git', ['rev-parse', '--verify', `${tag}^{}`], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(`signed release tag does not exist: ${tag}`);
  return result.stdout.trim();
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function parseChecksums(path) {
  const entries = new Map();
  for (const line of readFileSync(path, 'utf8').trim().split('\n')) {
    const match = /^([a-f0-9]{64})  ([^/\\]+)$/.exec(line);
    if (!match) throw new Error(`invalid checksum line: ${JSON.stringify(line)}`);
    if (entries.has(match[2])) throw new Error(`duplicate checksum entry: ${match[2]}`);
    entries.set(match[2], match[1]);
  }
  return entries;
}

if (flag('-h') || flag('--help')) usage(0);
const version = take('--version');
const assetsArgument = take('--assets');
const assetsDirectory = assetsArgument ? resolve(assetsArgument) : null;
const output = take('--out');
const live = flag('--live');
if (args.length) usage(2, `unknown option ${args[0]}`);
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version || '')) usage(2, '--version is required and must be semantic');
if (!assetsArgument || !existsSync(assetsDirectory)) usage(2, '--assets must be an existing directory');

try {
  const tag = `v${version}`;
  const prefix = `web-app-security-skill-${version}`;
  const names = [
    'SHA256SUMS',
    `${prefix}.release.json`,
    `${prefix}.spdx.json`,
    `${prefix}.tar.gz`,
  ];
  for (const name of names) {
    if (!existsSync(join(assetsDirectory, name))) throw new Error(`missing release asset: ${name}`);
  }
  const manifestPath = join(assetsDirectory, `${prefix}.release.json`);
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  if (manifest.version !== version || manifest.tag !== tag
      || !/^[a-f0-9]{40}$/.test(manifest.sourceCommit || '')) {
    throw new Error('manifest version, tag, or source commit mismatch');
  }
  const gates = {
    localArtifacts: 'pending',
    publicRelease: live ? 'pending' : 'not_requested',
    signedTag: live ? 'pending' : 'not_requested',
    provenance: live ? 'pending' : 'not_requested',
  };
  if (live) {
    const tagCommit = resolveSignedTagCommit(tag);
    if (tagCommit !== manifest.sourceCommit) throw new Error('signed tag commit differs from release manifest');
    run('git', ['-c', 'gpg.ssh.allowedSignersFile=.github/release-signers', 'verify-tag', tag]);
    gates.signedTag = 'verified';
    const verifier = run('git', ['show', `${manifest.sourceCommit}:scripts/verify-release-artifacts.mjs`]);
    run(process.execPath, ['--input-type=module', '-', '--manifest', manifestPath], { input: verifier });
  } else {
    run(process.execPath, [join(ROOT, 'scripts', 'verify-release-artifacts.mjs'), '--manifest', manifestPath]);
  }
  gates.localArtifacts = 'verified';
  const checksums = parseChecksums(join(assetsDirectory, 'SHA256SUMS'));
  const listed = names.filter((name) => name !== 'SHA256SUMS').sort();
  if ([...checksums.keys()].sort().join('\n') !== listed.join('\n')) {
    throw new Error('SHA256SUMS asset set mismatch');
  }
  const digests = Object.fromEntries(names.map((name) => [name, sha256(join(assetsDirectory, name))]));
  for (const [name, digest] of checksums) {
    if (digests[name] !== digest) throw new Error(`${name} differs from SHA256SUMS`);
  }

  let release = null;
  if (live) {
    const releaseResult = JSON.parse(run('gh', [
      'release', 'view', tag, '--repo', REPOSITORY,
      '--json', 'tagName,url,isDraft,isPrerelease,assets,publishedAt',
    ]));
    const expectedUrl = `https://github.com/${REPOSITORY}/releases/tag/${tag}`;
    if (releaseResult.tagName !== tag || releaseResult.url !== expectedUrl
        || releaseResult.isDraft || releaseResult.isPrerelease || !releaseResult.publishedAt) {
      throw new Error('public release identity or publication state mismatch');
    }
    const publicAssets = new Map((releaseResult.assets || []).map((asset) => [asset.name, asset]));
    const liveRecordName = `${prefix}.live-verification.json`;
    const unexpected = [...publicAssets.keys()].filter((name) => !names.includes(name) && name !== liveRecordName);
    const missing = names.filter((name) => !publicAssets.has(name));
    if (unexpected.length || missing.length) {
      throw new Error('public release asset set mismatch');
    }
    for (const name of names) {
      const asset = publicAssets.get(name);
      if (asset.state !== 'uploaded' || asset.digest !== `sha256:${digests[name]}`) {
        throw new Error(`public release digest or state mismatch: ${name}`);
      }
    }
    gates.publicRelease = 'verified';

    run('gh', ['attestation', 'verify', join(assetsDirectory, `${prefix}.tar.gz`), '--repo', REPOSITORY]);
    gates.provenance = 'verified';
    release = {
      version,
      tag,
      sourceCommit: manifest.sourceCommit,
      evidence: `docs/releases/${tag}.md`,
      url: releaseResult.url,
      publishedAt: releaseResult.publishedAt,
    };
  }

  const record = {
    schemaVersion: 1,
    generatedBy: 'scripts/prepare-release-promotion.mjs',
    state: live ? 'live_verified' : 'local_candidate',
    repository: REPOSITORY,
    version,
    tag,
    sourceCommit: manifest.sourceCommit,
    assets: digests,
    trustEntry: {
      tag,
      sourceCommit: manifest.sourceCommit,
      assets: digests,
    },
    publishedRelease: release,
    gates,
  };
  const rendered = `${JSON.stringify(record, null, 2)}\n`;
  if (output) {
    writeFileSync(resolve(output), rendered, { flag: 'wx', mode: 0o600 });
    console.log(`release promotion evidence: ${resolve(output)}`);
  } else process.stdout.write(rendered);
} catch (error) {
  console.error(`release promotion: ${error.message}`);
  process.exit(1);
}
