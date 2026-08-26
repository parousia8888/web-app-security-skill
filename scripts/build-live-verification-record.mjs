#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const args = process.argv.slice(2);
function take(name) {
  const index = args.indexOf(name);
  if (index === -1 || !args[index + 1] || args[index + 1].startsWith('--')) {
    throw new Error(`${name} requires a value`);
  }
  return args.splice(index, 2)[1];
}

try {
  const promotion = JSON.parse(readFileSync(resolve(take('--promotion')), 'utf8'));
  const publicState = JSON.parse(readFileSync(resolve(take('--public-state')), 'utf8'));
  const packageState = JSON.parse(readFileSync(resolve(take('--package-state')), 'utf8'));
  const installerLog = readFileSync(resolve(take('--installer-log')), 'utf8');
  const output = resolve(take('--out'));
  if (args.length) throw new Error(`unknown option ${args[0]}`);
  if (promotion.state !== 'live_verified'
      || Object.values(promotion.gates || {}).some((state) => state !== 'verified')) {
    throw new Error('release promotion evidence is not live verified');
  }
  if (publicState.state !== 'live_verified' || packageState.state !== 'live_verified') {
    throw new Error('public state or npm package evidence is not live verified');
  }
  if (promotion.version !== publicState.version || promotion.version !== packageState.version
      || promotion.sourceCommit !== publicState.publishedRelease?.sourceCommit
      || promotion.sourceCommit !== packageState.sourceCommit) {
    throw new Error('live verification identities disagree');
  }
  if (!installerLog.includes(`verified:    Web App Security Skill ${promotion.version}`)
      || !installerLog.includes('attestation: verified with GitHub CLI')) {
    throw new Error('verified installer evidence is incomplete');
  }
  if (process.env.WEBAPP_SECURITY_IMMUTABLE_CONSUMER_RESULT !== 'success'
      || process.env.WEBAPP_SECURITY_STABLE_CONSUMER_RESULT !== 'success') {
    throw new Error('immutable and stable Action consumers must both succeed');
  }
  const record = {
    schemaVersion: 1,
    generatedBy: 'scripts/build-live-verification-record.mjs',
    state: 'live_verified',
    repository: promotion.repository,
    version: promotion.version,
    tag: promotion.tag,
    sourceCommit: promotion.sourceCommit,
    publishedAt: promotion.publishedRelease?.publishedAt,
    gates: {
      releaseAssets: 'verified',
      signedTag: 'verified',
      githubProvenance: 'verified',
      npmPackageAndProvenance: 'verified',
      verifiedInstaller: 'verified',
      immutableActionConsumer: 'verified',
      stableV1ActionConsumer: 'verified',
      movingAliasState: 'verified',
    },
    evidence: {
      releasePromotionGenerator: promotion.generatedBy,
      publicStateGenerator: publicState.generatedBy,
      packageStateGenerator: packageState.generatedBy,
      workflow: '.github/workflows/action-v1-consumer.yml',
    },
  };
  writeFileSync(output, `${JSON.stringify(record, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  console.log(`live verification record: ${output}`);
} catch (error) {
  console.error(`live verification record: ${error.message}`);
  process.exit(1);
}
