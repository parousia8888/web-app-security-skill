#!/usr/bin/env node
import assert from 'node:assert/strict';
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  CHECKOV_RULES, GITLEAKS_RULES, OPENGREP_RULES, OSV_RULES,
} from '../scripts/lib/adapter-definitions.mjs';
import { SOURCE_RULES, sourceRuleset } from '../scripts/lib/source-rules.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(ROOT, 'scripts', 'webapp-security.mjs');
const CHECK = join(ROOT, 'scripts', 'check-case-journeys.mjs');
const CHECK_V050 = join(ROOT, 'scripts', 'check-v050-ordinary-review.mjs');
const RUN_JOURNEY = join(ROOT, 'scripts', 'run-case-journey.mjs');
const DENY_NETWORK = join(ROOT, 'test', 'helpers', 'deny-network.cjs');
const temp = mkdtempSync(join(tmpdir(), 'web-app-security-case-'));
const project = join(temp, 'project');

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: { ...process.env, NODE_OPTIONS: `--require=${DENY_NETWORK}`, SOURCE_DATE_EPOCH: '0' },
  });
}

function git(directory, args) {
  const result = spawnSync('git', ['-C', directory, ...args], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

const emptyFindingDigest = createHash('sha256').update('[]').digest('hex');
const currentRuleset = sourceRuleset(['builtin', 'checkov', 'gitleaks', 'opengrep', 'osv']);
const adapter = (id, status, findingDigests = false) => {
  const identity = currentRuleset.adapters.find((item) => item.id === id);
  return {
    id, version: identity.version, status, rulesetDigest: identity.rulesetDigest,
    ...(findingDigests ? {
      deterministicFindingIdsDigest: emptyFindingDigest,
      deterministicFindingContentDigest: emptyFindingDigest,
    } : {}),
  };
};
const currentCoverage = Object.fromEntries([
  ...SOURCE_RULES, ...CHECKOV_RULES, ...GITLEAKS_RULES, ...OPENGREP_RULES, ...OSV_RULES,
].map((rule) => [rule.id, 'completed']));
for (const rule of OPENGREP_RULES.filter((item) => item.id.startsWith('opengrep-python-'))) {
  currentCoverage[rule.id] = 'not_applicable';
}
for (const rule of CHECKOV_RULES) currentCoverage[rule.id] = 'not_applicable';
currentCoverage['js-route-security-evidence-incomplete'] = 'not_applicable';

try {
  let result = spawnSync(process.execPath, [CHECK], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /5 projects/);

  const ordinaryEvidence = JSON.parse(readFileSync(join(ROOT, 'docs', 'case-studies', 'journeys',
    'v0.5.0-evidence.json'), 'utf8'));
  const reviewed = ordinaryEvidence.projects[0];
  const reviewedIds = [
    ...reviewed.review.useful_lead.map((id) => ({ id, state: 'suspected' })),
    ...reviewed.review.expected_benign_match.map((id) => ({ id, state: 'suspected' })),
    ...reviewed.review.unknown.map((id) => ({ id, state: 'unknown' })),
    ...reviewed.review.confirmed.map((id) => ({ id, state: 'confirmed' })),
  ];
  const reproducedReportPath = join(temp, 'reproduced-report.json');
  const reproducedReport = {
    schemaVersion: reviewed.report.schemaVersion,
    ruleset: { digest: ordinaryEvidence.rulesetDigest },
    summary: {
      total: reviewed.report.summary.total,
      byState: {
        confirmed: reviewed.report.summary.confirmed,
        suspected: reviewed.report.summary.suspected,
        unknown: reviewed.report.summary.unknown,
      },
    },
    findings: reviewedIds,
  };
  writeFileSync(reproducedReportPath, `${JSON.stringify(reproducedReport)}\n`);
  result = spawnSync(process.execPath, [CHECK_V050, '--report', reviewed.id, reproducedReportPath],
    { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /reproduced report semantics match/);
  reproducedReport.findings[0].state = 'unknown';
  writeFileSync(reproducedReportPath, `${JSON.stringify(reproducedReport)}\n`);
  result = spawnSync(process.execPath, [CHECK_V050, '--report', reviewed.id, reproducedReportPath],
    { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /reproduced report semantics differ/);

  cpSync(join(ROOT, 'test', 'fixtures', 'case-open-webui'), project, { recursive: true });
  const runRoot = join(temp, 'representative-runs');
  result = run(['start', project, '--out', runRoot, '--run-id', 'baseline']);
  assert.equal(result.status, 0, result.stderr);
  const baselineDir = join(runRoot, 'baseline');
  result = run(['audit', baselineDir, '--name', 'report', '--fail-on', 'never']);
  assert.equal(result.status, 0, result.stderr);
  const baselinePath = join(baselineDir, 'report.json');
  const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'));
  assert.equal(baseline.summary.total, 1);
  const finding = baseline.findings[0];
  assert.equal(finding.rule.id, 'production-source-map-enabled');
  assert.equal(finding.severity, 'medium');
  assert.equal(finding.state, 'suspected');
  assert.equal(finding.location.path, 'vite.config.ts');
  assert.match(readFileSync(join(baselineDir, 'proposed.patch'), 'utf8'), /sourcemap: false/);

  const configPath = join(project, 'vite.config.ts');
  writeFileSync(configPath, readFileSync(configPath, 'utf8').replace('sourcemap: true', 'sourcemap: false'));
  result = run(['start', project, '--out', runRoot, '--run-id', 'retest']);
  assert.equal(result.status, 0, result.stderr);
  const retestDir = join(runRoot, 'retest');
  result = run(['retest', retestDir, '--name', 'report', '--baseline', baselinePath, '--fail-on', 'low']);
  assert.equal(result.status, 0, result.stderr);
  const retest = JSON.parse(readFileSync(join(retestDir, 'report.json'), 'utf8'));
  assert.equal(retest.summary.byBaseline.fixed, 1);
  assert.equal(retest.findings[0].state, 'suspected');
  assert.equal(retest.findings[0].baseline.state, 'fixed');
  assert.equal(JSON.parse(readFileSync(join(retestDir, 'report.sarif'), 'utf8')).runs[0].results.length, 0);

  const checkout = join(temp, 'checkout');
  mkdirSync(checkout);
  writeFileSync(join(checkout, 'package.json'), '{"private":true}\n');
  writeFileSync(join(checkout, 'package-lock.json'), '{"lockfileVersion":3}\n');
  writeFileSync(join(checkout, 'source.js'), 'export const value = "safe";\n');
  git(checkout, ['init', '-q']);
  git(checkout, ['config', 'user.name', 'Case Test']);
  git(checkout, ['config', 'user.email', 'case-test@example.invalid']);
  git(checkout, ['add', '.']);
  git(checkout, ['commit', '-q', '-m', 'fixture']);
  const commit = git(checkout, ['rev-parse', 'HEAD']);
  const fakeGitleaks = join(temp, 'fake-gitleaks.mjs');
  const fakeCheckov = join(temp, 'fake-checkov.mjs');
  const fakeOpengrep = join(temp, 'fake-opengrep.mjs');
  const fakeOsv = join(temp, 'fake-osv.mjs');
  writeFileSync(fakeGitleaks, `#!/usr/bin/env node
if (process.argv[2] === 'version') console.log('8.30.1'); else console.log('[]');
`);
  writeFileSync(fakeCheckov, `#!/usr/bin/env node
if (process.argv[2] === '--version') console.log('3.3.9'); else console.log('{}');
`);
  writeFileSync(fakeOsv, `#!/usr/bin/env node
if (process.argv[2] === '--version') console.log('osv-scanner version: 2.5.0');
else console.log('{"results":[]}');
`);
  writeFileSync(fakeOpengrep, `#!/usr/bin/env node
if (process.argv[2] === '--version') console.log('1.27.0');
else console.log('{"version":"1.27.0","results":[],"errors":[],"paths":{"scanned":["source.js"]}}');
`);
  chmodSync(fakeCheckov, 0o755);
  chmodSync(fakeGitleaks, 0o755);
  chmodSync(fakeOpengrep, 0o755);
  chmodSync(fakeOsv, 0o755);
  const catalogPath = join(temp, 'catalog.json');
  const catalog = {
    journeys: [{
      id: 'local-case',
      commit,
      discovery: {
        status: 'ambiguous',
        layout: 'single-root',
        frameworks: [],
        packageManagers: ['npm@.'],
        lockfiles: ['package-lock.json'],
      },
      corpus: {
        runDate: '1970-01-01T00:00:00.000Z',
        rulesetDigest: currentRuleset.digest,
        adapters: [
          adapter('builtin-source', 'built_in', true),
          adapter('checkov', 'not_applicable', true),
          adapter('gitleaks', 'available', true),
          adapter('opengrep', 'available', true),
          adapter('osv', 'available'),
        ],
        coverage: currentCoverage,
        snapshot: { summary: { confirmed: 0 }, byRule: {} },
        confirmedFindingIds: [],
      },
    }],
  };
  writeFileSync(catalogPath, `${JSON.stringify(catalog)}\n`);
  const journeyOut = join(temp, 'journey-output');
  const runnerEnv = {
    ...process.env,
    WEBAPP_SECURITY_CHECKOV_BIN: fakeCheckov,
    WEBAPP_SECURITY_GITLEAKS_BIN: fakeGitleaks,
    WEBAPP_SECURITY_OPENGREP_BIN: fakeOpengrep,
    WEBAPP_SECURITY_OSV_SCANNER_BIN: fakeOsv,
  };
  result = spawnSync(process.execPath, [RUN_JOURNEY, 'local-case', checkout, '--out', journeyOut, '--catalog', catalogPath], { encoding: 'utf8', env: runnerEnv });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /checkout:\s+clean and unchanged/);
  assert.match(result.stdout, /catalog:\s+stable contract matched/);
  assert.equal(git(checkout, ['status', '--porcelain', '--untracked-files=normal']), '');

  const contentDriftCatalog = structuredClone(catalog);
  contentDriftCatalog.journeys[0].corpus.adapters[0].deterministicFindingContentDigest = '0'.repeat(64);
  const contentDriftCatalogPath = join(temp, 'content-drift-catalog.json');
  writeFileSync(contentDriftCatalogPath, `${JSON.stringify(contentDriftCatalog)}\n`);
  result = spawnSync(process.execPath, [RUN_JOURNEY, 'local-case', checkout, '--out',
    join(temp, 'content-drift-output'), '--catalog', contentDriftCatalogPath], {
    encoding: 'utf8', env: runnerEnv,
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /observed evidence differs from catalog/);

  result = spawnSync(process.execPath, [RUN_JOURNEY, 'local-case', checkout, '--out', join(temp, 'missing-binary-output'), '--catalog', catalogPath], { encoding: 'utf8' });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /set WEBAPP_SECURITY_CHECKOV_BIN.*WEBAPP_SECURITY_GITLEAKS_BIN/);

  writeFileSync(join(checkout, 'dirty.txt'), 'uncommitted\n');
  result = spawnSync(process.execPath, [RUN_JOURNEY, 'local-case', checkout, '--out', join(temp, 'dirty-output'), '--catalog', catalogPath], { encoding: 'utf8', env: runnerEnv });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /checkout must be clean/);
  rmSync(join(checkout, 'dirty.txt'));

  const wrongCatalog = structuredClone(catalog);
  wrongCatalog.journeys[0].commit = '0'.repeat(40);
  const wrongCatalogPath = join(temp, 'wrong-catalog.json');
  writeFileSync(wrongCatalogPath, `${JSON.stringify(wrongCatalog)}\n`);
  result = spawnSync(process.execPath, [RUN_JOURNEY, 'local-case', checkout, '--out', join(temp, 'wrong-output'), '--catalog', wrongCatalogPath], { encoding: 'utf8', env: runnerEnv });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /does not match/);

  result = spawnSync(process.execPath, [RUN_JOURNEY, 'local-case', checkout, '--out', join(checkout, 'evidence'), '--catalog', catalogPath], { encoding: 'utf8', env: runnerEnv });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /outside the source checkout/);

  console.log('✓ case journeys: v3 source reports, pinned adapter runner, and representative patch/retest');
} finally {
  rmSync(temp, { recursive: true, force: true });
}
