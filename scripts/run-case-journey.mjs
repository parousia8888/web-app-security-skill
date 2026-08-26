#!/usr/bin/env node
import { createHash } from 'node:crypto';
import {
  existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync,
} from 'node:fs';
import { basename, dirname, relative, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  annotationIdentity, classifyJourneyAuditExit, journeyAdapterDefinitions, journeyPrerequisites,
  reportSemanticDigest, sha256Bytes, sha256File, toolSourceIdentity,
} from './lib/journey-contract.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const DEFAULT_CATALOG = `${ROOT}/docs/case-studies/journeys/evidence-v0.7.3.json`;
const CLI = `${ROOT}/scripts/webapp-security.mjs`;

function usage(code, message) {
  if (message) console.error(`error: ${message}`);
  console.log(`node scripts/run-case-journey.mjs <journey-id> <checkout> --out <directory> [options]

Options:
  --catalog <json>  Active catalog (default: docs/case-studies/journeys/evidence-v0.7.3.json)
  --refresh         Record observed evidence without claiming it matches the catalog

The checkout must be a clean Git worktree at the journey's exact immutable commit. The output
directory must be outside the checkout. The catalog's adapterSelection controls the exact tools
that run. Required environment variables and versions are derived from the shared adapter
definition; read the active journey README for the generated prerequisite table. The runner does
not download tools, execute project dependencies, or contact a hosted project; OSV-Scanner may
query the public OSV advisory service when selected.`);
  process.exit(code);
}

function take(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return null;
  if (!args[index + 1] || args[index + 1].startsWith('--')) usage(2, `${name} requires a value`);
  return args.splice(index, 2)[1];
}

function git(checkout, args) {
  const result = spawnSync('git', ['-C', checkout, ...args], { encoding: 'utf8' });
  if (result.status !== 0) throw new Error(result.stderr.trim() || `git ${args.join(' ')} failed`);
  return result.stdout.trim();
}

function isInside(parent, child) {
  const path = relative(parent, child);
  return path === '' || (path !== '..' && !path.startsWith(`..${sep}`));
}

function canonicalFuturePath(path) {
  let cursor = resolve(path);
  const tail = [];
  while (!existsSync(cursor)) {
    const parent = dirname(cursor);
    if (parent === cursor) throw new Error(`cannot resolve output ancestor: ${path}`);
    tail.push(basename(cursor));
    cursor = parent;
  }
  return resolve(realpathSync(cursor), ...tail.reverse());
}

function digestFindingIds(report, adapterId) {
  const ids = report.findings.filter((finding) => finding.adapter.id === adapterId)
    .map((finding) => finding.id).sort();
  return createHash('sha256').update(JSON.stringify(ids)).digest('hex');
}

function digestFindingContent(report, adapterId) {
  const findings = report.findings.filter((finding) => finding.adapter.id === adapterId)
    .map((finding) => ({
      id: finding.id,
      fingerprint: finding.fingerprint,
      rule: finding.rule,
      adapter: finding.adapter,
      domain: finding.domain,
      title: finding.title,
      severity: finding.severity,
      state: finding.state,
      summary: finding.summary,
      location: finding.location,
      evidence: finding.evidence,
      remediation: finding.remediation,
      retest: finding.retest,
    })).sort((left, right) => left.id.localeCompare(right.id));
  return createHash('sha256').update(JSON.stringify(findings)).digest('hex');
}

function sameArray(left, right) {
  return Array.isArray(left) && Array.isArray(right)
    && left.length === right.length && left.every((value, index) => value === right[index]);
}

function reportAdapterIds(report) {
  return report.ruleset.adapters.map((item) => item.id);
}

function compareReport(catalog, journey, report, observed, toolIdentity) {
  const expected = journey.corpus;
  const definitions = journeyAdapterDefinitions(journey.adapterSelection);
  const expectedReportIds = definitions.map((item) => item.reportId);
  const errors = [];
  if (report.schemaVersion !== expected.reportSchemaVersion) {
    errors.push(`source report schemaVersion expected ${expected.reportSchemaVersion}, observed ${report.schemaVersion}`);
  }
  if (!sameArray(reportAdapterIds(report), expectedReportIds)) {
    errors.push(`report adapter set expected [${expectedReportIds.join(', ')}], observed [${reportAdapterIds(report).join(', ')}]`);
  }
  if (!sameArray(expected.adapters.map((item) => item.id), expectedReportIds)) {
    errors.push('catalog adapter identities do not match adapterSelection');
  }
  if (report.ruleset.digest !== expected.rulesetDigest) {
    errors.push(`ruleset digest expected ${expected.rulesetDigest}, observed ${report.ruleset.digest}`);
  }
  if (observed.auditExit.code !== expected.auditExit.code
      || observed.auditExit.classification !== expected.auditExit.classification) {
    errors.push(`audit exit expected ${expected.auditExit.code}/${expected.auditExit.classification}, observed ${observed.auditExit.code}/${observed.auditExit.classification}`);
  }
  if (catalog.toolSource?.sourceDigest !== toolIdentity.sourceDigest) {
    errors.push(`tool source digest expected ${catalog.toolSource?.sourceDigest || 'missing'}, observed ${toolIdentity.sourceDigest}`);
  }
  if (expected.digests?.stableReportSemantics !== observed.digests.stableReportSemantics) {
    errors.push(`stable report semantic digest expected ${expected.digests?.stableReportSemantics || 'missing'}, observed ${observed.digests.stableReportSemantics}`);
  }
  if (expected.digests?.manualAnnotationIdentity !== observed.digests.manualAnnotationIdentity) {
    errors.push(`manual annotation identity expected ${expected.digests?.manualAnnotationIdentity || 'missing'}, observed ${observed.digests.manualAnnotationIdentity}`);
  }
  if (report.summary.byState.confirmed !== expected.snapshot.summary.confirmed) {
    errors.push(`confirmed count expected ${expected.snapshot.summary.confirmed}, observed ${report.summary.byState.confirmed}`);
  }
  if (report.findings.some((finding) => finding.adapter.id !== 'builtin-source'
      && finding.state !== 'suspected' && finding.state !== 'unknown')) {
    errors.push('external adapter finding exceeded suspected/unknown evidence state');
  }
  for (const adapter of expected.adapters) {
    const ruleset = report.ruleset.adapters.find((item) => item.id === adapter.id);
    const runtime = report.scope.adapters.find((item) => item.id === adapter.id);
    const binary = observed.adapters.find((item) => item.id === adapter.id);
    if (!ruleset || ruleset.version !== adapter.version || ruleset.rulesetDigest !== adapter.rulesetDigest) {
      errors.push(`${adapter.id} ruleset identity changed`);
    }
    if (adapter.id !== 'builtin-source') {
      const expectedObservedVersion = adapter.status === 'available' ? adapter.observedVersion : null;
      if (!runtime || runtime.status !== adapter.status
          || runtime.observedVersion !== expectedObservedVersion) {
        errors.push(`${adapter.id} runtime identity expected ${adapter.status}/${expectedObservedVersion || 'n/a'}, observed ${runtime?.status || 'missing'}/${runtime?.observedVersion || 'n/a'}`);
      }
      if (!binary || binary.binarySha256 !== adapter.binarySha256) {
        errors.push(`${adapter.id} binary digest changed`);
      }
    }
    if (adapter.deterministicFindingIdsDigest
        && digestFindingIds(report, adapter.id) !== adapter.deterministicFindingIdsDigest) {
      errors.push(`${adapter.id} deterministic finding identity changed`);
    }
    if (adapter.deterministicFindingContentDigest
        && digestFindingContent(report, adapter.id) !== adapter.deterministicFindingContentDigest) {
      errors.push(`${adapter.id} sanitized finding content changed`);
    }
  }
  const actualCoverage = Object.fromEntries(report.coverage.map((entry) => [entry.ruleId, entry.status]));
  const expectedCoverage = expected.coverage || {};
  for (const [ruleId, status] of Object.entries(expectedCoverage)) {
    if (actualCoverage[ruleId] !== status) {
      errors.push(`${ruleId} coverage expected ${status}, observed ${actualCoverage[ruleId] || 'missing'}`);
    }
  }
  for (const ruleId of Object.keys(actualCoverage)) {
    if (!(ruleId in expectedCoverage)) errors.push(`unexpected coverage rule ${ruleId}`);
  }
  const allowedConfirmed = new Set(expected.confirmedFindingIds || []);
  const observedConfirmed = report.findings.filter((item) => item.state === 'confirmed');
  for (const finding of observedConfirmed) {
    if (!allowedConfirmed.has(finding.id)) errors.push(`unreviewed confirmed finding ${finding.id}`);
  }
  if (allowedConfirmed.size !== observedConfirmed.length) errors.push('reviewed confirmed finding set changed');
  return errors;
}

function observedCorpus(journey, report, reportBytes, exit, runtimeBinaries) {
  const mutableAdapters = journey.mutableAdapters || [];
  const runtimeById = new Map(report.scope.adapters.map((item) => [item.id, item]));
  const binaryById = new Map(runtimeBinaries.map((item) => [item.definition.reportId, item]));
  const adapters = report.ruleset.adapters.map((ruleset) => {
    if (ruleset.id === 'builtin-source') {
      return {
        id: ruleset.id, version: ruleset.version, status: 'built_in',
        rulesetDigest: ruleset.rulesetDigest,
        deterministicFindingIdsDigest: digestFindingIds(report, ruleset.id),
        deterministicFindingContentDigest: digestFindingContent(report, ruleset.id),
      };
    }
    const runtime = runtimeById.get(ruleset.id);
    const binary = binaryById.get(ruleset.id);
    return {
      id: ruleset.id,
      version: ruleset.version,
      status: runtime?.status || 'missing',
      observedVersion: runtime?.observedVersion || null,
      rulesetDigest: ruleset.rulesetDigest,
      binarySha256: binary?.binarySha256 || null,
      ...(!mutableAdapters.includes(ruleset.id) ? {
        deterministicFindingIdsDigest: digestFindingIds(report, ruleset.id),
        deterministicFindingContentDigest: digestFindingContent(report, ruleset.id),
      } : {}),
    };
  });
  return {
    runDate: journey.corpus?.runDate || new Date().toISOString(),
    reportSchemaVersion: report.schemaVersion,
    auditExit: exit,
    rulesetDigest: report.ruleset.digest,
    mutableAdapters,
    digests: {
      reportBytes: sha256Bytes(reportBytes),
      reportSemantics: reportSemanticDigest(report),
      stableReportSemantics: reportSemanticDigest(report, { excludedAdapters: mutableAdapters }),
      manualAnnotationIdentity: annotationIdentity(journey),
    },
    adapters,
    coverage: Object.fromEntries(report.coverage.map((entry) => [entry.ruleId, entry.status])),
    snapshot: {
      summary: {
        total: report.summary.total,
        confirmed: report.summary.byState.confirmed,
        suspected: report.summary.byState.suspected,
        unknown: report.summary.byState.unknown,
      },
      byRule: Object.fromEntries([...new Set(report.findings.map((finding) => finding.rule.id))]
        .sort().map((ruleId) => [ruleId, report.findings.filter((finding) => finding.rule.id === ruleId).length])),
      externalStates: [...new Set(report.findings.filter((finding) => finding.adapter.id !== 'builtin-source')
        .map((finding) => finding.state))].sort(),
    },
    confirmedFindingIds: report.findings.filter((item) => item.state === 'confirmed').map((item) => item.id).sort(),
  };
}

const args = process.argv.slice(2);
if (args.includes('-h') || args.includes('--help')) usage(0);
const refresh = args.includes('--refresh');
if (refresh) args.splice(args.indexOf('--refresh'), 1);
const catalogPath = resolve(take(args, '--catalog') || DEFAULT_CATALOG);
const outArg = take(args, '--out');
const id = args.shift();
const checkoutArg = args.shift();
if (!id || !checkoutArg || !outArg || args.length) usage(2, 'journey-id, checkout, and --out are required');

try {
  const catalog = JSON.parse(readFileSync(catalogPath, 'utf8'));
  const journey = catalog.journeys?.find((item) => item.id === id);
  if (!journey) throw new Error(`unknown journey: ${id}`);
  const definitions = journeyAdapterDefinitions(journey.adapterSelection);
  const prerequisites = journeyPrerequisites(journey.adapterSelection);
  const catalogAdapterIds = journey.corpus?.adapters?.map((item) => item.id) || [];
  const selectedReportIds = definitions.map((item) => item.reportId);
  if (!refresh && !sameArray(catalogAdapterIds, selectedReportIds)) {
    throw new Error(`catalog adapters [${catalogAdapterIds.join(', ')}] do not match adapterSelection [${selectedReportIds.join(', ')}]`);
  }
  const checkout = realpathSync(resolve(checkoutArg));
  const output = canonicalFuturePath(outArg);
  if (isInside(checkout, output)) throw new Error('output directory must be outside the source checkout');
  const head = git(checkout, ['rev-parse', 'HEAD']);
  if (head !== journey.commit) throw new Error(`checkout HEAD ${head} does not match ${journey.commit}`);
  if (git(checkout, ['status', '--porcelain', '--untracked-files=normal'])) {
    throw new Error('checkout must be clean before a case journey runs');
  }
  if (existsSync(output)) throw new Error(`output already exists: ${output}`);
  const runtimeBinaries = prerequisites.map((definition) => {
    const supplied = process.env[definition.envVariable];
    if (!supplied) throw new Error(`set ${definition.envVariable} to a pinned ${definition.displayName} ${definition.expectedVersion} binary`);
    if (!existsSync(supplied)) throw new Error(`${definition.displayName} binary does not exist: ${supplied}`);
    const path = realpathSync(supplied);
    return { definition, path, binarySha256: sha256File(path) };
  });
  mkdirSync(output, { recursive: true, mode: 0o700 });
  const epoch = Date.parse(journey.corpus.runDate);
  if (!Number.isFinite(epoch)) throw new Error('catalog runDate is invalid');
  const env = { ...process.env, SOURCE_DATE_EPOCH: String(epoch / 1000) };
  for (const binary of runtimeBinaries) env[binary.definition.envVariable] = binary.path;
  const auditArgs = ['audit', checkout, '--out', `${output}/audit`, '--name', 'report',
    ...journey.adapterSelection.flatMap((adapter) => ['--adapter', adapter]), '--fail-on', 'never'];
  const result = spawnSync(process.execPath, [CLI, ...auditArgs], { encoding: 'utf8', env });
  if (result.error) throw new Error(`audit invocation failed: ${result.error.message}`);
  const exit = { code: result.status, classification: classifyJourneyAuditExit(result.status) };
  const scopePath = `${output}/audit/security-scope.yml`;
  const reportPath = `${output}/audit/report.json`;
  if (!existsSync(scopePath) || !existsSync(reportPath)) {
    throw new Error(`audit exit ${exit.code}/${exit.classification} did not produce required scope and report artifacts`);
  }
  let scope;
  let report;
  const reportBytes = readFileSync(reportPath);
  try {
    scope = JSON.parse(readFileSync(scopePath, 'utf8'));
    report = JSON.parse(reportBytes.toString('utf8'));
  } catch (error) {
    throw new Error(`audit artifact schema could not be parsed: ${error.message}`);
  }
  if (!Array.isArray(report.findings) || !Array.isArray(report.coverage)
      || !Array.isArray(report.ruleset?.adapters) || !Array.isArray(report.scope?.adapters)) {
    throw new Error('audit report is missing required v3 artifact fields');
  }
  const observed = observedCorpus(journey, report, reportBytes, exit, runtimeBinaries);
  const toolIdentity = toolSourceIdentity(ROOT);
  const runRecord = {
    schemaVersion: 1,
    journey: id,
    targetCommit: head,
    toolSource: toolIdentity,
    command: [process.execPath, CLI, ...auditArgs],
    auditExit: exit,
    adapterSelection: journey.adapterSelection,
    adapters: observed.adapters.map((adapter) => ({
      id: adapter.id, version: adapter.version, status: adapter.status,
      observedVersion: adapter.observedVersion || null, binarySha256: adapter.binarySha256 || null,
    })),
    digests: observed.digests,
    catalogMode: refresh ? 'refresh_observation' : 'contract_match',
  };
  writeFileSync(`${output}/journey-run.json`, `${JSON.stringify(runRecord, null, 2)}\n`, { mode: 0o600 });
  const actualDiscovery = {
    status: scope.target.discoveryStatus,
    layout: scope.target.layout,
    frameworks: scope.target.frameworks.map((item) => `${item.name}@${item.root}`),
    packageManagers: scope.target.packageManagers.map((item) => `${item.name}@${item.root}`),
    lockfiles: scope.target.lockfiles,
  };
  const errors = [];
  if (JSON.stringify(actualDiscovery) !== JSON.stringify(journey.discovery)) {
    errors.push(`discovery expected ${JSON.stringify(journey.discovery)}, observed ${JSON.stringify(actualDiscovery)}`);
  }
  if (refresh) {
    writeFileSync(`${output}/observed-corpus.json`, `${JSON.stringify({
      id, commit: head, discovery: actualDiscovery, corpus: observed, toolSource: toolIdentity,
    }, null, 2)}\n`, { mode: 0o600 });
  } else {
    errors.push(...compareReport(catalog, journey, report, observed, toolIdentity));
  }
  if (errors.length) throw new Error(`observed evidence differs from catalog for ${id}:\n- ${errors.join('\n- ')}`);
  if (git(checkout, ['status', '--porcelain', '--untracked-files=normal'])) {
    throw new Error('source checkout changed while the case journey ran');
  }
  console.log(`journey:    ${id}`);
  console.log(`commit:     ${head}`);
  console.log('checkout:   clean and unchanged');
  console.log(`audit exit: ${exit.code} (${exit.classification})`);
  if (result.stdout.trim()) console.log(result.stdout.trim());
  if (refresh) console.log('catalog:    refresh evidence recorded; no match claimed');
  else console.log('catalog:    stable contract matched');
} catch (error) {
  usage(2, error.message);
}
