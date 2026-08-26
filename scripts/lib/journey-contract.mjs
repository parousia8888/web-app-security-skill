import { createHash } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import {
  CHECKOV_ADAPTER, GITLEAKS_ADAPTER, OPENGREP_ADAPTER, OSV_ADAPTER,
} from './adapter-definitions.mjs';
import { BUILTIN_SOURCE_ADAPTER } from './source-rules.mjs';

export const JOURNEY_ADAPTER_DEFINITIONS = Object.freeze([
  {
    selectionId: 'builtin', reportId: BUILTIN_SOURCE_ADAPTER.id, displayName: 'Built-in source',
    expectedVersion: BUILTIN_SOURCE_ADAPTER.version, envVariable: null, defaultBinary: null,
  },
  {
    selectionId: 'checkov', reportId: CHECKOV_ADAPTER.id, displayName: 'Checkov',
    expectedVersion: CHECKOV_ADAPTER.version, envVariable: 'WEBAPP_SECURITY_CHECKOV_BIN',
    defaultBinary: 'checkov',
  },
  {
    selectionId: 'gitleaks', reportId: GITLEAKS_ADAPTER.id, displayName: 'Gitleaks',
    expectedVersion: GITLEAKS_ADAPTER.version, envVariable: 'WEBAPP_SECURITY_GITLEAKS_BIN',
    defaultBinary: 'gitleaks',
  },
  {
    selectionId: 'opengrep', reportId: OPENGREP_ADAPTER.id, displayName: 'Opengrep',
    expectedVersion: OPENGREP_ADAPTER.version, envVariable: 'WEBAPP_SECURITY_OPENGREP_BIN',
    defaultBinary: 'opengrep',
  },
  {
    selectionId: 'osv', reportId: OSV_ADAPTER.id, displayName: 'OSV-Scanner',
    expectedVersion: OSV_ADAPTER.version, envVariable: 'WEBAPP_SECURITY_OSV_SCANNER_BIN',
    defaultBinary: 'osv-scanner',
  },
]);

const definitionBySelection = new Map(JOURNEY_ADAPTER_DEFINITIONS.map((item) => [item.selectionId, item]));

export function journeyAdapterDefinitions(selection) {
  if (!Array.isArray(selection) || !selection.length) {
    throw new Error('adapterSelection must be a non-empty array');
  }
  const unique = new Set();
  for (const id of selection) {
    if (typeof id !== 'string' || !definitionBySelection.has(id)) {
      throw new Error(`adapterSelection contains unsupported adapter ${String(id)}`);
    }
    if (unique.has(id)) throw new Error(`adapterSelection repeats ${id}`);
    unique.add(id);
  }
  if (!unique.has('builtin')) throw new Error('adapterSelection must include builtin');
  const canonical = JOURNEY_ADAPTER_DEFINITIONS.filter((item) => unique.has(item.selectionId));
  if (canonical.some((item, index) => item.selectionId !== selection[index])) {
    throw new Error(`adapterSelection must use canonical order: ${canonical.map((item) => item.selectionId).join(', ')}`);
  }
  return canonical;
}

export function journeyPrerequisites(selection) {
  return journeyAdapterDefinitions(selection).filter((item) => item.envVariable);
}

export function classifyJourneyAuditExit(status) {
  const classifications = new Map([
    [0, 'complete'],
    [1, 'policy_threshold_reached'],
    [2, 'setup_or_usage_failed'],
    [3, 'evidence_incomplete'],
  ]);
  if (!classifications.has(status)) {
    throw new Error(`audit returned undocumented exit ${String(status)}`);
  }
  return classifications.get(status);
}

export function sha256Bytes(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function sha256File(path) {
  return sha256Bytes(readFileSync(realpathSync(path)));
}

function canonicalFindings(report, excludedAdapters = []) {
  const excluded = new Set(excludedAdapters);
  return report.findings.filter((finding) => !excluded.has(finding.adapter.id)).map((finding) => ({
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
}

export function reportSemanticDigest(report, options = {}) {
  const excludedAdapters = options.excludedAdapters || [];
  const excluded = new Set(excludedAdapters);
  const semantic = {
    schemaVersion: report.schemaVersion,
    ruleset: {
      digest: report.ruleset.digest,
      adapters: report.ruleset.adapters.filter((item) => !excluded.has(item.id)),
    },
    summary: report.summary,
    coverage: report.coverage.filter((entry) => !excluded.has(entry.adapterId))
      .map((entry) => ({
        adapterId: entry.adapterId, ruleId: entry.ruleId, ruleRevision: entry.ruleRevision,
        status: entry.status, counts: entry.counts, reasons: entry.reasons,
      })).sort((left, right) => `${left.adapterId}/${left.ruleId}`.localeCompare(`${right.adapterId}/${right.ruleId}`)),
    findings: canonicalFindings(report, excludedAdapters),
  };
  return sha256Bytes(JSON.stringify(semantic));
}

export function annotationIdentity(journey) {
  return sha256Bytes(JSON.stringify({
    manualTrace: journey.manualTrace || null,
    falsePositiveClosures: journey.falsePositiveClosures || [],
    unreached: journey.unreached || [],
  }));
}

export function toolSourceIdentity(root) {
  const listed = spawnSync('git', ['-C', root, 'ls-files', '-z', '--',
    'scripts/webapp-security.mjs', 'scripts/project-audit.mjs', 'scripts/run-case-journey.mjs',
    'scripts/lib'], {
    encoding: 'buffer',
  });
  if (listed.status !== 0) throw new Error('cannot enumerate tool source identity');
  const files = listed.stdout.toString('utf8').split('\0').filter(Boolean).sort();
  const hash = createHash('sha256');
  for (const path of files) {
    hash.update(path);
    hash.update('\0');
    hash.update(readFileSync(join(root, path)));
    hash.update('\0');
  }
  const commit = spawnSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
  if (commit.status !== 0) throw new Error('cannot resolve tool source commit');
  return {
    version: readFileSync(join(root, 'VERSION'), 'utf8').trim(),
    commit: commit.stdout.trim(),
    sourceDigest: hash.digest('hex'),
  };
}

export function renderJourneyPrerequisiteBlock(selection) {
  const prerequisites = journeyPrerequisites(selection);
  const lines = [
    '<!-- journey-prerequisites:start -->',
    `The active catalog selects \`${selection.join(', ')}\`. The runner requires only these external binaries:`,
    '',
    '| Adapter | Required version | Environment variable |',
    '|---|---:|---|',
    ...prerequisites.map((item) =>
      `| ${item.displayName} | \`${item.expectedVersion}\` | \`${item.envVariable}\` |`),
    '',
    '```bash',
    ...prerequisites.map((item) =>
      `export ${item.envVariable}=/verified/path/to/${item.defaultBinary}-${item.expectedVersion}`),
    '```',
    '<!-- journey-prerequisites:end -->',
  ];
  return lines.join('\n');
}
