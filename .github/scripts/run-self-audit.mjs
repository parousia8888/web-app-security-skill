#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { policyForFailOn } from '../../scripts/lib/evidence-v2.mjs';
import {
  createReportV3, exitCodeV3, initializeFindingsV3, sourceFindingV3, writeReportBundleV3,
} from '../../scripts/lib/evidence-v3.mjs';
import { compileAuditScope } from '../../scripts/lib/audit-scope.mjs';
import { discoverProject } from '../../scripts/lib/project-discovery.mjs';
import { sourceTraversalLimits } from '../../scripts/lib/project-identity.mjs';
import { auditSource } from '../../scripts/lib/source-audit.mjs';
import { sourceCoverage, sourceRuleset } from '../../scripts/lib/source-rules.mjs';
import { applySuppressions, readSuppressionPolicy } from '../../scripts/lib/suppressions.mjs';

const ROOT = fileURLToPath(new URL('../..', import.meta.url));
const POLICY_PATH = resolve(ROOT, '.github/self-audit-policy.json');
const args = process.argv.slice(2);

function take(name, fallback = null) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
  args.splice(index, 2);
  return value;
}

function loadPolicy() {
  const policy = JSON.parse(readFileSync(POLICY_PATH, 'utf8'));
  const fields = Object.keys(policy).sort();
  if (JSON.stringify(fields) !== JSON.stringify([
    'auditBoundary', 'schemaVersion', 'subjectId', 'suppressionFile',
  ]) || policy.schemaVersion !== 1 || !/^project-[a-f0-9]{32}$/.test(policy.subjectId)
      || typeof policy.suppressionFile !== 'string') {
    throw new Error('repository self-audit policy is invalid');
  }
  return policy;
}

try {
  const output = resolve(take('--out', resolve(ROOT, 'self-audit-report')));
  if (args.length) throw new Error(`unknown argument ${args[0]}`);
  if (existsSync(output)) throw new Error(`self-audit output already exists: ${output}`);
  const generatedAt = process.env.SOURCE_DATE_EPOCH
    ? new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000) : new Date();
  if (Number.isNaN(generatedAt.getTime())) throw new Error('SOURCE_DATE_EPOCH must be numeric');

  const policy = loadPolicy();
  const scopePolicy = compileAuditScope(ROOT, policy.auditBoundary);
  const limits = sourceTraversalLimits(policy.auditBoundary.traversalLimits);
  const discovery = discoverProject(ROOT, { traversalLimits: limits });
  const audit = auditSource(ROOT, limits, {
    gitRoot: ROOT,
    scopeBoundary: policy.auditBoundary,
    manifests: discovery.manifests,
    lockfiles: discovery.lockfiles,
  });
  const ruleset = sourceRuleset(['builtin']);
  const subject = {
    id: policy.subjectId,
    binding: 'persisted',
    scopeDigest: scopePolicy.scopeDigest,
    localPathIncluded: false,
  };
  const suppressionPolicy = readSuppressionPolicy(ROOT, subject.id, generatedAt, {
    gateEnabled: true,
    policyPath: policy.suppressionFile,
  });
  const coverage = sourceCoverage(audit);
  const initialized = initializeFindingsV3(
    audit.findings.map((finding) => sourceFindingV3(finding, ruleset)), coverage,
  );
  const applied = applySuppressions(initialized, suppressionPolicy);
  const findings = applied.findings;
  const report = createReportV3({
    version: readFileSync(resolve(ROOT, 'VERSION'), 'utf8').trim(),
    generatedAt: generatedAt.toISOString(),
    mode: 'audit',
    subject,
    ruleset,
    scope: {
      auditBoundary: policy.auditBoundary,
      authorizationStatus: 'pending',
      checkModes: policy.auditBoundary.checkModes,
      networkAccessPerformed: false,
      runId: 'repository-self-audit',
      traversal: audit.traversal,
      selection: null,
      adapters: [],
      suppression: {
        status: suppressionPolicy.status,
        path: suppressionPolicy.path,
        digest: suppressionPolicy.digest,
        configuredEntries: suppressionPolicy.entries.length,
        suppressedFindings: findings.filter((finding) =>
          finding.disposition.status === 'suppressed').length,
        diagnostics: applied.diagnostics,
      },
    },
    coverage,
    findings,
    policy: policyForFailOn('high'),
    limitations: [
      'This repository self-audit scans the versioned production scope with built-in static rules only; it does not prove the repository is secure.',
      'Tests, intentional vulnerable examples, documentation, generated adoption material and release archives are outside this production-only file-read scope.',
      'No network request, dependency execution or external adapter was performed.',
      'A suppression is a reviewable repository policy disposition, not proof that the matched condition is safe.',
      ...applied.diagnostics.map((diagnostic) =>
        `Suppression ${diagnostic.id || 'file'} was not applied (${diagnostic.code}).`),
    ],
  });
  const files = writeReportBundleV3(report, output);
  console.log(`self-audit report: ${files.json}`);
  console.log(`findings: total=${report.summary.total}; active=${report.summary.activeTotal}; suppressed=${report.summary.suppressedTotal}`);
  console.log('network: none');
  process.exit(exitCodeV3(report));
} catch (error) {
  console.error(`self-audit error: ${error.message}`);
  process.exit(2);
}
