#!/usr/bin/env node
import { existsSync, readFileSync, statSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { policyForFailOn } from './lib/evidence-v2.mjs';
import {
  assertComparableBaselineV3, compareFindingsV3, createFindingV3, createReportV3, exitCodeV3,
  initializeFindingsV3, readBaselineV3, sourceFindingV3, writeReportBundleV3,
} from './lib/evidence-v3.mjs';
import { auditSource, renderPatch } from './lib/source-audit.mjs';
import {
  parseAdapterTimeout, resolveAdapterSelection,
} from './lib/adapter-definitions.mjs';
import { runExternalAdapters } from './lib/external-adapters.mjs';
import { buildScope, discoverProject } from './lib/project-discovery.mjs';
import {
  ephemeralSubject, readProjectIdentity, sourceAuditBoundary, validatePersistedScope,
  sourceTraversalLimits,
} from './lib/project-identity.mjs';
import { sourceCoverage, sourceRuleForAdapter, sourceRuleset } from './lib/source-rules.mjs';
import { sourceRuleExplanation } from './lib/source-rule-registry.mjs';
import { createGitDiffScope, selectDiffFindings, selectDiffRoutes } from './lib/git-diff-scope.mjs';
import { assertRouteSecurityDocument } from './lib/route-security-contract.mjs';
import {
  compareRouteSecurityDocuments, readRouteSecurityBaseline, routeSecurityDigest, routeSecurityJson,
  routeSecurityRegressions,
} from './lib/route-security-baseline.mjs';
import { createRouteSecurityDocument } from './lib/route-security-model.mjs';
import { renderRouteSecurityMarkdown } from './lib/route-security-renderer.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const args = process.argv.slice(2);
const mode = args.shift();

function usage(code, message) {
  if (message) console.error(`error: ${message}`);
  console.log(`webapp-security ${mode || 'audit'} <project-or-run> [options]

Options:
  --out <directory>       Output directory (default: run directory or a new project run)
  --name <basename>       Report basename (default: report)
  --baseline <report>     Required by retest; optional comparison for audit
  --since <git-ref>       Show built-in findings on lines added since a commit
  --staged                Audit the Git index and show findings in staged changes
  --fail-on <severity>    critical, high, medium, low, or never (default: high)
  --fail-on-domain <d=t> Override one domain threshold; may be repeated
  --fail-on-route-regression
                           Exit 1 for defined route/action control regressions against a baseline
  --max-depth <n>         Maximum directory depth, 1..64 (default: 12)
  --max-files <n>         Maximum discovered files, 1..200000 (default: 20000)
  --max-entries <n>       Maximum directory entries, 1..500000 (default: 50000)
  --max-file-bytes <n>    Maximum candidate bytes, 1024..16777216 (default: 1048576)
  --profile <id>          deep selects built-in plus all four external adapters
  --adapter <id>           builtin, checkov, gitleaks, opengrep, osv, or all; repeatable (default: builtin)
  --adapter-timeout <sec> External adapter timeout, 1..600 (default: 120)
  --acknowledge-alert-policy
                           Allow selected external adapter findings to use the configured gate
`);
  process.exit(code);
}

function take(name, fallback = null) {
  const index = args.indexOf(name);
  if (index === -1) return fallback;
  if (!args[index + 1] || args[index + 1].startsWith('--')) usage(2, `${name} requires a value`);
  const value = args[index + 1];
  args.splice(index, 2);
  return value;
}

function takeAll(name) {
  const values = [];
  while (args.includes(name)) values.push(take(name));
  return values;
}

if (!['audit', 'retest'].includes(mode)) usage(2, 'mode must be audit or retest');
if (args.includes('-h') || args.includes('--help')) usage(0);
const outArg = take('--out');
const name = take('--name', 'report');
const baselinePath = take('--baseline');
const sinceRef = take('--since');
const staged = args.includes('--staged');
if (staged) args.splice(args.indexOf('--staged'), 1);
const failOn = take('--fail-on', 'high');
const failOnDomains = takeAll('--fail-on-domain');
const profile = take('--profile');
const adapterValues = takeAll('--adapter');
const adapterTimeoutArg = take('--adapter-timeout');
const gitleaksHistoryRef = process.env.WEBAPP_SECURITY_GITLEAKS_HISTORY_REF || null;
const acknowledgeAlertPolicy = args.includes('--acknowledge-alert-policy');
if (acknowledgeAlertPolicy) args.splice(args.indexOf('--acknowledge-alert-policy'), 1);
const failOnRouteRegression = args.includes('--fail-on-route-regression');
if (failOnRouteRegression) args.splice(args.indexOf('--fail-on-route-regression'), 1);
const limitArgs = {
  maxDepth: take('--max-depth'),
  maxFiles: take('--max-files'),
  maxEntries: take('--max-entries'),
  maxFileBytes: take('--max-file-bytes'),
};
const targetArg = args.shift();
if (!targetArg) usage(2, 'project-or-run is required');
if (args.length) usage(2, `unknown argument ${args[0]}`);
if (!/^[a-zA-Z0-9._-]+$/.test(name)) usage(2, '--name contains unsupported characters');
if (!['critical', 'high', 'medium', 'low', 'never'].includes(failOn)) usage(2, '--fail-on is invalid');
if (mode === 'retest' && !baselinePath) usage(2, 'retest requires --baseline <report>');
if (failOnRouteRegression && !baselinePath) {
  usage(2, '--fail-on-route-regression requires --baseline <report>');
}
if (sinceRef !== null && staged) usage(2, '--since and --staged are mutually exclusive');
if ((sinceRef !== null || staged) && mode !== 'audit') usage(2, 'diff scope is only supported by audit');
if ((sinceRef !== null || staged) && baselinePath) usage(2, 'diff scope cannot be combined with --baseline');
if (profile !== null && adapterValues.length) usage(2, '--profile cannot be combined with --adapter');
if (gitleaksHistoryRef !== null && !/^[a-f0-9]{40}$/.test(gitleaksHistoryRef)) {
  usage(2, 'WEBAPP_SECURITY_GITLEAKS_HISTORY_REF must be an exact 40-character commit');
}

function timestamp() {
  const now = process.env.SOURCE_DATE_EPOCH ? new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000) : new Date();
  if (Number.isNaN(now.getTime())) usage(2, 'SOURCE_DATE_EPOCH must be numeric');
  return now;
}

function evidenceConflicts(output, reportName, includeRoute) {
  return [
    `${reportName}.json`, `${reportName}.md`, `${reportName}.html`, `${reportName}.sarif`,
    `${reportName}.junit.xml`, `${reportName}.sha256`, 'proposed.patch',
    ...(includeRoute ? ['route-security.json', 'route-security.md', 'route-security.sha256'] : []),
  ].filter((file) => existsSync(join(output, file)));
}

let activeDiffScope = null;
try {
  const target = resolve(targetArg);
  if (!existsSync(target) || !statSync(target).isDirectory()) throw new Error(`target must be an existing directory: ${targetArg}`);
  const scopePath = join(target, 'security-scope.yml');
  const now = timestamp();
  let localScope;
  let projectRoot;
  let output;
  let subject;
  let persistScope = false;
  let limits;
  let selectedAdapters;
  let adapterTimeoutSeconds;
  let diffScope = null;

  if (existsSync(scopePath)) {
    localScope = validatePersistedScope(JSON.parse(readFileSync(scopePath, 'utf8')));
    const suppliedLimits = Object.values(limitArgs).some((value) => value !== null);
    if (suppliedLimits) {
      const requested = sourceTraversalLimits(Object.fromEntries(Object.entries(limitArgs)
        .filter(([, value]) => value !== null).map(([key, value]) => [key, Number(value)])));
      if (JSON.stringify(requested) !== JSON.stringify(localScope.auditBoundary.traversalLimits)) {
        throw new Error('traversal limits are fixed by the persisted scope; create a new run to change them');
      }
    }
    limits = sourceTraversalLimits(localScope.auditBoundary.traversalLimits);
    selectedAdapters = localScope.auditBoundary.adapters || ['builtin'];
    adapterTimeoutSeconds = localScope.auditBoundary.adapterTimeoutSeconds || 120;
    if ((adapterValues.length || profile !== null)
        && JSON.stringify(resolveAdapterSelection(adapterValues, profile)) !== JSON.stringify(selectedAdapters)) {
      throw new Error('adapter selection is fixed by the persisted scope; create a new run to change it');
    }
    if (adapterTimeoutArg !== null && parseAdapterTimeout(adapterTimeoutArg) !== adapterTimeoutSeconds) {
      throw new Error('adapter timeout is fixed by the persisted scope; create a new run to change it');
    }
    projectRoot = resolve(localScope.target.projectRoot);
    const identity = readProjectIdentity(projectRoot);
    if (!identity || identity.subjectId !== localScope.subject.id) {
      throw new Error('scope subject does not match the current project identity');
    }
    subject = localScope.subject;
    output = resolve(outArg || target);
  } else {
    if (mode === 'retest' || baselinePath) {
      throw new Error('baseline comparison requires a persisted run created by webapp-security start');
    }
    limits = sourceTraversalLimits(Object.fromEntries(Object.entries(limitArgs)
      .filter(([, value]) => value !== null).map(([key, value]) => [key, Number(value)])));
    selectedAdapters = resolveAdapterSelection(adapterValues, profile);
    adapterTimeoutSeconds = parseAdapterTimeout(adapterTimeoutArg === null ? undefined : adapterTimeoutArg);
    const auditBoundary = sourceAuditBoundary(limits, {
      adapters: selectedAdapters, timeoutSeconds: adapterTimeoutSeconds,
    });
    const discovery = discoverProject(target, { traversalLimits: limits });
    projectRoot = discovery.projectRoot;
    output = resolve(outArg || join(projectRoot, '.webapp-security', 'runs', `audit-${now.toISOString().replace(/[:.]/g, '-')}`));
    subject = ephemeralSubject(auditBoundary);
    localScope = buildScope(discovery, {
      version: readFileSync(join(ROOT, 'VERSION'), 'utf8').trim(),
      generatedAt: now.toISOString(),
      runId: basename(output),
      runDirectory: output,
      subject,
      auditBoundary,
    });
    persistScope = true;
  }

  if (!existsSync(projectRoot) || !statSync(projectRoot).isDirectory()) throw new Error('scope projectRoot no longer exists');
  const diffMode = sinceRef !== null || staged;
  if (diffMode && selectedAdapters.some((adapter) => adapter !== 'builtin')) {
    throw new Error('diff scope supports the built-in adapter only');
  }
  if (diffMode) diffScope = createGitDiffScope(projectRoot, {
    mode: staged ? 'staged' : 'since', ref: sinceRef,
  });
  activeDiffScope = diffScope;
  const externalGateEnabled = failOn !== 'never'
    || failOnDomains.some((value) => !value.endsWith('=never'));
  if (selectedAdapters.some((adapter) => adapter !== 'builtin') && externalGateEnabled && !acknowledgeAlertPolicy) {
    throw new Error('external adapter gating requires --acknowledge-alert-policy; use --fail-on never for evidence-only execution');
  }
  if (gitleaksHistoryRef !== null && !selectedAdapters.includes('gitleaks')) {
    throw new Error('WEBAPP_SECURITY_GITLEAKS_HISTORY_REF requires the gitleaks adapter');
  }
  const routeEnabled = selectedAdapters.includes('builtin');
  const conflicts = evidenceConflicts(output, name, routeEnabled);
  if (conflicts.length) throw new Error(`refusing to overwrite existing evidence: ${conflicts.join(', ')}`);

  const ruleset = sourceRuleset(selectedAdapters);
  const audit = selectedAdapters.includes('builtin')
    ? auditSource(diffScope?.auditRoot || projectRoot, limits, { gitRoot: projectRoot })
    : { findings: [], coverage: {}, traversal: null };
  const rawFindings = diffScope ? selectDiffFindings(audit, diffScope) : audit.findings;
  const external = diffScope ? [] : runExternalAdapters(
    projectRoot, localScope.target.lockfiles || [], selectedAdapters, {
      timeoutSeconds: adapterTimeoutSeconds, gitleaksHistoryRef,
    },
  );
  const coverage = [
    ...(selectedAdapters.includes('builtin') ? sourceCoverage(audit) : []),
    ...external.flatMap((result) => result.coverage),
  ];
  const current = [
    ...rawFindings.map((finding) => sourceFindingV3(finding, ruleset)),
    ...external.flatMap((result) => result.findings).map((finding) => {
      const rule = sourceRuleForAdapter(finding.adapterId, finding.ruleId, selectedAdapters);
      return createFindingV3({
        ruleset,
        adapterId: finding.adapterId,
        rule,
        title: finding.title,
        severity: finding.severity,
        state: finding.state,
        summary: finding.summary,
        location: finding.location,
        evidence: finding.evidence,
        remediation: finding.remediation,
        retest: finding.retest,
        explanation: sourceRuleExplanation(finding.adapterId, finding.ruleId, finding),
      });
    }),
  ];
  let baseline = null;
  let findings;
  if (baselinePath) {
    const loaded = readBaselineV3(resolve(baselinePath));
    baseline = assertComparableBaselineV3(subject, loaded.report, loaded.rawBytes);
    if (baseline.sourceDigest !== loaded.sourceDigest) throw new Error('baseline digest metadata is inconsistent');
    findings = compareFindingsV3(current, coverage, loaded.report, ruleset);
  } else {
    findings = initializeFindingsV3(current, coverage);
  }

  const report = createReportV3({
    version: readFileSync(join(ROOT, 'VERSION'), 'utf8').trim(),
    generatedAt: now.toISOString(),
    mode,
    subject,
    ruleset,
    scope: {
      auditBoundary: localScope.auditBoundary,
      authorizationStatus: localScope.authorization?.status || 'pending',
      checkModes: localScope.auditBoundary.checkModes,
      networkAccessPerformed: external.some((result) => result.networkAccessPerformed),
      runId: localScope.run?.id || null,
      traversal: audit.traversal,
      selection: diffScope?.selection || null,
      adapters: external.map((result) => ({
        id: result.adapter.id,
        expectedVersion: result.adapter.version,
        observedVersion: result.identity.observedVersion || null,
        status: result.identity.status,
      })),
    },
    coverage,
    findings,
    baseline,
    policy: policyForFailOn(failOn, failOnDomains),
    limitations: [
      'Only the recorded built-in and selected external adapters ran; agent-guided API, identity, LLM, data-layer and deployment/runtime review did not run.',
      external.some((result) => result.networkAccessPerformed)
        ? 'OSV-Scanner may query the public OSV service and Checkov may query PyPI for version metadata when selected; no project dependency was executed and Checkov was not given project source over the network.'
        : 'No network request or dependency execution was performed.',
      'Suspected findings require deployment or runtime evidence before confirmation.',
      ...(gitleaksHistoryRef ? [
        `Gitleaks committed-history evidence was bounded to commits reachable from exact commit ${gitleaksHistoryRef}; unrelated repository refs were excluded.`,
      ] : []),
      ...(diffScope ? [
        `This ${diffScope.selection.mode} report filters built-in findings to changed inputs; a clean result does not establish whole-repository safety.`,
        diffScope.selection.mode === 'since'
          ? `Untracked files are outside the Git diff and were excluded (${diffScope.selection.untrackedFilesExcluded} observed).`
          : 'The audit used an isolated Git index snapshot; unstaged working-tree content was excluded.',
        'Diff-scoped audit does not support baseline/retest lifecycle claims or external adapters.',
      ] : []),
    ],
  });

  let routeDocument = null;
  if (routeEnabled) {
    const routeAnalysis = audit.routeAnalysis;
    const selectedRoutes = diffScope
      ? selectDiffRoutes(routeAnalysis.routes, diffScope) : routeAnalysis.routes;
    const routeLimitations = [
      ...routeAnalysis.limitations,
      ...(diffScope ? [
        `This ${diffScope.selection.mode} artifact filters route records to changed declarations or control evidence after whole-project context analysis.`,
        diffScope.selection.mode === 'since'
          ? `Untracked files were outside the Git diff (${diffScope.selection.untrackedFilesExcluded} observed).`
          : 'The route analysis used the isolated Git index snapshot; unstaged content was excluded.',
      ] : []),
    ];
    routeDocument = createRouteSecurityDocument({
      version: report.tool.version, generatedAt: now.toISOString(), mode, subject,
      routes: selectedRoutes, coverage: routeAnalysis.coverage,
      applicationControls: routeAnalysis.applicationControls,
      serverActions: routeAnalysis.serverActions || [], limitations: routeLimitations,
    });
    if (baselinePath) {
      const routeBaseline = readRouteSecurityBaseline(resolve(baselinePath));
      if (routeBaseline) {
        routeDocument = compareRouteSecurityDocuments(
          routeDocument, routeBaseline.document, routeBaseline.sourceDigest,
        );
      } else {
        routeDocument = createRouteSecurityDocument({
          version: routeDocument.tool.version, generatedAt: routeDocument.generatedAt,
          mode: routeDocument.mode, subject: routeDocument.subject, routes: routeDocument.routes,
          coverage: routeDocument.coverage, applicationControls: routeDocument.applicationControls,
          serverActions: routeDocument.serverActions,
          limitations: [...routeDocument.limitations,
            'The report baseline has no route-security companion artifact, so route baseline comparison was not attempted.'],
        });
      }
    }
  }

  const routeJson = routeDocument ? routeSecurityJson(routeDocument) : null;
  const files = writeReportBundleV3(report, output, name, { additionalFiles: [
    ...(persistScope ? [{ name: 'security-scope.yml', json: localScope, sanitize: false }] : []),
    { name: 'proposed.patch', content: renderPatch(rawFindings) },
    ...(routeDocument ? [
      { key: 'routeJson', name: 'route-security.json', content: routeJson, sanitize: false,
        validate: (bytes) => assertRouteSecurityDocument(JSON.parse(bytes.toString('utf8'))) },
      { key: 'routeMarkdown', name: 'route-security.md',
        content: renderRouteSecurityMarkdown(routeDocument), sanitize: false },
      { key: 'routeDigest', name: 'route-security.sha256',
        content: `${routeSecurityDigest(routeJson)}  route-security.json\n`, sanitize: false },
    ] : []),
  ] });
  console.log(`report:    ${files.json}`);
  if (routeDocument) {
    console.log(`routes:    ${files.routeMarkdown} (${routeDocument.summary.total} records)`);
    if (routeDocument.baseline) {
      console.log(`route-regressions: ${routeSecurityRegressions(routeDocument).length}`);
    }
  }
  console.log(`findings:  ${report.summary.total}`);
  console.log(`subject:   ${report.subject.id} (${report.subject.binding})`);
  console.log(`states:    confirmed=${report.summary.byState.confirmed}, suspected=${report.summary.byState.suspected}, unknown=${report.summary.byState.unknown}`);
  console.log(`baseline:  new=${report.summary.byBaseline.new}, fixed=${report.summary.byBaseline.fixed}, unchanged=${report.summary.byBaseline.unchanged}, regressed=${report.summary.byBaseline.regressed}, unretested=${report.summary.byBaseline.unretested}, not_comparable=${report.summary.byBaseline.not_comparable}`);
  console.log(`network:   ${external.some((result) => result.networkAccessPerformed) ? 'selected adapter metadata/advisory query may occur' : 'none'}`);
  diffScope?.cleanup();
  activeDiffScope = null;
  const reportExit = exitCodeV3(report);
  const routeGateFailed = failOnRouteRegression && routeDocument
    && routeSecurityRegressions(routeDocument).length > 0;
  process.exit(reportExit || (routeGateFailed ? 1 : 0));
} catch (error) {
  activeDiffScope?.cleanup();
  usage(2, error.message);
}
