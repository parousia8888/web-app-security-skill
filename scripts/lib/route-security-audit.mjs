import { extractExpressRoutes } from './frameworks/express-route-extractor.mjs';
import { extractNestRoutes } from './frameworks/nest-route-extractor.mjs';
import { extractNextAppRoutes } from './frameworks/next-app-route-extractor.mjs';
import { extractNextServerActions } from './frameworks/next-server-action-extractor.mjs';
import { createAccessPathBudget } from './js-ts-access-path.mjs';
import { callableIndexForGraph } from './js-ts-callable-index.mjs';
import { auditJsTsRouteAuthorization } from './js-ts-route-authorization-audit.mjs';
import { buildJsTsModuleGraph } from './js-ts-module-graph.mjs';

export const ROUTE_INTEGRITY_RULE_ID = 'js-route-security-evidence-incomplete';

const FRAMEWORK_PACKAGES = new Map([
  ['express', 'express'],
  ['nestjs', '@nestjs/common'],
  ['next-app', 'next'],
]);

function frameworkHints(manifests) {
  const packages = new Set();
  for (const manifest of manifests || []) {
    for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
      for (const name of Object.keys(manifest?.[field] || {})) packages.add(name);
    }
  }
  return new Set([...FRAMEWORK_PACKAGES].filter(([, packageName]) => packages.has(packageName))
    .map(([framework]) => framework));
}

function primaryIssues(reasons) {
  const byPath = new Map();
  for (const reason of reasons) {
    const path = reason.path || '<route-analysis>';
    if (!byPath.has(path)) byPath.set(path, { code: reason.code, path });
  }
  return [...byPath.values()];
}

function aggregateReasons(items) {
  const grouped = new Map();
  for (const item of items) {
    const entry = grouped.get(item.code) || { code: item.code, count: 0, samplePaths: [] };
    entry.count += 1;
    if (item.path && entry.samplePaths.length < 10 && !entry.samplePaths.includes(item.path)) {
      entry.samplePaths.push(item.path);
    }
    grouped.set(item.code, entry);
  }
  return [...grouped.values()].sort((left, right) => left.code.localeCompare(right.code));
}

function mergeReasonGroups(...groups) {
  const merged = new Map();
  for (const reason of groups.flat()) {
    const entry = merged.get(reason.code) || { code: reason.code, count: 0, samplePaths: [] };
    entry.count = Math.max(entry.count, reason.count);
    for (const path of reason.samplePaths) {
      if (entry.samplePaths.length < 10 && !entry.samplePaths.includes(path)) entry.samplePaths.push(path);
    }
    merged.set(reason.code, entry);
  }
  return [...merged.values()].sort((left, right) => left.code.localeCompare(right.code));
}

function sumReasonGroups(...groups) {
  const merged = new Map();
  for (const reason of groups.flat()) {
    const entry = merged.get(reason.code) || { code: reason.code, count: 0, samplePaths: [] };
    entry.count += reason.count;
    for (const path of reason.samplePaths) {
      if (entry.samplePaths.length < 10 && !entry.samplePaths.includes(path)) entry.samplePaths.push(path);
    }
    merged.set(reason.code, entry);
  }
  return [...merged.values()].sort((left, right) => left.code.localeCompare(right.code));
}

function normalizeFrameworkCoverage(coverage, hinted, inputCount, inputIssues = []) {
  const applicable = hinted || coverage.counts.eligible > 0;
  if (!applicable) return {
    framework: coverage.framework,
    status: 'not_applicable',
    counts: { discovered: inputCount, eligible: 0, parsed: 0, incomplete: 0 },
    reasons: [],
  };
  if (inputIssues.length) {
    const reasons = mergeReasonGroups(coverage.reasons, aggregateReasons(inputIssues));
    return {
      ...coverage,
      status: 'partial',
      counts: {
        discovered: inputCount,
        eligible: Math.min(inputCount, coverage.counts.eligible + inputIssues.length),
        parsed: coverage.counts.parsed,
        incomplete: Math.max(coverage.counts.incomplete, inputIssues.length),
      },
      reasons,
    };
  }
  if (hinted && coverage.counts.eligible === 0) return {
    ...coverage,
    status: 'partial',
    counts: {
      discovered: Math.max(inputCount, 1), eligible: 1, parsed: 0, incomplete: 1,
    },
    reasons: mergeReasonGroups(coverage.reasons, [{
      code: 'framework_hinted_no_eligible_module', count: 1, samplePaths: [],
    }]),
  };
  if (coverage.status !== 'partial') return { ...coverage, status: 'completed' };
  return coverage;
}

function mergedCoverageReasons(coverageGroups, errorBudget) {
  const grouped = new Map();
  for (const coverage of coverageGroups.filter((item) => item.status === 'partial')) {
    for (const reason of coverage.reasons) {
      const entry = grouped.get(reason.code) || { code: reason.code, count: 0, samplePaths: [] };
      entry.count = Math.max(entry.count, reason.count);
      for (const path of reason.samplePaths) {
        if (entry.samplePaths.length < 10 && !entry.samplePaths.includes(path)) entry.samplePaths.push(path);
      }
      grouped.set(reason.code, entry);
    }
  }
  const output = [];
  let remaining = errorBudget;
  for (const reason of [...grouped.values()].sort((left, right) => left.code.localeCompare(right.code))) {
    const count = Math.min(reason.count, remaining);
    if (count > 0) output.push({ ...reason, count });
    remaining -= count;
  }
  if (remaining > 0) output.push({
    code: 'route_analysis_incomplete', count: remaining,
    samplePaths: [...new Set(output.flatMap((reason) => reason.samplePaths))].slice(0, 10),
  });
  return output;
}

function reportCoverage(frameworkCoverage, accessPathCoverage, inputCount) {
  const coverageGroups = [...frameworkCoverage, accessPathCoverage];
  const applicable = coverageGroups.some((coverage) => coverage.status !== 'not_applicable');
  if (!applicable) return {
    id: `source-${ROUTE_INTEGRITY_RULE_ID}`,
    adapterId: 'builtin-source', ruleId: ROUTE_INTEGRITY_RULE_ID, ruleRevision: '1',
    status: 'not_applicable',
    counts: { discovered: inputCount, eligible: inputCount, scanned: inputCount,
      excluded: 0, skipped: 0, truncated: 0, errors: 0 },
    reasons: [],
  };
  const effectiveInputCount = Math.max(inputCount,
    coverageGroups.some((item) => item.status === 'partial') ? 1 : 0);
  const frameworkErrors = frameworkCoverage.filter((item) => item.status === 'partial')
    .reduce((count, item) => count + item.counts.incomplete, 0);
  const pathErrors = accessPathCoverage.status === 'partial'
    ? accessPathCoverage.counts.errors + accessPathCoverage.counts.truncated
      + accessPathCoverage.counts.skipped
    : 0;
  const errors = Math.min(frameworkErrors + pathErrors, effectiveInputCount);
  const reasons = mergedCoverageReasons(coverageGroups, errors);
  const scanned = Math.max(0, effectiveInputCount - errors);
  return {
    id: `source-${ROUTE_INTEGRITY_RULE_ID}`,
    adapterId: 'builtin-source', ruleId: ROUTE_INTEGRITY_RULE_ID, ruleRevision: '1',
    status: errors ? (scanned ? 'partial' : 'unavailable') : 'completed',
    counts: { discovered: effectiveInputCount, eligible: effectiveInputCount, scanned,
      excluded: 0, skipped: 0, truncated: 0, errors },
    reasons,
  };
}

function combineAccessPathCoverage(...coverages) {
  const applicable = coverages.filter((coverage) => coverage.status !== 'not_applicable');
  const counts = {
    discovered: 0, eligible: 0, scanned: 0, skipped: 0, truncated: 0, errors: 0,
  };
  for (const coverage of coverages) {
    for (const key of Object.keys(counts)) counts[key] += coverage.counts[key];
  }
  return {
    status: !applicable.length ? 'not_applicable'
      : applicable.some((coverage) => coverage.status === 'partial') ? 'partial' : 'completed',
    counts,
    reasons: sumReasonGroups(...coverages.map((coverage) => coverage.reasons)),
  };
}

function mergeFrameworkCoverage(left, right) {
  if (right.status === 'not_applicable') return left;
  if (left.status === 'not_applicable') return right;
  const reasons = new Map();
  for (const reason of [...left.reasons, ...right.reasons]) {
    const current = reasons.get(reason.code) || { code: reason.code, count: 0, samplePaths: [] };
    current.count += reason.count;
    for (const path of reason.samplePaths) {
      if (current.samplePaths.length < 10 && !current.samplePaths.includes(path)) current.samplePaths.push(path);
    }
    reasons.set(reason.code, current);
  }
  return {
    framework: left.framework,
    status: left.status === 'partial' || right.status === 'partial' ? 'partial' : 'completed',
    counts: {
      discovered: Math.max(left.counts.discovered, right.counts.discovered),
      eligible: left.counts.eligible + right.counts.eligible,
      parsed: left.counts.parsed + right.counts.parsed,
      incomplete: left.counts.incomplete + right.counts.incomplete,
    },
    reasons: [...reasons.values()].sort((a, b) => a.code.localeCompare(b.code)),
  };
}

export function analyzeRouteSecurity(sourceFiles, options = {}) {
  const inputIssues = options.inputIssues || [];
  const graph = buildJsTsModuleGraph(sourceFiles, {
    ...(options.graphLimits || {}),
    configFiles: options.configFiles || [],
    packageManifests: options.packageManifestRecords || [],
  });
  for (const issue of inputIssues) graph.reasons.push({ code: issue.code, path: issue.path });
  graph.completed = graph.reasons.length === 0;
  const hints = frameworkHints(options.packageManifests || []);
  const extracted = [
    extractExpressRoutes(graph), extractNestRoutes(graph), extractNextAppRoutes(graph),
  ];
  const routes = extracted.flatMap((result) => result.routes);
  const applicationControls = extracted.flatMap((result) =>
    (result.applicationControls || []).map((control) => ({
      ...control,
      framework: result.coverage.framework,
      role: ['authentication', 'authorization'].includes(control.role)
        ? control.role : 'unclassified',
    })));
  const accessPathContext = options.accessPathContext || {
    budget: createAccessPathBudget(),
    callableIndex: callableIndexForGraph(graph),
  };
  const authorization = auditJsTsRouteAuthorization(graph, routes, { accessPathContext });
  const actionAnalysis = extractNextServerActions(graph, { accessPathContext });
  const rawFrameworkCoverage = extracted.map((result) => result.coverage);
  const nextIndex = rawFrameworkCoverage.findIndex((item) => item.framework === 'next-app');
  if (nextIndex >= 0) rawFrameworkCoverage[nextIndex] = mergeFrameworkCoverage(
    rawFrameworkCoverage[nextIndex], actionAnalysis.coverage,
  );
  const frameworkCoverage = rawFrameworkCoverage.map((item) => normalizeFrameworkCoverage(
    item, hints.has(item.framework), sourceFiles.length + inputIssues.length, inputIssues,
  ));
  const accessPathCoverage = combineAccessPathCoverage(
    authorization.coverage, actionAnalysis.pathCoverage,
  );
  const coverage = reportCoverage(
    frameworkCoverage, accessPathCoverage, sourceFiles.length + inputIssues.length,
  );
  return {
    routes: authorization.routes,
    serverActions: actionAnalysis.serverActions,
    applicationControls,
    coverage: frameworkCoverage,
    accessPathCoverage,
    reportCoverage: coverage,
    graph,
    limitations: [
      'Static route and control evidence does not prove deployed routing, runtime enforcement or authorization correctness.',
      'Dynamic registration, service-layer policy, database row-level security, GraphQL and unsupported framework syntax require manual review.',
      'Access chains are bounded review evidence; they do not create standalone vulnerability findings.',
    ],
  };
}
