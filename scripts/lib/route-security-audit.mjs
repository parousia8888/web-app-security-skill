import { extractExpressRoutes } from './frameworks/express-route-extractor.mjs';
import { extractNestRoutes } from './frameworks/nest-route-extractor.mjs';
import { extractNextAppRoutes } from './frameworks/next-app-route-extractor.mjs';
import { extractNextServerActions } from './frameworks/next-server-action-extractor.mjs';
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

function normalizeFrameworkCoverage(coverage, hinted, inputCount) {
  const applicable = hinted || coverage.counts.eligible > 0;
  if (!applicable) return {
    framework: coverage.framework,
    status: 'not_applicable',
    counts: { discovered: inputCount, eligible: 0, parsed: 0, incomplete: 0 },
    reasons: [],
  };
  if (coverage.status !== 'partial') return { ...coverage, status: 'completed' };
  return coverage;
}

function mergedCoverageReasons(frameworkCoverage, errorBudget) {
  const grouped = new Map();
  for (const coverage of frameworkCoverage.filter((item) => item.status === 'partial')) {
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

function reportCoverage(frameworkCoverage, inputCount) {
  const applicable = frameworkCoverage.some((coverage) => coverage.status !== 'not_applicable');
  if (!applicable) return {
    id: `source-${ROUTE_INTEGRITY_RULE_ID}`,
    adapterId: 'builtin-source', ruleId: ROUTE_INTEGRITY_RULE_ID, ruleRevision: '1',
    status: 'not_applicable',
    counts: { discovered: inputCount, eligible: inputCount, scanned: inputCount,
      excluded: 0, skipped: 0, truncated: 0, errors: 0 },
    reasons: [],
  };
  const errors = Math.min(frameworkCoverage.filter((item) => item.status === 'partial')
    .reduce((count, item) => count + item.counts.incomplete, 0), inputCount);
  const reasons = mergedCoverageReasons(frameworkCoverage, errors);
  const scanned = Math.max(0, inputCount - errors);
  return {
    id: `source-${ROUTE_INTEGRITY_RULE_ID}`,
    adapterId: 'builtin-source', ruleId: ROUTE_INTEGRITY_RULE_ID, ruleRevision: '1',
    status: errors ? (scanned ? 'partial' : 'unavailable') : 'completed',
    counts: { discovered: inputCount, eligible: inputCount, scanned,
      excluded: 0, skipped: 0, truncated: 0, errors },
    reasons,
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
  const actionAnalysis = extractNextServerActions(graph);
  const frameworkCoverage = extracted.map((result) => normalizeFrameworkCoverage(
    result.coverage, hints.has(result.coverage.framework), sourceFiles.length + inputIssues.length,
  ));
  const nextIndex = frameworkCoverage.findIndex((item) => item.framework === 'next-app');
  if (nextIndex >= 0) frameworkCoverage[nextIndex] = mergeFrameworkCoverage(
    frameworkCoverage[nextIndex], actionAnalysis.coverage,
  );
  const routes = extracted.flatMap((result) => result.routes);
  const applicationControls = extracted.flatMap((result) =>
    (result.applicationControls || []).map((control) => ({
      ...control,
      framework: result.coverage.framework,
      role: ['authentication', 'authorization'].includes(control.role)
        ? control.role : 'unclassified',
    })));
  const authorization = auditJsTsRouteAuthorization(graph, routes);
  const coverage = reportCoverage(frameworkCoverage, sourceFiles.length + inputIssues.length);
  return {
    routes: authorization.routes,
    serverActions: actionAnalysis.serverActions,
    applicationControls,
    coverage: frameworkCoverage,
    reportCoverage: coverage,
    experimentalFindings: authorization.findings,
    graph,
    limitations: [
      'Static route and control evidence does not prove deployed routing, runtime enforcement or authorization correctness.',
      'Dynamic registration, service-layer policy, database row-level security, GraphQL and unsupported framework syntax require manual review.',
      'The direct Prisma object-authorization rule is experimental until its ordinary-project review is complete.',
    ],
  };
}
