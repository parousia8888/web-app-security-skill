import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { assertRouteSecurityDocument } from './route-security-contract.mjs';
import { createRouteSecurityDocument } from './route-security-model.mjs';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function routeKey(route) {
  return `${route.framework}\u0000${route.method}\u0000${route.path ?? '<dynamic>'}`;
}

function grouped(routes) {
  const output = new Map();
  for (const route of routes) {
    const key = routeKey(route);
    if (!output.has(key)) output.set(key, []);
    output.get(key).push(route);
  }
  return output;
}

function controlSnapshot(route) {
  const control = (value) => ({ state: value.state, signals: value.signals.map((signal) => ({
    kind: signal.kind, origin: signal.origin, location: signal.location,
  })) });
  return JSON.stringify({
    authentication: control(route.authentication), authorization: control(route.authorization),
    operations: route.operations, limitations: route.limitations,
  });
}

function withBaseline(route, state, previous = null, reasonCode = null) {
  return {
    ...route,
    baseline: {
      state,
      priorFingerprint: previous?.fingerprint || null,
      reasonCode,
    },
  };
}

function recreate(document, routes, baseline, limitations = document.limitations) {
  return createRouteSecurityDocument({
    version: document.tool.version,
    generatedAt: document.generatedAt,
    mode: document.mode,
    subject: document.subject,
    routes,
    coverage: document.coverage,
    limitations,
    baseline,
  });
}

export function compareRouteSecurityDocuments(current, previous, sourceDigest) {
  assertRouteSecurityDocument(current);
  assertRouteSecurityDocument(previous);
  if (previous.subject.id !== current.subject.id || previous.subject.scopeDigest !== current.subject.scopeDigest) {
    throw new Error('route baseline subject or scope does not match the current project');
  }
  const analyzerCompatible = previous.analyzer.id === current.analyzer.id
    && previous.analyzer.revision === current.analyzer.revision
    && previous.analyzer.parser.sha256 === current.analyzer.parser.sha256;
  if (!analyzerCompatible) {
    return recreate(current, current.routes.map((route) => withBaseline(
      route, 'not_comparable', null, 'route_analyzer_changed',
    )), { sourceDigest, compatibility: 'not_comparable', reasonCode: 'route_analyzer_changed' });
  }

  const currentGroups = grouped(current.routes);
  const previousGroups = grouped(previous.routes.filter((route) =>
    !['removed', 'unretested'].includes(route.baseline?.state)));
  const complete = new Map(current.coverage.map((coverage) =>
    [coverage.framework, coverage.status === 'completed']));
  const routes = [];
  for (const route of current.routes) {
    const key = routeKey(route);
    const currentGroup = currentGroups.get(key);
    const previousGroup = previousGroups.get(key) || [];
    if (route.pathKind === 'dynamic' || currentGroup.length !== 1 || previousGroup.length > 1) {
      routes.push(withBaseline(route, 'not_comparable', previousGroup[0],
        route.pathKind === 'dynamic' ? 'dynamic_route_identity' : 'duplicate_route_identity'));
      continue;
    }
    if (!previousGroup.length) {
      routes.push(withBaseline(route, 'added', null, 'no_prior_route'));
      continue;
    }
    const prior = previousGroup[0];
    if (!complete.get(route.framework)) {
      routes.push(withBaseline(route, 'unretested', prior, 'current_framework_coverage_incomplete'));
      continue;
    }
    const unchanged = controlSnapshot(route) === controlSnapshot(prior);
    routes.push(withBaseline(route, unchanged ? 'unchanged' : 'changed', prior,
      unchanged ? 'same_route_control_evidence' : 'route_control_evidence_changed'));
  }

  for (const prior of previous.routes.filter((route) =>
    !['removed', 'unretested'].includes(route.baseline?.state))) {
    if (currentGroups.has(routeKey(prior))) continue;
    const comparable = prior.pathKind !== 'dynamic' && previousGroups.get(routeKey(prior))?.length === 1;
    const completed = complete.get(prior.framework);
    const state = !comparable ? 'not_comparable' : completed ? 'removed' : 'unretested';
    const reason = !comparable ? 'prior_route_identity_ambiguous'
      : completed ? 'route_not_observed_after_completed_check' : 'current_framework_coverage_incomplete';
    routes.push(withBaseline({
      ...prior,
      limitations: [...new Set([...prior.limitations,
        state === 'removed' ? 'baseline-route-not-observed-current' : 'baseline-route-current-check-incomplete'])].sort(),
    }, state, prior, reason));
  }

  return recreate(current, routes,
    { sourceDigest, compatibility: 'compatible', reasonCode: null },
    [...new Set([...current.limitations,
      'Removed and unretested baseline routes are retained as historical records and are not current route observations.'])]);
}

export function readRouteSecurityBaseline(reportPath) {
  const directory = dirname(reportPath);
  const jsonPath = join(directory, 'route-security.json');
  const digestPath = join(directory, 'route-security.sha256');
  if (!existsSync(jsonPath) && !existsSync(digestPath)) return null;
  if (!existsSync(jsonPath) || !existsSync(digestPath)) {
    throw new Error('route baseline artifact or digest sidecar is missing');
  }
  const rawBytes = readFileSync(jsonPath);
  const match = /^([a-f0-9]{64})  route-security\.json$/.exec(readFileSync(digestPath, 'utf8').trim());
  if (!match || sha256(rawBytes) !== match[1]) throw new Error('route baseline bytes do not match the recorded digest');
  let document;
  try { document = JSON.parse(rawBytes.toString('utf8')); } catch {
    throw new Error(`invalid route baseline JSON: ${basename(jsonPath)}`);
  }
  assertRouteSecurityDocument(document);
  return { document, sourceDigest: match[1], rawBytes };
}

export function routeSecurityJson(document) {
  assertRouteSecurityDocument(document);
  return `${JSON.stringify(document, null, 2)}\n`;
}

export function routeSecurityDigest(jsonBytes) {
  return sha256(jsonBytes);
}
