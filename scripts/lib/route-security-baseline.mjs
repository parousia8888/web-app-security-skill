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

function actionKey(action) {
  return `${action.framework}\u0000${action.name}\u0000${action.location.path}`;
}

function groupedBy(items, keyFor) {
  const output = new Map();
  for (const item of items) {
    const key = keyFor(item);
    if (!output.has(key)) output.set(key, []);
    output.get(key).push(item);
  }
  return output;
}

function evidenceControl(value) {
  return { state: value.state, signals: value.signals.map((signal) => ({
    kind: signal.kind, origin: signal.origin, location: signal.location,
  })) };
}

function evidenceChain(chain) {
  return {
    status: chain.status, outcome: chain.outcome,
    identity: { state: chain.identity.state, provider: chain.identity.provider,
      signals: chain.identity.signals },
    objectSelectors: chain.objectSelectors, callEdges: chain.callEdges,
    dataOperation: chain.dataOperation,
    authorizationEvidence: chain.authorizationEvidence,
    reason: chain.reason,
    limitations: chain.limitations,
  };
}

function controlSnapshot(route) {
  return JSON.stringify({
    authentication: evidenceControl(route.authentication), authorization: evidenceControl(route.authorization),
    routeScopedControl: { state: route.routeScopedControl.state,
      unclassifiedSignals: route.routeScopedControl.unclassifiedSignals },
    accessChains: route.accessChains.map(evidenceChain),
    operations: route.operations, limitations: route.limitations,
  });
}

function actionSnapshot(action) {
  return JSON.stringify({
    authentication: evidenceControl(action.authentication),
    authorization: evidenceControl(action.authorization),
    actionScopedControl: { state: action.actionScopedControl.state,
      unclassifiedSignals: action.actionScopedControl.unclassifiedSignals },
    accessChains: action.accessChains.map(evidenceChain),
    operations: action.operations, limitations: action.limitations,
  });
}

const CONTROL_ABSENT = new Set(['not_observed', 'incomplete', 'not_applicable']);

function observedAuthorization(chain) {
  return (chain.authorizationEvidence || []).some((evidence) =>
    ['principal', 'tenant'].includes(evidence.category) && evidence.state === 'observed'
      && ['query_predicate', 'post_load_comparison'].includes(evidence.kind));
}

function entryPathIncomplete(entry) {
  return entry.accessChains.some((chain) => chain.status === 'partial')
    || entry.limitations.some((item) => [
      'route-object-authorization-analysis-incomplete',
      'route-access-path-analysis-incomplete',
      'server-action-access-path-analysis-incomplete',
    ].includes(item));
}

function chainKey(chain) {
  const operation = chain.dataOperation;
  if (operation) return [operation.provider, operation.resource, operation.operation,
    chain.objectSelectors.map((item) => `${item.kind}:${item.name}:${item.origin || 'legacy'}`).join(','),
    chain.callEdges.map((edge) => `${edge.kind}:${edge.from}:${edge.to}`).join(',')].join('\u0000');
  return [chain.callEdges.at(-1)?.to || '<none>',
    chain.objectSelectors.map((item) => `${item.kind}:${item.name}:${item.origin || 'legacy'}`).join(','),
    chain.callEdges.map((edge) => `${edge.kind}:${edge.from}:${edge.to}`).join(',')].join('\u0000');
}

function uniqueChains(chains) {
  const groups = groupedBy(chains, chainKey);
  return new Map([...groups].filter(([, items]) => items.length === 1)
    .map(([key, items]) => [key, items[0]]));
}

function degradationReason(current, previous, scopedField) {
  if (!CONTROL_ABSENT.has(previous.authentication.state)
      && CONTROL_ABSENT.has(current.authentication.state)) return 'classified_authentication_disappeared';
  if (!CONTROL_ABSENT.has(previous.authorization.state)
      && CONTROL_ABSENT.has(current.authorization.state)) return 'classified_authorization_disappeared';
  if (previous[scopedField].state === 'classified_controls_observed'
      && current[scopedField].state !== 'classified_controls_observed') {
    return scopedField === 'routeScopedControl'
      ? 'route_scoped_control_degraded' : 'action_scoped_control_degraded';
  }
  const priorChains = uniqueChains(previous.accessChains);
  const currentChains = uniqueChains(current.accessChains);
  for (const [key, prior] of priorChains) {
    const next = currentChains.get(key);
    if (!next) {
      if (observedAuthorization(prior) && !entryPathIncomplete(current)) {
        return 'authorization_evidence_disappeared';
      }
      continue;
    }
    if (observedAuthorization(prior) && !observedAuthorization(next)) {
      return 'authorization_evidence_disappeared';
    }
    if (prior.status === 'completed' && next.status === 'partial') {
      return 'complete_access_path_became_incomplete';
    }
  }
  return null;
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

function recreate(document, routes, serverActions, baseline, limitations = document.limitations) {
  return createRouteSecurityDocument({
    version: document.tool.version,
    generatedAt: document.generatedAt,
    mode: document.mode,
    subject: document.subject,
    routes,
    coverage: document.coverage,
    accessPathCoverage: document.accessPathCoverage,
    applicationControls: document.applicationControls,
    serverActions,
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
  if (previous.schemaVersion !== current.schemaVersion) {
    return recreate(current, current.routes.map((route) => withBaseline(
      route, 'not_comparable', null, 'route_schema_changed',
    )), current.serverActions.map((action) => withBaseline(action,
      'not_comparable', null, 'route_schema_changed')),
    { sourceDigest, compatibility: 'not_comparable', reasonCode: 'route_schema_changed' });
  }
  const analyzerCompatible = previous.analyzer.id === current.analyzer.id
    && previous.analyzer.revision === current.analyzer.revision
    && previous.analyzer.parser.sha256 === current.analyzer.parser.sha256;
  if (!analyzerCompatible) {
    return recreate(current, current.routes.map((route) => withBaseline(
      route, 'not_comparable', null, 'route_analyzer_changed',
    )), current.serverActions.map((action) => withBaseline(action,
      'not_comparable', null, 'route_analyzer_changed')),
    { sourceDigest, compatibility: 'not_comparable', reasonCode: 'route_analyzer_changed' });
  }
  const priorLimits = previous.analyzer.analysisLimits || {};
  const currentLimits = current.analyzer.analysisLimits || {};
  const limitsCompatible = Object.keys(priorLimits).length === Object.keys(currentLimits).length
    && Object.entries(currentLimits).every(([key, value]) => priorLimits[key] === value);
  if (!limitsCompatible) {
    return recreate(current, current.routes.map((route) => withBaseline(
      route, 'not_comparable', null, 'route_analysis_limits_changed',
    )), current.serverActions.map((action) => withBaseline(action,
      'not_comparable', null, 'route_analysis_limits_changed')),
    { sourceDigest, compatibility: 'not_comparable', reasonCode: 'route_analysis_limits_changed' });
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
      const sensitiveUnresolved = (route.stateChanging || route.objectAddressed)
        && route.routeScopedControl.state !== 'classified_controls_observed';
      routes.push(withBaseline(route, 'added', null,
        sensitiveUnresolved ? 'new_sensitive_route_control_unresolved' : 'no_prior_route'));
      continue;
    }
    const prior = previousGroup[0];
    if (!complete.get(route.framework)) {
      routes.push(withBaseline(route, 'unretested', prior, 'current_framework_coverage_incomplete'));
      continue;
    }
    const unchanged = controlSnapshot(route) === controlSnapshot(prior);
    const degradation = unchanged ? null : degradationReason(route, prior, 'routeScopedControl');
    if (!unchanged && !degradation && entryPathIncomplete(route)
        && prior.accessChains.some((chain) => chain.status === 'completed')) {
      routes.push(withBaseline(route, 'unretested', prior,
        'current_access_path_coverage_incomplete'));
    } else {
      routes.push(withBaseline(route, unchanged ? 'unchanged' : 'changed', prior,
        unchanged ? 'same_route_control_evidence'
          : degradation || 'route_control_evidence_changed'));
    }
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

  const currentActionGroups = groupedBy(current.serverActions, actionKey);
  const previousActionGroups = groupedBy(previous.serverActions.filter((action) =>
    !['removed', 'unretested'].includes(action.baseline?.state)), actionKey);
  const actions = [];
  const actionCoverageComplete = complete.get('next-app');
  for (const action of current.serverActions) {
    const key = actionKey(action);
    const currentGroup = currentActionGroups.get(key);
    const previousGroup = previousActionGroups.get(key) || [];
    if (currentGroup.length !== 1 || previousGroup.length > 1) {
      actions.push(withBaseline(action, 'not_comparable', previousGroup[0],
        'duplicate_server_action_identity'));
    } else if (!previousGroup.length) {
      const unresolved = action.accessChains.length
        && action.actionScopedControl.state !== 'classified_controls_observed';
      actions.push(withBaseline(action, 'added', null,
        unresolved ? 'new_server_action_control_unresolved' : 'no_prior_server_action'));
    } else if (!actionCoverageComplete) {
      actions.push(withBaseline(action, 'unretested', previousGroup[0],
        'current_framework_coverage_incomplete'));
    } else {
      const prior = previousGroup[0];
      const unchanged = actionSnapshot(action) === actionSnapshot(prior);
      const degradation = unchanged ? null : degradationReason(action, prior, 'actionScopedControl');
      if (!unchanged && !degradation && entryPathIncomplete(action)
          && prior.accessChains.some((chain) => chain.status === 'completed')) {
        actions.push(withBaseline(action, 'unretested', prior,
          'current_access_path_coverage_incomplete'));
      } else {
        actions.push(withBaseline(action, unchanged ? 'unchanged' : 'changed', prior,
          unchanged ? 'same_server_action_control_evidence'
            : degradation || 'server_action_control_evidence_changed'));
      }
    }
  }
  for (const prior of previous.serverActions.filter((action) =>
    !['removed', 'unretested'].includes(action.baseline?.state))) {
    if (currentActionGroups.has(actionKey(prior))) continue;
    actions.push(withBaseline({ ...prior, limitations: [...new Set([...prior.limitations,
      actionCoverageComplete ? 'baseline-server-action-not-observed-current'
        : 'baseline-server-action-current-check-incomplete'])].sort() },
    actionCoverageComplete ? 'removed' : 'unretested', prior,
    actionCoverageComplete ? 'server_action_not_observed_after_completed_check'
      : 'current_framework_coverage_incomplete'));
  }

  return recreate(current, routes, actions,
    { sourceDigest, compatibility: 'compatible', reasonCode: null },
    [...new Set([...current.limitations,
      'Removed and unretested baseline routes are retained as historical records and are not current route observations.'])]);
}

const ROUTE_REGRESSION_REASONS = new Set([
  'classified_authentication_disappeared', 'classified_authorization_disappeared',
  'route_scoped_control_degraded', 'action_scoped_control_degraded',
  'authorization_evidence_disappeared', 'complete_access_path_became_incomplete',
  'new_sensitive_route_control_unresolved', 'new_server_action_control_unresolved',
]);

export function routeSecurityRegressions(document) {
  return [...document.routes, ...document.serverActions].filter((item) =>
    ROUTE_REGRESSION_REASONS.has(item.baseline?.reasonCode));
}

export function readRouteSecurityBaseline(reportPath) {
  const directory = dirname(reportPath);
  const jsonPath = join(directory, 'route-security.json');
  const markdownPath = join(directory, 'route-security.md');
  const digestPath = join(directory, 'route-security.sha256');
  if (!existsSync(jsonPath) && !existsSync(digestPath)) return null;
  if (!existsSync(jsonPath) || !existsSync(digestPath)) {
    throw new Error('route baseline artifact or digest sidecar is missing');
  }
  const rawBytes = readFileSync(jsonPath);
  const digestLines = readFileSync(digestPath, 'utf8').trim().split('\n');
  const entries = new Map();
  for (const line of digestLines) {
    const match = /^([a-f0-9]{64})  (route-security\.(?:json|md))$/.exec(line);
    if (!match || entries.has(match[2])) throw new Error('route baseline digest sidecar is invalid');
    entries.set(match[2], match[1]);
  }
  if (!entries.has('route-security.json') || sha256(rawBytes) !== entries.get('route-security.json')) {
    throw new Error('route baseline bytes do not match the recorded digest');
  }
  if (entries.has('route-security.md')) {
    if (!existsSync(markdownPath)
        || sha256(readFileSync(markdownPath)) !== entries.get('route-security.md')) {
      throw new Error('route baseline Markdown does not match the recorded digest');
    }
  }
  let document;
  try { document = JSON.parse(rawBytes.toString('utf8')); } catch {
    throw new Error(`invalid route baseline JSON: ${basename(jsonPath)}`);
  }
  assertRouteSecurityDocument(document);
  return { document, sourceDigest: entries.get('route-security.json'), rawBytes };
}

export function routeSecurityJson(document) {
  assertRouteSecurityDocument(document);
  return `${JSON.stringify(document, null, 2)}\n`;
}

export function routeSecurityDigest(jsonBytes) {
  return sha256(jsonBytes);
}

export function routeSecurityDigestManifest(jsonBytes, markdownBytes) {
  return `${sha256(jsonBytes)}  route-security.json\n${sha256(markdownBytes)}  route-security.md\n`;
}
