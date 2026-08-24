import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { posix } from 'node:path';

export const ROUTE_FRAMEWORKS = ['express', 'nestjs', 'next-app'];
export const CONTROL_STATES = [
  'local_observed', 'inherited_observed', 'candidate_observed',
  'not_observed', 'incomplete', 'not_applicable',
];
export const ROUTE_SCOPED_CONTROL_STATES = [
  'classified_controls_observed', 'unclassified_control_observed',
  'no_route_scoped_control_observed',
];
export const APPLICATION_CONTROL_ROLES = ['authentication', 'authorization', 'unclassified'];
export const ACCESS_CHAIN_STATUSES = ['completed', 'partial', 'not_applicable'];
export const ACCESS_CHAIN_OUTCOMES = [
  'principal_constraint_observed', 'external_policy_required',
  'principal_constraint_not_observed', 'no_supported_object_operation', 'incomplete',
];
export const REVIEW_PRIORITIES = [
  'review_first', 'review_next', 'review_later', 'no_automatic_priority',
];
export const ROUTE_METHODS = [
  'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'ALL', 'UNKNOWN',
];
// Express ALL accepts state-changing methods even when the same handler also serves reads.
const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE', 'ALL']);
const parserManifest = JSON.parse(readFileSync(new URL(
  '../vendor/js-ts-parser.manifest.json', import.meta.url), 'utf8'));

export function sha256(value) {
  return createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex');
}

export function sanitizeRoutePath(path) {
  if (path === null) return null;
  const value = String(path).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 512);
  if (!value) return null;
  const leading = value.startsWith('/') ? value : `/${value}`;
  return leading.replace(/\/{2,}/g, '/').replace(/\/$/, '') || '/';
}

export function safeRelativePath(path) {
  const value = String(path).replace(/\\/g, '/');
  if (!value || posix.isAbsolute(value) || /^[A-Za-z]:\//.test(value)
      || value.split('/').includes('..') || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error('route artifact path must be safe and relative');
  }
  return value.slice(0, 240);
}

export function emptyControlCounts() {
  return Object.fromEntries(CONTROL_STATES.map((state) => [state, 0]));
}

export function emptyPriorityCounts() {
  return Object.fromEntries(REVIEW_PRIORITIES.map((level) => [level, 0]));
}

export function controlEvidence(state = 'not_observed', signals = [], boundary = null) {
  if (!CONTROL_STATES.includes(state)) throw new Error(`invalid route control state: ${state}`);
  return {
    state,
    signals: signals.slice(0, 20).map(sanitizedSignal),
    boundary: boundary || 'Static source evidence does not prove runtime enforcement or correctness.',
  };
}

export function applicationControlRecord(input) {
  const role = APPLICATION_CONTROL_ROLES.includes(input.role) ? input.role : 'unclassified';
  const location = { path: safeRelativePath(input.location.path), line: input.location.line ?? null };
  const fingerprint = sha256([input.framework, input.kind, input.origin, location.path,
    location.line ?? 0, role].join('\u0000'));
  return {
    id: `application-control.${fingerprint.slice(0, 24)}`,
    fingerprint,
    framework: input.framework,
    kind: input.kind,
    origin: String(input.origin).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 2048),
    role,
    location,
    boundary: input.boundary
      || 'An application-scoped control declaration was observed once; route applicability and runtime enforcement are not proved.',
  };
}

export function accessChainRecord(input) {
  const identity = input.identity || { state: 'not_observed', provider: null, signals: [], boundary:
    'No supported identity source was observed within this bounded chain.' };
  const dataOperation = input.dataOperation || null;
  const structural = [input.entryKind, input.entryId, input.outcome,
    dataOperation?.provider || '', dataOperation?.resource || '', dataOperation?.operation || '',
    dataOperation?.location?.path || '', dataOperation?.location?.line || 0,
    ...(input.callEdges || []).flatMap((edge) => [edge.kind, edge.from, edge.to,
      edge.location?.path || '', edge.location?.line || 0]),
    ...(input.objectSelectors || []).flatMap((selector) => [selector.kind, selector.name,
      selector.location?.path || '', selector.location?.line || 0])].join('\u0000');
  const fingerprint = sha256(structural);
  return {
    id: `access-chain.${fingerprint.slice(0, 24)}`,
    fingerprint,
    status: ACCESS_CHAIN_STATUSES.includes(input.status) ? input.status : 'partial',
    outcome: ACCESS_CHAIN_OUTCOMES.includes(input.outcome) ? input.outcome : 'incomplete',
    identity: {
      state: identity.state,
      provider: identity.provider || null,
      signals: (identity.signals || []).slice(0, 20).map(sanitizedSignal),
      boundary: identity.boundary,
    },
    objectSelectors: (input.objectSelectors || []).slice(0, 20).map((selector) => ({
      kind: selector.kind,
      name: String(selector.name || 'object').replace(/[^A-Za-z0-9_$.-]/g, '').slice(0, 120) || 'object',
      location: { path: safeRelativePath(selector.location.path), line: selector.location.line ?? null },
    })),
    callEdges: (input.callEdges || []).slice(0, 2).map((edge) => ({
      kind: edge.kind,
      from: String(edge.from).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 160),
      to: String(edge.to).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 160),
      location: { path: safeRelativePath(edge.location.path), line: edge.location.line ?? null },
    })),
    dataOperation: dataOperation ? {
      provider: dataOperation.provider,
      resource: String(dataOperation.resource || 'unknown').replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 160),
      operation: dataOperation.operation,
      location: { path: safeRelativePath(dataOperation.location.path), line: dataOperation.location.line ?? null },
      objectConstraint: dataOperation.objectConstraint,
      principalConstraint: dataOperation.principalConstraint,
      tenantConstraint: dataOperation.tenantConstraint,
      externalPolicy: dataOperation.externalPolicy,
    } : null,
    evidenceBoundary: input.evidenceBoundary
      || 'This bounded static chain does not prove deployed reachability, policy enforcement or exploitability.',
    verification: {
      unauthenticated: input.verification?.unauthenticated || 'Verify the owned surface rejects an unauthenticated request when authentication is required.',
      owner: input.verification?.owner || 'Verify an owner-controlled account can complete the intended operation.',
      nonOwner: input.verification?.nonOwner || 'Using two owner-controlled accounts, verify one account cannot access the other account\'s object.',
      lowerRole: input.verification?.lowerRole || 'Verify a lower-privileged owner-controlled account cannot perform a higher-privileged operation.',
      functional: input.verification?.functional || 'Run the normal product flow and project tests after any approved control change.',
    },
  };
}

function sanitizedSignal(signal) {
  return {
    kind: signal.kind,
    origin: String(signal.origin).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 2048),
    location: { path: safeRelativePath(signal.location.path), line: signal.location.line ?? null },
  };
}

export function routeScopedControlEvidence(classifiedSignals = [], unknownSignals = []) {
  const state = classifiedSignals.length ? 'classified_controls_observed'
    : unknownSignals.length ? 'unclassified_control_observed' : 'no_route_scoped_control_observed';
  return {
    state,
    unclassifiedSignals: unknownSignals.slice(0, 20).map(sanitizedSignal),
    boundary: state === 'no_route_scoped_control_observed'
      ? 'No route, controller or statically inherited route-scoped control was observed; application controls and runtime policy still require review.'
      : state === 'unclassified_control_observed'
        ? 'A route-scoped control candidate is visible, but its authentication or authorization role was not established.'
        : 'At least one route-scoped control has an evidence-backed role; runtime enforcement and correctness are not proved.',
  };
}

export function routeRecord(input) {
  const method = ROUTE_METHODS.includes(input.method) ? input.method : 'UNKNOWN';
  const path = sanitizeRoutePath(input.path ?? null);
  const pathKind = input.pathKind || (path?.match(/[:[*]/) ? 'parameterized' : path ? 'static' : 'unknown');
  const location = { path: safeRelativePath(input.location.path), line: input.location.line ?? null };
  const structural = [input.framework, method, path || '<dynamic>', location.path,
    input.declarationRole || 'route'].join('\u0000');
  const fingerprint = sha256(structural);
  return {
    id: `route.${fingerprint.slice(0, 24)}`,
    fingerprint,
    framework: input.framework,
    method,
    path,
    pathKind,
    location,
    handler: input.handler ? String(input.handler).slice(0, 160) : null,
    stateChanging: input.stateChanging ?? STATE_CHANGING.has(method),
    objectAddressed: Boolean(input.objectAddressed),
    authentication: input.authentication || controlEvidence(),
    authorization: input.authorization || controlEvidence(),
    routeScopedControl: input.routeScopedControl || routeScopedControlEvidence(),
    accessChains: (input.accessChains || []).map(accessChainRecord),
    operations: [...new Set(input.operations || [])].sort().slice(0, 30),
    priority: input.priority || { level: 'no_automatic_priority', reasons: [] },
    limitations: [...new Set(input.limitations || [])].sort().slice(0, 20),
    baseline: input.baseline || { state: null, priorFingerprint: null, reasonCode: null },
  };
}

export function serverActionRecord(input) {
  const location = { path: safeRelativePath(input.location.path), line: input.location.line ?? null };
  const structural = ['next-app', 'server-action', input.name, location.path, location.line || 0]
    .join('\u0000');
  const fingerprint = sha256(structural);
  return {
    id: `server-action.${fingerprint.slice(0, 24)}`,
    fingerprint,
    framework: 'next-app',
    name: String(input.name || 'action').replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 160),
    location,
    authentication: input.authentication || controlEvidence(),
    authorization: input.authorization || controlEvidence(),
    actionScopedControl: input.actionScopedControl || routeScopedControlEvidence(),
    accessChains: (input.accessChains || []).map(accessChainRecord),
    operations: [...new Set(input.operations || [])].sort().slice(0, 30),
    priority: input.priority || { level: 'no_automatic_priority', reasons: [] },
    limitations: [...new Set(input.limitations || [])].sort().slice(0, 20),
    baseline: input.baseline || { state: null, priorFingerprint: null, reasonCode: null },
  };
}

function summaryFor(routes, applicationControls = [], serverActions = []) {
  const byFramework = {};
  const byPriority = emptyPriorityCounts();
  const byAuthentication = emptyControlCounts();
  const byAuthorization = emptyControlCounts();
  const byRouteScopedControl = Object.fromEntries(ROUTE_SCOPED_CONTROL_STATES.map((state) => [state, 0]));
  const byApplicationControlRole = Object.fromEntries(APPLICATION_CONTROL_ROLES.map((role) => [role, 0]));
  for (const route of routes) {
    byFramework[route.framework] = (byFramework[route.framework] || 0) + 1;
    byPriority[route.priority.level] += 1;
    byAuthentication[route.authentication.state] += 1;
    byAuthorization[route.authorization.state] += 1;
    byRouteScopedControl[route.routeScopedControl.state] += 1;
  }
  for (const control of applicationControls) byApplicationControlRole[control.role] += 1;
  return {
    total: routes.length,
    serverActions: serverActions.length,
    stateChanging: routes.filter((route) => route.stateChanging).length,
    objectAddressed: routes.filter((route) => route.objectAddressed).length,
    byFramework: Object.fromEntries(Object.entries(byFramework).sort()),
    byPriority,
    byAuthentication,
    byAuthorization,
    byRouteScopedControl,
    applicationControls: applicationControls.length,
    byApplicationControlRole,
  };
}

export function createRouteSecurityDocument(options) {
  const routes = [...(options.routes || [])].sort((left, right) =>
    [left.framework, left.path || '', left.method, left.location.path, left.location.line || 0].join('\u0000')
      .localeCompare([right.framework, right.path || '', right.method, right.location.path,
        right.location.line || 0].join('\u0000')));
  const applicationControls = (options.applicationControls || []).map(applicationControlRecord)
    .sort((left, right) => [left.framework, left.location.path, left.location.line || 0, left.kind]
      .join('\u0000').localeCompare([right.framework, right.location.path,
        right.location.line || 0, right.kind].join('\u0000')));
  const serverActions = [...(options.serverActions || [])];
  return {
    schemaVersion: 2,
    tool: { name: 'Web App Security Skill', version: options.version },
    generatedAt: options.generatedAt || new Date().toISOString(),
    mode: options.mode || 'audit',
    subject: { id: options.subject.id, scopeDigest: options.subject.scopeDigest },
    analyzer: {
      id: 'builtin-route', revision: '2',
      parser: { component: parserManifest.component, version: parserManifest.version, sha256: parserManifest.sha256 },
    },
    summary: summaryFor(routes, applicationControls, serverActions),
    coverage: [...(options.coverage || [])].sort((a, b) => a.framework.localeCompare(b.framework)),
    applicationControls,
    routes,
    serverActions,
    limitations: [...new Set(options.limitations || [])].sort(),
    baseline: options.baseline || null,
  };
}
