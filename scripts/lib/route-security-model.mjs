import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { posix } from 'node:path';

export const ROUTE_FRAMEWORKS = ['express', 'nestjs', 'next-app'];
export const CONTROL_STATES = [
  'local_observed', 'inherited_observed', 'candidate_observed',
  'not_observed', 'incomplete', 'not_applicable',
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
    signals: signals.slice(0, 20).map((signal) => ({
      kind: signal.kind,
      origin: String(signal.origin).replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 2048),
      location: { path: safeRelativePath(signal.location.path), line: signal.location.line ?? null },
    })),
    boundary: boundary || 'Static source evidence does not prove runtime enforcement or correctness.',
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
    operations: [...new Set(input.operations || [])].sort().slice(0, 30),
    priority: input.priority || { level: 'no_automatic_priority', reasons: [] },
    limitations: [...new Set(input.limitations || [])].sort().slice(0, 20),
    baseline: input.baseline || { state: null, priorFingerprint: null, reasonCode: null },
  };
}

function summaryFor(routes) {
  const byFramework = {};
  const byPriority = emptyPriorityCounts();
  const byAuthentication = emptyControlCounts();
  const byAuthorization = emptyControlCounts();
  for (const route of routes) {
    byFramework[route.framework] = (byFramework[route.framework] || 0) + 1;
    byPriority[route.priority.level] += 1;
    byAuthentication[route.authentication.state] += 1;
    byAuthorization[route.authorization.state] += 1;
  }
  return {
    total: routes.length,
    stateChanging: routes.filter((route) => route.stateChanging).length,
    objectAddressed: routes.filter((route) => route.objectAddressed).length,
    byFramework: Object.fromEntries(Object.entries(byFramework).sort()),
    byPriority,
    byAuthentication,
    byAuthorization,
  };
}

export function createRouteSecurityDocument(options) {
  const routes = [...(options.routes || [])].sort((left, right) =>
    [left.framework, left.path || '', left.method, left.location.path, left.location.line || 0].join('\u0000')
      .localeCompare([right.framework, right.path || '', right.method, right.location.path,
        right.location.line || 0].join('\u0000')));
  return {
    schemaVersion: 1,
    tool: { name: 'Web App Security Skill', version: options.version },
    generatedAt: options.generatedAt || new Date().toISOString(),
    mode: options.mode || 'audit',
    subject: { id: options.subject.id, scopeDigest: options.subject.scopeDigest },
    analyzer: {
      id: 'builtin-route', revision: '1',
      parser: { component: parserManifest.component, version: parserManifest.version, sha256: parserManifest.sha256 },
    },
    summary: summaryFor(routes),
    coverage: [...(options.coverage || [])].sort((a, b) => a.framework.localeCompare(b.framework)),
    routes,
    limitations: [...new Set(options.limitations || [])].sort(),
    baseline: options.baseline || null,
  };
}
