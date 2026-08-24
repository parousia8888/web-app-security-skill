import {
  ACCESS_CHAIN_OUTCOMES, ACCESS_CHAIN_STATUSES, APPLICATION_CONTROL_ROLES, CONTROL_STATES,
  REVIEW_PRIORITIES, ROUTE_FRAMEWORKS, ROUTE_METHODS, ROUTE_SCOPED_CONTROL_STATES,
} from './route-security-model.mjs';

const digest = (value) => /^[a-f0-9]{64}$/.test(value || '');
const safePath = (value) => typeof value === 'string' && value.length > 0 && value.length <= 240
  && !value.startsWith('/') && !/^[A-Za-z]:[\\/]/.test(value)
  && !value.split(/[\\/]/).includes('..') && !/[\u0000-\u001f\u007f]/.test(value);

export function validateRouteSecurityDocument(document) {
  const errors = [];
  const version = document?.schemaVersion;
  if (![1, 2].includes(version)) errors.push('schemaVersion must be 1 or 2');
  if (document?.tool?.name !== 'Web App Security Skill' || !document?.tool?.version) errors.push('tool identity is invalid');
  if (!['audit', 'retest', 'demo-before', 'demo-after'].includes(document?.mode)) errors.push('mode is invalid');
  if (!document?.subject?.id || !digest(document?.subject?.scopeDigest)) errors.push('subject is invalid');
  if (document?.analyzer?.id !== 'builtin-route' || !digest(document?.analyzer?.parser?.sha256)) errors.push('analyzer is invalid');
  if (!Array.isArray(document?.coverage) || !Array.isArray(document?.routes)
      || !Array.isArray(document?.limitations)) errors.push('route arrays are invalid');
  if (version === 2 && (!Array.isArray(document?.applicationControls)
      || !Array.isArray(document?.serverActions))) errors.push('v2 control/action arrays are invalid');
  if (document?.baseline !== null && (!digest(document?.baseline?.sourceDigest)
      || !['compatible', 'not_comparable'].includes(document?.baseline?.compatibility))) {
    errors.push('baseline is invalid');
  }
  for (const [index, coverage] of (document?.coverage || []).entries()) {
    if (!ROUTE_FRAMEWORKS.includes(coverage.framework)) errors.push(`coverage[${index}].framework is invalid`);
    if (!['completed', 'partial', 'not_applicable'].includes(coverage.status)) errors.push(`coverage[${index}].status is invalid`);
    for (const key of ['discovered', 'eligible', 'parsed', 'incomplete']) {
      if (!Number.isInteger(coverage.counts?.[key]) || coverage.counts[key] < 0) errors.push(`coverage[${index}].counts.${key} is invalid`);
    }
  }
  if (version === 2) for (const [index, control] of document.applicationControls.entries()) {
    const label = `applicationControls[${index}]`;
    if (!control?.id?.startsWith('application-control.') || !digest(control?.fingerprint)) {
      errors.push(`${label} identity is invalid`);
    }
    if (!ROUTE_FRAMEWORKS.includes(control?.framework)) errors.push(`${label}.framework is invalid`);
    if (!APPLICATION_CONTROL_ROLES.includes(control?.role)) errors.push(`${label}.role is invalid`);
    if (!safePath(control?.location?.path)) errors.push(`${label}.location.path is invalid`);
  }
  for (const [index, route] of (document?.routes || []).entries()) {
    const label = `routes[${index}]`;
    if (!route?.id?.startsWith('route.') || !digest(route?.fingerprint)) errors.push(`${label} identity is invalid`);
    if (!ROUTE_FRAMEWORKS.includes(route?.framework)) errors.push(`${label}.framework is invalid`);
    if (!ROUTE_METHODS.includes(route?.method)) errors.push(`${label}.method is invalid`);
    if (!['static', 'parameterized', 'dynamic', 'unknown'].includes(route?.pathKind)) errors.push(`${label}.pathKind is invalid`);
    if (!safePath(route?.location?.path)) errors.push(`${label}.location.path is invalid`);
    if (!CONTROL_STATES.includes(route?.authentication?.state)) errors.push(`${label}.authentication.state is invalid`);
    if (!CONTROL_STATES.includes(route?.authorization?.state)) errors.push(`${label}.authorization.state is invalid`);
    if (version === 2 && !ROUTE_SCOPED_CONTROL_STATES.includes(route?.routeScopedControl?.state)) {
      errors.push(`${label}.routeScopedControl.state is invalid`);
    }
    if (version === 2 && !Array.isArray(route?.accessChains)) errors.push(`${label}.accessChains is invalid`);
    if (!REVIEW_PRIORITIES.includes(route?.priority?.level)) errors.push(`${label}.priority.level is invalid`);
    if (![null, 'new', 'unchanged', 'changed', 'added', 'removed', 'unretested',
      'not_comparable'].includes(route?.baseline?.state)) errors.push(`${label}.baseline.state is invalid`);
    if (route?.baseline?.priorFingerprint !== null && !digest(route?.baseline?.priorFingerprint)) {
      errors.push(`${label}.baseline.priorFingerprint is invalid`);
    }
    for (const control of [route?.authentication, route?.authorization]) {
      for (const signal of control?.signals || []) if (!safePath(signal?.location?.path)) errors.push(`${label} signal path is invalid`);
    }
    if (version === 2) {
      for (const signal of route.routeScopedControl?.unclassifiedSignals || []) {
        if (!safePath(signal?.location?.path)) errors.push(`${label} route-scoped signal path is invalid`);
      }
      for (const [chainIndex, chain] of route.accessChains.entries()) {
        const chainLabel = `${label}.accessChains[${chainIndex}]`;
        if (!chain?.id?.startsWith('access-chain.') || !digest(chain?.fingerprint)) {
          errors.push(`${chainLabel} identity is invalid`);
        }
        if (!ACCESS_CHAIN_STATUSES.includes(chain?.status)) errors.push(`${chainLabel}.status is invalid`);
        if (!ACCESS_CHAIN_OUTCOMES.includes(chain?.outcome)) errors.push(`${chainLabel}.outcome is invalid`);
        if (chain?.dataOperation && !safePath(chain.dataOperation.location?.path)) {
          errors.push(`${chainLabel}.dataOperation.location.path is invalid`);
        }
      }
    }
  }
  if (version === 2) for (const [index, action] of document.serverActions.entries()) {
    const label = `serverActions[${index}]`;
    if (!action?.id?.startsWith('server-action.') || !digest(action?.fingerprint)) {
      errors.push(`${label} identity is invalid`);
    }
    if (action?.framework !== 'next-app' || !safePath(action?.location?.path)) {
      errors.push(`${label} source identity is invalid`);
    }
    if (!CONTROL_STATES.includes(action?.authentication?.state)
        || !CONTROL_STATES.includes(action?.authorization?.state)) {
      errors.push(`${label} control state is invalid`);
    }
    if (!ROUTE_SCOPED_CONTROL_STATES.includes(action?.actionScopedControl?.state)) {
      errors.push(`${label}.actionScopedControl.state is invalid`);
    }
    if (!Array.isArray(action?.accessChains)) errors.push(`${label}.accessChains is invalid`);
    if (!REVIEW_PRIORITIES.includes(action?.priority?.level)) errors.push(`${label}.priority.level is invalid`);
    if (![null, 'new', 'unchanged', 'changed', 'added', 'removed', 'unretested',
      'not_comparable'].includes(action?.baseline?.state)) errors.push(`${label}.baseline.state is invalid`);
    if (action?.baseline?.priorFingerprint !== null && !digest(action?.baseline?.priorFingerprint)) {
      errors.push(`${label}.baseline.priorFingerprint is invalid`);
    }
    for (const [chainIndex, chain] of (action?.accessChains || []).entries()) {
      const chainLabel = `${label}.accessChains[${chainIndex}]`;
      if (!chain?.id?.startsWith('access-chain.') || !digest(chain?.fingerprint)) {
        errors.push(`${chainLabel} identity is invalid`);
      }
      if (!ACCESS_CHAIN_STATUSES.includes(chain?.status)) errors.push(`${chainLabel}.status is invalid`);
      if (!ACCESS_CHAIN_OUTCOMES.includes(chain?.outcome)) errors.push(`${chainLabel}.outcome is invalid`);
      if (chain?.dataOperation && !safePath(chain.dataOperation.location?.path)) {
        errors.push(`${chainLabel}.dataOperation.location.path is invalid`);
      }
    }
  }
  if (document?.summary?.total !== document?.routes?.length) errors.push('summary.total differs from routes');
  return errors;
}

export function assertRouteSecurityDocument(document) {
  const errors = validateRouteSecurityDocument(document);
  if (errors.length) throw new Error(`route security contract failed: ${errors.join('; ')}`);
  return document;
}
