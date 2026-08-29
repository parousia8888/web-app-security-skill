import {
  ACCESS_CHAIN_INCOMPLETE_REASONS, ACCESS_CHAIN_OUTCOMES, ACCESS_CHAIN_STATUSES,
  ACCESS_PATH_LIMITS, APPLICATION_CONTROL_ROLES, AUTHORIZATION_EVIDENCE_CATEGORIES,
  AUTHORIZATION_EVIDENCE_KINDS, CONSTRAINT_STATES, CONTROL_STATES,
  LEGACY_ACCESS_CHAIN_OUTCOMES, REVIEW_PRIORITIES, ROUTE_FRAMEWORKS, ROUTE_METHODS,
  ROUTE_SCOPED_CONTROL_STATES, SELECTOR_ORIGINS,
} from './route-security-model.mjs';

const digest = (value) => /^[a-f0-9]{64}$/.test(value || '');
const safePath = (value) => typeof value === 'string' && value.length > 0 && value.length <= 240
  && !value.startsWith('/') && !/^[A-Za-z]:[\\/]/.test(value)
  && !value.split(/[\\/]/).includes('..') && !/[\u0000-\u001f\u007f]/.test(value);
const id = (value) => typeof value === 'string' && /^[a-z0-9][a-z0-9._-]{2,127}$/.test(value);
const text = (value, max = 2048) => typeof value === 'string' && value.length > 0
  && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value);
const field = (value) => typeof value === 'string' && /^[A-Za-z0-9_$.-]{1,120}$/.test(value);
const location = (value) => safePath(value?.path)
  && (value.line === null || (Number.isInteger(value.line) && value.line >= 1 && value.line <= 10_000_000));
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

function rejectUnknown(errors, label, value, allowed) {
  if (!object(value)) {
    errors.push(`${label} must be an object`);
    return;
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) errors.push(`${label}.${key} is not allowed`);
  }
}

function validateV3Signal(signal, label, errors) {
  rejectUnknown(errors, label, signal, ['kind', 'origin', 'location']);
  if (!id(signal?.kind) || !text(signal?.origin) || !location(signal?.location)) {
    errors.push(`${label} is invalid`);
  }
}

function validateV3Control(control, label, errors) {
  rejectUnknown(errors, label, control, ['state', 'signals', 'boundary']);
  if (!CONTROL_STATES.includes(control?.state) || !Array.isArray(control?.signals)
      || control.signals.length > 20 || !text(control?.boundary)) {
    errors.push(`${label} is invalid`);
  }
  for (const [index, signal] of (control?.signals || []).entries()) {
    validateV3Signal(signal, `${label}.signals[${index}]`, errors);
  }
}

function validateV3ScopedControl(control, label, errors) {
  rejectUnknown(errors, label, control, ['state', 'unclassifiedSignals', 'boundary']);
  if (!ROUTE_SCOPED_CONTROL_STATES.includes(control?.state)
      || !Array.isArray(control?.unclassifiedSignals)
      || control.unclassifiedSignals.length > 20 || !text(control?.boundary)) {
    errors.push(`${label} is invalid`);
  }
  for (const [index, signal] of (control?.unclassifiedSignals || []).entries()) {
    validateV3Signal(signal, `${label}.unclassifiedSignals[${index}]`, errors);
  }
}

function validateV3Priority(priority, label, errors) {
  rejectUnknown(errors, label, priority, ['level', 'reasons']);
  if (!REVIEW_PRIORITIES.includes(priority?.level) || !Array.isArray(priority?.reasons)
      || priority.reasons.length > 12 || !priority.reasons.every(id)) {
    errors.push(`${label} is invalid`);
  }
}

function validateV3RecordBaseline(baseline, label, errors) {
  rejectUnknown(errors, label, baseline, ['state', 'priorFingerprint', 'reasonCode']);
  if (![null, 'new', 'unchanged', 'changed', 'added', 'removed', 'unretested',
    'not_comparable'].includes(baseline?.state)
      || (baseline?.priorFingerprint !== null && !digest(baseline?.priorFingerprint))
      || (baseline?.reasonCode !== null && !id(baseline?.reasonCode))) {
    errors.push(`${label} is invalid`);
  }
}

function validateV3Chain(chain, label, errors) {
  rejectUnknown(errors, label, chain, [
    'id', 'fingerprint', 'status', 'outcome', 'identity', 'objectSelectors', 'callEdges',
    'dataOperation', 'authorizationEvidence', 'reason', 'limitations', 'evidenceBoundary',
    'verification',
  ]);
  if (!chain?.id?.startsWith('access-chain.') || !digest(chain?.fingerprint)) {
    errors.push(`${label} identity is invalid`);
  }
  if (!ACCESS_CHAIN_STATUSES.includes(chain?.status)) errors.push(`${label}.status is invalid`);
  if (!ACCESS_CHAIN_OUTCOMES.includes(chain?.outcome)) errors.push(`${label}.outcome is invalid`);
  if (chain?.status === 'partial'
      && (!ACCESS_CHAIN_INCOMPLETE_REASONS.includes(chain?.reason) || chain?.outcome !== 'incomplete')) {
    errors.push(`${label} partial reason is invalid`);
  }
  if (['completed', 'not_applicable'].includes(chain?.status) && chain?.reason !== null) {
    errors.push(`${label} completed/not-applicable reason must be null`);
  }
  if (!Array.isArray(chain?.objectSelectors) || chain.objectSelectors.length > 20) {
    errors.push(`${label}.objectSelectors is invalid`);
  }
  for (const [index, selector] of (chain?.objectSelectors || []).entries()) {
    const selectorLabel = `${label}.objectSelectors[${index}]`;
    rejectUnknown(errors, selectorLabel, selector, ['kind', 'name', 'origin', 'location']);
    if (!id(selector?.kind) || !field(selector?.name)
        || !SELECTOR_ORIGINS.includes(selector?.origin) || !location(selector?.location)) {
      errors.push(`${selectorLabel} is invalid`);
    }
  }
  if (!Array.isArray(chain?.callEdges)
      || chain.callEdges.length > ACCESS_PATH_LIMITS.maxLocalCallEdges) {
    errors.push(`${label}.callEdges is invalid`);
  }
  const edgeKinds = [
    'direct', 'local_function', 'local_import', 'local_reexport', 'class_method',
    'nest_injected_service', 'static_member', 'react_cache_callback', 'wrapper_handler',
  ];
  for (const [index, edge] of (chain?.callEdges || []).entries()) {
    const edgeLabel = `${label}.callEdges[${index}]`;
    rejectUnknown(errors, edgeLabel, edge, ['kind', 'from', 'to', 'location']);
    if (!edgeKinds.includes(edge?.kind) || !text(edge?.from, 160) || !text(edge?.to, 160)
        || !location(edge?.location)) errors.push(`${edgeLabel} is invalid`);
  }
  if (chain?.dataOperation !== null) {
    const operation = chain?.dataOperation;
    rejectUnknown(errors, `${label}.dataOperation`, operation, [
      'provider', 'resource', 'operation', 'location', 'objectConstraint',
      'principalConstraint', 'tenantConstraint',
    ]);
    if (!id(operation?.provider) || !text(operation?.resource, 160) || !id(operation?.operation)
        || !location(operation?.location)
        || !['objectConstraint', 'principalConstraint', 'tenantConstraint']
          .every((key) => CONSTRAINT_STATES.includes(operation?.[key]))) {
      errors.push(`${label}.dataOperation is invalid`);
    }
  }
  if (!Array.isArray(chain?.authorizationEvidence) || chain.authorizationEvidence.length > 20) {
    errors.push(`${label}.authorizationEvidence is invalid`);
  }
  for (const [index, evidence] of (chain?.authorizationEvidence || []).entries()) {
    const evidenceLabel = `${label}.authorizationEvidence[${index}]`;
    rejectUnknown(errors, evidenceLabel, evidence, ['kind', 'category', 'state', 'field', 'location']);
    if (!AUTHORIZATION_EVIDENCE_KINDS.includes(evidence?.kind)
        || !AUTHORIZATION_EVIDENCE_CATEGORIES.includes(evidence?.category)
        || !CONSTRAINT_STATES.includes(evidence?.state)
        || (evidence?.field !== null && !field(evidence?.field))
        || (evidence?.location !== null && !location(evidence?.location))) {
      errors.push(`${evidenceLabel} is invalid`);
    }
  }
  const authorizationEvidence = chain?.authorizationEvidence || [];
  if (chain?.outcome === 'authorization_constraint_observed'
      && !authorizationEvidence.some((evidence) =>
        ['query_predicate', 'post_load_comparison'].includes(evidence.kind)
          && ['principal', 'tenant'].includes(evidence.category) && evidence.state === 'observed')) {
    errors.push(`${label} observed authorization outcome lacks observed evidence`);
  }
  if (chain?.outcome === 'external_policy_required'
      && !authorizationEvidence.some((evidence) => evidence.kind === 'external_policy_dependency')) {
    errors.push(`${label} external-policy outcome lacks dependency evidence`);
  }
  if (chain?.outcome === 'authorization_constraint_not_observed'
      && !authorizationEvidence.some((evidence) => evidence.kind === 'none'
        && evidence.category === 'none' && evidence.state === 'not_observed')) {
    errors.push(`${label} not-observed outcome lacks bounded absence evidence`);
  }
  if (chain?.outcome === 'no_supported_object_operation' && chain?.dataOperation !== null) {
    errors.push(`${label} no-operation outcome has a data operation`);
  }
  if (!Array.isArray(chain?.limitations) || chain.limitations.length > 20
      || !chain.limitations.every(id)) errors.push(`${label}.limitations is invalid`);
  if (!text(chain?.evidenceBoundary)) errors.push(`${label}.evidenceBoundary is invalid`);
  rejectUnknown(errors, `${label}.identity`, chain?.identity, ['state', 'provider', 'signals', 'boundary']);
  const identityStates = [
    'identity_call_observed', 'session_lookup_observed', 'candidate_observed',
    'not_observed', 'incomplete', 'not_applicable',
  ];
  if (!identityStates.includes(chain?.identity?.state)
      || (chain?.identity?.provider !== null && !text(chain?.identity?.provider, 80))
      || !Array.isArray(chain?.identity?.signals) || chain.identity.signals.length > 20
      || !text(chain?.identity?.boundary)) errors.push(`${label}.identity is invalid`);
  for (const [index, signal] of (chain?.identity?.signals || []).entries()) {
    validateV3Signal(signal, `${label}.identity.signals[${index}]`, errors);
  }
  rejectUnknown(errors, `${label}.verification`, chain?.verification,
    ['unauthenticated', 'owner', 'nonOwner', 'lowerRole', 'functional']);
  if (!['unauthenticated', 'owner', 'nonOwner', 'lowerRole', 'functional']
    .every((key) => text(chain?.verification?.[key]))) {
    errors.push(`${label}.verification is invalid`);
  }
}

export function validateRouteSecurityDocument(document) {
  const errors = [];
  const chainIds = new Set();
  if (document === null || typeof document !== 'object' || Array.isArray(document)) {
    return ['route document must be an object'];
  }
  const version = document?.schemaVersion;
  if (![1, 2, 3].includes(version)) errors.push('schemaVersion must be 1, 2 or 3');
  const allowed = version === 1
    ? ['schemaVersion', 'tool', 'generatedAt', 'mode', 'subject', 'analyzer', 'summary', 'coverage',
      'routes', 'limitations', 'baseline']
    : ['schemaVersion', 'tool', 'generatedAt', 'mode', 'subject', 'analyzer', 'summary', 'coverage',
      ...(version === 3 ? ['accessPathCoverage'] : []),
      'applicationControls', 'routes', 'serverActions', 'limitations', 'baseline'];
  for (const key of Object.keys(document)) {
    if (!allowed.includes(key)) errors.push(`document.${key} is not allowed`);
  }
  if (document?.tool?.name !== 'Web App Security Skill' || !document?.tool?.version) errors.push('tool identity is invalid');
  if (!['audit', 'retest', 'demo-before', 'demo-after'].includes(document?.mode)) errors.push('mode is invalid');
  if (!document?.subject?.id || !digest(document?.subject?.scopeDigest)) errors.push('subject is invalid');
  if (document?.analyzer?.id !== 'builtin-route' || !digest(document?.analyzer?.parser?.sha256)
      || document?.analyzer?.revision !== String(version)) errors.push('analyzer is invalid');
  if (version === 3) {
    rejectUnknown(errors, 'tool', document?.tool, ['name', 'version']);
    rejectUnknown(errors, 'subject', document?.subject, ['id', 'scopeDigest']);
    rejectUnknown(errors, 'analyzer', document?.analyzer, ['id', 'revision', 'parser', 'analysisLimits']);
    rejectUnknown(errors, 'analyzer.parser', document?.analyzer?.parser,
      ['component', 'version', 'sha256']);
    rejectUnknown(errors, 'analyzer.analysisLimits', document?.analyzer?.analysisLimits,
      Object.keys(ACCESS_PATH_LIMITS));
    const limits = document?.analyzer?.analysisLimits || {};
    const boundedLimits = Number.isInteger(limits.maxLocalCallEdges)
      && limits.maxLocalCallEdges >= 1 && limits.maxLocalCallEdges <= 4
      && Number.isInteger(limits.maxEmittedChainsPerEntry)
      && limits.maxEmittedChainsPerEntry >= 1 && limits.maxEmittedChainsPerEntry <= 50
      && Number.isInteger(limits.maxActiveStatesPerEntry)
      && limits.maxActiveStatesPerEntry >= 1 && limits.maxActiveStatesPerEntry <= 10_000
      && Number.isInteger(limits.maxExaminedCallSitesPerSummary)
      && limits.maxExaminedCallSitesPerSummary >= 1 && limits.maxExaminedCallSitesPerSummary <= 10_000
      && Number.isInteger(limits.maxTotalTransitionsPerAudit)
      && limits.maxTotalTransitionsPerAudit >= 1 && limits.maxTotalTransitionsPerAudit <= 1_000_000;
    if (!boundedLimits) {
      errors.push('analyzer.analysisLimits is invalid');
    }
    if (!id(document?.subject?.id) || !text(document?.tool?.version, 64)
        || document?.analyzer?.parser?.component !== '@babel/parser'
        || !text(document?.analyzer?.parser?.version, 40)) {
      errors.push('v3 document identity is invalid');
    }
    rejectUnknown(errors, 'summary', document?.summary, [
      'total', 'serverActions', 'stateChanging', 'objectAddressed', 'byFramework',
      'byPriority', 'byAuthentication', 'byAuthorization', 'byRouteScopedControl',
      'applicationControls', 'byApplicationControlRole',
    ]);
  }
  if (!Array.isArray(document?.coverage) || !Array.isArray(document?.routes)
      || !Array.isArray(document?.limitations)) errors.push('route arrays are invalid');
  if (version >= 2 && (!Array.isArray(document?.applicationControls)
      || !Array.isArray(document?.serverActions))) errors.push('v2/v3 control/action arrays are invalid');
  if (version === 3 && ((document.coverage || []).length > 3
      || (document.routes || []).length > 10_000
      || (document.applicationControls || []).length > 1_000
      || (document.serverActions || []).length > 5_000
      || (document.limitations || []).length > 100
      || !(document.limitations || []).every((item) => text(item)))) {
    errors.push('v3 document arrays exceed their bounds');
  }
  if (document?.baseline !== null && (!digest(document?.baseline?.sourceDigest)
      || !['compatible', 'not_comparable'].includes(document?.baseline?.compatibility))) {
    errors.push('baseline is invalid');
  }
  for (const [index, coverage] of (document?.coverage || []).entries()) {
    if (version === 3) {
      const label = `coverage[${index}]`;
      rejectUnknown(errors, label, coverage, ['framework', 'status', 'counts', 'reasons']);
      rejectUnknown(errors, `${label}.counts`, coverage?.counts,
        ['discovered', 'eligible', 'parsed', 'incomplete']);
      if (!Array.isArray(coverage?.reasons) || coverage.reasons.length > 100) {
        errors.push(`${label}.reasons is invalid`);
      }
      for (const [reasonIndex, reason] of (coverage?.reasons || []).entries()) {
        const reasonLabel = `${label}.reasons[${reasonIndex}]`;
        rejectUnknown(errors, reasonLabel, reason, ['code', 'count', 'samplePaths']);
        if (!id(reason?.code) || !Number.isInteger(reason?.count) || reason.count < 1
            || !Array.isArray(reason?.samplePaths) || reason.samplePaths.length > 10
            || !reason.samplePaths.every(safePath)) errors.push(`${reasonLabel} is invalid`);
      }
    }
    if (!ROUTE_FRAMEWORKS.includes(coverage.framework)) errors.push(`coverage[${index}].framework is invalid`);
    if (!['completed', 'partial', 'not_applicable'].includes(coverage.status)) errors.push(`coverage[${index}].status is invalid`);
    for (const key of ['discovered', 'eligible', 'parsed', 'incomplete']) {
      if (!Number.isInteger(coverage.counts?.[key]) || coverage.counts[key] < 0) errors.push(`coverage[${index}].counts.${key} is invalid`);
    }
  }
  if (version === 3) {
    const coverage = document?.accessPathCoverage;
    rejectUnknown(errors, 'accessPathCoverage', coverage, ['status', 'counts', 'reasons']);
    rejectUnknown(errors, 'accessPathCoverage.counts', coverage?.counts,
      ['discovered', 'eligible', 'scanned', 'skipped', 'truncated', 'errors']);
    const counts = coverage?.counts || {};
    const countKeys = ['discovered', 'eligible', 'scanned', 'skipped', 'truncated', 'errors'];
    if (!['completed', 'partial', 'not_applicable'].includes(coverage?.status)
        || !countKeys.every((key) => Number.isInteger(counts[key])
          && counts[key] >= 0 && counts[key] <= 15_000)
        || counts.eligible > counts.discovered || counts.scanned > counts.eligible
        || counts.skipped !== counts.eligible - counts.scanned
        || counts.errors > counts.eligible || counts.truncated > counts.scanned
        || !Array.isArray(coverage?.reasons) || coverage.reasons.length > 100) {
      errors.push('accessPathCoverage is invalid');
    }
    if (coverage?.status === 'not_applicable' && counts.eligible !== 0) {
      errors.push('accessPathCoverage not_applicable has eligible entries');
    }
    if (coverage?.status === 'completed'
        && (counts.eligible === 0 || counts.skipped || counts.truncated || counts.errors)) {
      errors.push('accessPathCoverage completed counts are inconsistent');
    }
    if (coverage?.status === 'partial'
        && !(counts.skipped || counts.truncated || counts.errors)) {
      errors.push('accessPathCoverage partial lacks an incomplete count');
    }
    for (const [index, reason] of (coverage?.reasons || []).entries()) {
      const label = `accessPathCoverage.reasons[${index}]`;
      rejectUnknown(errors, label, reason, ['code', 'count', 'samplePaths']);
      if (!id(reason?.code) || !Number.isInteger(reason?.count) || reason.count < 1
          || !Array.isArray(reason?.samplePaths) || reason.samplePaths.length > 10
          || !reason.samplePaths.every(safePath)) errors.push(`${label} is invalid`);
    }
  }
  if (version >= 2) for (const [index, control] of (document.applicationControls || []).entries()) {
    const label = `applicationControls[${index}]`;
    if (version === 3) rejectUnknown(errors, label, control,
      ['id', 'fingerprint', 'framework', 'kind', 'origin', 'role', 'location', 'boundary']);
    if (!control?.id?.startsWith('application-control.') || !digest(control?.fingerprint)) {
      errors.push(`${label} identity is invalid`);
    }
    if (!ROUTE_FRAMEWORKS.includes(control?.framework)) errors.push(`${label}.framework is invalid`);
    if (!APPLICATION_CONTROL_ROLES.includes(control?.role)) errors.push(`${label}.role is invalid`);
    if (!safePath(control?.location?.path)) errors.push(`${label}.location.path is invalid`);
    if (version === 3 && (!id(control?.kind) || !text(control?.origin)
        || !location(control?.location) || !text(control?.boundary))) {
      errors.push(`${label} evidence is invalid`);
    }
  }
  for (const [index, route] of (document?.routes || []).entries()) {
    const label = `routes[${index}]`;
    if (version === 3) rejectUnknown(errors, label, route, [
      'id', 'fingerprint', 'framework', 'method', 'path', 'pathKind', 'location', 'handler',
      'stateChanging', 'objectAddressed', 'authentication', 'authorization',
      'routeScopedControl', 'accessChains', 'operations', 'priority', 'limitations', 'baseline',
    ]);
    if (!route?.id?.startsWith('route.') || !digest(route?.fingerprint)) errors.push(`${label} identity is invalid`);
    if (!ROUTE_FRAMEWORKS.includes(route?.framework)) errors.push(`${label}.framework is invalid`);
    if (!ROUTE_METHODS.includes(route?.method)) errors.push(`${label}.method is invalid`);
    if (!['static', 'parameterized', 'dynamic', 'unknown'].includes(route?.pathKind)) errors.push(`${label}.pathKind is invalid`);
    if (!safePath(route?.location?.path)) errors.push(`${label}.location.path is invalid`);
    if (!CONTROL_STATES.includes(route?.authentication?.state)) errors.push(`${label}.authentication.state is invalid`);
    if (!CONTROL_STATES.includes(route?.authorization?.state)) errors.push(`${label}.authorization.state is invalid`);
    if (version === 3) {
      if ((route.path !== null && (!text(route.path, 512)))
          || (route.handler !== null && !text(route.handler, 160))
          || typeof route.stateChanging !== 'boolean' || typeof route.objectAddressed !== 'boolean'
          || !Array.isArray(route.operations) || route.operations.length > 30
          || !route.operations.every(id) || !Array.isArray(route.limitations)
          || route.limitations.length > 20 || !route.limitations.every(id)
          || !Array.isArray(route.accessChains) || route.accessChains.length > 50) {
        errors.push(`${label} bounded fields are invalid`);
      }
      validateV3Control(route.authentication, `${label}.authentication`, errors);
      validateV3Control(route.authorization, `${label}.authorization`, errors);
      validateV3ScopedControl(route.routeScopedControl, `${label}.routeScopedControl`, errors);
      validateV3Priority(route.priority, `${label}.priority`, errors);
      validateV3RecordBaseline(route.baseline, `${label}.baseline`, errors);
    }
    if (version >= 2 && !ROUTE_SCOPED_CONTROL_STATES.includes(route?.routeScopedControl?.state)) {
      errors.push(`${label}.routeScopedControl.state is invalid`);
    }
    if (version >= 2 && !Array.isArray(route?.accessChains)) errors.push(`${label}.accessChains is invalid`);
    if (!REVIEW_PRIORITIES.includes(route?.priority?.level)) errors.push(`${label}.priority.level is invalid`);
    if (![null, 'new', 'unchanged', 'changed', 'added', 'removed', 'unretested',
      'not_comparable'].includes(route?.baseline?.state)) errors.push(`${label}.baseline.state is invalid`);
    if (route?.baseline?.priorFingerprint !== null && !digest(route?.baseline?.priorFingerprint)) {
      errors.push(`${label}.baseline.priorFingerprint is invalid`);
    }
    for (const control of [route?.authentication, route?.authorization]) {
      for (const signal of control?.signals || []) if (!safePath(signal?.location?.path)) errors.push(`${label} signal path is invalid`);
    }
    if (version >= 2) {
      for (const signal of route.routeScopedControl?.unclassifiedSignals || []) {
        if (!safePath(signal?.location?.path)) errors.push(`${label} route-scoped signal path is invalid`);
      }
      for (const [chainIndex, chain] of (route.accessChains || []).entries()) {
        const chainLabel = `${label}.accessChains[${chainIndex}]`;
        if (version === 3) {
          validateV3Chain(chain, chainLabel, errors);
          if (chainIds.has(chain?.id)) errors.push(`${chainLabel}.id is duplicated`);
          else chainIds.add(chain?.id);
          continue;
        }
        if (!chain?.id?.startsWith('access-chain.') || !digest(chain?.fingerprint)) {
          errors.push(`${chainLabel} identity is invalid`);
        }
        if (!ACCESS_CHAIN_STATUSES.includes(chain?.status)) errors.push(`${chainLabel}.status is invalid`);
        if (!LEGACY_ACCESS_CHAIN_OUTCOMES.includes(chain?.outcome)) errors.push(`${chainLabel}.outcome is invalid`);
        if (chain?.dataOperation && !safePath(chain.dataOperation.location?.path)) {
          errors.push(`${chainLabel}.dataOperation.location.path is invalid`);
        }
      }
    }
  }
  if (version >= 2) for (const [index, action] of (document.serverActions || []).entries()) {
    const label = `serverActions[${index}]`;
    if (version === 3) rejectUnknown(errors, label, action, [
      'id', 'fingerprint', 'framework', 'name', 'location', 'authentication', 'authorization',
      'actionScopedControl', 'accessChains', 'operations', 'priority', 'limitations', 'baseline',
    ]);
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
    if (version === 3) {
      if (!text(action?.name, 160) || !Array.isArray(action?.operations)
          || action.operations.length > 30 || !action.operations.every(id)
          || !Array.isArray(action?.limitations) || action.limitations.length > 20
          || !action.limitations.every(id) || !Array.isArray(action?.accessChains)
          || action.accessChains.length > 50) errors.push(`${label} bounded fields are invalid`);
      validateV3Control(action.authentication, `${label}.authentication`, errors);
      validateV3Control(action.authorization, `${label}.authorization`, errors);
      validateV3ScopedControl(action.actionScopedControl, `${label}.actionScopedControl`, errors);
      validateV3Priority(action.priority, `${label}.priority`, errors);
      validateV3RecordBaseline(action.baseline, `${label}.baseline`, errors);
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
      if (version === 3) {
        validateV3Chain(chain, chainLabel, errors);
        if (chainIds.has(chain?.id)) errors.push(`${chainLabel}.id is duplicated`);
        else chainIds.add(chain?.id);
        continue;
      }
      if (!chain?.id?.startsWith('access-chain.') || !digest(chain?.fingerprint)) {
        errors.push(`${chainLabel} identity is invalid`);
      }
      if (!ACCESS_CHAIN_STATUSES.includes(chain?.status)) errors.push(`${chainLabel}.status is invalid`);
      if (!LEGACY_ACCESS_CHAIN_OUTCOMES.includes(chain?.outcome)) errors.push(`${chainLabel}.outcome is invalid`);
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
