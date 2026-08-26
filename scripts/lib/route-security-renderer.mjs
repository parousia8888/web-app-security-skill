import { assertRouteSecurityDocument } from './route-security-contract.mjs';

const code = (value) => `\`${String(value).replace(/`/g, '\\`')}\``;
const listCounts = (value) => Object.entries(value).filter(([, count]) => count)
  .map(([key, count]) => `${key}=${count}`).join(', ') || 'none';
const signalList = (signals) => signals?.length
  ? signals.map((signal) => `${code(signal.kind)} at ${code(`${signal.location.path}:${signal.location.line || '?'}`)}`).join(', ')
  : 'none';

function chainTitle(chain) {
  if (chain.outcome === 'principal_constraint_not_observed') return {
    term: 'Object-level authorization review (BOLA/IDOR)',
    plain: 'A user-selected record ID reaches a database operation, but this bounded path did not show the same user or tenant in that operation.',
    consequence: 'If no equivalent policy exists elsewhere, one signed-in user may be able to read or change another user\'s record.',
    proposal: 'Trace the real authorization boundary. If this query owns it, constrain the lookup by the authenticated user or tenant and preserve explicit privileged paths.',
  };
  if (chain.outcome === 'external_policy_required') return {
    term: 'External row-level security (RLS) dependency review',
    plain: 'The source query selects a user-chosen record, while the decisive per-row permission may live in the database rather than this code.',
    consequence: 'If the database policy is missing, disabled or uses the wrong identity, cross-account access may be possible.',
    proposal: 'Inspect the deployed table policy and role used by this request. Do not add a duplicate code filter until the database boundary is understood.',
  };
  return {
    term: 'Incomplete static access-control chain',
    plain: 'The analyzer could follow part of the path but stopped before it reached a supported authorization decision.',
    consequence: 'The route may be protected or exposed; the available source evidence cannot distinguish those outcomes.',
    proposal: 'Inspect the unresolved call or dynamic boundary manually, then rerun after simplifying only if the project owner approves that refactor.',
  };
}

function chainOperation(chain) {
  const operation = chain.dataOperation;
  return operation
    ? `${operation.provider}.${operation.resource}.${operation.operation} at ${operation.location.path}:${operation.location.line || '?'}`
    : 'no supported data operation reached';
}

function chainSummary(chains) {
  return chains.length ? chains.map((chain) => {
    const operation = chain.dataOperation;
    return code(`${operation ? `${operation.provider}.${operation.resource}.${operation.operation}` : 'unresolved'}:${chain.outcome}`);
  }).join(', ') : 'none observed';
}

function reviewEntries(document) {
  const entries = [];
  for (const route of document.routes) for (const chain of route.accessChains || []) {
    if (['principal_constraint_not_observed', 'external_policy_required', 'incomplete'].includes(chain.outcome)) {
      entries.push({ kind: 'Route', name: `${route.method} ${route.path || '(dynamic path)'}`, chain });
    }
  }
  for (const action of document.serverActions || []) for (const chain of action.accessChains || []) {
    if (['principal_constraint_not_observed', 'external_policy_required', 'incomplete'].includes(chain.outcome)) {
      entries.push({ kind: 'Server Action', name: action.name, chain });
    }
  }
  return entries;
}

export function renderRouteSecurityMarkdown(document) {
  assertRouteSecurityDocument(document);
  const lines = [
    '# Route security review', '',
    `- Tool: ${code(`${document.tool.name} ${document.tool.version}`)}`,
    `- Mode: ${code(document.mode)}`,
    `- Routes inventoried: ${document.summary.total}`,
    `- State-changing: ${document.summary.stateChanging}`,
    `- Object-addressed: ${document.summary.objectAddressed}`,
    `- Server Actions inventoried: ${document.summary.serverActions || 0}`,
    '', 'Review priority orders manual work; it is not vulnerability severity. A control marked',
    'observed is static source evidence and does not prove runtime enforcement or correctness.', '',
    '## Summary', '',
    `- Frameworks: ${listCounts(document.summary.byFramework)}`,
    `- Priority: ${listCounts(document.summary.byPriority)}`,
    `- Authentication evidence: ${listCounts(document.summary.byAuthentication)}`,
    `- Authorization evidence: ${listCounts(document.summary.byAuthorization)}`,
    `- Route-scoped controls: ${listCounts(document.summary.byRouteScopedControl || {})}`,
    `- Application controls: ${document.summary.applicationControls || 0} (${listCounts(document.summary.byApplicationControlRole || {})})`,
    '', '## Coverage', '',
  ];
  if (!document.coverage.length) lines.push('No supported framework coverage was applicable.', '');
  for (const item of document.coverage) {
    const counts = Object.entries(item.counts).map(([key, value]) => `${key}=${value}`).join(', ');
    const reasons = item.reasons.map((reason) => `${reason.code}=${reason.count}`).join(', ');
    lines.push(`- ${code(item.framework)}: ${item.status}; ${counts}${reasons ? `; ${reasons}` : ''}`);
  }
  lines.push('', '## Application-scoped controls', '');
  if (!document.applicationControls?.length) {
    lines.push('No supported application-scoped control declaration was observed.', '');
  } else {
    lines.push('These declarations are recorded once. They are not copied into every route and do not prove route applicability.', '');
    for (const control of document.applicationControls) {
      lines.push(`- ${code(control.kind)} (${code(control.role)}) from ${code(control.origin)} at ${code(`${control.location.path}:${control.location.line || '?'}`)}. ${control.boundary}`);
    }
    lines.push('');
  }
  const scopedReview = document.routes.filter((route) =>
    ['no_route_scoped_control_observed', 'unclassified_control_observed']
      .includes(route.routeScopedControl?.state)
      && (route.stateChanging || route.objectAddressed));
  lines.push('## Route-scoped control review', '');
  lines.push('This queue includes state-changing or object-addressed routes with no classified route/controller security control. Expected-public routes can be valid and still require owner classification.', '');
  if (!scopedReview.length) lines.push('No route matched this bounded review condition.', '');
  else {
    for (const route of scopedReview) {
      const state = route.routeScopedControl.state;
      const guidance = state === 'unclassified_control_observed'
        ? `Unclassified candidates: ${signalList(route.routeScopedControl.unclassifiedSignals)}; identify whether each one authenticates, authorizes, rate-limits or only observes the request.`
        : 'No route-scoped control was observed; classify whether this route is intentionally public.';
      lines.push(`- ${route.method} ${route.path ? code(route.path) : '(dynamic path)'} at ${code(`${route.location.path}:${route.location.line || '?'}`)} (${code(route.priority.level)}; ${code(state)}). ${guidance}`);
    }
    lines.push('');
  }
  const accessReview = reviewEntries(document);
  lines.push('## Access-control chain review', '',
    'These items are review leads, not confirmed vulnerabilities. Missing source evidence never proves that deployed authorization is absent.', '');
  if (!accessReview.length) lines.push('No access chain matched the bounded review conditions.', '');
  for (const [index, item] of accessReview.entries()) {
    const description = chainTitle(item.chain);
    const selectors = item.chain.objectSelectors.map((selector) => selector.name).join(', ') || 'unknown';
    lines.push(
      `### ${index + 1}. ${item.kind}: ${item.name}`, '',
      `- Industry term: ${description.term}.`,
      `- Plain language: ${description.plain}`,
      `- Observed fact: selector ${code(selectors)} reaches ${code(chainOperation(item.chain))}; chain outcome is ${code(item.chain.outcome)}.`,
      `- Not proved: ${item.chain.evidenceBoundary}`,
      `- Possible consequence if project review confirms a defect: ${description.consequence}`,
      `- Review proposal: ${description.proposal}`,
      '- Change risks: owner or tenant filters can break deliberate sharing, administrator, support, background-job and cross-tenant workflows; preserve and test each approved exception.',
      `- Unauthenticated check: ${item.chain.verification.unauthenticated}`,
      `- Owner check: ${item.chain.verification.owner}`,
      `- Non-owner check: ${item.chain.verification.nonOwner}`,
      `- Lower-role check: ${item.chain.verification.lowerRole}`,
      `- Normal-flow retest: ${item.chain.verification.functional}`,
      '',
    );
  }
  lines.push('## Routes', '');
  if (!document.routes.length) lines.push('No routes were inventoried within the supported syntax boundary.', '');
  for (const route of document.routes) {
    lines.push(
      `### ${route.method} ${route.path ? code(route.path) : '(dynamic path)'}`, '',
      `- Framework: ${code(route.framework)}`,
      `- Source: ${code(`${route.location.path}:${route.location.line || '?'}`)}`,
      `- Review priority: ${code(route.priority.level)}${route.priority.reasons.length ? ` (${route.priority.reasons.join(', ')})` : ''}`,
      `- Baseline: ${route.baseline.state ? code(route.baseline.state) : 'not compared'}`,
      `- Authentication: ${code(route.authentication.state)}. ${route.authentication.boundary}`,
      `- Authentication signals: ${signalList(route.authentication.signals)}`,
      `- Authorization: ${code(route.authorization.state)}. ${route.authorization.boundary}`,
      `- Authorization signals: ${signalList(route.authorization.signals)}`,
      `- Route-scoped control: ${code(route.routeScopedControl?.state || 'legacy-v1')}. ${route.routeScopedControl?.boundary || 'This legacy v1 record has no separate route-scoped-control state.'}`,
      `- Unclassified route controls: ${signalList(route.routeScopedControl?.unclassifiedSignals)}`,
      `- State-changing: ${route.stateChanging ? 'yes' : 'no'}; object-addressed: ${route.objectAddressed ? 'yes' : 'no'}`,
      `- Sensitive operations: ${route.operations.length ? route.operations.map(code).join(', ') : 'none observed'}`,
      `- Access chains: ${chainSummary(route.accessChains || [])}`,
      `- Evidence limits: ${route.limitations.length ? route.limitations.map(code).join(', ') : 'none beyond the global limits below'}`,
      '',
    );
  }
  lines.push('## Server Actions', '');
  if (!document.serverActions?.length) lines.push('No direct static Server Actions were inventoried.', '');
  for (const action of document.serverActions || []) {
    lines.push(
      `### ${action.name}`, '',
      `- Source: ${code(`${action.location.path}:${action.location.line || '?'}`)}`,
      '- HTTP mapping: not inferred; Server Actions are not represented as fictional routes.',
      `- Review priority: ${code(action.priority.level)}${action.priority.reasons.length ? ` (${action.priority.reasons.join(', ')})` : ''}`,
      `- Baseline: ${action.baseline.state ? code(action.baseline.state) : 'not compared'}`,
      `- Authentication: ${code(action.authentication.state)}. ${action.authentication.boundary}`,
      `- Authorization: ${code(action.authorization.state)}. ${action.authorization.boundary}`,
      `- Action-scoped control: ${code(action.actionScopedControl.state)}. ${action.actionScopedControl.boundary}`,
      `- Sensitive operations: ${action.operations.length ? action.operations.map(code).join(', ') : 'none observed'}`,
      `- Access chains: ${chainSummary(action.accessChains || [])}`,
      `- Evidence limits: ${action.limitations.length ? action.limitations.map(code).join(', ') : 'none beyond the global limits below'}`,
      '',
    );
  }
  lines.push('## Limitations', '');
  if (!document.limitations.length) lines.push('- Static route evidence does not prove deployed behavior.', '');
  else lines.push(...document.limitations.map((item) => `- ${item}`), '');
  return `${lines.join('\n')}\n`;
}
