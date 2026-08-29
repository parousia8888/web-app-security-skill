import { assertRouteSecurityDocument } from './route-security-contract.mjs';
import { markdownCodeSpan } from './markdown-escaping.mjs';

const code = markdownCodeSpan;
const listCounts = (value) => Object.entries(value).filter(([, count]) => count)
  .map(([key, count]) => `${key}=${count}`).join(', ') || 'none';
const signalList = (signals) => signals?.length
  ? signals.map((signal) => `${code(signal.kind)} at ${code(`${signal.location.path}:${signal.location.line || '?'}`)}`).join(', ')
  : 'none';

function chainTitle(chain) {
  if (chain.outcome === 'authorization_constraint_observed') return {
    term: 'Bounded object-authorization constraint observed',
    plain: 'This source path connected the user-selected object to a supported query or comparison that also used the current user or tenant.',
    consequence: 'This lowers concern for this exact static path, but it does not prove the deployed request is reachable only through this control or that every role behaves correctly.',
    proposal: 'Keep the constraint and verify unauthenticated, owner, non-owner and privileged-role behavior before treating the path as accepted.',
    risk: 'Changing a working owner or tenant constraint can break deliberate sharing, administrator, support, background-job or cross-tenant workflows.',
  };
  if (['authorization_constraint_not_observed', 'principal_constraint_not_observed']
    .includes(chain.outcome)) return {
    term: 'Object-level authorization review (BOLA/IDOR)',
    plain: 'A user-selected record ID reaches a database operation, but this bounded path did not show the same user or tenant in that operation.',
    consequence: 'If no equivalent policy exists elsewhere, one signed-in user may be able to read or change another user\'s record.',
    proposal: 'Trace the real authorization boundary. If this query owns it, constrain the lookup by the authenticated user or tenant and preserve explicit privileged paths.',
    risk: 'Adding an owner or tenant predicate can block deliberate sharing, administrator, support, background-job and cross-tenant workflows; preserve and test each approved exception.',
  };
  if (chain.outcome === 'external_policy_required') return {
    term: 'External row-level security (RLS) dependency review',
    plain: 'The source query selects a user-chosen record, while the decisive per-row permission may live in the database rather than this code.',
    consequence: 'If the database policy is missing, disabled or uses the wrong identity, cross-account access may be possible.',
    proposal: 'Inspect the deployed table policy and role used by this request. Do not add a duplicate code filter until the database boundary is understood.',
    risk: 'Duplicating a database policy in application code can create inconsistent behavior across roles and make policy changes harder to review.',
  };
  if (chain.outcome === 'no_supported_object_operation') return {
    term: 'No supported object operation on this bounded path',
    plain: 'The selected value did not reach a database operation that this analyzer knows how to evaluate along this exact local path.',
    consequence: 'No object-authorization conclusion is available from this path; unsupported storage, remote APIs or later runtime work may still matter.',
    proposal: 'Do not change authorization solely because of this result. Confirm whether the value reaches an unsupported data or policy boundary.',
    risk: 'Adding a speculative control can reject legitimate traffic without addressing the real enforcement layer.',
  };
  return {
    term: 'Incomplete static access-control chain',
    plain: 'The analyzer could follow part of the path but stopped before it reached a supported authorization decision.',
    consequence: 'The route may be protected or exposed; the available source evidence cannot distinguish those outcomes.',
    proposal: 'Inspect the unresolved call or dynamic boundary manually, then rerun after simplifying only if the project owner approves that refactor.',
    risk: 'Refactoring only to satisfy static analysis can change runtime behavior; preserve the existing flow and tests before simplifying the boundary.',
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

function chainEntries(document) {
  const entries = [];
  for (const route of document.routes) for (const chain of route.accessChains || []) {
    entries.push({ kind: 'Route', name: `${route.method} ${route.path || '(dynamic path)'}`,
      location: route.location, chain });
  }
  for (const action of document.serverActions || []) for (const chain of action.accessChains || []) {
    entries.push({ kind: 'Server Action', name: action.name, location: action.location, chain });
  }
  return entries;
}

function selectorList(chain) {
  return chain.objectSelectors.map((selector) =>
    `${selector.kind}:${selector.name} (${selector.origin || 'legacy-origin-unrecorded'}) at ${selector.location.path}:${selector.location.line || '?'}`)
    .join(', ') || 'none recorded';
}

function callPath(chain) {
  return chain.callEdges.length ? chain.callEdges.map((edge, index) =>
    `${index + 1}. ${edge.from} -> ${edge.to} (${edge.kind}) at ${edge.location.path}:${edge.location.line || '?'}`)
    .join('; ') : 'direct entry body; no local call edge';
}

function authorizationList(chain) {
  return (chain.authorizationEvidence || []).map((evidence) =>
    `${evidence.kind}/${evidence.category}/${evidence.state}${evidence.field ? `:${evidence.field}` : ''}${evidence.location ? ` at ${evidence.location.path}:${evidence.location.line || '?'}` : ''}`)
    .join(', ') || 'none recorded';
}

function chainRank(chain) {
  if (['authorization_constraint_not_observed', 'principal_constraint_not_observed']
    .includes(chain.outcome)) return 0;
  if (chain.outcome === 'external_policy_required') return 1;
  if (chain.outcome === 'incomplete') return 2;
  if (chain.outcome === 'authorization_constraint_observed') return 3;
  return 4;
}

function appendChainEvidence(lines, entries, startIndex = 0) {
  for (const [offset, item] of entries.entries()) {
    const description = chainTitle(item.chain);
    lines.push(
      `### ${startIndex + offset + 1}. ${item.kind}: ${code(item.name)}`, '',
      `- Industry term: ${description.term}.`,
      `- Plain language: ${description.plain}`,
      `- Entry: ${code(`${item.location.path}:${item.location.line || '?'}`)}.`,
      `- Object selector: ${code(selectorList(item.chain))}.`,
      `- Ordered local calls: ${code(callPath(item.chain))}.`,
      `- Data operation: ${code(chainOperation(item.chain))}.`,
      `- Analysis result: status ${code(item.chain.status)}; outcome ${code(item.chain.outcome)}.`,
      `- Authorization evidence: ${code(authorizationList(item.chain))}.`,
      `- Primary incomplete reason: ${item.chain.reason ? code(item.chain.reason) : 'not applicable'}.`,
      `- Not proved: ${item.chain.evidenceBoundary}`,
      `- Possible consequence if project review confirms a defect: ${description.consequence}`,
      `- Review proposal: ${description.proposal}`,
      `- Change risks: ${description.risk}`,
      `- Unauthenticated check: ${item.chain.verification.unauthenticated}`,
      `- Owner check: ${item.chain.verification.owner}`,
      `- Non-owner check: ${item.chain.verification.nonOwner}`,
      `- Lower-role check: ${item.chain.verification.lowerRole}`,
      `- Normal-flow retest: ${item.chain.verification.functional}`,
      '',
    );
  }
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
  const pathCounts = Object.entries(document.accessPathCoverage.counts)
    .map(([key, value]) => `${key}=${value}`).join(', ');
  const pathReasons = document.accessPathCoverage.reasons
    .map((reason) => `${reason.code}=${reason.count}`).join(', ');
  lines.push('', `- Access-path analysis: ${code(document.accessPathCoverage.status)}; ${pathCounts}${pathReasons ? `; ${pathReasons}` : ''}`,
    '- Framework inventory says whether supported entries were found and parsed. Access-path coverage separately says whether eligible object paths were followed within the bounded model.', '');
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
  const accessReview = chainEntries(document).sort((left, right) =>
    chainRank(left.chain) - chainRank(right.chain)
      || [left.kind, left.name, left.location.path, left.location.line || 0].join('\u0000')
        .localeCompare([right.kind, right.name, right.location.path,
          right.location.line || 0].join('\u0000')));
  const highSignal = accessReview.filter((item) => chainRank(item.chain) <= 2);
  const supporting = accessReview.filter((item) => chainRank(item.chain) > 2);
  lines.push('## Access-path review leads', '',
    'Every item below is bounded static evidence, not a confirmed vulnerability or a safety verdict. `completed` means the supported path analysis finished; it does not mean the route is safe.', '');
  if (!highSignal.length) lines.push('No access chain matched the bounded review-lead outcomes.', '');
  else appendChainEvidence(lines, highSignal);
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
  lines.push('## Supporting access-path evidence', '',
    'Completed paths with visible authorization evidence and paths without a supported object operation are retained here so later refactors can preserve or investigate them.', '');
  if (!supporting.length) lines.push('No supporting access chain was emitted.', '');
  else appendChainEvidence(lines, supporting, highSignal.length);
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
      `### ${code(action.name)}`, '',
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
