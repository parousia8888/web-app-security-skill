import { analyzeAccessPaths, createAccessPathBudget } from '../js-ts-access-path.mjs';
import { analyzeIdentityEvidence } from '../js-ts-identity-evidence.mjs';
import { extractSelectorEvidence } from '../js-ts-selector-evidence.mjs';
import {
  accessChainRecord, controlEvidence, routeScopedControlEvidence, serverActionRecord,
} from '../route-security-model.mjs';
import {
  aggregateReasons, importedBindings, sourceLocation,
} from './route-extractor-helpers.mjs';

const FUNCTION_TYPES = new Set(['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression']);

function directiveObserved(container) {
  return (container?.directives || []).some((directive) => directive.value?.value === 'use server');
}

function functionDeclarations(module) {
  const values = new Map();
  for (const raw of module.ast?.body || []) {
    const node = raw.type === 'ExportNamedDeclaration' ? raw.declaration : raw;
    if (node?.type === 'FunctionDeclaration' && node.id?.name) values.set(node.id.name, node);
    for (const declaration of node?.declarations || []) {
      if (declaration.id?.type === 'Identifier' && FUNCTION_TYPES.has(declaration.init?.type)) {
        values.set(declaration.id.name, declaration.init);
      }
    }
  }
  return values;
}

function exportedActions(module) {
  const values = functionDeclarations(module);
  const moduleDirective = directiveObserved(module.ast);
  const actions = [];
  const reasons = [];
  for (const node of module.ast?.body || []) {
    if (node.type !== 'ExportNamedDeclaration') continue;
    if (node.source) {
      if (moduleDirective) reasons.push({ code: 'next_server_action_reexport_unresolved', path: module.path });
      continue;
    }
    const candidates = [];
    if (node.declaration?.type === 'FunctionDeclaration') {
      candidates.push({ name: node.declaration.id?.name, handler: node.declaration });
    }
    for (const declaration of node.declaration?.declarations || []) {
      if (declaration.id?.type === 'Identifier' && FUNCTION_TYPES.has(declaration.init?.type)) {
        candidates.push({ name: declaration.id.name, handler: declaration.init });
      }
    }
    for (const specifier of node.specifiers || []) {
      const name = specifier.exported?.name || specifier.exported?.value;
      const local = specifier.local?.name || specifier.local?.value;
      if (values.has(local)) candidates.push({ name, handler: values.get(local) });
    }
    for (const candidate of candidates) {
      const functionDirective = directiveObserved(candidate.handler.body);
      if (!moduleDirective && !functionDirective) continue;
      if (!candidate.handler.async) {
        reasons.push({ code: 'next_server_action_not_async', path: module.path });
        continue;
      }
      actions.push(candidate);
    }
  }
  return { actions: actions.filter((item, index, items) => items.findIndex((candidate) =>
    candidate.name === item.name && candidate.handler.start === item.handler.start) === index), reasons,
    applicable: moduleDirective || [...values.values()].some((handler) => directiveObserved(handler.body)) };
}

function authenticationEvidence(identity) {
  if (identity.state === 'not_observed') return controlEvidence('not_observed', [],
    'No exact supported identity-provider call was observed in this Server Action.');
  return controlEvidence('local_observed', identity.signals,
    'An exact supported identity-provider call was observed in this Server Action; denial behavior and session validity are not proved.');
}

function priorityFor(action) {
  const reasons = [];
  if (action.accessChains.some((chain) => ['authorization_constraint_not_observed',
    'external_policy_required', 'incomplete'].includes(chain.outcome))) {
    reasons.push('server-action-object-authorization-review');
  }
  if (action.accessChains.length && action.actionScopedControl.state === 'no_route_scoped_control_observed') {
    reasons.push('no-action-scoped-control-observed');
  }
  return { level: reasons.length ? 'review_first' : action.accessChains.length
    ? 'review_next' : 'no_automatic_priority', reasons };
}

export function extractNextServerActions(graph) {
  const records = [];
  const reasons = [];
  const accessBudget = createAccessPathBudget();
  let eligible = 0;
  for (const module of graph.modules.values()) {
    if (!module.ast) continue;
    const exported = exportedActions(module);
    if (!exported.applicable) continue;
    eligible += 1;
    reasons.push(...exported.reasons);
    for (const candidate of exported.actions) {
      const identity = analyzeIdentityEvidence(graph, module, candidate.handler);
      const selected = extractSelectorEvidence({
        module, handler: candidate.handler, entryKind: 'server-action',
        imports: importedBindings(module), principalAliases: identity.principalAliases,
      });
      reasons.push(...selected.limitations.map((item) => ({ code: item.code, path: module.path })));
      const authentication = authenticationEvidence(identity.identity);
      const actionScopedControl = routeScopedControlEvidence(
        authentication.state === 'local_observed' ? authentication.signals : [], [],
      );
      const seed = serverActionRecord({
        name: candidate.name, location: sourceLocation(module.path, candidate.handler),
        authentication, authorization: controlEvidence('not_observed', [],
          'No supported action-scoped authorization construct was observed.'),
        actionScopedControl, limitations: selected.limitations.map((item) => item.code),
      });
      const exactSelectors = selected.selectors.filter((selector) => selector.origin === 'request_selected');
      const paths = analyzeAccessPaths({
        graph, module, handler: candidate.handler, entry: { kind: 'server-action', id: seed.id,
          name: candidate.name, module },
        identity: identity.identity, selectorGroups: selected.selectorGroups,
        principalAliases: identity.principalAliases, tenantAliases: identity.tenantAliases,
        budget: accessBudget,
      });
      reasons.push(...paths.coverage.reasons.map((code) => ({ code, path: module.path })));
      const accessChains = paths.chains.map(accessChainRecord);
      if (!accessChains.length && selected.limitations.length && selected.selectors.length) {
        const unresolvedSelectors = selected.selectors.some((selector) => selector.origin === 'unknown')
          ? selected.selectors.filter((selector) => selector.origin === 'unknown')
          : exactSelectors.map((selector) => ({ ...selector, origin: 'unknown' }));
        accessChains.push(accessChainRecord({
          entryKind: 'server-action', entryId: seed.id, status: 'partial', outcome: 'incomplete',
          identity: identity.identity,
          objectSelectors: unresolvedSelectors,
          callEdges: [], dataOperation: null, reason: 'selector_source_unresolved',
          limitations: selected.limitations.map((item) => item.code),
          evidenceBoundary: 'A dynamic or ambiguous Server Action selector was observed, but its exact field or value origin could not be established. No object-authorization conclusion is available.',
        }));
      }
      const action = serverActionRecord({
        ...seed, accessChains,
        operations: paths.operations.map((item) => `${item.provider}-${item.operation}`),
        limitations: [...selected.limitations.map((item) => item.code),
          ...paths.limitations, ...paths.chains.map((item) => item.reason).filter(Boolean)],
      });
      records.push({ ...action, priority: priorityFor(action) });
    }
  }
  return {
    serverActions: records,
    coverage: {
      framework: 'next-app',
      status: reasons.length ? 'partial' : eligible ? 'completed' : 'not_applicable',
      counts: { discovered: graph.modules.size, eligible, parsed: eligible,
        incomplete: new Set(reasons.map((item) => item.path)).size },
      reasons: aggregateReasons(reasons),
    },
  };
}
