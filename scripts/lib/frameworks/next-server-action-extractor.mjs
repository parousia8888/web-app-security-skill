import { analyzeDataOperations } from '../js-ts-data-operation-evidence.mjs';
import { analyzeIdentityEvidence } from '../js-ts-identity-evidence.mjs';
import { analyzeOneHopAccess } from '../js-ts-one-hop-access.mjs';
import {
  accessChainRecord, controlEvidence, routeScopedControlEvidence, serverActionRecord,
} from '../route-security-model.mjs';
import {
  aggregateReasons, sourceLocation, walkJsTsAst,
} from './route-extractor-helpers.mjs';

const ID_NAME = /(?:^|[_-])id$|Id$/;
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

function objectSelectors(module, handler) {
  const aliases = new Set();
  const selectors = [];
  const parameters = new Set();
  for (const raw of handler.params || []) {
    const parameter = raw.type === 'AssignmentPattern' ? raw.left : raw;
    if (parameter?.type !== 'Identifier') continue;
    parameters.add(parameter.name);
    if (ID_NAME.test(parameter.name)) {
      aliases.add(parameter.name);
      selectors.push({ kind: 'action-parameter', name: parameter.name,
        location: sourceLocation(module.path, parameter) });
    }
  }
  walkJsTsAst(handler.body, (node) => {
    if (node.type !== 'VariableDeclarator' || node.id?.type !== 'Identifier'
        || node.init?.type !== 'CallExpression' || node.init.arguments.length !== 1) return;
    const callee = node.init.callee;
    if (callee?.type !== 'MemberExpression' || callee.computed
        || callee.property?.name !== 'get' || callee.object?.type !== 'Identifier'
        || !parameters.has(callee.object.name)) return;
    const selected = node.init.arguments[0]?.type === 'StringLiteral' ? node.init.arguments[0].value : null;
    if (!selected || !ID_NAME.test(selected)) return;
    aliases.add(node.id.name);
    selectors.push({ kind: 'form-data-field', name: selected,
      location: sourceLocation(module.path, node) });
  });
  return { aliases, selectors };
}

function authenticationEvidence(identity) {
  if (identity.state === 'not_observed') return controlEvidence('not_observed', [],
    'No exact supported identity-provider call was observed in this Server Action.');
  return controlEvidence('local_observed', identity.signals,
    'An exact supported identity-provider call was observed in this Server Action; denial behavior and session validity are not proved.');
}

function chainOutcome(operation) {
  if (operation.principalConstraint === 'observed' || operation.tenantConstraint === 'observed') {
    return 'principal_constraint_observed';
  }
  return operation.externalPolicy === 'external_policy_required'
    ? 'external_policy_required' : 'principal_constraint_not_observed';
}

function directChain(action, identity, selectors, operation) {
  return accessChainRecord({
    entryKind: 'server-action', entryId: action.id, status: 'completed',
    outcome: chainOutcome(operation), identity, objectSelectors: selectors,
    callEdges: [], dataOperation: operation,
    evidenceBoundary: operation.externalPolicy === 'external_policy_required'
      ? 'A client-selected Server Action value reaches a supported Supabase operation. Database row-level security remains external evidence.'
      : 'A client-selected Server Action value reaches a supported same-function data operation. Runtime authorization and exploitability are not proved.',
  });
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
  let eligible = 0;
  for (const module of graph.modules.values()) {
    if (!module.ast) continue;
    const exported = exportedActions(module);
    if (!exported.applicable) continue;
    eligible += 1;
    reasons.push(...exported.reasons);
    for (const candidate of exported.actions) {
      const selected = objectSelectors(module, candidate.handler);
      const identity = analyzeIdentityEvidence(graph, module, candidate.handler);
      const authentication = authenticationEvidence(identity.identity);
      const actionScopedControl = routeScopedControlEvidence(
        authentication.state === 'local_observed' ? authentication.signals : [], [],
      );
      const seed = serverActionRecord({
        name: candidate.name, location: sourceLocation(module.path, candidate.handler),
        authentication, authorization: controlEvidence('not_observed', [],
          'No supported action-scoped authorization construct was observed.'),
        actionScopedControl, limitations: [],
      });
      const direct = analyzeDataOperations(graph, module, candidate.handler, {
        objectAliases: selected.aliases, principalAliases: identity.principalAliases,
      });
      const oneHop = analyzeOneHopAccess({
        graph, module, handler: candidate.handler, entry: { kind: 'server-action', id: seed.id,
          name: candidate.name, module },
        identity: identity.identity, objectAliases: selected.aliases,
        principalAliases: identity.principalAliases, objectSelectors: selected.selectors,
      });
      const accessChains = [
        ...direct.operations.map((operation) => directChain(seed, identity.identity,
          selected.selectors, operation)),
        ...oneHop.map(accessChainRecord),
      ];
      const action = serverActionRecord({
        ...seed, accessChains,
        operations: [...direct.operations, ...oneHop.map((item) => item.dataOperation).filter(Boolean)]
          .map((item) => `${item.provider}-${item.operation}`),
        limitations: oneHop.map((item) => item.reason).filter(Boolean),
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
