import { analyzeDataOperations } from './js-ts-data-operation-evidence.mjs';
import { callableIndexForGraph } from './js-ts-callable-index.mjs';
import { analyzeIdentityEvidence } from './js-ts-identity-evidence.mjs';
import { expressionName } from './js-ts-module-graph.mjs';
import {
  callCarriesObject, expandSummaryFacts, mapCallFacts, summarizeCallable,
} from './js-ts-function-summary.mjs';
import { sourceLocation } from './frameworks/route-extractor-helpers.mjs';
import { ACCESS_PATH_LIMITS } from './route-security-model.mjs';

const DATA_OPERATION_METHODS = new Set([
  'findUnique', 'findUniqueOrThrow', 'findFirst', 'findFirstOrThrow', 'findMany',
  'select', 'insert', 'update', 'updateMany', 'delete', 'deleteMany', 'upsert',
]);

function entryTarget(module, handler, entry) {
  const offset = Number.isInteger(handler?.start) ? handler.start : handler?.loc?.start?.line ?? 0;
  return {
    id: `${module.path}#entry:${entry.id}:${offset}`,
    module,
    node: handler,
    name: entry.name,
    kind: 'entry',
  };
}

function normalizedFacts(facts) {
  return ['objectAliases', 'principalAliases', 'tenantAliases'].map((key) =>
    [...facts[key]].sort().join(',')).join('\u0000');
}

function mergeIdentity(left, right) {
  if (!right || right.state === 'not_observed') return left;
  if (!left || left.state === 'not_observed') return right;
  const signals = [...(left.signals || []), ...(right.signals || [])].filter((signal, index, items) =>
    items.findIndex((candidate) => candidate.kind === signal.kind
      && candidate.location?.path === signal.location?.path
      && candidate.location?.line === signal.location?.line) === index);
  if (left.state === right.state && left.provider === right.provider) {
    return { ...left, signals };
  }
  return {
    state: left.state === 'incomplete' && right.state === 'incomplete'
      ? 'incomplete' : 'candidate_observed',
    provider: left.provider === right.provider ? left.provider : 'multiple',
    signals,
    boundary: 'Multiple bounded identity observations contribute to this path; their runtime relationship and enforcement are not proved.',
  };
}

function addReturnedIdentityAlias(facts, category, name) {
  if (!name || !['principal', 'tenant'].includes(category)) return;
  facts[`${category}Aliases`].add(name);
}

function applyReturnedIdentityFacts(graph, summary, facts) {
  const identities = [];
  const limitations = new Set();
  for (const call of summary.calls) {
    if (call.resolution?.state !== 'exact' || call.resultMapping.kind === 'unused') continue;
    const returned = analyzeIdentityEvidence(graph, call.resolution.target.module,
      call.resolution.target.node);
    if (returned.returnFacts?.state === 'incomplete') {
      limitations.add('identity_return_mapping_unresolved');
      continue;
    }
    if (returned.returnFacts?.state !== 'exact') continue;
    identities.push(returned.identity);
    for (const limitation of returned.limitations || []) limitations.add(limitation);
    const shape = returned.returnFacts.shape;
    if (shape.kind === 'scalar' && call.resultMapping.kind === 'identifier') {
      addReturnedIdentityAlias(facts, shape.category, call.resultMapping.name);
      continue;
    }
    if (shape.kind === 'object' && call.resultMapping.kind === 'identifier') {
      for (const field of shape.fields) {
        addReturnedIdentityAlias(facts, field.category, `${call.resultMapping.name}.${field.field}`);
      }
      continue;
    }
    if (shape.kind === 'object' && call.resultMapping.kind === 'object_pattern') {
      for (const binding of call.resultMapping.bindings) {
        const field = shape.fields.find((candidate) => candidate.field === binding.field);
        if (field) addReturnedIdentityAlias(facts, field.category, binding.local);
      }
      continue;
    }
    limitations.add('identity_return_mapping_unresolved');
  }
  return { facts, identities, limitations: [...limitations].sort() };
}

function stateKey(state) {
  return [state.target.id, normalizedFacts(state.facts),
    ...state.callEdges.flatMap((edge) => [edge.kind, edge.from, edge.to])].join('\u0000');
}

function chainKey(chain) {
  return JSON.stringify([
    chain.status, chain.outcome, chain.reason,
    chain.objectSelectors.map((selector) => [selector.kind, selector.name, selector.origin]),
    chain.callEdges.map((edge) => [edge.kind, edge.from, edge.to]),
    chain.dataOperation && [chain.dataOperation.provider, chain.dataOperation.resource,
      chain.dataOperation.operation, chain.dataOperation.location.path, chain.dataOperation.location.line],
    chain.limitations || [],
  ]);
}

function outcomeFor(operation) {
  if (operation.principalConstraint === 'observed' || operation.tenantConstraint === 'observed') {
    return 'principal_constraint_observed';
  }
  return operation.externalPolicy === 'external_policy_required'
    ? 'external_policy_required' : 'principal_constraint_not_observed';
}

function completed(state, operation) {
  return {
    entryKind: state.entry.kind,
    entryId: state.entry.id,
    status: 'completed',
    outcome: outcomeFor(operation),
    identity: state.identity,
    objectSelectors: [state.selector],
    callEdges: state.callEdges,
    dataOperation: operation,
    authorizationEvidence: null,
    limitations: state.limitations,
    evidenceBoundary: state.callEdges.length
      ? 'An exact bounded local call path reached a supported data operation. Static source relationships do not prove deployed authorization or exploitability.'
      : 'The request-selected object reaches a supported same-handler data operation. Static source relationships do not prove deployed authorization or exploitability.',
    reason: null,
  };
}

function partial(state, reason, limitation = reason, callEdges = state.callEdges) {
  return {
    entryKind: state.entry.kind,
    entryId: state.entry.id,
    status: 'partial',
    outcome: 'incomplete',
    identity: state.identity,
    objectSelectors: [state.selector],
    callEdges,
    dataOperation: null,
    authorizationEvidence: null,
    limitations: [...new Set([...state.limitations, limitation].filter(Boolean))].sort(),
    evidenceBoundary: `A request-selected object remained live on a bounded local path, but analysis stopped at ${reason}. No authorization conclusion is available.`,
    reason,
  };
}

function notApplicable(state) {
  return {
    entryKind: state.entry.kind,
    entryId: state.entry.id,
    status: 'not_applicable',
    outcome: 'no_supported_object_operation',
    identity: state.identity,
    objectSelectors: [state.selector],
    callEdges: state.callEdges,
    dataOperation: null,
    authorizationEvidence: [],
    limitations: state.limitations,
    evidenceBoundary: 'The exact local callable path ended without a supported object data operation.',
    reason: null,
  };
}

function edgeFor(state, call) {
  return {
    kind: call.resolution.edgeKind,
    from: state.target.name,
    to: call.resolution.target.name,
    location: sourceLocation(state.target.module.path, call.node),
  };
}

function ignoredResponseBoundary(call) {
  const name = expressionName(call.node.callee) || '';
  return /^(?:res|response|Response|console)\./.test(name);
}

function dataOperationBoundary(call) {
  const parts = (expressionName(call.node.callee) || '').split('.');
  return parts.length >= 2 && DATA_OPERATION_METHODS.has(parts.at(-1));
}

function withinOperation(node, operations, parents) {
  const roots = new Set(operations.map((operation) => operation.node).filter(Boolean));
  let current = node;
  while (current) {
    if (roots.has(current)) return true;
    current = parents.get(current);
  }
  return false;
}

function incompleteOperation(state, item) {
  const reason = item.code === 'prisma_client_identity_unresolved'
    ? 'data_client_unresolved' : 'module_or_parser_evidence_incomplete';
  return partial(state, reason, item.code);
}

export function createAccessPathBudget(limit = ACCESS_PATH_LIMITS.maxTotalTransitionsPerAudit) {
  return { transitions: 0, limit };
}

export function analyzeAccessPaths(input) {
  const limits = { ...ACCESS_PATH_LIMITS, ...(input.limits || {}) };
  const budget = input.budget || createAccessPathBudget(limits.maxTotalTransitionsPerAudit);
  const index = input.callableIndex || callableIndexForGraph(input.graph);
  const entry = input.entry;
  const target = entryTarget(input.module, input.handler, entry);
  const groups = input.selectorGroups || [{
    selector: input.objectSelectors?.[0],
    aliases: input.objectAliases || new Set(),
    nodes: input.objectNodes || new Set(),
  }];
  const worklist = groups.filter((group) => group.selector).map((group) => ({
    entry,
    target,
    identity: input.identity,
    selector: group.selector,
    facts: {
      objectAliases: new Set(group.aliases || []),
      objectNodes: new Set(group.nodes || []),
      principalAliases: new Set(input.principalAliases || []),
      tenantAliases: new Set(input.tenantAliases || []),
    },
    callEdges: [],
    visited: new Set([target.id]),
    limitations: [],
  }));
  const seen = new Set();
  const chains = [];
  const operations = [];
  const limitations = new Set();
  const counts = { seeded: worklist.length, states: 0, transitions: 0, callSites: 0, truncated: 0 };
  let chainLimitRecorded = false;

  const emit = (chain) => {
    if (chains.length >= limits.maxEmittedChainsPerEntry) {
      counts.truncated += 1;
      limitations.add('emitted_chain_limit_reached');
      return false;
    }
    chains.push(chain);
    for (const item of chain.limitations || []) limitations.add(item);
    return true;
  };

  while (worklist.length) {
    if (counts.states >= limits.maxActiveStatesPerEntry) {
      const stopped = worklist.shift();
      emit(partial(stopped, 'call_state_budget_reached'));
      counts.truncated += worklist.length + 1;
      limitations.add('call_state_budget_reached');
      break;
    }
    const state = worklist.shift();
    const key = stateKey(state);
    if (seen.has(key)) continue;
    seen.add(key);
    counts.states += 1;
    const summary = summarizeCallable(index, state.target,
      { maxCallSites: limits.maxExaminedCallSitesPerSummary });
    counts.callSites += summary.calls.length;
    const localIdentity = analyzeIdentityEvidence(input.graph, state.target.module, state.target.node);
    const identitySeed = {
      ...state.facts,
      principalAliases: new Set([
        ...state.facts.principalAliases, ...localIdentity.principalAliases,
      ]),
      tenantAliases: new Set([
        ...state.facts.tenantAliases, ...localIdentity.tenantAliases,
      ]),
    };
    let facts = expandSummaryFacts(summary, identitySeed);
    const returnedIdentity = applyReturnedIdentityFacts(input.graph, summary, facts);
    facts = expandSummaryFacts(summary, returnedIdentity.facts);
    const identity = returnedIdentity.identities.reduce(mergeIdentity,
      mergeIdentity(state.identity, localIdentity.identity));
    const active = { ...state, facts, limitations: [...new Set([
      ...state.limitations, ...facts.limitations, ...(localIdentity.limitations || []),
      ...returnedIdentity.limitations,
    ])].sort(), identity };
    const analyzed = analyzeDataOperations(input.graph, state.target.module, state.target.node, {
      objectAliases: facts.objectAliases,
      objectNodes: facts.objectNodes,
      principalAliases: facts.principalAliases,
      tenantAliases: facts.tenantAliases,
    });
    for (const operation of analyzed.operations) {
      operations.push(operation);
      if (!emit(completed(active, operation))) chainLimitRecorded = true;
    }
    for (const item of analyzed.incomplete) emit(incompleteOperation(active, item));
    if (active.limitations.includes('identity_provider_wrapper_unresolved')) {
      emit(partial(active, 'identity_source_unresolved', 'identity_provider_wrapper_unresolved'));
    }
    if (summary.limitations.includes('call_site_budget_reached')) {
      emit(partial(active, 'call_site_budget_reached'));
      counts.truncated += Math.max(0, summary.counts.callSites - summary.counts.retainedCallSites);
    }

    let relevantCalls = 0;
    for (const call of summary.calls) {
      if (withinOperation(call.node, analyzed.operations, summary.parents)
          || !callCarriesObject(call, facts)) continue;
      relevantCalls += 1;
      if (!call.resolution) {
        if (!ignoredResponseBoundary(call) && !dataOperationBoundary(call)) {
          emit(partial(active, 'call_target_unresolved'));
        }
        continue;
      }
      if (call.resolution.state === 'incomplete') {
        if (!dataOperationBoundary(call)) {
          emit(partial(active, call.resolution.reason, call.resolution.limitation));
        }
        continue;
      }
      if (call.resolution.state !== 'exact') continue;
      const mapped = mapCallFacts(summary, call, facts);
      if (!mapped.objectAliases.size) {
        if (mapped.limitations.length) {
          emit(partial(active, mapped.limitations[0], mapped.limitations[0]));
        }
        continue;
      }
      const edge = edgeFor(active, call);
      if (active.callEdges.length >= limits.maxLocalCallEdges) {
        emit(partial(active, 'call_depth_limit_reached'));
        continue;
      }
      const nextEdges = [...active.callEdges, edge];
      if (active.visited.has(call.resolution.target.id)) {
        emit(partial(active, 'call_cycle_detected', 'call_cycle_detected', nextEdges));
        continue;
      }
      if (budget.transitions >= budget.limit) {
        emit(partial(active, 'transition_budget_reached'));
        counts.truncated += 1;
        continue;
      }
      budget.transitions += 1;
      counts.transitions += 1;
      worklist.push({
        ...active,
        target: call.resolution.target,
        facts: mapped,
        callEdges: nextEdges,
        visited: new Set([...active.visited, call.resolution.target.id]),
        limitations: [...new Set([...active.limitations, ...mapped.limitations])].sort(),
      });
    }
    if (state.callEdges.length && !analyzed.operations.length && !analyzed.incomplete.length
        && relevantCalls === 0 && !summary.limitations.includes('call_site_budget_reached')) {
      emit(notApplicable(active));
    }
  }

  if (chainLimitRecorded && chains.length < limits.maxEmittedChainsPerEntry) {
    emit(partial(worklist[0] || {
      entry, target, identity: input.identity, selector: groups[0]?.selector,
      callEdges: [], limitations: [],
    }, 'emitted_chain_limit_reached'));
  }
  const uniqueChains = chains.filter((chain, indexValue, items) => {
    const key = chainKey(chain);
    return items.findIndex((candidate) => chainKey(candidate) === key) === indexValue;
  });
  const uniqueOperations = operations.filter((operation, indexValue, items) =>
    items.findIndex((candidate) => candidate.provider === operation.provider
      && candidate.resource === operation.resource && candidate.operation === operation.operation
      && candidate.location.path === operation.location.path
      && candidate.location.line === operation.location.line) === indexValue);
  return {
    chains: uniqueChains,
    operations: uniqueOperations,
    limitations: [...limitations].sort(),
    coverage: {
      status: limitations.size ? 'partial' : groups.length ? 'completed' : 'not_applicable',
      counts,
      reasons: [...limitations].sort(),
    },
    budget,
  };
}
