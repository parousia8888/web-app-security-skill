import { walkJsTsAst } from './js-ts-ast-parser.mjs';
import { callableIndexForGraph, resolveCallableCall } from './js-ts-callable-index.mjs';
import { analyzeDataOperations } from './js-ts-data-operation-evidence.mjs';
import { expressionName } from './js-ts-module-graph.mjs';
import { sourceLocation } from './frameworks/route-extractor-helpers.mjs';

const FUNCTION_TYPES = new Set([
  'ArrowFunctionExpression', 'FunctionDeclaration', 'FunctionExpression', 'ClassMethod',
  'ClassPrivateMethod', 'ObjectMethod',
]);

function unwrap(node) {
  let current = node;
  while (current && [
    'AwaitExpression', 'TSAsExpression', 'TSTypeAssertion', 'TSNonNullExpression',
    'TypeCastExpression', 'ParenthesizedExpression',
  ].includes(current.type)) current = current.argument || current.expression;
  return current;
}

function safeName(node) {
  return expressionName(unwrap(node));
}

function functionWalk(root, visit) {
  const stack = [{ node: root, root: true }];
  while (stack.length) {
    const { node, root: isRoot } = stack.pop();
    if (!node || typeof node !== 'object') continue;
    if (!isRoot && FUNCTION_TYPES.has(node.type)) continue;
    if (typeof node.type === 'string') visit(node);
    for (const [key, value] of Object.entries(node)) {
      if (['loc', 'start', 'end', 'extra', 'errors', 'comments', 'tokens'].includes(key)) continue;
      if (Array.isArray(value)) {
        for (let index = value.length - 1; index >= 0; index -= 1) {
          stack.push({ node: value[index], root: false });
        }
      } else if (value && typeof value === 'object') stack.push({ node: value, root: false });
    }
  }
}

function directAlias(node, aliases, nodes = new Set()) {
  const current = unwrap(node);
  if (nodes.has(current)) return true;
  const name = safeName(current);
  if (name && aliases.has(name)) return true;
  if (current?.type === 'CallExpression' && ['String', 'Number', 'parseInt'].includes(safeName(current.callee))) {
    return directAlias(current.arguments[0], aliases, nodes);
  }
  return false;
}

function argumentCarriesAlias(argument, aliases, nodes = new Set()) {
  if (argument?.type !== 'SpreadElement') return directAlias(argument, aliases, nodes);
  const stack = [argument.argument];
  let visited = 0;
  while (stack.length && visited < 200) {
    const node = stack.pop();
    if (!node || typeof node !== 'object') continue;
    visited += 1;
    if (directAlias(node, aliases, nodes)) return true;
    if (FUNCTION_TYPES.has(node.type)) continue;
    for (const [key, value] of Object.entries(node)) {
      if (['loc', 'start', 'end', 'extra', 'comments', 'tokens'].includes(key)) continue;
      if (Array.isArray(value)) stack.push(...value);
      else if (value && typeof value === 'object') stack.push(value);
    }
  }
  return false;
}

function mapArguments(call, callee, objectAliases, principalAliases, objectNodes = new Set()) {
  if (call.arguments.some((argument) => argument.type === 'SpreadElement')
      || callee.params.some((parameter) => parameter.type === 'RestElement')) {
    return { incomplete: 'one_hop_spread_or_rest_ambiguous' };
  }
  const mappedObjects = new Set();
  const mappedPrincipals = new Set();
  for (let index = 0; index < Math.min(call.arguments.length, callee.params.length); index += 1) {
    const rawParameter = callee.params[index]?.type === 'TSParameterProperty'
      ? callee.params[index].parameter : callee.params[index];
    if (rawParameter?.type !== 'Identifier') {
      if (directAlias(call.arguments[index], objectAliases, objectNodes)) {
        return { incomplete: 'one_hop_parameter_pattern_ambiguous' };
      }
      continue;
    }
    if (directAlias(call.arguments[index], objectAliases, objectNodes)) mappedObjects.add(rawParameter.name);
    if (directAlias(call.arguments[index], principalAliases)) mappedPrincipals.add(rawParameter.name);
  }
  return { objectAliases: mappedObjects, principalAliases: mappedPrincipals };
}

function secondLocalEdge(index, module, handler, objectAliases) {
  let observed = false;
  functionWalk(handler, (node) => {
    if (observed || node.type !== 'CallExpression'
        || !node.arguments.some((argument) => argumentCarriesAlias(argument, objectAliases))) return;
    const resolved = resolveCallableCall(index, module, handler, node);
    if (resolved?.state === 'exact' || resolved?.state === 'incomplete') observed = true;
  });
  return observed;
}

function partialResult(entry, identity, selector, call, resolved, reason) {
  return {
    entryKind: entry.kind, entryId: entry.id,
    status: 'partial', outcome: 'incomplete', identity,
    objectSelectors: selector, dataOperation: null,
    callEdges: resolved?.node ? [{ kind: resolved.kind, from: entry.name, to: resolved.name,
      location: sourceLocation(entry.module.path, call) }] : [],
    evidenceBoundary: `A request-selected object entered a possible local call, but analysis stopped: ${reason}. No authorization conclusion is available.`,
    reason,
  };
}

export function analyzeOneHopAccess(input) {
  const { graph, module, handler, entry, identity, objectAliases, principalAliases } = input;
  const objectNodes = input.objectNodes || new Set();
  const selectors = input.objectSelectors || [];
  const index = input.callableIndex || callableIndexForGraph(graph);
  const results = [];
  functionWalk(handler, (call) => {
    if (call.type !== 'CallExpression'
        || !call.arguments.some((argument) => argumentCarriesAlias(argument, objectAliases,
          objectNodes))) return;
    const resolution = resolveCallableCall(index, module, handler, call);
    const resolved = resolution?.state === 'exact' ? {
      module: resolution.target.module,
      node: resolution.target.node,
      name: resolution.target.name,
      kind: resolution.edgeKind,
    } : null;
    if (resolution?.state === 'incomplete'
        && resolution.reason !== 'dynamic_dispatch_unresolved') {
      results.push(partialResult(entry, identity, selectors, call, null, resolution.reason));
      return;
    }
    if (!resolved) return;
    const mapped = mapArguments(call, resolved.node, objectAliases, principalAliases, objectNodes);
    if (mapped.incomplete) {
      results.push(partialResult(entry, identity, selectors, call, resolved, mapped.incomplete));
      return;
    }
    if (!mapped.objectAliases.size) return;
    const analyzed = analyzeDataOperations(graph, resolved.module, resolved.node, mapped);
    const edge = { kind: resolved.kind, from: entry.name, to: resolved.name,
      location: sourceLocation(module.path, call) };
    if (!analyzed.operations.length) {
      const secondEdge = secondLocalEdge(index, resolved.module, resolved.node, mapped.objectAliases);
      results.push({
        entryKind: entry.kind, entryId: entry.id,
        status: secondEdge ? 'partial' : 'not_applicable',
        outcome: secondEdge ? 'incomplete' : 'no_supported_object_operation',
        identity, objectSelectors: selectors, callEdges: [edge], dataOperation: null,
        evidenceBoundary: secondEdge
          ? 'The first local call was resolved, but the selected object entered a second local call. Analysis stops before that second edge.'
          : 'The first local call was resolved, but no supported object data operation was observed in that callee.',
        reason: secondEdge ? 'second_local_call_edge_not_followed' : 'no_supported_object_operation',
      });
      return;
    }
    for (const dataOperation of analyzed.operations) {
      const constrained = dataOperation.principalConstraint === 'observed'
        || dataOperation.tenantConstraint === 'observed';
      const outcome = constrained ? 'principal_constraint_observed'
        : dataOperation.externalPolicy === 'external_policy_required'
          ? 'external_policy_required' : 'principal_constraint_not_observed';
      results.push({
        entryKind: entry.kind, entryId: entry.id,
        status: 'completed', outcome, identity, objectSelectors: selectors,
        callEdges: [edge], dataOperation,
        evidenceBoundary: dataOperation.externalPolicy === 'external_policy_required'
          ? 'One exact local call was followed to a supported Supabase operation. Database row-level security remains external evidence.'
          : 'One exact local call was followed to a supported data operation. This bounded chain does not prove runtime authorization or exploitability.',
        reason: null,
      });
    }
  });
  return results.slice(0, 50);
}
