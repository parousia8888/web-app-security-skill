import { walkJsTsAst } from './js-ts-ast-parser.mjs';
import { analyzeDataOperations } from './js-ts-data-operation-evidence.mjs';
import { expressionName } from './js-ts-module-graph.mjs';
import {
  importedBindings, localModuleExport, sourceLocation,
} from './frameworks/route-extractor-helpers.mjs';

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

function topLevelDeclarations(module) {
  const values = new Map();
  const duplicates = new Set();
  const record = (name, node) => {
    if (!name || !FUNCTION_TYPES.has(node?.type)) return;
    if (values.has(name) && values.get(name) !== node) duplicates.add(name);
    else values.set(name, node);
  };
  for (const raw of module.ast?.body || []) {
    const node = raw.type === 'ExportNamedDeclaration' || raw.type === 'ExportDefaultDeclaration'
      ? raw.declaration : raw;
    if (node?.type === 'FunctionDeclaration') record(node.id?.name, node);
    if (node?.type === 'VariableDeclaration') {
      for (const declaration of node.declarations) {
        if (declaration.id?.type === 'Identifier') record(declaration.id.name, unwrap(declaration.init));
      }
    }
  }
  for (const name of duplicates) values.delete(name);
  return values;
}

function classDeclarations(module) {
  const values = new Map();
  for (const raw of module.ast?.body || []) {
    const node = raw.type === 'ExportNamedDeclaration' || raw.type === 'ExportDefaultDeclaration'
      ? raw.declaration : raw;
    if (node?.type === 'ClassDeclaration' && node.id?.name) values.set(node.id.name, node);
  }
  return values;
}

function importedFunction(graph, module, name) {
  const binding = importedBindings(module).get(name);
  if (!binding || binding.imported === 'default' || binding.imported === '*') return null;
  if (binding.resolutionReason) return { incomplete: binding.resolutionReason };
  if (!binding.resolvedPath) return null;
  const target = graph.modules.get(binding.resolvedPath);
  const local = localModuleExport(graph, binding.resolvedPath, binding.imported);
  const node = local ? topLevelDeclarations(target).get(local) : null;
  return node ? { module: target, node, name: local, kind: 'local_function' }
    : { incomplete: 'local_function_export_unresolved' };
}

function containingClass(module, handler) {
  for (const klass of classDeclarations(module).values()) {
    if (klass.body?.body?.includes(handler)) return klass;
  }
  return null;
}

function typeName(parameter) {
  const target = parameter?.typeAnnotation?.typeAnnotation;
  return target?.type === 'TSTypeReference' ? safeName(target.typeName) : null;
}

function nestInjectedServices(graph, module, handler) {
  const services = new Map();
  const klass = containingClass(module, handler);
  const constructor = klass?.body?.body?.find((node) => node.type === 'ClassMethod'
    && node.kind === 'constructor');
  const imports = importedBindings(module);
  for (const raw of constructor?.params || []) {
    const parameter = raw.type === 'TSParameterProperty' ? raw.parameter : raw;
    if (parameter?.type !== 'Identifier') continue;
    const importedType = typeName(parameter);
    const binding = imports.get(importedType);
    if (!binding?.resolvedPath || binding.resolutionReason || ['default', '*'].includes(binding.imported)) continue;
    const target = graph.modules.get(binding.resolvedPath);
    const local = localModuleExport(graph, binding.resolvedPath, binding.imported);
    const targetClass = local ? classDeclarations(target).get(local) : null;
    if (targetClass) services.set(parameter.name, { module: target, klass: targetClass, name: local });
  }
  return services;
}

function resolveCall(graph, module, handler, call, services = null) {
  const called = safeName(call.callee);
  if (!called) return null;
  if (!called.includes('.')) {
    const local = topLevelDeclarations(module).get(called);
    if (local && local !== handler) return { module, node: local, name: called, kind: 'local_function' };
    return importedFunction(graph, module, called);
  }
  const parts = called.split('.');
  if (parts.length !== 3 || parts[0] !== 'this') return null;
  const registry = services || nestInjectedServices(graph, module, handler);
  const service = registry.get(parts[1]);
  if (!service) return null;
  const matches = service.klass.body.body.filter((node) => ['ClassMethod', 'ClassPrivateMethod'].includes(node.type)
    && safeName(node.key) === parts[2]);
  return matches.length === 1
    ? { module: service.module, node: matches[0], name: `${service.name}.${parts[2]}`,
      kind: 'nest_injected_service' }
    : { incomplete: 'nest_service_method_unresolved' };
}

function directAlias(node, aliases) {
  const current = unwrap(node);
  const name = safeName(current);
  if (name && aliases.has(name)) return true;
  if (current?.type === 'CallExpression' && ['String', 'Number', 'parseInt'].includes(safeName(current.callee))) {
    return directAlias(current.arguments[0], aliases);
  }
  return false;
}

function argumentCarriesAlias(argument, aliases) {
  if (argument?.type !== 'SpreadElement') return directAlias(argument, aliases);
  const stack = [argument.argument];
  let visited = 0;
  while (stack.length && visited < 200) {
    const node = stack.pop();
    if (!node || typeof node !== 'object') continue;
    visited += 1;
    if (directAlias(node, aliases)) return true;
    if (FUNCTION_TYPES.has(node.type)) continue;
    for (const [key, value] of Object.entries(node)) {
      if (['loc', 'start', 'end', 'extra', 'comments', 'tokens'].includes(key)) continue;
      if (Array.isArray(value)) stack.push(...value);
      else if (value && typeof value === 'object') stack.push(value);
    }
  }
  return false;
}

function mapArguments(call, callee, objectAliases, principalAliases) {
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
      if (directAlias(call.arguments[index], objectAliases)) {
        return { incomplete: 'one_hop_parameter_pattern_ambiguous' };
      }
      continue;
    }
    if (directAlias(call.arguments[index], objectAliases)) mappedObjects.add(rawParameter.name);
    if (directAlias(call.arguments[index], principalAliases)) mappedPrincipals.add(rawParameter.name);
  }
  return { objectAliases: mappedObjects, principalAliases: mappedPrincipals };
}

function secondLocalEdge(graph, module, handler, objectAliases) {
  const services = nestInjectedServices(graph, module, handler);
  let observed = false;
  functionWalk(handler, (node) => {
    if (observed || node.type !== 'CallExpression'
        || !node.arguments.some((argument) => argumentCarriesAlias(argument, objectAliases))) return;
    const resolved = resolveCall(graph, module, handler, node, services);
    if (resolved?.node || resolved?.incomplete) observed = true;
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
  const selectors = input.objectSelectors || [];
  const services = nestInjectedServices(graph, module, handler);
  const results = [];
  functionWalk(handler, (call) => {
    if (call.type !== 'CallExpression'
        || !call.arguments.some((argument) => argumentCarriesAlias(argument, objectAliases))) return;
    const resolved = resolveCall(graph, module, handler, call, services);
    if (!resolved) return;
    if (resolved.incomplete) {
      results.push(partialResult(entry, identity, selectors, call, null, resolved.incomplete));
      return;
    }
    const mapped = mapArguments(call, resolved.node, objectAliases, principalAliases);
    if (mapped.incomplete) {
      results.push(partialResult(entry, identity, selectors, call, resolved, mapped.incomplete));
      return;
    }
    if (!mapped.objectAliases.size) return;
    const analyzed = analyzeDataOperations(graph, resolved.module, resolved.node, mapped);
    const edge = { kind: resolved.kind, from: entry.name, to: resolved.name,
      location: sourceLocation(module.path, call) };
    if (!analyzed.operations.length) {
      const secondEdge = secondLocalEdge(graph, resolved.module, resolved.node, mapped.objectAliases);
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
