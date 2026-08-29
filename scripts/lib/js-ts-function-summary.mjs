import { expressionName } from './js-ts-module-graph.mjs';
import { resolveCallableCall } from './js-ts-callable-index.mjs';

const FUNCTION_TYPES = new Set([
  'ArrowFunctionExpression', 'FunctionDeclaration', 'FunctionExpression', 'ClassMethod',
  'ClassPrivateMethod', 'ObjectMethod',
]);
const CALL_TYPES = new Set(['CallExpression', 'OptionalCallExpression']);
const CONVERSIONS = new Set(['String', 'Number', 'parseInt']);
const SUMMARY_CACHE = new WeakMap();

function unwrap(node) {
  let current = node;
  while (current && [
    'AwaitExpression', 'TSAsExpression', 'TSTypeAssertion', 'TSNonNullExpression',
    'TypeCastExpression', 'ParenthesizedExpression', 'SatisfiesExpression',
  ].includes(current.type)) current = current.argument || current.expression;
  return current;
}

function safeName(node) {
  return expressionName(unwrap(node));
}

function parameterNode(raw) {
  const parameter = raw?.type === 'TSParameterProperty' ? raw.parameter : raw;
  return parameter?.type === 'AssignmentPattern' ? parameter.left : parameter;
}

function propertyName(property) {
  if (property?.computed) return null;
  return safeName(property?.key);
}

function localWalk(root, visit) {
  const stack = [{ node: root, parent: null, root: true }];
  while (stack.length) {
    const item = stack.pop();
    const { node, parent, root: isRoot } = item;
    if (!node || typeof node !== 'object') continue;
    if (!isRoot && FUNCTION_TYPES.has(node.type)) continue;
    if (typeof node.type === 'string') visit(node, parent);
    for (const [key, value] of Object.entries(node)) {
      if (['loc', 'start', 'end', 'extra', 'errors', 'comments', 'tokens'].includes(key)) continue;
      if (Array.isArray(value)) {
        for (let index = value.length - 1; index >= 0; index -= 1) {
          stack.push({ node: value[index], parent: node, root: false });
        }
      } else if (value && typeof value === 'object') {
        stack.push({ node: value, parent: node, root: false });
      }
    }
  }
}

function callResultMapping(call, parents) {
  let current = call;
  let parent = parents.get(current);
  while (parent && [
    'AwaitExpression', 'TSAsExpression', 'TSTypeAssertion', 'TSNonNullExpression',
    'TypeCastExpression', 'ParenthesizedExpression', 'SatisfiesExpression',
  ].includes(parent.type)) {
    current = parent;
    parent = parents.get(current);
  }
  if (parent?.type === 'ReturnStatement' && parent.argument === current) {
    return { kind: 'direct_return', name: null, reason: null };
  }
  if (parent?.type === 'VariableDeclarator' && parent.init === current) {
    const target = parameterNode(parent.id);
    if (target?.type === 'Identifier') return { kind: 'identifier', name: target.name, reason: null };
    if (target?.type === 'ArrayPattern' && target.elements.length === 1
        && target.elements[0]?.type === 'Identifier') {
      return { kind: 'single_element_array', name: target.elements[0].name, reason: null };
    }
    return { kind: 'unresolved', name: null, reason: target?.type === 'ArrayPattern'
      ? 'destructuring_mapping_ambiguous' : 'return_mapping_unresolved' };
  }
  if (parent?.type === 'AssignmentExpression' && parent.right === current
      && parent.left?.type === 'Identifier') {
    return { kind: 'identifier', name: parent.left.name, reason: null };
  }
  if (['MemberExpression', 'OptionalMemberExpression'].includes(parent?.type)
      && parent.object === current) {
    return { kind: 'unresolved', name: null, reason: 'return_mapping_unresolved' };
  }
  return { kind: 'unused', name: null, reason: null };
}

function normalizedReturn(node) {
  const current = unwrap(node);
  if (!current) return 'void';
  if (CALL_TYPES.has(current.type)) return `call:${safeName(current.callee) || '<dynamic>'}`;
  if (current.type === 'Identifier') return `identifier:${current.name}`;
  if (current.type === 'ObjectExpression') {
    const keys = current.properties.map(propertyName);
    return keys.every(Boolean) ? `object:${keys.sort().join(',')}` : 'object:<dynamic>';
  }
  return current.type;
}

function buildSummary(index, target, maxCallSites) {
  const calls = [];
  const declarations = [];
  const returns = [];
  const parents = new Map();
  const objectValues = new Map();
  const writes = new Map();
  localWalk(target.node, (node, parent) => {
    if (parent) parents.set(node, parent);
    if (CALL_TYPES.has(node.type)) calls.push(node);
    if (node.type === 'VariableDeclarator') {
      declarations.push(node);
      if (node.id?.type === 'Identifier') {
        writes.set(node.id.name, (writes.get(node.id.name) || 0) + 1);
        const value = unwrap(node.init);
        if (value?.type === 'ObjectExpression') objectValues.set(node.id.name, value);
      }
    }
    if (node.type === 'AssignmentExpression') {
      const name = safeName(node.left);
      if (name) writes.set(name, (writes.get(name) || 0) + 1);
    }
    if (node.type === 'UpdateExpression') {
      const name = safeName(node.argument);
      if (name) writes.set(name, (writes.get(name) || 0) + 1);
    }
    if (node.type === 'ReturnStatement') returns.push(node);
  });
  calls.sort((left, right) => (left.start ?? 0) - (right.start ?? 0));
  declarations.sort((left, right) => (left.start ?? 0) - (right.start ?? 0));
  returns.sort((left, right) => (left.start ?? 0) - (right.start ?? 0));
  const retainedCalls = calls.slice(0, maxCallSites).map((node) => ({
    node,
    resolution: resolveCallableCall(index, target.module, target.node, node),
    resultMapping: callResultMapping(node, parents),
  }));
  const returnShapes = [...new Set(returns.map((item) => normalizedReturn(item.argument)))];
  return {
    id: target.id,
    target,
    parameters: target.node.params || [],
    calls: retainedCalls,
    declarations,
    returns,
    objectValues,
    writes,
    parents,
    limitations: [
      ...(calls.length > maxCallSites ? ['call_site_budget_reached'] : []),
      ...(returnShapes.length > 1 ? ['return_mapping_unresolved'] : []),
      ...retainedCalls.map((item) => item.resultMapping.reason).filter(Boolean),
    ].filter((item, index, items) => items.indexOf(item) === index).sort(),
    counts: { callSites: calls.length, retainedCallSites: retainedCalls.length,
      returns: returns.length, declarations: declarations.length },
  };
}

export function summarizeCallable(index, target, options = {}) {
  const maxCallSites = options.maxCallSites ?? 200;
  let cache = SUMMARY_CACHE.get(index);
  if (!cache) {
    cache = new Map();
    SUMMARY_CACHE.set(index, cache);
  }
  const key = `${target.id}\u0000${maxCallSites}`;
  if (!cache.has(key)) cache.set(key, buildSummary(index, target, maxCallSites));
  return cache.get(key);
}

function emptyFacts(input = {}) {
  return {
    objectAliases: new Set(input.objectAliases || []),
    objectNodes: new Set(input.objectNodes || []),
    principalAliases: new Set(input.principalAliases || []),
    tenantAliases: new Set(input.tenantAliases || []),
  };
}

function expressionKinds(raw, facts) {
  const node = unwrap(raw);
  const kinds = [];
  if (!node) return kinds;
  if (facts.objectNodes.has(node)) kinds.push('object');
  const name = safeName(node);
  if (name && facts.objectAliases.has(name)) kinds.push('object');
  if (name && facts.principalAliases.has(name)) kinds.push('principal');
  if (name && facts.tenantAliases.has(name)) kinds.push('tenant');
  if (node.type === 'CallExpression' && CONVERSIONS.has(safeName(node.callee))
      && node.arguments.length === 1 && node.arguments[0].type !== 'SpreadElement') {
    kinds.push(...expressionKinds(node.arguments[0], facts));
  }
  return [...new Set(kinds)];
}

function addKind(facts, kind, name) {
  if (!name) return false;
  const set = facts[`${kind}Aliases`];
  const before = set.size;
  set.add(name);
  return set.size !== before;
}

function objectForArgument(summary, raw) {
  const node = unwrap(raw);
  if (node?.type === 'ObjectExpression') return node;
  if (node?.type === 'Identifier') return summary.objectValues.get(node.name) || null;
  return null;
}

function bindObjectPattern(pattern, source, sourceName, facts, output, limitations) {
  for (const property of pattern.properties || []) {
    if (property.type === 'RestElement') {
      limitations.add('destructuring_mapping_ambiguous');
      continue;
    }
    if (property.type !== 'ObjectProperty' || property.computed) {
      limitations.add('destructuring_mapping_ambiguous');
      continue;
    }
    const key = propertyName(property);
    const target = parameterNode(property.value);
    if (!key || target?.type !== 'Identifier') {
      limitations.add('destructuring_mapping_ambiguous');
      continue;
    }
    const candidates = [];
    if (source) {
      const matches = source.properties.filter((item) => item.type === 'ObjectProperty'
        && !item.computed && propertyName(item) === key);
      if (matches.length > 1) {
        limitations.add('argument_mapping_ambiguous');
        continue;
      }
      if (matches.length === 1) candidates.push(...expressionKinds(matches[0].value, facts));
    }
    if (sourceName) {
      for (const kind of ['object', 'principal', 'tenant']) {
        if (facts[`${kind}Aliases`].has(`${sourceName}.${key}`)) candidates.push(kind);
      }
    }
    const unique = [...new Set(candidates)];
    if (unique.length > 1) limitations.add('argument_mapping_ambiguous');
    else if (unique.length === 1) addKind(output, unique[0], target.name);
  }
}

function bindObjectToIdentifier(parameter, source, facts, output, limitations) {
  for (const property of source.properties || []) {
    if (property.type === 'SpreadElement' || property.computed) {
      limitations.add('argument_mapping_ambiguous');
      continue;
    }
    if (property.type !== 'ObjectProperty') continue;
    const key = propertyName(property);
    const kinds = expressionKinds(property.value, facts);
    if (!key || kinds.length > 1) {
      if (kinds.length) limitations.add('argument_mapping_ambiguous');
      continue;
    }
    if (kinds.length === 1) addKind(output, kinds[0], `${parameter.name}.${key}`);
  }
}

function containsFact(raw, facts, allowedKinds = null) {
  const stack = [unwrap(raw)];
  const expandedObjects = new Set();
  let visited = 0;
  while (stack.length && visited < 2_000) {
    const node = stack.pop();
    if (!node || typeof node !== 'object') continue;
    visited += 1;
    const kinds = expressionKinds(node, facts);
    if (allowedKinds ? kinds.some((kind) => allowedKinds.has(kind)) : kinds.length) return true;
    if (node.type === 'Identifier' && !expandedObjects.has(node.name)
        && facts.objectValues?.has(node.name)) {
      expandedObjects.add(node.name);
      stack.push(facts.objectValues.get(node.name));
    }
    if (FUNCTION_TYPES.has(node.type)) continue;
    for (const [key, value] of Object.entries(node)) {
      if (['loc', 'start', 'end', 'extra', 'comments', 'tokens'].includes(key)) continue;
      if (Array.isArray(value)) stack.push(...value);
      else if (value && typeof value === 'object') stack.push(value);
    }
  }
  return false;
}

export function expandSummaryFacts(summary, input) {
  const facts = emptyFacts(input);
  const limitations = new Set();
  for (let pass = 0; pass < 4; pass += 1) {
    let changed = false;
    for (const declaration of summary.declarations) {
      const target = parameterNode(declaration.id);
      if (target?.type === 'Identifier') {
        if (summary.writes.get(target.name) !== 1) continue;
        const kinds = expressionKinds(declaration.init, facts);
        if (kinds.length > 1) limitations.add('argument_mapping_ambiguous');
        else if (kinds.length === 1) changed = addKind(facts, kinds[0], target.name) || changed;
      } else if (target?.type === 'ObjectPattern') {
        const source = objectForArgument(summary, declaration.init);
        const sourceName = safeName(declaration.init);
        const before = [...facts.objectAliases, ...facts.principalAliases, ...facts.tenantAliases].length;
        bindObjectPattern(target, source, sourceName, facts, facts, limitations);
        const after = [...facts.objectAliases, ...facts.principalAliases, ...facts.tenantAliases].length;
        changed ||= after > before;
      }
    }
    if (!changed) break;
  }
  return { ...facts, objectValues: summary.objectValues,
    limitations: [...limitations].sort() };
}

export function callCarriesObject(call, facts) {
  const objectOnly = new Set(['object']);
  return call.node.arguments.some((argument) => containsFact(argument, facts, objectOnly));
}

export function mapCallFacts(summary, call, facts) {
  const output = emptyFacts();
  const limitations = new Set();
  const parameters = call.resolution?.target?.node?.params || [];
  if (call.node.arguments.some((item) => item.type === 'SpreadElement')
      || parameters.some((item) => parameterNode(item)?.type === 'RestElement')) {
    if (callCarriesObject(call, facts)) limitations.add('argument_mapping_ambiguous');
    return { ...output, limitations: [...limitations] };
  }
  for (let index = 0; index < call.node.arguments.length; index += 1) {
    const argument = call.node.arguments[index];
    const parameter = parameterNode(parameters[index]);
    if (!parameter) {
      if (containsFact(argument, facts)) limitations.add('argument_mapping_ambiguous');
      continue;
    }
    if (['ArrayExpression', 'ArrayPattern'].includes(unwrap(argument)?.type)) {
      if (containsFact(argument, facts)) limitations.add('destructuring_mapping_ambiguous');
      continue;
    }
    if (parameter.type === 'Identifier') {
      const kinds = expressionKinds(argument, facts);
      if (kinds.length > 1) limitations.add('argument_mapping_ambiguous');
      else if (kinds.length === 1) addKind(output, kinds[0], parameter.name);
      const source = objectForArgument(summary, argument);
      if (source) bindObjectToIdentifier(parameter, source, facts, output, limitations);
      continue;
    }
    if (parameter.type === 'ObjectPattern') {
      const source = objectForArgument(summary, argument);
      const sourceName = safeName(argument);
      if (!source && !sourceName && containsFact(argument, facts)) {
        limitations.add('argument_mapping_ambiguous');
        continue;
      }
      bindObjectPattern(parameter, source, sourceName, facts, output, limitations);
      continue;
    }
    if (containsFact(argument, facts)) limitations.add('argument_mapping_ambiguous');
  }
  return { ...output, limitations: [...limitations].sort() };
}
