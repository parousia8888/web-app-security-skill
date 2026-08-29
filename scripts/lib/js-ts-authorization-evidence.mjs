import { accessControlKeyCategory } from './access-control-vocabulary.mjs';
import { sourceLocation } from './frameworks/route-extractor-helpers.mjs';
import { expressionName } from './js-ts-module-graph.mjs';
import { mapCallFacts, summarizeCallable } from './js-ts-function-summary.mjs';

const CATEGORIES = ['object', 'principal', 'tenant'];
const CONVERSIONS = new Set(['String', 'Number', 'parseInt']);
const COMPARISON_OPERATORS = new Set(['==', '===', '!=', '!==']);
const FUNCTION_TYPES = new Set([
  'ArrowFunctionExpression', 'FunctionDeclaration', 'FunctionExpression', 'ClassMethod',
  'ClassPrivateMethod', 'ObjectMethod',
]);

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

function propertyName(property) {
  if (property?.type !== 'ObjectProperty' || property.computed) return null;
  return safeName(property.key);
}

function emptyState(state = 'not_observed') {
  return Object.fromEntries(CATEGORIES.map((category) => [category,
    { state, evidence: null }]));
}

function result(states = emptyState(), limitations = []) {
  return { states, limitations: [...new Set(limitations)].sort() };
}

function evidence(module, node, category, field, state = 'observed') {
  return {
    kind: 'query_predicate', category, state, field: field || null,
    location: sourceLocation(module.path, node),
  };
}

function expressionMatches(raw, facts, category) {
  const node = unwrap(raw);
  if (!node) return false;
  if (category === 'object' && facts.objectNodes?.has(node)) return true;
  const name = safeName(node);
  if (name && facts[`${category}Aliases`]?.has(name)) return true;
  if (node.type === 'CallExpression' && CONVERSIONS.has(safeName(node.callee))
      && node.arguments.length === 1 && node.arguments[0].type !== 'SpreadElement') {
    return expressionMatches(node.arguments[0], facts, category);
  }
  return false;
}

function containsTrackedFact(raw, facts) {
  const stack = [unwrap(raw)];
  let visited = 0;
  while (stack.length && visited < 2_000) {
    const node = stack.pop();
    if (!node || typeof node !== 'object') continue;
    visited += 1;
    if (CATEGORIES.some((category) => expressionMatches(node, facts, category))) return true;
    for (const [key, value] of Object.entries(node)) {
      if (['loc', 'start', 'end', 'extra', 'comments', 'tokens'].includes(key)) continue;
      if (Array.isArray(value)) stack.push(...value);
      else if (value && typeof value === 'object') stack.push(value);
    }
  }
  return false;
}

function resolvedObject(raw, facts) {
  const node = unwrap(raw);
  if (node?.type === 'ObjectExpression' || node?.type === 'ArrayExpression') return node;
  if (node?.type === 'Identifier') return facts.objectValues?.get(node.name) || null;
  return null;
}

function incomplete(module, node, field = null) {
  return result(Object.fromEntries(CATEGORIES.map((category) => [category, {
    state: 'incomplete', evidence: category === 'object' ? null
      : evidence(module, node, category, field, 'incomplete'),
  }])), ['constraint_expression_unresolved']);
}

function mergeLimitations(items) {
  return [...new Set(items.flatMap((item) => item.limitations))].sort();
}

function mergeAnd(items) {
  if (!items.length) return result();
  const states = emptyState();
  for (const category of CATEGORIES) {
    const values = items.map((item) => item.states[category]);
    states[category] = values.find((value) => value.state === 'observed')
      || values.find((value) => value.state === 'incomplete')
      || { state: 'not_observed', evidence: null };
  }
  return result(states, mergeLimitations(items));
}

function mergeOr(items) {
  if (!items.length) return null;
  const states = emptyState();
  for (const category of CATEGORIES) {
    const values = items.map((item) => item.states[category]);
    if (values.every((value) => value.state === 'observed')) states[category] = values[0];
    else if (values.some((value) => value.state === 'incomplete')) {
      states[category] = values.find((value) => value.state === 'incomplete');
    }
  }
  return result(states, mergeLimitations(items));
}

function prismaValue(module, raw, facts, visiting, depth) {
  const node = resolvedObject(raw, facts) || unwrap(raw);
  if (!node || depth > 24 || visiting.has(node)) return incomplete(module, node || raw);
  visiting.add(node);
  let evaluated;
  if (node.type === 'ArrayExpression') {
    if (node.elements.some((item) => !item || item.type === 'SpreadElement')) {
      evaluated = incomplete(module, node);
    } else {
      evaluated = mergeAnd(node.elements.map((item) =>
        prismaValue(module, item, facts, visiting, depth + 1)));
    }
  } else if (node.type === 'ObjectExpression') {
    const parts = [];
    let structuralIncomplete = false;
    for (const property of node.properties || []) {
      if (property.type !== 'ObjectProperty' || property.computed) {
        structuralIncomplete = true;
        continue;
      }
      const field = propertyName(property);
      if (!field) {
        structuralIncomplete = true;
        continue;
      }
      if (field === 'NOT') {
        const ignored = result();
        const nested = prismaValue(module, property.value, facts, visiting, depth + 1);
        ignored.limitations.push(...nested.limitations);
        parts.push(ignored);
        continue;
      }
      if (field === 'AND' || field === 'OR') {
        const value = resolvedObject(property.value, facts) || unwrap(property.value);
        const branches = value?.type === 'ArrayExpression'
          ? value.elements.filter(Boolean).map((item) =>
            item.type === 'SpreadElement' ? incomplete(module, item)
              : prismaValue(module, item, facts, visiting, depth + 1))
          : [prismaValue(module, property.value, facts, visiting, depth + 1)];
        parts.push(field === 'AND' ? mergeAnd(branches)
          : mergeOr(branches) || incomplete(module, property.value));
        continue;
      }
      const category = accessControlKeyCategory(field);
      if (category && expressionMatches(property.value, facts, category)) {
        const states = emptyState();
        states[category] = { state: 'observed',
          evidence: category === 'object' ? null : evidence(module, property, category, field) };
        parts.push(result(states));
      } else if (category && ['CallExpression', 'OptionalCallExpression'].includes(unwrap(property.value)?.type)) {
        const states = emptyState();
        states[category] = { state: 'incomplete',
          evidence: category === 'object' ? null
            : evidence(module, property, category, field, 'incomplete') };
        parts.push(result(states, ['constraint_expression_unresolved']));
      }
      const nested = resolvedObject(property.value, facts);
      if (nested && nested !== node) {
        parts.push(prismaValue(module, nested, facts, visiting, depth + 1));
      }
    }
    evaluated = structuralIncomplete ? incomplete(module, node) : mergeAnd(parts);
  } else if (containsTrackedFact(node, facts)) {
    evaluated = incomplete(module, node);
  } else evaluated = result();
  visiting.delete(node);
  return evaluated;
}

export function evaluatePrismaPredicate(module, where, facts) {
  return prismaValue(module, where, facts, new Set(), 0);
}

function drizzleField(node) {
  const current = unwrap(node);
  if (!['MemberExpression', 'OptionalMemberExpression'].includes(current?.type) || current.computed) {
    return null;
  }
  const name = safeName(current.property);
  return name ? { name, category: accessControlKeyCategory(name) } : null;
}

function drizzleEq(module, node, facts) {
  if (node.arguments.length !== 2 || node.arguments.some((item) => item.type === 'SpreadElement')) {
    return incomplete(module, node);
  }
  for (const [fieldNode, valueNode] of [[node.arguments[0], node.arguments[1]],
    [node.arguments[1], node.arguments[0]]]) {
    const field = drizzleField(fieldNode);
    if (!field?.category || !expressionMatches(valueNode, facts, field.category)) continue;
    const states = emptyState();
    states[field.category] = { state: 'observed', evidence: field.category === 'object' ? null
      : evidence(module, node, field.category, field.name) };
    return result(states);
  }
  if (containsTrackedFact(node.arguments, facts)) return incomplete(module, node);
  return result();
}

function drizzleValue(module, raw, facts, operators, depth = 0) {
  const node = unwrap(raw);
  if (!node || depth > 24) return incomplete(module, node || raw);
  if (!['CallExpression', 'OptionalCallExpression'].includes(node.type)) {
    return containsTrackedFact(node, facts) ? incomplete(module, node) : result();
  }
  const callee = safeName(node.callee);
  const operator = operators.get(callee);
  if (operator === 'eq') return drizzleEq(module, node, facts);
  if (operator === 'and' || operator === 'or') {
    if (!node.arguments.length || node.arguments.some((item) => item.type === 'SpreadElement')) {
      return incomplete(module, node);
    }
    const branches = node.arguments.map((argument) =>
      drizzleValue(module, argument, facts, operators, depth + 1));
    return operator === 'and' ? mergeAnd(branches) : mergeOr(branches) || incomplete(module, node);
  }
  return containsTrackedFact(node, facts) ? incomplete(module, node) : result();
}

export function evaluateDrizzlePredicate(module, predicate, facts, operators) {
  return drizzleValue(module, predicate, facts, operators);
}

export function observedAuthorizationEvidence(evaluation) {
  return CATEGORIES.filter((category) => category !== 'object')
    .map((category) => evaluation.states[category].evidence)
    .filter(Boolean);
}

function localWalk(root, visit) {
  const stack = [{ node: root, root: true }];
  while (stack.length) {
    const { node, root } = stack.pop();
    if (!node || typeof node !== 'object') continue;
    if (!root && FUNCTION_TYPES.has(node.type)) continue;
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

function parameterNode(raw) {
  const parameter = raw?.type === 'TSParameterProperty' ? raw.parameter : raw;
  return parameter?.type === 'AssignmentPattern' ? parameter.left : parameter;
}

function nullishReturn(node) {
  const current = unwrap(node);
  return !current || current.type === 'NullLiteral'
    || (current.type === 'Identifier' && current.name === 'undefined')
    || (current.type === 'UnaryExpression' && current.operator === 'void');
}

function aliasesReturned(summary, aliases) {
  let observed = false;
  let ambiguous = false;
  for (const item of summary.returns) {
    if (nullishReturn(item.argument)) continue;
    const name = safeName(item.argument);
    if (name && aliases.has(name)) observed = true;
    else ambiguous = true;
  }
  return { returned: observed && !ambiguous,
    limitations: ambiguous && observed ? ['return_mapping_unresolved'] : [] };
}

function aliasesForMapping(mapping) {
  if (['identifier', 'single_element_array'].includes(mapping?.kind) && mapping.name) {
    return new Set([mapping.name]);
  }
  return new Set();
}

export function operationResourceFlow(summary, operation) {
  const call = summary.calls.find((item) => item.node === operation.node);
  if (!call) return { aliases: new Set(), returned: false,
    limitations: ['return_mapping_unresolved'] };
  if (call.resultMapping.kind === 'direct_return') {
    return { aliases: new Set(), returned: true, limitations: [] };
  }
  const aliases = aliasesForMapping(call.resultMapping);
  const returned = aliasesReturned(summary, aliases);
  return { aliases, returned: returned.returned,
    limitations: [...new Set([call.resultMapping.reason, ...returned.limitations].filter(Boolean))] };
}

export function callResourceFlow(summary, call) {
  if (call.resultMapping.kind === 'direct_return') {
    return { aliases: new Set(), returned: true, limitations: [] };
  }
  const aliases = aliasesForMapping(call.resultMapping);
  const returned = aliasesReturned(summary, aliases);
  return { aliases, returned: returned.returned,
    limitations: [...new Set([call.resultMapping.reason, ...returned.limitations].filter(Boolean))] };
}

function expandResourceAliases(summary, seed) {
  const aliases = new Set(seed);
  const fieldAliases = new Map();
  const unresolvedAliases = new Set();
  const limitations = new Set();
  for (let pass = 0; pass < 4; pass += 1) {
    let changed = false;
    for (const declaration of summary.declarations) {
      const source = safeName(declaration.init);
      const directField = resourceField(declaration.init, aliases);
      if (declaration.id?.type === 'Identifier' && directField) {
        if (summary.writes.get(declaration.id.name) === 1) {
          fieldAliases.set(declaration.id.name, directField);
        } else limitations.add('return_mapping_unresolved');
        continue;
      }
      if (!source || !aliases.has(source)) {
        if (declaration.id?.type === 'Identifier' && containsResource(declaration.init, aliases)) {
          unresolvedAliases.add(declaration.id.name);
        }
        continue;
      }
      if (declaration.id?.type === 'Identifier') {
        if (summary.writes.get(declaration.id.name) !== 1) {
          limitations.add('return_mapping_unresolved');
          continue;
        }
        if (!aliases.has(declaration.id.name)) {
          aliases.add(declaration.id.name);
          changed = true;
        }
        continue;
      }
      if (declaration.id?.type === 'ArrayPattern' && declaration.id.elements.length === 1
          && declaration.id.elements[0]?.type === 'Identifier') {
        const name = declaration.id.elements[0].name;
        if (!aliases.has(name)) {
          aliases.add(name);
          changed = true;
        }
      } else if (declaration.id?.type === 'ArrayPattern') {
        limitations.add('destructuring_mapping_ambiguous');
      }
    }
    if (!changed) break;
  }
  return { aliases, fieldAliases, unresolvedAliases,
    limitations: [...limitations].sort() };
}

function resourceField(raw, resourceAliases) {
  const node = unwrap(raw);
  if (!['MemberExpression', 'OptionalMemberExpression'].includes(node?.type) || node.computed) {
    return null;
  }
  const resource = safeName(node.object);
  const field = safeName(node.property);
  const category = accessControlKeyCategory(field);
  return resource && resourceAliases.has(resource) && ['principal', 'tenant'].includes(category)
    ? { category, field } : null;
}

function participatesInDecision(summary, raw) {
  let node = raw;
  let parent = summary.parents.get(node);
  while (parent && [
    'AwaitExpression', 'TSAsExpression', 'TSTypeAssertion', 'TSNonNullExpression',
    'TypeCastExpression', 'ParenthesizedExpression', 'SatisfiesExpression', 'UnaryExpression',
    'LogicalExpression', 'ChainExpression',
  ].includes(parent.type)) {
    node = parent;
    parent = summary.parents.get(node);
  }
  if (parent?.type === 'ReturnStatement' && parent.argument === node) return true;
  if (parent?.type === 'ThrowStatement' && parent.argument === node) return true;
  if (parent?.type === 'ConditionalExpression' && parent.test === node) return true;
  return ['IfStatement', 'WhileStatement', 'DoWhileStatement', 'ForStatement'].includes(parent?.type)
    && parent.test === node;
}

function containsResource(raw, resourceAliases) {
  const stack = [unwrap(raw)];
  let visited = 0;
  while (stack.length && visited < 2_000) {
    const node = stack.pop();
    if (!node || typeof node !== 'object') continue;
    visited += 1;
    const name = safeName(node);
    if (name && resourceAliases.has(name)) return true;
    if (FUNCTION_TYPES.has(node.type)) continue;
    for (const [key, value] of Object.entries(node)) {
      if (['loc', 'start', 'end', 'extra', 'comments', 'tokens'].includes(key)) continue;
      if (Array.isArray(value)) stack.push(...value);
      else if (value && typeof value === 'object') stack.push(value);
    }
  }
  return false;
}

function comparisonFor(module, summary, node, facts, resourceState) {
  if (node.type !== 'BinaryExpression' || !COMPARISON_OPERATORS.has(node.operator)) return null;
  if (!participatesInDecision(summary, node)) return null;
  for (const [resourceNode, identityNode] of [[node.left, node.right], [node.right, node.left]]) {
    const field = resourceField(resourceNode, resourceState.aliases)
      || resourceState.fieldAliases.get(safeName(resourceNode));
    if (!field || !expressionMatches(identityNode, facts, field.category)) continue;
    return {
      kind: 'post_load_comparison', category: field.category, state: 'observed',
      field: field.field, location: sourceLocation(module.path, node),
    };
  }
  for (const [resourceNode, identityNode] of [[node.left, node.right], [node.right, node.left]]) {
    const current = unwrap(resourceNode);
    const unresolvedName = ['MemberExpression', 'OptionalMemberExpression'].includes(current?.type)
      ? safeName(current.object) : safeName(current);
    if (!resourceState.unresolvedAliases.has(unresolvedName)) continue;
    for (const category of ['principal', 'tenant']) {
      if (!expressionMatches(identityNode, facts, category)) continue;
      return {
        kind: 'post_load_comparison', category, state: 'incomplete', field: null,
        location: sourceLocation(module.path, node), limitation: 'return_mapping_unresolved',
      };
    }
  }
  return null;
}

function argumentMatchesResource(node, resourceAliases) {
  const name = safeName(node);
  return Boolean(name && resourceAliases.has(name));
}

function mapResourceArguments(call, resourceAliases) {
  const aliases = new Set();
  const parameters = call.resolution?.target?.node?.params || [];
  for (let index = 0; index < call.node.arguments.length; index += 1) {
    const argument = call.node.arguments[index];
    const parameter = parameterNode(parameters[index]);
    if (argument.type === 'SpreadElement' || parameter?.type !== 'Identifier') continue;
    if (argumentMatchesResource(argument, resourceAliases)) aliases.add(parameter.name);
  }
  return aliases;
}

function ignoredHelper(node) {
  const name = safeName(node.callee) || '';
  return /^(?:console|Response|res|response)\./.test(name);
}

function callIdentityCategories(call, facts) {
  const categories = new Set();
  for (const argument of call.node.arguments) {
    if (argument.type === 'SpreadElement') continue;
    for (const category of ['principal', 'tenant']) {
      if (expressionMatches(argument, facts, category)) categories.add(category);
    }
  }
  return categories;
}

function uniqueEvidence(items) {
  return items.filter((item, index, all) => all.findIndex((candidate) =>
    candidate.kind === item.kind && candidate.category === item.category
      && candidate.state === item.state && candidate.field === item.field
      && candidate.location?.path === item.location?.path
      && candidate.location?.line === item.location?.line) === index);
}

export function analyzePostLoadComparisons(index, summary, input, context = {}) {
  const expanded = expandResourceAliases(summary, input.resourceAliases || []);
  const facts = {
    objectAliases: new Set(), objectNodes: new Set(), omittedAliases: new Set(),
    principalAliases: new Set(input.principalAliases || []),
    tenantAliases: new Set(input.tenantAliases || []),
    objectValues: summary.objectValues,
  };
  const evidence = [];
  const limitations = new Set(expanded.limitations);
  localWalk(summary.target.node, (node) => {
    const found = comparisonFor(summary.target.module, summary, node, facts, expanded);
    if (found) {
      const { limitation, ...record } = found;
      evidence.push(record);
      if (limitation) limitations.add(limitation);
    }
  });

  const depth = context.depth || 0;
  const maxEdges = context.maxEdges ?? 4;
  const visited = context.visited || new Set([summary.target.id]);
  if (depth < maxEdges) {
    for (const call of summary.calls) {
      const resourceArguments = call.node.arguments.some((argument) =>
        argument.type !== 'SpreadElement' && argumentMatchesResource(argument, expanded.aliases));
      if (!resourceArguments || ignoredHelper(call.node)) continue;
      const categories = callIdentityCategories(call, facts);
      if (call.resolution?.state === 'exact' && !visited.has(call.resolution.target.id)) {
        const resourceAliases = mapResourceArguments(call, expanded.aliases);
        const mapped = mapCallFacts(summary, call, facts);
        if (!resourceAliases.size) {
          if (categories.size) limitations.add('argument_mapping_ambiguous');
          continue;
        }
        const nested = analyzePostLoadComparisons(index,
          summarizeCallable(index, call.resolution.target), {
            resourceAliases,
            principalAliases: mapped.principalAliases,
            tenantAliases: mapped.tenantAliases,
          }, { depth: depth + 1, maxEdges,
            visited: new Set([...visited, call.resolution.target.id]) });
        evidence.push(...nested.evidence);
        for (const limitation of [...mapped.limitations, ...nested.limitations]) {
          limitations.add(limitation);
        }
      } else if (categories.size && participatesInDecision(summary, call.node)) {
        for (const category of categories) {
          evidence.push({
            kind: 'post_load_comparison', category, state: 'incomplete', field: null,
            location: sourceLocation(summary.target.module.path, call.node),
          });
        }
        limitations.add(call.resolution?.limitation || 'call_target_unresolved');
      }
    }
  } else {
    for (const call of summary.calls) {
      const resourceArguments = call.node.arguments.some((argument) =>
        argument.type !== 'SpreadElement' && argumentMatchesResource(argument, expanded.aliases));
      const categories = callIdentityCategories(call, facts);
      if (!resourceArguments || !categories.size || ignoredHelper(call.node)
          || !participatesInDecision(summary, call.node)) continue;
      for (const category of categories) {
        evidence.push({
          kind: 'post_load_comparison', category, state: 'incomplete', field: null,
          location: sourceLocation(summary.target.module.path, call.node),
        });
      }
      limitations.add('call_depth_limit_reached');
    }
  }
  return { evidence: uniqueEvidence(evidence), limitations: [...limitations].sort(),
    resourceAliases: expanded.aliases };
}
