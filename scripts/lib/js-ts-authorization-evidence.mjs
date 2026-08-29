import { accessControlKeyCategory } from './access-control-vocabulary.mjs';
import { sourceLocation } from './frameworks/route-extractor-helpers.mjs';
import { expressionName } from './js-ts-module-graph.mjs';

const CATEGORIES = ['object', 'principal', 'tenant'];
const CONVERSIONS = new Set(['String', 'Number', 'parseInt']);

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
