import { walkJsTsAst } from './js-ts-ast-parser.mjs';
import { expressionName } from './js-ts-module-graph.mjs';
import {
  importedBindings, localModuleExport, sourceLocation,
} from './frameworks/route-extractor-helpers.mjs';
import { identityProviderSymbolsForHandler } from './js-ts-identity-evidence.mjs';
import { accessControlKeyCategory } from './access-control-vocabulary.mjs';
import { resolveCallableCall } from './js-ts-callable-index.mjs';
import {
  evaluateDrizzlePredicate, evaluatePrismaPredicate, observedAuthorizationEvidence,
} from './js-ts-authorization-evidence.mjs';

const FUNCTION_TYPES = new Set([
  'ArrowFunctionExpression', 'FunctionDeclaration', 'FunctionExpression', 'ClassMethod',
  'ClassPrivateMethod', 'ObjectMethod',
]);
const PRISMA_OPERATIONS = new Set([
  'findUnique', 'findUniqueOrThrow', 'findFirst', 'findFirstOrThrow', 'findMany',
  'update', 'updateMany', 'delete', 'deleteMany', 'upsert',
]);
const DRIZZLE_QUERY_OPERATIONS = new Set(['findFirst', 'findMany']);
const DRIZZLE_BUILDERS = new Set(['select', 'update', 'delete', 'insert']);
const SUPABASE_OPERATIONS = new Set(['select', 'insert', 'update', 'delete', 'upsert']);

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

function propertyName(property) {
  if (property?.type !== 'ObjectProperty') return null;
  if (property.computed && property.key?.type === 'StringLiteral') return property.key.value;
  return safeName(property.key);
}

function literalString(node) {
  const current = unwrap(node);
  if (current?.type === 'StringLiteral') return current.value;
  if (current?.type === 'TemplateLiteral' && current.expressions.length === 0) {
    return current.quasis.map((item) => item.value.cooked ?? item.value.raw).join('');
  }
  return null;
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

function expressionMatches(node, aliases, nodes = new Set()) {
  const current = unwrap(node);
  if (nodes.has(current)) return true;
  const name = safeName(current);
  if (name && aliases.has(name)) return true;
  if (current?.type === 'CallExpression' && ['String', 'Number', 'parseInt'].includes(safeName(current.callee))) {
    return expressionMatches(current.arguments[0], aliases, nodes);
  }
  return false;
}

function containsExpression(node, aliases, includeFunctions = true, nodes = new Set()) {
  let matched = false;
  let visited = 0;
  const stack = [unwrap(node)];
  while (stack.length && !matched && visited < 4_000) {
    const current = stack.pop();
    if (!current || typeof current !== 'object') continue;
    visited += 1;
    if (expressionMatches(current, aliases, nodes)) {
      matched = true;
      break;
    }
    if (!includeFunctions && FUNCTION_TYPES.has(current.type)) continue;
    for (const [key, value] of Object.entries(current)) {
      if (['loc', 'start', 'end', 'extra', 'comments', 'tokens'].includes(key)) continue;
      if (Array.isArray(value)) stack.push(...value);
      else if (value && typeof value === 'object') stack.push(value);
    }
  }
  return matched;
}

function collectLocalAliases(handler, objectSeed, principalSeed, objectNodeSeed = [], tenantSeed = [],
  omittedSeed = []) {
  const objectAliases = new Set(objectSeed);
  const objectNodes = new Set(objectNodeSeed);
  const principalAliases = new Set(principalSeed);
  const tenantAliases = new Set(tenantSeed);
  const omittedAliases = new Set(omittedSeed);
  const objectValues = new Map();
  const declarations = [];
  functionWalk(handler, (node) => {
    if (node.type === 'VariableDeclarator') declarations.push(node);
  });
  for (let pass = 0; pass < 4; pass += 1) {
    let changed = false;
    for (const declaration of declarations) {
      const init = unwrap(declaration.init);
      if (declaration.id?.type !== 'Identifier') continue;
      if (init?.type === 'ObjectExpression') objectValues.set(declaration.id.name, init);
      if (expressionMatches(init, objectAliases, objectNodes) && !objectAliases.has(declaration.id.name)) {
        objectAliases.add(declaration.id.name);
        changed = true;
      }
      if (expressionMatches(init, principalAliases) && !principalAliases.has(declaration.id.name)) {
        principalAliases.add(declaration.id.name);
        changed = true;
      }
      if (expressionMatches(init, tenantAliases) && !tenantAliases.has(declaration.id.name)) {
        tenantAliases.add(declaration.id.name);
        changed = true;
      }
      const initName = safeName(init);
      if (initName && omittedAliases.has(initName) && !omittedAliases.has(declaration.id.name)) {
        omittedAliases.add(declaration.id.name);
        changed = true;
      }
    }
    if (!changed) break;
  }
  return { objectAliases, objectNodes, principalAliases, tenantAliases, omittedAliases,
    objectValues };
}

function resolvedObject(node, objectValues) {
  const current = unwrap(node);
  if (current?.type === 'ObjectExpression') return current;
  if (current?.type === 'Identifier') return objectValues.get(current.name) || null;
  return null;
}

function objectProperty(object, name, objectValues) {
  for (const property of object?.properties || []) {
    if (property.type !== 'ObjectProperty') continue;
    if (propertyName(property) === name) return resolvedObject(property.value, objectValues) || unwrap(property.value);
  }
  return null;
}

function keyCategory(key) {
  return accessControlKeyCategory(key);
}

function constraintsIn(node, facts, objectValues = new Map()) {
  const result = { object: false, principal: false, tenant: false };
  const stack = [unwrap(node)];
  let visited = 0;
  while (stack.length && visited < 6_000) {
    const current = stack.pop();
    if (!current || typeof current !== 'object') continue;
    visited += 1;
    if (current.type === 'ObjectExpression') {
      for (const property of current.properties) {
        if (property.type !== 'ObjectProperty') continue;
        const category = keyCategory(propertyName(property));
        if (category === 'object' && containsExpression(property.value, facts.objectAliases,
          true, facts.objectNodes)) result.object = true;
        if (category === 'principal' && containsExpression(property.value, facts.principalAliases)) result.principal = true;
        if (category === 'tenant' && containsExpression(property.value, facts.tenantAliases)) result.tenant = true;
        const nested = resolvedObject(property.value, objectValues);
        if (nested && nested !== current) stack.push(nested);
      }
    }
    const called = current.type === 'CallExpression'
      ? (safeName(current.callee) || '').split('.').at(-1)
      : (current.node?.type === 'CallExpression' ? current.name : null);
    if (['eq', 'equals', 'filter'].includes(called) && current.arguments?.length >= 2) {
        const key = literalString(current.arguments[0]) || safeName(current.arguments[0]);
        const value = current.arguments[1];
        const category = keyCategory(key);
        if (category === 'object' && containsExpression(value, facts.objectAliases,
          true, facts.objectNodes)) result.object = true;
        if (category === 'principal' && containsExpression(value, facts.principalAliases)) result.principal = true;
        if (category === 'tenant' && containsExpression(value, facts.tenantAliases)) result.tenant = true;
    }
    for (const [key, value] of Object.entries(current)) {
      if (['loc', 'start', 'end', 'extra', 'comments', 'tokens'].includes(key)) continue;
      if (Array.isArray(value)) stack.push(...value);
      else if (value && typeof value === 'object') stack.push(value);
    }
  }
  return result;
}

function clientExportDescriptor(graph, module, exported, cache, visiting,
  exportVisiting = new Set()) {
  const key = `${module.path}\u0000${exported}`;
  if (exportVisiting.has(key)) return null;
  const next = new Set(exportVisiting);
  next.add(key);
  const symbols = moduleClientSymbols(graph, module, cache, visiting);
  const direct = module.exports.filter((item) => item.exported === exported && item.local
      && !item.typeOnly)
    .map((item) => symbols.get(item.local)).filter(Boolean);
  if (direct.length === 1) return direct[0];
  if (direct.length > 1 || exported === 'default') return null;
  const starSources = new Set((module.ast?.body || []).filter((node) =>
    node.type === 'ExportAllDeclaration' && node.exportKind !== 'type')
    .map((node) => literalString(node.source)).filter(Boolean));
  const candidates = [];
  for (const imported of module.imports.filter((item) => starSources.has(item.source)
      && item.bindings.length === 0 && item.resolution?.path && !item.resolution.reason)) {
    const target = graph.modules.get(imported.resolution.path);
    if (!target?.ast) continue;
    const descriptor = clientExportDescriptor(graph, target, exported, cache, visiting, next);
    if (descriptor) candidates.push(descriptor);
  }
  return candidates.length === 1 ? candidates[0] : null;
}

function moduleClientSymbols(graph, module, cache = new Map(), visiting = new Set()) {
  if (cache.has(module.path)) return cache.get(module.path);
  const symbols = new Map();
  cache.set(module.path, symbols);
  if (visiting.has(module.path)) return symbols;
  visiting.add(module.path);
  const imports = importedBindings(module);
  const prismaConstructors = new Set();
  const drizzleFactories = new Set();
  for (const [local, binding] of imports) {
    if (binding.typeOnly) continue;
    if (binding.source === '@prisma/client' && binding.imported === 'PrismaClient') prismaConstructors.add(local);
    if (binding.generatedProvider === 'prisma' && binding.imported === 'PrismaClient') {
      prismaConstructors.add(local);
      symbols.set(local, { provider: 'prisma-constructor' });
    }
    if (/^drizzle-orm(?:\/|$)/.test(binding.source)
        && ['drizzle', 'default'].includes(binding.imported)) drizzleFactories.add(local);
  }
  for (const [local, binding] of imports) {
    if (binding.typeOnly) continue;
    if (!binding.resolvedPath || binding.resolutionReason) continue;
    const target = graph.modules.get(binding.resolvedPath);
    if (!target?.ast) continue;
    const descriptor = clientExportDescriptor(graph, target, binding.imported, cache, visiting);
    if (!descriptor) continue;
    symbols.set(local, descriptor);
    if (descriptor.provider === 'prisma-constructor') prismaConstructors.add(local);
  }
  const candidates = [];
  walkJsTsAst(module.ast, (node) => {
    let name = null;
    let value = null;
    if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier') {
      name = node.id.name;
      value = unwrap(node.init);
    } else if (['ClassProperty', 'ClassPrivateProperty'].includes(node.type)) {
      name = `this.${safeName(node.key)}`;
      value = unwrap(node.value);
    } else if (node.type === 'AssignmentExpression') {
      name = safeName(node.left);
      value = unwrap(node.right);
    }
    if (!name || !value) return;
    candidates.push({ name, value });
  });
  const topLevelNames = new Set(imports.keys());
  const topLevelConstDeclarations = [];
  for (const statement of module.ast?.body || []) {
    const declaration = statement.type === 'VariableDeclaration' ? statement
      : (statement.type === 'ExportNamedDeclaration'
        && statement.declaration?.type === 'VariableDeclaration' ? statement.declaration : null);
    if (declaration) {
      for (const item of declaration.declarations || []) {
        if (item.id?.type !== 'Identifier') continue;
        topLevelNames.add(item.id.name);
        if (declaration.kind === 'const' && item.init) topLevelConstDeclarations.push(item);
      }
      continue;
    }
    if (['FunctionDeclaration', 'ClassDeclaration'].includes(statement.type) && statement.id?.name) {
      topLevelNames.add(statement.id.name);
    }
  }
  const globalRoots = new Set(['globalThis', 'global'].filter((name) => !topLevelNames.has(name)));
  for (const declaration of topLevelConstDeclarations) {
    const initializer = unwrap(declaration.init);
    if (initializer?.type === 'Identifier' && globalRoots.has(initializer.name)) {
      globalRoots.add(declaration.id.name);
    }
  }
  const globalCache = (name) => {
    const match = /^([A-Za-z_$][\w$]*)\.[A-Za-z_$][\w$]*$/.exec(name || '');
    return Boolean(match && globalRoots.has(match[1]));
  };
  const factories = new Map(candidates.filter(({ value }) => FUNCTION_TYPES.has(value.type))
    .map(({ name, value }) => [name, value]));
  function factoryReturns(node) {
    if (node.type === 'ArrowFunctionExpression' && node.body?.type !== 'BlockStatement') return [node.body];
    const returned = [];
    functionWalk(node, (current) => {
      if (current.type === 'ReturnStatement' && current.argument) returned.push(current.argument);
    });
    return returned;
  }
  function prismaInitializer(node, target, depth = 0) {
    const value = unwrap(node);
    if (!value || depth > 8) return false;
    if (value.type === 'NewExpression') return prismaConstructors.has(safeName(value.callee));
    if (value.type === 'CallExpression' && value.arguments.length === 0) {
      const factory = factories.get(safeName(value.callee));
      const returned = factory ? factoryReturns(factory) : [];
      return returned.length === 1 && prismaInitializer(returned[0], target, depth + 1);
    }
    const name = safeName(value);
    if (name && symbols.get(name)?.provider === 'prisma') return true;
    if (value.type === 'AssignmentExpression') return prismaInitializer(value.right, target, depth + 1);
    if (value.type === 'SequenceExpression') {
      return prismaInitializer(value.expressions.at(-1), target, depth + 1);
    }
    if (value.type === 'ConditionalExpression') {
      return prismaInitializer(value.consequent, target, depth + 1)
        && prismaInitializer(value.alternate, target, depth + 1);
    }
    if (value.type !== 'LogicalExpression' || !['??', '||'].includes(value.operator)) return false;
    const left = safeName(unwrap(value.left));
    const right = safeName(unwrap(value.right));
    const leftKnown = prismaInitializer(value.left, target, depth + 1);
    const rightKnown = prismaInitializer(value.right, target, depth + 1);
    if (leftKnown && rightKnown) return true;
    if (rightKnown && (globalCache(left) || left === target)) return true;
    if (leftKnown && (globalCache(right) || right === target)) return true;
    return false;
  }
  for (let pass = 0; pass < 4; pass += 1) {
    let changed = false;
    for (const { name, value } of candidates) {
      if (!symbols.has(name) && prismaInitializer(value, name)) {
        symbols.set(name, { provider: 'prisma' });
        changed = true;
      }
      if (!symbols.has(name) && safeName(value) && prismaConstructors.has(safeName(value))) {
        symbols.set(name, { provider: 'prisma-constructor' });
        prismaConstructors.add(name);
        changed = true;
      }
      if (!symbols.has(name) && value.type === 'CallExpression'
          && drizzleFactories.has(safeName(value.callee))) {
        symbols.set(name, { provider: 'drizzle' });
        changed = true;
      }
    }
    if (!changed) break;
  }
  visiting.delete(module.path);
  return symbols;
}

function handlerBinding(handler, name) {
  let binding = null;
  for (const parameter of handler.params || []) {
    const candidate = parameterNode(parameter);
    if (candidate?.type === 'Identifier' && candidate.name === name) {
      return { kind: 'parameter', node: candidate, init: null };
    }
  }
  functionWalk(handler, (node) => {
    if (binding || node.type !== 'VariableDeclarator' || node.id?.type !== 'Identifier'
        || node.id.name !== name) return;
    binding = { kind: 'variable', node: node.id, init: unwrap(node.init) };
  });
  return binding;
}

function exactLocalClientBinding(module, handler, name, descriptor) {
  const binding = handlerBinding(handler, name);
  if (!binding) return true;
  if (descriptor.handlerLocal) return true;
  const imports = importedBindings(module);
  if (descriptor.provider === 'prisma' && binding.init?.type === 'NewExpression') {
    const constructor = imports.get(safeName(binding.init.callee));
    return constructor?.source === '@prisma/client' && constructor.imported === 'PrismaClient';
  }
  if (descriptor.provider === 'drizzle' && binding.init?.type === 'CallExpression') {
    const factory = imports.get(safeName(binding.init.callee));
    return /^drizzle-orm(?:\/|$)/.test(factory?.source || '')
      && ['drizzle', 'default'].includes(factory.imported);
  }
  return false;
}

function decomposeChain(node) {
  const current = unwrap(node);
  if (!current) return null;
  if (current.type === 'Identifier' || current.type === 'ThisExpression') {
    return { root: safeName(current), stages: [] };
  }
  if (current.type === 'MemberExpression' || current.type === 'OptionalMemberExpression') {
    const direct = safeName(current);
    if (direct) return { root: direct, stages: [] };
    return null;
  }
  if (current.type !== 'CallExpression' || !['MemberExpression', 'OptionalMemberExpression'].includes(current.callee?.type)) {
    return null;
  }
  const base = decomposeChain(current.callee.object);
  const name = safeName(current.callee.property);
  if (!base || !name) return null;
  base.stages.push({ name, arguments: current.arguments, node: current });
  return base;
}

function resourceName(node) {
  return literalString(node) || safeName(node) || 'unknown';
}

function parameterNode(raw) {
  const parameter = raw?.type === 'TSParameterProperty' ? raw.parameter : raw;
  return parameter?.type === 'AssignmentPattern' ? parameter.left : parameter;
}

function parameterOmittable(raw) {
  const parameter = raw?.type === 'TSParameterProperty' ? raw.parameter : raw;
  return parameter?.type === 'AssignmentPattern' || parameter?.optional === true;
}

function callableReturns(target) {
  if (target.node.type === 'ArrowFunctionExpression' && target.node.body?.type !== 'BlockStatement') {
    return [target.node.body];
  }
  const returned = [];
  functionWalk(target.node, (node) => {
    if (node.type === 'ReturnStatement' && node.argument) returned.push(node.argument);
  });
  return returned;
}

function mappedOmittedAliases(call, target, facts) {
  const omitted = new Set();
  const parameters = target.node.params || [];
  for (let index = 0; index < parameters.length; index += 1) {
    const parameter = parameterNode(parameters[index]);
    if (parameter?.type !== 'Identifier') continue;
    if (index >= call.arguments.length) {
      if (parameterOmittable(parameters[index])) omitted.add(parameter.name);
      continue;
    }
    const argument = call.arguments[index];
    if (argument.type !== 'SpreadElement' && facts.omittedAliases.has(safeName(argument))) {
      omitted.add(parameter.name);
    }
  }
  return omitted;
}

function resolvePrismaClientExpression(index, graph, module, handler, raw, facts, clientCache,
  visiting = new Set(), depth = 0) {
  const node = unwrap(raw);
  if (!node || depth > 4) return { state: 'incomplete' };
  const clients = moduleClientSymbols(graph, module, clientCache);
  const name = safeName(node);
  if (name && clients.get(name)?.provider === 'prisma'
      && exactLocalClientBinding(module, handler, name, clients.get(name))) {
    return { state: 'exact', name };
  }
  if (node.type === 'LogicalExpression' && node.operator === '??') {
    const left = safeName(node.left);
    if (!left || !facts.omittedAliases.has(left)) return { state: 'incomplete' };
    return resolvePrismaClientExpression(index, graph, module, handler, node.right, facts,
      clientCache, visiting, depth + 1);
  }
  if (node.type !== 'CallExpression' || !index) return { state: 'incomplete' };
  const resolution = resolveCallableCall(index, module, handler, node);
  if (resolution?.state !== 'exact' || visiting.has(resolution.target.id)) {
    return { state: 'incomplete' };
  }
  const returns = callableReturns(resolution.target);
  if (returns.length !== 1) return { state: 'incomplete' };
  const nextFacts = { ...facts,
    omittedAliases: mappedOmittedAliases(node, resolution.target, facts) };
  return resolvePrismaClientExpression(index, graph, resolution.target.module,
    resolution.target.node, returns[0], nextFacts, clientCache,
    new Set([...visiting, resolution.target.id]), depth + 1);
}

function prismaCallShape(call) {
  const callee = unwrap(call.callee);
  if (!['MemberExpression', 'OptionalMemberExpression'].includes(callee?.type) || callee.computed) {
    return null;
  }
  const operationName = safeName(callee.property);
  const resourceMember = unwrap(callee.object);
  if (!PRISMA_OPERATIONS.has(operationName)
      || !['MemberExpression', 'OptionalMemberExpression'].includes(resourceMember?.type)
      || resourceMember.computed) return null;
  const resource = safeName(resourceMember.property);
  if (!resource) return null;
  return { client: resourceMember.object, resource, operationName };
}

function prismaEvidence(graph, module, handler, call, facts, index, clientCache) {
  const shape = prismaCallShape(call);
  if (!shape) return null;
  const client = resolvePrismaClientExpression(index, graph, module, handler, shape.client,
    facts, clientCache);
  const options = resolvedObject(call.arguments[0], facts.objectValues);
  const where = objectProperty(options, 'where', facts.objectValues);
  if (client.state !== 'exact') {
    return containsExpression(where, facts.objectAliases, true, facts.objectNodes)
      ? { incomplete: { code: 'prisma_client_identity_unresolved', path: module.path,
        location: sourceLocation(module.path, call) } } : null;
  }
  const evaluated = evaluatePrismaPredicate(module, where, facts);
  if (evaluated.states.object.state === 'not_observed') return null;
  return { operation: operation(module, call, 'prisma', shape.resource, shape.operationName,
    evaluated, 'not_applicable') };
}

function drizzleEvidence(module, handler, call, clients, facts, operators) {
  const direct = safeName(call.callee);
  for (const [client, descriptor] of clients) {
    if (descriptor.provider !== 'drizzle') continue;
    if (!exactLocalClientBinding(module, handler, client, descriptor)) continue;
    if (direct?.startsWith(`${client}.query.`)) {
      const parts = direct.slice(client.length + 1).split('.');
      if (parts.length === 3 && parts[0] === 'query' && DRIZZLE_QUERY_OPERATIONS.has(parts[2])) {
        const options = resolvedObject(call.arguments[0], facts.objectValues);
        const where = objectProperty(options, 'where', facts.objectValues);
        const evaluated = evaluateDrizzlePredicate(module, where, facts, operators);
        if (evaluated.states.object.state !== 'not_observed') {
          return operation(module, call, 'drizzle', parts[1], parts[2], evaluated,
            'not_applicable');
        }
      }
    }
    const chain = decomposeChain(call);
    if (!chain || chain.root !== client) continue;
    const builder = chain.stages.find((stage) => DRIZZLE_BUILDERS.has(stage.name));
    if (!builder) continue;
    const where = chain.stages.filter((stage) => stage.name === 'where').at(-1);
    if (!where) continue;
    const evaluated = evaluateDrizzlePredicate(module, where.arguments[0], facts, operators);
    if (evaluated.states.object.state === 'not_observed') continue;
    const from = chain.stages.find((stage) => stage.name === 'from');
    const resource = resourceName((from || builder).arguments[0]);
    return operation(module, call, 'drizzle', resource, builder.name, evaluated, 'not_applicable');
  }
  return null;
}

function supabaseEvidence(module, handler, call, clients, facts) {
  const chain = decomposeChain(call);
  if (!chain) return null;
  for (const [client, descriptor] of clients) {
    if (descriptor.provider !== 'supabase' || chain.root !== client) continue;
    if (!exactLocalClientBinding(module, handler, client, descriptor)) continue;
    const from = chain.stages.find((stage) => stage.name === 'from');
    const selected = [...chain.stages].reverse().find((stage) => SUPABASE_OPERATIONS.has(stage.name));
    if (!from || !selected) continue;
    const constraints = constraintsIn(chain.stages, facts, facts.objectValues);
    if (!constraints.object) continue;
    return operation(module, call, 'supabase', resourceName(from.arguments[0]), selected.name,
      constraints, 'external_policy_required');
  }
  return null;
}

function operation(module, call, provider, resource, operationName, constraints, externalPolicy) {
  const structured = constraints.states ? constraints.states : {
    object: { state: constraints.object ? 'observed' : 'not_observed' },
    principal: { state: constraints.principal ? 'observed' : 'not_observed' },
    tenant: { state: constraints.tenant ? 'observed' : 'not_observed' },
  };
  const authorizationEvidence = constraints.states ? observedAuthorizationEvidence(constraints) : null;
  return {
    provider,
    resource,
    operation: operationName.replace(/[A-Z]/g, (character) => `-${character.toLowerCase()}`),
    location: sourceLocation(module.path, call),
    objectConstraint: structured.object.state,
    principalConstraint: structured.principal.state,
    tenantConstraint: structured.tenant.state,
    authorizationEvidence: authorizationEvidence?.length ? authorizationEvidence : null,
    limitations: constraints.limitations || [],
    externalPolicy,
    node: call,
  };
}

export function analyzeDataOperations(graph, module, handler, options = {}) {
  const facts = collectLocalAliases(handler, options.objectAliases || [], options.principalAliases || [],
    options.objectNodes || [], options.tenantAliases || [], options.omittedAliases || []);
  const clientCache = options.clientCache || new Map();
  const clients = moduleClientSymbols(graph, module, clientCache);
  for (const [name, descriptor] of identityProviderSymbolsForHandler(graph, module, handler,
    { moduleCache: options.identityModuleCache })) {
    if (descriptor.instance === 'supabase') {
      clients.set(name, { provider: 'supabase', handlerLocal: true });
    }
  }
  const prismaRelevant = [...importedBindings(module).values()].some((binding) =>
    binding.source === '@prisma/client')
    || [...clients.values()].some((descriptor) => descriptor.provider === 'prisma');
  const drizzleOperators = new Map([...importedBindings(module)].flatMap(([local, binding]) =>
    /^drizzle-orm(?:\/|$)/.test(binding.source) && ['and', 'or', 'eq'].includes(binding.imported)
      ? [[local, binding.imported]] : []));
  const operations = [];
  const incomplete = [];
  functionWalk(handler, (node) => {
    if (node.type !== 'CallExpression') return;
    const prisma = prismaRelevant
      ? prismaEvidence(graph, module, handler, node, facts, options.callableIndex, clientCache)
      : null;
    if (prisma?.operation) operations.push(prisma.operation);
    if (prisma?.incomplete) incomplete.push(prisma.incomplete);
    if (prisma) return;
    const found = drizzleEvidence(module, handler, node, clients, facts, drizzleOperators)
      || supabaseEvidence(module, handler, node, clients, facts);
    if (found) {
      operations.push(found);
      return;
    }
    const name = safeName(node.callee);
    const parts = name?.split('.') || [];
    if (parts.length === 3 && PRISMA_OPERATIONS.has(parts[2])
        && /(?:^|_)(?:prisma|db|database)(?:$|_)/i.test(parts[0])
        && !clients.has(parts[0]) && prismaRelevant) {
      incomplete.push({ code: 'prisma_client_identity_unresolved', path: module.path,
        location: sourceLocation(module.path, node) });
    }
  });
  const unique = operations.filter((item, index, items) => items.findIndex((candidate) =>
    candidate.provider === item.provider && candidate.location.path === item.location.path
      && candidate.location.line === item.location.line && candidate.operation === item.operation) === index);
  return { operations: unique, facts, clients,
    incomplete: incomplete.filter((item, index, items) => items.findIndex((candidate) =>
      candidate.code === item.code && candidate.location.line === item.location.line) === index) };
}

export function dataProviderInventory() {
  return [
    { provider: 'prisma', boundary: 'Exact PrismaClient construction, bounded global singleton initialization or one local exported client.' },
    { provider: 'drizzle', boundary: 'Exact drizzle-orm factory construction or one local exported client.' },
    { provider: 'supabase', boundary: 'Exact @supabase/ssr server-client factory through the supported identity registry.' },
  ];
}
