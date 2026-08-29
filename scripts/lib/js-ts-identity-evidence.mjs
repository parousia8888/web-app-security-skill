import { walkJsTsAst } from './js-ts-ast-parser.mjs';
import { expressionName } from './js-ts-module-graph.mjs';
import { importedBindings, sourceLocation } from './frameworks/route-extractor-helpers.mjs';
import { accessControlKeyCategory } from './access-control-vocabulary.mjs';

const FUNCTION_TYPES = new Set([
  'ArrowFunctionExpression', 'FunctionDeclaration', 'FunctionExpression', 'ClassMethod',
  'ClassPrivateMethod', 'ObjectMethod',
]);
const SCALAR_CONVERSIONS = new Set(['String', 'Number', 'parseInt']);

const DIRECT = new Map([
  ['next-auth:getServerSession', { provider: 'authjs', kind: 'next-auth-server-session', state: 'session_lookup_observed' }],
  ['next-auth/next:getServerSession', { provider: 'authjs', kind: 'next-auth-server-session', state: 'session_lookup_observed' }],
  ['next-auth:default', { provider: 'authjs', kind: 'authjs-nextauth-factory', factory: 'authjs' }],
  ['next-auth:NextAuth', { provider: 'authjs', kind: 'authjs-nextauth-factory', factory: 'authjs' }],
  ['better-auth:betterAuth', { provider: 'better-auth', kind: 'better-auth-factory', factory: 'better-auth' }],
  ['@clerk/nextjs/server:auth', { provider: 'clerk', kind: 'clerk-auth', state: 'identity_call_observed' }],
  ['@clerk/nextjs/server:currentUser', { provider: 'clerk', kind: 'clerk-current-user', state: 'identity_call_observed' }],
  ['@supabase/ssr:createServerClient', { provider: 'supabase', kind: 'supabase-server-client-factory', factory: 'supabase' }],
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

function propertyName(property) {
  return property?.type === 'ObjectProperty' ? safeName(property.key) : null;
}

function functionWalk(root, visit) {
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

function exportedLocals(module) {
  const output = new Map();
  for (const node of module.ast?.body || []) {
    if (node.type === 'ExportDefaultDeclaration') {
      const local = safeName(node.declaration);
      if (local) output.set('default', local);
    }
    if (node.type !== 'ExportNamedDeclaration') continue;
    const declaration = node.declaration;
    if (declaration?.id?.name) output.set(declaration.id.name, declaration.id.name);
    for (const item of declaration?.declarations || []) {
      if (item.id?.type === 'Identifier') output.set(item.id.name, item.id.name);
      if (item.id?.type === 'ObjectPattern') {
        for (const property of item.id.properties) {
          if (property.type !== 'ObjectProperty') continue;
          const local = safeName(property.value);
          if (local) output.set(local, local);
        }
      }
    }
    for (const specifier of node.specifiers || []) {
      const exported = safeName(specifier.exported);
      const local = safeName(specifier.local);
      if (exported && local) output.set(exported, local);
    }
  }
  return output;
}

function descriptorForFactory(factory, property = null) {
  if (factory === 'authjs' && property === 'auth') {
    return { provider: 'authjs', kind: 'authjs-local-auth', state: 'identity_call_observed' };
  }
  if (factory === 'authjs') return { provider: 'authjs', kind: 'authjs-instance', instance: 'authjs' };
  if (factory === 'better-auth') {
    return { provider: 'better-auth', kind: 'better-auth-instance', instance: 'better-auth' };
  }
  if (factory === 'supabase') {
    return { provider: 'supabase', kind: 'supabase-server-client', instance: 'supabase' };
  }
  return null;
}

function directImportSymbols(module) {
  const symbols = new Map();
  for (const [local, binding] of importedBindings(module)) {
    const descriptor = DIRECT.get(`${binding.source}:${binding.imported}`);
    if (descriptor) symbols.set(local, descriptor);
  }
  return symbols;
}

function callDescriptor(node, symbols) {
  const call = unwrap(node);
  if (call?.type !== 'CallExpression') return null;
  const name = safeName(call.callee);
  if (!name) return null;
  if (symbols.has(name)) return symbols.get(name);
  const parts = name.split('.');
  const root = symbols.get(parts[0]);
  if (root?.instance === 'better-auth' && parts.slice(1).join('.') === 'api.getSession') {
    return { provider: 'better-auth', kind: 'better-auth-server-session', state: 'session_lookup_observed' };
  }
  if (root?.instance === 'supabase' && parts.slice(-2).join('.') === 'auth.getUser') {
    return { provider: 'supabase', kind: 'supabase-auth-get-user', state: 'identity_call_observed' };
  }
  return null;
}

function wrapperFactory(functionNode, symbols) {
  const returned = [];
  functionWalk(functionNode, (node) => {
    if (node.type === 'ReturnStatement' && node.argument) returned.push(node.argument);
  });
  if (functionNode.type === 'ArrowFunctionExpression' && functionNode.body?.type !== 'BlockStatement') {
    returned.push(functionNode.body);
  }
  const factories = returned.map((node) => callDescriptor(node, symbols)?.factory).filter(Boolean);
  return factories.length === 1 && returned.length === 1 ? factories[0] : null;
}

function moduleSymbols(graph, module, cache = new Map(), visiting = new Set(), depth = 0) {
  if (cache.has(module.path)) return cache.get(module.path);
  const symbols = directImportSymbols(module);
  cache.set(module.path, symbols);
  if (visiting.has(module.path) || depth > 2) return symbols;
  visiting.add(module.path);

  for (const [local, binding] of importedBindings(module)) {
    if (!binding.resolvedPath || binding.resolutionReason || symbols.has(local)) continue;
    const target = graph.modules.get(binding.resolvedPath);
    if (!target?.ast) continue;
    const exported = exportedLocals(target).get(binding.imported);
    if (!exported) continue;
    const targetSymbols = moduleSymbols(graph, target, cache, visiting, depth + 1);
    if (targetSymbols.has(exported)) symbols.set(local, targetSymbols.get(exported));
  }

  for (let pass = 0; pass < 3; pass += 1) {
    walkJsTsAst(module.ast, (node) => {
      if (node.type === 'FunctionDeclaration' && node.id?.name && !symbols.has(node.id.name)) {
        const factory = wrapperFactory(node, symbols);
        if (factory) symbols.set(node.id.name, { provider: factory,
          kind: `${factory}-local-client-factory`, factory });
      }
      if (node.type !== 'VariableDeclarator') return;
      const descriptor = callDescriptor(node.init, symbols);
      if (!descriptor?.factory) return;
      if (node.id?.type === 'Identifier') {
        const value = descriptorForFactory(descriptor.factory);
        if (value) symbols.set(node.id.name, value);
      }
      if (node.id?.type === 'ObjectPattern') {
        for (const property of node.id.properties) {
          if (property.type !== 'ObjectProperty') continue;
          const local = safeName(property.value);
          const value = descriptorForFactory(descriptor.factory, propertyName(property));
          if (local && value) symbols.set(local, value);
        }
      }
    });
  }
  visiting.delete(module.path);
  return symbols;
}

function cachedModuleSymbols(graph, module, cache) {
  if (!cache) return moduleSymbols(graph, module);
  if (cache.has(module.path)) return cache.get(module.path);
  // Recursive moduleSymbols entries can be depth-limited or cycle-incomplete. Only cache a
  // module after resolving it from a fresh top-level traversal.
  const symbols = moduleSymbols(graph, module);
  cache.set(module.path, symbols);
  return symbols;
}

function objectBindings(pattern, prefix = []) {
  const output = [];
  if (pattern?.type === 'Identifier') return [{ local: pattern.name, path: prefix }];
  if (pattern?.type === 'AssignmentPattern') return objectBindings(pattern.left, prefix);
  if (pattern?.type !== 'ObjectPattern') return output;
  for (const property of pattern.properties) {
    if (property.type !== 'ObjectProperty') continue;
    output.push(...objectBindings(property.value, [...prefix, propertyName(property) || 'unknown']));
  }
  return output;
}

function addIdentityBindings(principalAliases, tenantAliases, pattern, descriptor) {
  if (pattern?.type === 'Identifier') {
    const local = pattern.name;
    if (descriptor.kind === 'clerk-current-user') principalAliases.add(`${local}.id`);
    else if (descriptor.kind === 'clerk-auth') {
      principalAliases.add(`${local}.userId`);
      tenantAliases.add(`${local}.orgId`);
    } else if (descriptor.kind === 'supabase-auth-get-user') {
      principalAliases.add(`${local}.data.user.id`);
    }
    else {
      principalAliases.add(`${local}.user.id`);
      principalAliases.add(`${local}.userId`);
      tenantAliases.add(`${local}.tenantId`);
      tenantAliases.add(`${local}.organizationId`);
      tenantAliases.add(`${local}.orgId`);
    }
    return;
  }
  for (const binding of objectBindings(pattern)) {
    const tail = binding.path.at(-1) || '';
    const category = accessControlKeyCategory(tail);
    if (category === 'principal') principalAliases.add(binding.local);
    if (category === 'tenant') tenantAliases.add(binding.local);
    if (/^(?:user|currentUser)$/i.test(tail)) principalAliases.add(`${binding.local}.id`);
  }
}

function expressionIdentityCategory(raw, principalAliases, tenantAliases) {
  const node = unwrap(raw);
  if (!node) return null;
  const name = safeName(node);
  const categories = [];
  if (name && principalAliases.has(name)) categories.push('principal');
  if (name && tenantAliases.has(name)) categories.push('tenant');
  if (node.type === 'CallExpression' && SCALAR_CONVERSIONS.has(safeName(node.callee))
      && node.arguments.length === 1 && node.arguments[0].type !== 'SpreadElement') {
    const converted = expressionIdentityCategory(node.arguments[0], principalAliases, tenantAliases);
    if (converted) categories.push(converted);
  }
  const unique = [...new Set(categories)];
  return unique.length === 1 ? unique[0] : unique.length ? 'ambiguous' : null;
}

function returnedIdentityFacts(handler, principalAliases, tenantAliases) {
  const returns = [];
  functionWalk(handler, (node) => {
    if (node.type === 'ReturnStatement' && node.argument) returns.push(unwrap(node.argument));
  });
  if (handler.type === 'ArrowFunctionExpression' && handler.body?.type !== 'BlockStatement') {
    returns.push(unwrap(handler.body));
  }
  const shapes = [];
  let observed = false;
  let unresolved = false;
  for (const returned of returns) {
    const scalar = expressionIdentityCategory(returned, principalAliases, tenantAliases);
    if (scalar && scalar !== 'ambiguous') {
      observed = true;
      shapes.push({ kind: 'scalar', category: scalar });
      continue;
    }
    if (scalar === 'ambiguous') {
      observed = true;
      unresolved = true;
      continue;
    }
    if (returned?.type !== 'ObjectExpression') {
      if (observed) unresolved = true;
      continue;
    }
    const fields = [];
    let objectObserved = false;
    let objectUnresolved = false;
    for (const property of returned.properties || []) {
      if (property.type !== 'ObjectProperty' || property.computed) {
        objectUnresolved = true;
        continue;
      }
      const field = propertyName(property);
      const category = expressionIdentityCategory(property.value, principalAliases, tenantAliases);
      if (category === 'ambiguous') objectUnresolved = true;
      else if (field && category) {
        objectObserved = true;
        fields.push({ field, category });
      }
    }
    if (objectObserved) {
      observed = true;
      unresolved ||= objectUnresolved;
      shapes.push({ kind: 'object', fields: fields.sort((left, right) =>
        left.field.localeCompare(right.field)) });
    } else if (observed) unresolved = true;
  }
  if (!observed) return { state: 'not_observed', shape: null };
  const normalized = [...new Set(shapes.map((shape) => JSON.stringify(shape)))];
  if (unresolved || normalized.length !== 1 || shapes.length !== returns.length) {
    return { state: 'incomplete', shape: null };
  }
  return { state: 'exact', shape: JSON.parse(normalized[0]) };
}

function unresolvedProviderWrappers(declarations, symbols, module) {
  const wrappers = [];
  for (const declaration of declarations) {
    const call = unwrap(declaration.init);
    if (call?.type !== 'CallExpression' || callDescriptor(call, symbols)?.state) continue;
    const providers = [];
    for (const argument of call.arguments || []) {
      if (argument.type === 'SpreadElement') continue;
      const descriptor = symbols.get(safeName(argument));
      if (descriptor?.state || descriptor?.factory || descriptor?.instance) {
        providers.push(descriptor.provider);
      }
    }
    for (const provider of [...new Set(providers.filter(Boolean))]) {
      wrappers.push({ provider, kind: `${provider}-provider-wrapper-unresolved`,
        origin: `${provider}:${safeName(call.callee) || '<dynamic-wrapper>'}`,
        location: sourceLocation(module.path, call) });
    }
  }
  return wrappers;
}

function localSymbolsForHandler(handler, baseSymbols) {
  const symbols = new Map(baseSymbols);
  const declarations = [];
  functionWalk(handler, (node) => {
    if (node.type === 'VariableDeclarator') declarations.push(node);
  });
  for (let pass = 0; pass < 3; pass += 1) {
    for (const declaration of declarations) {
      if (declaration.id?.type !== 'Identifier') continue;
      const descriptor = callDescriptor(declaration.init, symbols);
      if (!descriptor?.factory) continue;
      const value = descriptorForFactory(descriptor.factory);
      if (value) symbols.set(declaration.id.name, value);
    }
  }
  return { symbols, declarations };
}

export function identityProviderSymbolsForHandler(graph, module, handler, options = {}) {
  return localSymbolsForHandler(handler,
    cachedModuleSymbols(graph, module, options.moduleCache)).symbols;
}

export function analyzeIdentityEvidence(graph, module, handler, options = {}) {
  const baseSymbols = cachedModuleSymbols(graph, module, options.moduleCache);
  const { symbols, declarations } = localSymbolsForHandler(handler, baseSymbols);
  const calls = [];
  const principalAliases = new Set();
  const tenantAliases = new Set();
  functionWalk(handler, (node) => {
    if (node.type !== 'CallExpression') return;
    const descriptor = callDescriptor(node, symbols);
    if (!descriptor?.state) return;
    calls.push({ descriptor, node });
  });
  for (const declaration of declarations) {
    let matched = null;
    functionWalk(declaration.init, (node) => {
      if (matched || node.type !== 'CallExpression') return;
      const descriptor = callDescriptor(node, symbols);
      if (descriptor?.state) matched = descriptor;
    });
    if (matched) addIdentityBindings(principalAliases, tenantAliases, declaration.id, matched);
  }
  const unresolvedWrappers = unresolvedProviderWrappers(declarations, symbols, module);
  const unique = calls.filter((item, index, items) => items.findIndex((candidate) =>
    candidate.descriptor.kind === item.descriptor.kind && candidate.node.start === item.node.start) === index);
  if (!unique.length) return {
    identity: unresolvedWrappers.length ? {
      state: 'incomplete',
      provider: [...new Set(unresolvedWrappers.map((item) => item.provider))].length === 1
        ? unresolvedWrappers[0].provider : 'multiple',
      signals: unresolvedWrappers,
      boundary: 'A supported identity-provider value enters an unresolved wrapper. Authentication, returned identity and enforcement are not established.',
    } : { state: 'not_observed', provider: null, signals: [],
      boundary: 'No exact supported identity-provider call was observed in this bounded handler.' },
    principalAliases,
    tenantAliases,
    returnFacts: { state: 'not_observed', shape: null },
    limitations: unresolvedWrappers.length ? ['identity_provider_wrapper_unresolved'] : [],
  };
  const providers = [...new Set(unique.map((item) => item.descriptor.provider))];
  const states = [...new Set(unique.map((item) => item.descriptor.state))];
  const mixed = providers.length > 1 || states.length > 1;
  return {
    identity: {
      state: mixed ? 'candidate_observed' : states[0],
      provider: mixed ? 'multiple' : providers[0],
      signals: unique.map((item) => ({ kind: item.descriptor.kind,
        origin: `${item.descriptor.provider}:${safeName(item.node.callee)}`,
        location: sourceLocation(module.path, item.node) })),
      boundary: mixed
        ? 'Multiple supported identity-related calls were observed; their runtime relationship requires review.'
        : 'An exact supported identity-provider call was observed; returned identity, session validity and downstream enforcement are not proved.',
    },
    principalAliases,
    tenantAliases,
    returnFacts: returnedIdentityFacts(handler, principalAliases, tenantAliases),
    limitations: unresolvedWrappers.length ? ['identity_provider_wrapper_unresolved'] : [],
  };
}

export function identityProviderInventory() {
  return [...DIRECT.entries()].map(([identity, descriptor]) => ({ identity, ...descriptor }));
}
