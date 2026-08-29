import { expressionName, literalString } from './js-ts-module-graph.mjs';

const FUNCTION_TYPES = new Set([
  'ArrowFunctionExpression', 'FunctionDeclaration', 'FunctionExpression', 'ClassMethod',
  'ClassPrivateMethod', 'ObjectMethod',
]);
const CALL_TYPES = new Set(['CallExpression', 'OptionalCallExpression']);
const DEFAULT_LIMITS = Object.freeze({
  maxCallables: 20_000,
  maxSymbolsPerModule: 2_000,
  maxReexportDepth: 16,
  maxResolutionSteps: 256,
});
const INDEX_CACHE = new WeakMap();

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

function add(map, key, value) {
  if (!key) return;
  const values = map.get(key) || [];
  values.push(value);
  map.set(key, values);
}

function keyName(node) {
  if (!node || node.computed) return null;
  return safeName(node.key);
}

function callableRecord(module, node, name, kind = 'function') {
  const line = node?.loc?.start?.line ?? 0;
  const offset = Number.isInteger(node?.start) ? node.start : line;
  return {
    id: `${module.path}#${kind}:${name || '<inline>'}:${offset}`,
    module,
    node,
    name: name || '<inline>',
    kind,
  };
}

function classRecord(module, node, name, remainingCallables = Number.POSITIVE_INFINITY) {
  const methods = new Map();
  let retained = 0;
  let discovered = 0;
  for (const method of node?.body?.body || []) {
    if (!['ClassMethod', 'ClassPrivateMethod'].includes(method.type)) continue;
    const nameValue = keyName(method);
    if (!nameValue) continue;
    discovered += 1;
    if (retained >= remainingCallables) continue;
    add(methods, nameValue, callableRecord(module, method,
      `${name || '<anonymous>'}.${nameValue}`, method.static ? 'static_method' : 'class_method'));
    retained += 1;
  }
  const line = node?.loc?.start?.line ?? 0;
  const offset = Number.isInteger(node?.start) ? node.start : line;
  return {
    id: `${module.path}#class:${name || '<anonymous>'}:${offset}`,
    module,
    node,
    name: name || '<anonymous>',
    kind: 'class',
    methods,
    discoveredMethods: discovered,
    retainedMethods: retained,
  };
}

function sourceResolution(module, source, predicate = () => true) {
  const matches = module.imports.filter((item) => item.source === source && predicate(item));
  const identities = new Map();
  for (const match of matches) {
    const key = `${match.resolution?.path || ''}\u0000${match.resolution?.reason || ''}`;
    identities.set(key, match.resolution || null);
  }
  if (identities.size !== 1) return { path: null, reason: 'module_resolution_ambiguous' };
  return [...identities.values()][0];
}

function directImports(module) {
  const imports = new Map();
  for (const item of module.imports) {
    for (const binding of item.bindings) {
      if (!binding.local || ![
        'ImportSpecifier', 'ImportDefaultSpecifier', 'ImportNamespaceSpecifier',
        'CommonJSNamed', 'CommonJSDefault',
      ].includes(binding.kind)) continue;
      add(imports, binding.local, {
        source: item.source,
        imported: binding.imported,
        resolvedPath: item.resolution?.path || null,
        resolutionReason: item.resolution?.reason || null,
        kind: binding.kind,
      });
    }
  }
  return imports;
}

function collectExports(module) {
  const exports = new Map();
  const stars = [];
  for (const raw of module.ast?.body || []) {
    if (raw.type === 'ExportNamedDeclaration' && raw.exportKind === 'type') continue;
    if (raw.type === 'ExportAllDeclaration') {
      const source = literalString(raw.source);
      const resolution = sourceResolution(module, source,
        (item) => item.bindings.length === 0);
      stars.push({ kind: 'star', source, resolvedPath: resolution?.path || null,
        resolutionReason: resolution?.reason || null });
      continue;
    }
    if (raw.type === 'ExportDefaultDeclaration') {
      const declaration = raw.declaration;
      if (declaration?.type === 'Identifier') add(exports, 'default', {
        kind: 'local', local: declaration.name,
      });
      else if (declaration?.type === 'FunctionDeclaration' && declaration.id?.name) {
        add(exports, 'default', { kind: 'local', local: declaration.id.name });
      } else if (declaration?.type === 'ClassDeclaration' && declaration.id?.name) {
        add(exports, 'default', { kind: 'local', local: declaration.id.name });
      } else add(exports, 'default', { kind: 'expression', node: declaration, name: 'default' });
      continue;
    }
    if (raw.type !== 'ExportNamedDeclaration') continue;
    const declaration = raw.declaration;
    if (declaration?.id?.name) add(exports, declaration.id.name,
      { kind: 'local', local: declaration.id.name });
    for (const item of declaration?.declarations || []) {
      if (item.id?.type === 'Identifier') add(exports, item.id.name,
        { kind: 'local', local: item.id.name });
    }
    if (raw.source && raw.specifiers.length === 0) {
      const source = literalString(raw.source);
      const resolution = sourceResolution(module, source,
        (item) => item.bindings.length === 0);
      stars.push({ kind: 'star', source, resolvedPath: resolution?.path || null,
        resolutionReason: resolution?.reason || null });
      continue;
    }
    for (const specifier of raw.specifiers) {
      const exported = safeName(specifier.exported);
      const local = safeName(specifier.local);
      if (!exported || !local) continue;
      if (!raw.source) add(exports, exported, { kind: 'local', local });
      else {
        const source = literalString(raw.source);
        const resolution = sourceResolution(module, source, (item) => item.bindings.some((binding) =>
          binding.kind === 'ExportNamedReexport' && binding.local === exported
            && binding.imported === local));
        add(exports, exported, {
          kind: 'reexport', imported: local, source,
          resolvedPath: resolution?.path || null,
          resolutionReason: resolution?.reason || null,
        });
      }
    }
  }
  for (const item of module.exports || []) {
    if (!item.exported || item.typeOnly || exports.has(item.exported)) continue;
    if (item.local) add(exports, item.exported, { kind: 'local', local: item.local });
    else if (item.node) add(exports, item.exported,
      { kind: 'expression', node: item.node, name: item.exported });
  }
  return { exports, stars };
}

function collectModule(module, limits, counts, reasons) {
  const locals = new Map();
  const classes = new Map();
  const methodOwners = new Map();
  const instances = new Map();
  let symbols = 0;
  const recordSymbol = (name, value) => {
    symbols += 1;
    if (symbols > limits.maxSymbolsPerModule) return false;
    add(locals, name, value);
    return true;
  };
  for (const raw of module.ast?.body || []) {
    const node = ['ExportNamedDeclaration', 'ExportDefaultDeclaration'].includes(raw.type)
      ? raw.declaration : raw;
    if (node?.type === 'FunctionDeclaration' && node.id?.name) {
      if (counts.callables >= limits.maxCallables) {
        recordSymbol(node.id.name, { kind: 'unavailable' });
        reasons.push({ code: 'callable_index_callable_limit', path: module.path });
      } else {
        const callable = callableRecord(module, node, node.id.name);
        if (recordSymbol(node.id.name, { kind: 'callable', target: callable })) counts.callables += 1;
      }
    } else if (node?.type === 'ClassDeclaration' && node.id?.name) {
      const remaining = Math.max(0, limits.maxCallables - counts.callables);
      const klass = classRecord(module, node, node.id.name, remaining);
      if (recordSymbol(node.id.name, { kind: 'class', target: klass })) {
        add(classes, node.id.name, klass);
        counts.callables += klass.retainedMethods;
        if (klass.discoveredMethods > klass.retainedMethods) {
          reasons.push({ code: 'callable_index_callable_limit', path: module.path });
        }
        for (const values of klass.methods.values()) {
          for (const method of values) methodOwners.set(method.node, klass);
        }
      }
    } else if (node?.type === 'VariableDeclaration') {
      for (const declaration of node.declarations) {
        if (declaration.id?.type !== 'Identifier') continue;
        const init = unwrap(declaration.init);
        if (FUNCTION_TYPES.has(init?.type)) {
          if (counts.callables >= limits.maxCallables) {
            recordSymbol(declaration.id.name, { kind: 'unavailable' });
            reasons.push({ code: 'callable_index_callable_limit', path: module.path });
          } else if (recordSymbol(declaration.id.name, { kind: 'callable',
            target: callableRecord(module, init, declaration.id.name) })) counts.callables += 1;
        } else if (CALL_TYPES.has(init?.type) && counts.callables >= limits.maxCallables) {
          recordSymbol(declaration.id.name, { kind: 'unavailable' });
          reasons.push({ code: 'callable_index_callable_limit', path: module.path });
        } else {
          recordSymbol(declaration.id.name, { kind: 'variable', node: declaration, init });
          if (CALL_TYPES.has(init?.type)) counts.callables += 1;
        }
        if (init?.type === 'NewExpression') {
          add(instances, declaration.id.name, init);
        }
      }
    }
  }
  if (symbols > limits.maxSymbolsPerModule) {
    reasons.push({ code: 'callable_index_symbol_limit', path: module.path });
  }
  const exported = collectExports(module);
  return {
    module,
    locals,
    classes,
    methodOwners,
    instances,
    imports: directImports(module),
    exports: exported.exports,
    stars: exported.stars,
    limited: symbols > limits.maxSymbolsPerModule,
  };
}

export function buildJsTsCallableIndex(graph, options = {}) {
  const limits = {
    maxCallables: options.maxCallables ?? DEFAULT_LIMITS.maxCallables,
    maxSymbolsPerModule: options.maxSymbolsPerModule ?? DEFAULT_LIMITS.maxSymbolsPerModule,
    maxReexportDepth: options.maxReexportDepth ?? DEFAULT_LIMITS.maxReexportDepth,
    maxResolutionSteps: options.maxResolutionSteps ?? DEFAULT_LIMITS.maxResolutionSteps,
  };
  const counts = { modules: 0, callables: 0, imports: 0, exports: 0 };
  const reasons = [];
  const modules = new Map();
  for (const module of graph.modules.values()) {
    const indexed = collectModule(module, limits, counts, reasons);
    modules.set(module.path, indexed);
    counts.modules += 1;
    counts.imports += [...indexed.imports.values()].reduce((sum, values) => sum + values.length, 0);
    counts.exports += [...indexed.exports.values()].reduce((sum, values) => sum + values.length, 0)
      + indexed.stars.length;
  }
  return {
    graph,
    modules,
    limits,
    coverage: { status: reasons.length ? 'partial' : 'complete', reasons, counts },
  };
}

export function callableIndexForGraph(graph) {
  let index = INDEX_CACHE.get(graph);
  if (!index) {
    index = buildJsTsCallableIndex(graph);
    INDEX_CACHE.set(graph, index);
  }
  return index;
}

function exact(target, properties = {}) {
  return { state: 'exact', target, reexported: false, specialKind: null, ...properties };
}

function incomplete(reason, limitation = reason) {
  return { state: 'incomplete', reason, limitation };
}

function external() {
  return { state: 'external' };
}

function resolutionState(index) {
  return { steps: 0, exportStack: new Set(), localStack: new Set(), depth: 0,
    maxSteps: index.limits.maxResolutionSteps };
}

function advance(state) {
  state.steps += 1;
  return state.steps <= state.maxSteps;
}

function childState(state, changes = {}) {
  return {
    ...state,
    exportStack: new Set(state.exportStack),
    localStack: new Set(state.localStack),
    ...changes,
  };
}

function mergeExact(results, fallbackReason = 'call_target_unresolved') {
  const failures = results.filter((result) => result.state === 'incomplete');
  if (failures.length) return failures[0];
  const targets = new Map();
  for (const result of results.filter((item) => item.state === 'exact')) {
    targets.set(`${result.target.id}\u0000${result.specialKind || ''}`, result);
  }
  if (targets.size === 1) return [...targets.values()][0];
  if (targets.size > 1) return incomplete('call_target_ambiguous', 'callable_multiple_targets');
  if (results.some((result) => result.state === 'external')) return external();
  return incomplete(fallbackReason, 'callable_target_unresolved');
}

function resolveImport(index, indexed, binding, expected, state) {
  if (binding.kind === 'ImportNamespaceSpecifier' || binding.imported === '*') {
    return incomplete('dynamic_dispatch_unresolved', 'callable_namespace_import_unresolved');
  }
  if (binding.resolutionReason) {
    return incomplete(binding.resolutionReason.includes('ambiguous')
      ? 'call_target_ambiguous' : 'call_target_unresolved', binding.resolutionReason);
  }
  if (!binding.resolvedPath) return external();
  const result = resolveExport(index, binding.resolvedPath, binding.imported, expected,
    childState(state));
  if (result.state !== 'exact') return result;
  return { ...result, imported: true };
}

function exactReactCacheBinding(indexed, name) {
  const bindings = indexed.imports.get(name) || [];
  return bindings.length === 1 && bindings[0].source === 'react'
    && bindings[0].imported === 'cache' && bindings[0].kind === 'ImportSpecifier';
}

function resolveCache(index, indexed, node, expected, state) {
  const callee = unwrap(node.callee);
  if (callee?.type !== 'Identifier' || !exactReactCacheBinding(indexed, callee.name)) return null;
  if (expected !== 'callable' || node.arguments.length !== 1
      || node.arguments[0]?.type === 'SpreadElement') {
    return incomplete('call_target_unresolved', 'react_cache_callback_unresolved');
  }
  const callback = unwrap(node.arguments[0]);
  if (FUNCTION_TYPES.has(callback?.type)) {
    return exact(callableRecord(indexed.module, callback, '<cache-callback>', 'react_cache_callback'),
      { specialKind: 'react_cache_callback' });
  }
  if (callback?.type !== 'Identifier') {
    return incomplete('call_target_unresolved', 'react_cache_callback_unresolved');
  }
  const result = resolveLocal(index, indexed.module.path, callback.name, 'callable', childState(state),
    { allowWrapper: false });
  if (result.state !== 'exact' || result.target.module.path !== indexed.module.path
      || result.imported || result.reexported) {
    return incomplete('call_target_unresolved', 'react_cache_callback_not_local');
  }
  return { ...result, specialKind: 'react_cache_callback' };
}

function propertyHandlerCandidates(index, indexed, object, state) {
  const candidates = [];
  let unresolved = false;
  for (const property of object.properties || []) {
    if (property.type === 'SpreadElement') {
      unresolved = true;
      continue;
    }
    const name = property.computed ? null : safeName(property.key);
    if (name !== 'handler') continue;
    const value = property.type === 'ObjectMethod' ? property : property.value;
    const result = resolveExpression(index, indexed, value, 'callable', childState(state),
      { allowWrapper: false });
    if (result.state === 'exact') candidates.push(result);
    else unresolved = true;
  }
  return { candidates, unresolved };
}

function resolveWrapper(index, indexed, node, expected, state) {
  if (expected !== 'callable') return null;
  const wrapper = resolveCallTarget(index, indexed.module, null, node, childState(state),
    { allowSpecialBindings: false });
  if (!wrapper || wrapper.state !== 'exact' || wrapper.target.module.path === indexed.module.path
      && wrapper.target.node === node) return null;
  const candidates = [];
  let unresolved = false;
  for (const raw of node.arguments || []) {
    if (raw.type === 'SpreadElement') {
      unresolved = true;
      continue;
    }
    const argument = unwrap(raw);
    if (argument?.type === 'ObjectExpression') {
      const handlers = propertyHandlerCandidates(index, indexed, argument, state);
      candidates.push(...handlers.candidates);
      unresolved ||= handlers.unresolved;
      continue;
    }
    if (!FUNCTION_TYPES.has(argument?.type) && argument?.type !== 'Identifier') continue;
    const result = resolveExpression(index, indexed, argument, 'callable', childState(state),
      { allowWrapper: false });
    if (result.state === 'exact') candidates.push(result);
    else unresolved = true;
  }
  const unique = new Map(candidates.map((result) => [result.target.id, result]));
  if (unresolved || unique.size !== 1) {
    return incomplete('wrapper_handler_unresolved', unique.size > 1
      ? 'wrapper_handler_ambiguous' : 'wrapper_handler_unresolved');
  }
  const result = [...unique.values()][0];
  return { ...result, specialKind: 'wrapper_handler', wrapper: wrapper.target };
}

function resolveExpression(index, indexed, raw, expected, state, options = {}) {
  if (!advance(state)) return incomplete('call_target_unresolved', 'callable_resolution_step_limit');
  const node = unwrap(raw);
  if (!node) return incomplete('call_target_unresolved', 'callable_target_unresolved');
  if (expected === 'callable' && FUNCTION_TYPES.has(node.type)) {
    return exact(callableRecord(indexed.module, node, '<inline>'));
  }
  if (expected === 'class' && (node.type === 'ClassDeclaration' || node.type === 'ClassExpression')) {
    return exact(classRecord(indexed.module, node, node.id?.name || '<anonymous>'));
  }
  if (node.type === 'Identifier') {
    return resolveLocal(index, indexed.module.path, node.name, expected, state, options);
  }
  if (CALL_TYPES.has(node.type)) {
    if (options.allowSpecialBindings !== false) {
      const cached = resolveCache(index, indexed, node, expected, state);
      if (cached) return cached;
    }
    if (options.allowWrapper) {
      const wrapped = resolveWrapper(index, indexed, node, expected, state);
      if (wrapped) return wrapped;
    }
  }
  return incomplete('call_target_unresolved', 'callable_expression_unresolved');
}

function resolveLocal(index, modulePath, name, expected, state, options = {}) {
  if (!advance(state)) return incomplete('call_target_unresolved', 'callable_resolution_step_limit');
  const indexed = index.modules.get(modulePath);
  if (!indexed || indexed.limited) {
    return incomplete('call_target_unresolved', indexed?.limited
      ? 'callable_index_module_incomplete' : 'callable_module_unresolved');
  }
  const key = `${modulePath}\u0000${name}\u0000${expected}`;
  if (state.localStack.has(key)) return incomplete('call_target_unresolved', 'callable_local_cycle');
  const next = childState(state);
  next.localStack.add(key);
  const locals = indexed.locals.get(name) || [];
  const imports = indexed.imports.get(name) || [];
  if (locals.length + imports.length > 1) {
    return incomplete('call_target_ambiguous', 'callable_binding_ambiguous');
  }
  if (locals.length === 1) {
    const local = locals[0];
    if (expected === 'class') return local.kind === 'class' ? exact(local.target)
      : incomplete('call_target_unresolved', 'callable_class_unresolved');
    if (local.kind === 'callable') return exact(local.target);
    if (local.kind === 'variable') return resolveExpression(index, indexed, local.init, expected,
      next, { allowWrapper: options.allowWrapper !== false });
    if (local.kind === 'unavailable') {
      return incomplete('call_target_unresolved', 'callable_index_callable_limit');
    }
    return incomplete('call_target_unresolved', 'callable_target_unresolved');
  }
  if (imports.length === 1) return resolveImport(index, indexed, imports[0], expected, next);
  return incomplete('call_target_unresolved', 'callable_target_unresolved');
}

function resolveExport(index, modulePath, exported, expected, state) {
  if (!advance(state)) return incomplete('reexport_unresolved', 'callable_resolution_step_limit');
  const indexed = index.modules.get(modulePath);
  if (!indexed || indexed.limited) {
    return incomplete('reexport_unresolved', indexed?.limited
      ? 'callable_index_module_incomplete' : 'callable_module_unresolved');
  }
  const key = `${modulePath}\u0000${exported}\u0000${expected}`;
  if (state.exportStack.has(key)) return incomplete('reexport_unresolved', 'callable_reexport_cycle');
  if (state.depth > index.limits.maxReexportDepth) {
    return incomplete('reexport_unresolved', 'callable_reexport_depth_limit');
  }
  const next = childState(state, { depth: state.depth + 1 });
  next.exportStack.add(key);
  const descriptors = [...(indexed.exports.get(exported) || [])];
  if (exported !== 'default') descriptors.push(...indexed.stars);
  if (!descriptors.length) return incomplete('call_target_unresolved', 'callable_export_unresolved');
  const results = descriptors.map((descriptor) => {
    if (descriptor.kind === 'local') {
      return resolveLocal(index, modulePath, descriptor.local, expected, childState(next),
        { allowWrapper: true });
    }
    if (descriptor.kind === 'expression') {
      return resolveExpression(index, indexed, descriptor.node, expected, childState(next),
        { allowWrapper: true });
    }
    if (descriptor.resolutionReason) {
      return incomplete(descriptor.resolutionReason.includes('ambiguous')
        ? 'call_target_ambiguous' : 'reexport_unresolved', descriptor.resolutionReason);
    }
    if (!descriptor.resolvedPath) return external();
    const imported = descriptor.kind === 'star' ? exported : descriptor.imported;
    const result = resolveExport(index, descriptor.resolvedPath, imported, expected,
      childState(next));
    return result.state === 'exact' ? { ...result, reexported: true } : result;
  });
  return mergeExact(results, 'call_target_unresolved');
}

export function resolveCallableExport(index, modulePath, exported) {
  return resolveExport(index, modulePath, exported, 'callable', resolutionState(index));
}

function containingClass(indexed, handler) {
  return indexed.methodOwners.get(handler) || null;
}

function typeName(parameter) {
  const target = parameter?.typeAnnotation?.typeAnnotation;
  return target?.type === 'TSTypeReference' ? safeName(target.typeName) : null;
}

function resolveClassReference(index, indexed, name, state) {
  return resolveLocal(index, indexed.module.path, name, 'class', state, { allowWrapper: false });
}

function exactMethod(klass, name, staticOnly = null) {
  const candidates = (klass.methods.get(name) || []).filter((method) =>
    staticOnly === null || (staticOnly ? method.kind === 'static_method' : method.kind !== 'static_method'));
  if (candidates.length === 1) return exact(candidates[0]);
  return candidates.length > 1
    ? incomplete('call_target_ambiguous', 'callable_method_ambiguous')
    : incomplete('call_target_unresolved', 'callable_method_unresolved');
}

function nestService(index, indexed, handler, property, state) {
  const owner = containingClass(indexed, handler);
  const constructor = owner?.node?.body?.body?.find((node) => node.type === 'ClassMethod'
    && node.kind === 'constructor');
  const matches = [];
  for (const raw of constructor?.params || []) {
    const parameter = raw.type === 'TSParameterProperty' ? raw.parameter : raw;
    if (parameter?.type !== 'Identifier' || parameter.name !== property) continue;
    const importedType = typeName(parameter);
    if (!importedType || importedType.includes('.')) continue;
    const resolved = resolveClassReference(index, indexed, importedType, childState(state));
    if (resolved.state === 'exact') matches.push(resolved.target);
  }
  const unique = new Map(matches.map((klass) => [klass.id, klass]));
  if (unique.size === 1) return exact([...unique.values()][0]);
  if (unique.size > 1) return incomplete('call_target_ambiguous', 'nest_service_type_ambiguous');
  return null;
}

function resolveMemberCall(index, indexed, handler, callee, state) {
  if (callee.computed) return incomplete('dynamic_dispatch_unresolved', 'computed_call_property');
  const methodName = safeName(callee.property);
  if (!methodName) return incomplete('dynamic_dispatch_unresolved', 'dynamic_call_property');
  const object = unwrap(callee.object);
  if (CALL_TYPES.has(object?.type) || ['MemberExpression', 'OptionalMemberExpression'].includes(object?.type)
      && object.computed) {
    return incomplete('dynamic_dispatch_unresolved', 'runtime_container_lookup_unresolved');
  }
  if (object?.type === 'ThisExpression') {
    const owner = containingClass(indexed, handler);
    return owner ? exactMethod(owner, methodName, false) : null;
  }
  if (object?.type === 'MemberExpression' && !object.computed
      && object.object?.type === 'ThisExpression' && object.property?.type === 'Identifier') {
    const service = nestService(index, indexed, handler, object.property.name, childState(state));
    if (!service) return null;
    if (service.state !== 'exact') return service;
    const method = exactMethod(service.target, methodName, false);
    return method.state === 'exact' ? { ...method, specialKind: 'nest_injected_service' } : method;
  }
  if (object?.type !== 'Identifier') return null;
  const instances = indexed.instances.get(object.name) || [];
  if (instances.length > 1) return incomplete('call_target_ambiguous', 'callable_instance_ambiguous');
  if (instances.length === 1) {
    const className = safeName(instances[0].callee);
    if (!className || className.includes('.')) {
      return incomplete('dynamic_dispatch_unresolved', 'callable_instance_class_unresolved');
    }
    const klass = resolveClassReference(index, indexed, className, childState(state));
    if (klass.state !== 'exact') return klass;
    const method = exactMethod(klass.target, methodName, false);
    return method.state === 'exact' ? { ...method, specialKind: 'class_method' } : method;
  }
  const klass = resolveClassReference(index, indexed, object.name, childState(state));
  if (klass.state === 'exact') {
    const method = exactMethod(klass.target, methodName, true);
    return method.state === 'exact' ? { ...method, specialKind: 'static_member' } : method;
  }
  if (klass.reason === 'call_target_ambiguous') return klass;
  const imported = indexed.imports.get(object.name) || [];
  if (imported.length === 1 && (!imported[0].resolvedPath || imported[0].imported === '*')) return null;
  return null;
}

function resolveCallTarget(index, module, handler, call, state, options = {}) {
  if (!CALL_TYPES.has(call?.type)) return null;
  const indexed = index.modules.get(module.path);
  if (!indexed || indexed.limited) {
    return incomplete('call_target_unresolved', 'callable_index_module_incomplete');
  }
  const callee = unwrap(call.callee);
  if (callee?.type === 'Identifier') {
    const result = resolveLocal(index, module.path, callee.name, 'callable', state,
      { allowWrapper: options.allowSpecialBindings !== false });
    if (result.state === 'external') return null;
    if (result.state === 'exact' && result.target.node === handler) return null;
    if (result.state !== 'exact') return result;
    const edgeKind = result.specialKind || (result.reexported ? 'local_reexport'
      : result.imported ? 'local_import' : 'local_function');
    return { ...result, edgeKind };
  }
  if (['MemberExpression', 'OptionalMemberExpression'].includes(callee?.type)) {
    const result = resolveMemberCall(index, indexed, handler, callee, state);
    if (result?.state !== 'exact') return result;
    return { ...result, edgeKind: result.specialKind || 'class_method' };
  }
  return incomplete('dynamic_dispatch_unresolved', 'dynamic_call_target');
}

export function resolveCallableCall(index, module, handler, call) {
  return resolveCallTarget(index, module, handler, call, resolutionState(index));
}

export { DEFAULT_LIMITS as JS_TS_CALLABLE_INDEX_LIMITS };
