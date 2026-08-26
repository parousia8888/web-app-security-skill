import { routeRecord } from '../route-security-model.mjs';
import { signalForPrimitive, signalsForRole, unclassifiedSignals } from '../route-control-registry.mjs';
import { prioritizeRoute } from '../route-security-priority.mjs';
import {
  aggregateReasons, callName, controlFromSignals, expressionName, functionName,
  importedBindings, joinRoutePath, literalString, localModuleExport, objectAddressedPath,
  pathKind, routeScopeFromSignals, sourceLocation, structuralGraphReasons, walkJsTsAst,
} from './route-extractor-helpers.mjs';

const METHODS = new Map([
  ['get', 'GET'], ['post', 'POST'], ['put', 'PUT'], ['patch', 'PATCH'], ['delete', 'DELETE'],
  ['options', 'OPTIONS'], ['head', 'HEAD'], ['all', 'ALL'],
]);

function requiredSource(node) {
  return node?.type === 'CallExpression' && expressionName(node.callee) === 'require'
    && node.arguments.length === 1 ? literalString(node.arguments[0]) : null;
}

function directExpressFactory(node) {
  if (node?.type !== 'CallExpression') return null;
  if (requiredSource(node.callee) === 'express') return 'app';
  if (node.callee?.type !== 'MemberExpression'
      || requiredSource(node.callee.object) !== 'express') return null;
  return expressionName(node.callee.property) === 'Router' ? 'router' : null;
}

function receiverFactories(module) {
  const imports = importedBindings(module);
  const receivers = new Map();
  const aliases = [];
  walkJsTsAst(module.ast, (node) => {
    if (node.type !== 'VariableDeclarator' || node.id?.type !== 'Identifier') return;
    if (node.init?.type !== 'CallExpression') {
      aliases.push({ local: node.id.name, target: expressionName(node.init) });
      return;
    }
    const name = callName(node.init);
    const directFactory = directExpressFactory(node.init);
    if (directFactory) {
      receivers.set(node.id.name, directFactory);
      return;
    }
    if (!name) return;
    const root = name.split('.')[0];
    const binding = imports.get(root);
    if (binding?.source !== 'express') return;
    const factory = name.includes('.') ? name.split('.').at(-1) : binding.imported;
    if (factory === 'default' || factory === '*' || factory === 'express') receivers.set(node.id.name, 'app');
    if (factory === 'Router') receivers.set(node.id.name, 'router');
  });
  for (let pass = 0; pass < 4; pass += 1) {
    let changed = false;
    for (const alias of aliases) {
      if (!receivers.has(alias.local) && receivers.has(alias.target)) {
        receivers.set(alias.local, receivers.get(alias.target));
        changed = true;
      }
    }
    if (!changed) break;
  }
  return { imports, receivers };
}

function staticStringBindings(module) {
  const bindings = new Map();
  const declarations = [];
  walkJsTsAst(module.ast, (node) => {
    if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier') {
      declarations.push({ name: node.id.name, value: node.init });
    }
  });
  for (let pass = 0; pass < 4; pass += 1) {
    let changed = false;
    for (const declaration of declarations) {
      const literal = literalString(declaration.value);
      const alias = expressionName(declaration.value);
      const value = literal !== null ? literal : bindings.get(alias);
      if (value !== undefined && bindings.get(declaration.name) !== value) {
        bindings.set(declaration.name, value);
        changed = true;
      }
    }
    if (!changed) break;
  }
  return bindings;
}

function middlewareSignal(module, imports, node) {
  const name = expressionName(node?.callee || node);
  if (!name) {
    const required = requiredSource(node?.callee);
    return required ? { kind: 'custom-middleware-candidate', origin: `require(${required})`,
      location: sourceLocation(module.path, node), exact: false, role: 'unknown' } : null;
  }
  const root = name.split('.')[0];
  const binding = imports.get(root);
  let imported = binding?.imported;
  if (name.includes('.')) imported = name.split('.').slice(1).join('.');
  const key = binding ? `${binding.source}:${imported}` : null;
  const exact = key ? signalForPrimitive(binding.source, imported, sourceLocation(module.path, node)) : null;
  return exact || { kind: 'custom-middleware-candidate', origin: name,
    location: sourceLocation(module.path, node), exact: false, role: 'unknown' };
}

function mountTarget(module, imports, receivers, node, graph) {
  function resolvedReceiver(path, exportedLocal) {
    const targetModule = graph.modules.get(path);
    if (!targetModule?.ast || !exportedLocal) return null;
    return receiverFactories(targetModule).receivers.has(exportedLocal)
      ? `${path}::${exportedLocal}` : null;
  }
  const required = requiredSource(node);
  if (required) {
    const imported = module.imports.find((item) => item.source === required
      && item.resolution?.path && !item.resolution.reason);
    if (!imported) return null;
    const exportedLocal = localModuleExport(graph, imported.resolution.path, 'default');
    return resolvedReceiver(imported.resolution.path, exportedLocal);
  }
  const name = expressionName(node);
  if (!name) return null;
  if (receivers.has(name)) return `${module.path}::${name}`;
  const binding = imports.get(name);
  if (!binding?.resolvedPath || binding.resolutionReason) return null;
  const exportedLocal = localModuleExport(graph, binding.resolvedPath, binding.imported);
  return resolvedReceiver(binding.resolvedPath, exportedLocal);
}

function receiverRoot(node) {
  let current = node;
  while (current && ['MemberExpression', 'OptionalMemberExpression'].includes(current.type)) {
    current = current.object;
  }
  return expressionName(current);
}

function localFunctionNode(graph, path, name) {
  const target = graph.modules.get(path);
  if (!target?.ast || !name) return null;
  let found = null;
  walkJsTsAst(target.ast, (node) => {
    if (found) return;
    if (node.type === 'FunctionDeclaration' && node.id?.name === name) found = node;
    if (node.type === 'VariableDeclarator' && node.id?.name === name
        && ['FunctionExpression', 'ArrowFunctionExpression'].includes(node.init?.type)) found = node.init;
  });
  return found;
}

function registrationFunctionReason(module, imports, receivers, node, graph) {
  if (node.type !== 'CallExpression') return null;
  const called = expressionName(node.callee);
  if (!called) return null;
  const root = called.split('.')[0];
  const binding = imports.get(root);
  if (!binding?.resolvedPath || binding.resolutionReason || binding.source === 'express') return null;
  const receiverIndex = node.arguments.findIndex((argument) => receivers.has(expressionName(argument)));
  if (receiverIndex < 0) return null;
  const exported = localModuleExport(graph, binding.resolvedPath,
    called.includes('.') ? called.split('.').slice(1).join('.') : binding.imported);
  const target = localFunctionNode(graph, binding.resolvedPath, exported);
  const parameter = target?.params?.[receiverIndex];
  if (parameter?.type !== 'Identifier') return null;
  let routeReceiverObserved = false;
  walkJsTsAst(target.body, (candidate) => {
    if (candidate.type !== 'CallExpression' || candidate.callee?.type !== 'MemberExpression') return;
    const receiver = expressionName(candidate.callee.object);
    const method = expressionName(candidate.callee.property);
    if (receiver === parameter.name && (METHODS.has(method) || method === 'use')) {
      routeReceiverObserved = true;
    }
  });
  return routeReceiverObserved
    ? { code: 'express_registration_function_unresolved', path: module.path } : null;
}

function routeChainBase(node) {
  let current = node;
  while (current?.type === 'CallExpression' && current.callee?.type === 'MemberExpression') {
    if (expressionName(current.callee.property) === 'route') {
      return { receiver: expressionName(current.callee.object), pathNode: current.arguments[0] };
    }
    current = current.callee.object;
  }
  return null;
}

function moduleFacts(module, graph) {
  const { imports, receivers } = receiverFactories(module);
  const staticStrings = staticStringBindings(module);
  const routes = [];
  const mounts = [];
  const middleware = [];
  const reasons = [];
  walkJsTsAst(module.ast, (node) => {
    const registrationReason = registrationFunctionReason(module, imports, receivers, node, graph);
    if (registrationReason) reasons.push(registrationReason);
    if (!['CallExpression', 'OptionalCallExpression'].includes(node.type)
        || !['MemberExpression', 'OptionalMemberExpression'].includes(node.callee?.type)) return;
    const computedLiteral = node.callee.computed
      ? literalString(node.callee.property) ?? staticStrings.get(expressionName(node.callee.property))
      : null;
    const property = node.callee.computed ? computedLiteral : expressionName(node.callee.property);
    const receiver = expressionName(node.callee.object);
    const knownReceiver = receiver && receivers.has(receiver);
    const relatedReceiver = receiverRoot(node.callee.object);
    if ((node.optional || node.callee.optional) && (knownReceiver || receivers.has(relatedReceiver))) {
      reasons.push({ code: 'express_optional_route_registration', path: module.path });
      return;
    }
    if (node.callee.computed && knownReceiver && property === undefined) {
      reasons.push({ code: 'express_computed_route_method_unresolved', path: module.path });
      return;
    }
    if (!knownReceiver && receivers.has(relatedReceiver) && (METHODS.has(property) || property === 'use')) {
      reasons.push({ code: 'express_route_receiver_unresolved', path: module.path });
      return;
    }
    if (property === 'use' && receiver && receivers.has(receiver)) {
      const staticPrefix = literalString(node.arguments[0]);
      const offset = staticPrefix !== null ? 1 : 0;
      const argumentsToClassify = node.arguments.slice(offset);
      const targets = [];
      for (const [index, argument] of argumentsToClassify.entries()) {
        if (argument?.type === 'ArrayExpression') {
          reasons.push({ code: 'express_middleware_array_unresolved', path: module.path });
          continue;
        }
        const target = mountTarget(module, imports, receivers, argument, graph);
        if (target) {
          targets.push({ target, index });
          continue;
        }
        const possibleBinding = imports.get(expressionName(argument));
        if (possibleBinding?.resolutionReason) {
          reasons.push({ code: 'express_router_mount_resolution_incomplete', path: module.path });
        }
        const signal = middlewareSignal(module, imports, argument);
        if (signal) middleware.push({ receiver: `${module.path}::${receiver}`, signal,
          order: (node.start || 0) + index / 100 });
      }
      if (targets.length === 1) {
        mounts.push({ parent: `${module.path}::${receiver}`, target: targets[0].target,
          prefix: staticPrefix || '', order: (node.start || 0) + targets[0].index / 100 });
      } else if (targets.length > 1) {
        reasons.push({ code: 'express_router_mount_ambiguous', path: module.path });
      }
      return;
    }
    const method = METHODS.get(property);
    if (!method) {
      if (node.callee.computed && knownReceiver) {
        reasons.push({ code: 'express_computed_route_method_unsupported', path: module.path });
      }
      return;
    }
    let routeReceiver = receiver;
    let pathNode = node.arguments[0];
    let handlerArgs = node.arguments.slice(1);
    const chain = routeChainBase(node.callee.object);
    if (chain) {
      routeReceiver = chain.receiver;
      pathNode = chain.pathNode;
      handlerArgs = node.arguments;
    }
    if (!routeReceiver || !receivers.has(routeReceiver)) return;
    const staticPath = literalString(pathNode);
    if (staticPath === null) reasons.push({ code: 'express_dynamic_route_path', path: module.path });
    const handler = handlerArgs.at(-1);
    const signals = handlerArgs.slice(0, -1).map((item) => middlewareSignal(module, imports, item)).filter(Boolean);
    routes.push({ modulePath: module.path, receiver: `${module.path}::${routeReceiver}`,
      receiverKind: receivers.get(routeReceiver), method, path: staticPath, dynamic: staticPath === null,
      handler: functionName(handler), node, order: node.start || 0, signals });
  });
  return { routes, mounts, middleware, reasons, applicable: receivers.size > 0 };
}

function ancestorContexts(route, mounts, middleware, maxDepth = 12) {
  const contexts = [{ receiver: route.receiver, prefixes: [], inherited: [], depth: 0 }];
  const output = [];
  const seen = new Set();
  while (contexts.length) {
    const context = contexts.pop();
    const key = `${context.receiver}\u0000${context.prefixes.join('/')}`;
    if (seen.has(key) || context.depth > maxDepth) continue;
    seen.add(key);
    const localMiddleware = middleware.filter((item) => item.receiver === context.receiver
      && (context.depth > 0 || item.order < route.order)).map((item) => item.signal);
    const parents = mounts.filter((mount) => mount.target === context.receiver);
    if (!parents.length) output.push({ ...context, inherited: [...context.inherited, ...localMiddleware] });
    for (const parent of parents) {
      const parentMiddleware = middleware.filter((item) => item.receiver === parent.parent
        && item.order < parent.order).map((item) => item.signal);
      contexts.push({ receiver: parent.parent, prefixes: [parent.prefix, ...context.prefixes],
        inherited: [...context.inherited, ...localMiddleware, ...parentMiddleware], depth: context.depth + 1 });
    }
  }
  return output;
}

export function extractExpressRoutes(graph) {
  const facts = [...graph.modules.values()].filter((module) => module.ast).map((module) => moduleFacts(module, graph));
  const localRoutes = facts.flatMap((item) => item.routes);
  const mounts = facts.flatMap((item) => item.mounts);
  const middleware = facts.flatMap((item) => item.middleware);
  const reasons = [...structuralGraphReasons(graph), ...facts.flatMap((item) => item.reasons)];
  const routes = [];
  for (const route of localRoutes) {
    const contexts = ancestorContexts(route, mounts, middleware);
    const usable = contexts.length ? contexts : [{ prefixes: [], inherited: [] }];
    for (const context of usable) {
      const fullPath = route.dynamic ? null : joinRoutePath(...context.prefixes, route.path);
      const inherited = context.inherited;
      const localAuthn = signalsForRole(route.signals, 'authentication');
      const inheritedAuthn = signalsForRole(inherited, 'authentication');
      const localAuthz = signalsForRole(route.signals, 'authorization');
      const inheritedAuthz = signalsForRole(inherited, 'authorization');
      const authentication = localAuthn.some((item) => item.exact) ? controlFromSignals(localAuthn)
        : inheritedAuthn.some((item) => item.exact) ? controlFromSignals(inheritedAuthn, true)
          : localAuthn.length ? controlFromSignals(localAuthn)
            : inheritedAuthn.length ? controlFromSignals(inheritedAuthn, true) : controlFromSignals([]);
      const authorization = localAuthz.some((item) => item.exact)
        ? controlFromSignals(localAuthz, false, 'authorization')
        : inheritedAuthz.some((item) => item.exact)
          ? controlFromSignals(inheritedAuthz, true, 'authorization')
          : localAuthz.length ? controlFromSignals(localAuthz, false, 'authorization')
            : inheritedAuthz.length ? controlFromSignals(inheritedAuthz, true, 'authorization')
              : controlFromSignals([], false, 'authorization');
      const scopedSignals = [...route.signals, ...inherited];
      const routeScopedControl = routeScopeFromSignals(
        scopedSignals.filter((item) => item.role !== 'unknown'), unclassifiedSignals(scopedSignals),
      );
      const limitations = [];
      if (route.dynamic) limitations.push('dynamic-route-path');
      if (route.receiverKind === 'router' && !mounts.some((item) => item.target === route.receiver)) {
        limitations.push('router-mount-unresolved');
        reasons.push({ code: 'express_router_mount_unresolved', path: route.modulePath });
      }
      routes.push(prioritizeRoute(routeRecord({
        framework: 'express', method: route.method, path: fullPath,
        pathKind: pathKind(fullPath, route.dynamic), location: sourceLocation(route.modulePath, route.node),
        handler: route.handler, objectAddressed: objectAddressedPath(fullPath), authentication,
        authorization, routeScopedControl, limitations,
      })));
    }
  }
  const eligible = facts.filter((item) => item.applicable || item.routes.length
    || item.mounts.length || item.middleware.length).length;
  const frameworkReasons = reasons.filter((item) => item.path && graph.modules.has(item.path));
  return {
    routes,
    coverage: {
      framework: 'express', status: frameworkReasons.length ? 'partial' : eligible ? 'completed' : 'not_applicable',
      counts: { discovered: graph.modules.size, eligible, parsed: eligible, incomplete: new Set(frameworkReasons.map((item) => item.path)).size },
      reasons: aggregateReasons(frameworkReasons),
    },
  };
}
