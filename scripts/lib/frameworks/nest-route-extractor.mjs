import { routeRecord } from '../route-security-model.mjs';
import { signalForPrimitive, signalsForRole, unclassifiedSignals } from '../route-control-registry.mjs';
import { prioritizeRoute } from '../route-security-priority.mjs';
import {
  aggregateReasons, controlFromSignals, expressionName, importedBindings, joinRoutePath,
  literalString, localModuleExport, objectAddressedPath, pathKind, routeScopeFromSignals,
  sourceLocation, structuralGraphReasons, walkJsTsAst,
} from './route-extractor-helpers.mjs';

const HTTP = new Map([
  ['Get', 'GET'], ['Post', 'POST'], ['Put', 'PUT'], ['Patch', 'PATCH'], ['Delete', 'DELETE'],
  ['Options', 'OPTIONS'], ['Head', 'HEAD'], ['All', 'ALL'],
]);

function decoratorCall(decorator) {
  return decorator?.expression?.type === 'CallExpression' ? decorator.expression : null;
}

function nestImported(imports, local, imported, source = '@nestjs/common') {
  const binding = imports.get(local);
  return binding?.source === source && binding.imported === imported;
}

function classDeclaration(module, name) {
  let found = null;
  walkJsTsAst(module?.ast, (node) => {
    if (!found && node.type === 'ClassDeclaration' && node.id?.name === name) found = node;
  });
  return found;
}

function variableValue(module, name) {
  let found = null;
  walkJsTsAst(module?.ast, (node) => {
    if (!found && node.type === 'VariableDeclarator' && expressionName(node.id) === name) found = node.init;
  });
  return found;
}

function resolvedLocalSymbol(graph, module, imports, name) {
  const direct = classDeclaration(module, name);
  if (direct) return { module, name, node: direct };
  const binding = imports.get(name);
  if (!binding?.resolvedPath || binding.resolutionReason) return null;
  const target = graph.modules.get(binding.resolvedPath);
  const local = localModuleExport(graph, binding.resolvedPath, binding.imported);
  const node = local ? classDeclaration(target, local) : null;
  return node ? { module: target, name: local, node } : null;
}

function staticString(graph, module, imports, node, depth = 0) {
  if (!node || depth > 2) return null;
  const literal = literalString(node);
  if (literal !== null) return literal;
  const name = expressionName(node);
  if (!name || name.includes('.')) return null;
  const local = variableValue(module, name);
  if (local) return staticString(graph, module, imports, local, depth + 1);
  const binding = imports.get(name);
  if (!binding?.resolvedPath || binding.resolutionReason) return null;
  const target = graph.modules.get(binding.resolvedPath);
  const exported = localModuleExport(graph, binding.resolvedPath, binding.imported);
  return exported ? staticString(graph, target, importedBindings(target),
    variableValue(target, exported), depth + 1) : null;
}

function structuralGuardRole(graph, module, imports, guardName, location) {
  const resolved = resolvedLocalSymbol(graph, module, imports, guardName);
  if (!resolved) return null;
  const targetImports = importedBindings(resolved.module);
  const superCall = resolved.node.superClass?.type === 'CallExpression' ? resolved.node.superClass : null;
  const superName = expressionName(superCall?.callee || resolved.node.superClass);
  const superBinding = targetImports.get(superName);
  const exactSuper = superBinding ? signalForPrimitive(
    superBinding.source, superBinding.imported, location,
  ) : null;
  if (exactSuper?.role === 'authentication') {
    return { ...exactSuper, kind: 'nest-passport-derived-auth-guard',
      origin: `${resolved.module.path}:${resolved.name}` };
  }

  let authorizationMetadata = null;
  walkJsTsAst(resolved.node, (node) => {
    if (authorizationMetadata || node.type !== 'CallExpression') return;
    const called = expressionName(node.callee) || '';
    if (!/\.(?:get|getAll|getAllAndMerge|getAllAndOverride)$/.test(called)) return;
    const key = staticString(graph, resolved.module, targetImports, node.arguments[0]);
    if (key && /(?:^|[-_.:])(role|roles|permission|permissions|ability|abilities|policy|policies|scope|scopes)(?:$|[-_.:])/i.test(`.${key}.`)) {
      authorizationMetadata = key;
    }
  });
  if (authorizationMetadata) {
    return { kind: 'nest-metadata-authorization-guard-candidate',
      origin: `${resolved.module.path}:${resolved.name}`, location,
      exact: false, role: 'authorization' };
  }
  return null;
}

function guardSignals(graph, module, imports, decorators) {
  const signals = [];
  for (const decorator of decorators || []) {
    const call = decoratorCall(decorator);
    const name = expressionName(call?.callee);
    if (!name || !nestImported(imports, name, 'UseGuards')) continue;
    for (const argument of call.arguments) {
      const guardCall = argument.type === 'CallExpression' ? argument : null;
      const guardName = expressionName(guardCall?.callee || argument);
      const binding = imports.get(guardName);
      const exact = binding ? signalForPrimitive(binding.source, binding.imported,
        sourceLocation(module.path, argument)) : null;
      const structural = guardName ? structuralGuardRole(
        graph, module, imports, guardName, sourceLocation(module.path, argument),
      ) : null;
      signals.push(exact || structural || { kind: 'nest-custom-guard-candidate',
        origin: guardName || 'anonymous-guard', location: sourceLocation(module.path, argument),
        exact: false, role: 'unknown' });
    }
  }
  return signals;
}

function publicSignals(module, imports, decorators) {
  const signals = [];
  for (const decorator of decorators || []) {
    const call = decoratorCall(decorator);
    const name = expressionName(call?.callee || decorator.expression);
    if (!name || !/(?:^|\.)Public$/.test(name)) continue;
    const binding = imports.get(name.split('.')[0]);
    signals.push({ kind: 'nest-public-override-candidate', origin: binding?.source || name,
      location: sourceLocation(module.path, decorator), exact: false, role: 'unknown' });
  }
  return signals;
}

function globalGuardSignals(graph, module, imports) {
  const signals = [];
  walkJsTsAst(module.ast, (node) => {
    if (node.type !== 'ObjectExpression') return;
    let provider = false;
    let guard = null;
    for (const property of node.properties) {
      if (property.type !== 'ObjectProperty') continue;
      const key = expressionName(property.key);
      if (key === 'provide' && expressionName(property.value)) {
        const value = expressionName(property.value);
        const binding = imports.get(value);
        provider = binding?.source === '@nestjs/core' && binding.imported === 'APP_GUARD';
      }
      if (['useClass', 'useFactory', 'useValue'].includes(key)) guard = expressionName(property.value);
    }
    if (provider) {
      const location = sourceLocation(module.path, node);
      const structural = guard ? structuralGuardRole(graph, module, imports, guard, location) : null;
      signals.push(structural ? { ...structural, kind: `nest-global-${structural.kind}` }
        : { kind: 'nest-global-guard-candidate', origin: guard || 'APP_GUARD',
          location, exact: false, role: 'unknown' });
    }
  });
  return signals;
}

function literalPaths(node) {
  const direct = literalString(node);
  if (direct !== null) return [direct];
  if (node?.type !== 'ArrayExpression') return null;
  const values = node.elements.map(literalString);
  return values.every((value) => value !== null) ? values : null;
}

function controllerPaths(argument) {
  if (!argument) return [''];
  const direct = literalPaths(argument);
  if (direct) return direct;
  if (argument.type !== 'ObjectExpression') return null;
  const property = argument.properties.find((item) => item.type === 'ObjectProperty'
    && !item.computed && expressionName(item.key) === 'path');
  return property ? literalPaths(property.value) : [''];
}

export function extractNestRoutes(graph) {
  const routes = [];
  const reasons = [...structuralGraphReasons(graph)];
  const globalSignals = [...graph.modules.values()].filter((module) => module.ast)
    .flatMap((module) => globalGuardSignals(graph, module, importedBindings(module)));
  let eligible = 0;
  for (const module of graph.modules.values()) {
    if (!module.ast) continue;
    const imports = importedBindings(module);
    walkJsTsAst(module.ast, (node) => {
      if (node.type !== 'ClassDeclaration') return;
      const controller = (node.decorators || []).map(decoratorCall).find((call) => {
        const name = expressionName(call?.callee);
        return name && nestImported(imports, name, 'Controller');
      });
      if (!controller) return;
      eligible += 1;
      const prefixes = controllerPaths(controller.arguments[0]);
      const dynamicController = prefixes === null;
      if (dynamicController) {
        reasons.push({ code: 'nest_dynamic_controller_path', path: module.path });
      }
      const classGuards = guardSignals(graph, module, imports, node.decorators);
      const classPublic = publicSignals(module, imports, node.decorators);
      for (const methodNode of node.body.body) {
        if (!['ClassMethod', 'ClassPrivateMethod'].includes(methodNode.type)) continue;
        for (const decorator of methodNode.decorators || []) {
          const call = decoratorCall(decorator);
          const local = expressionName(call?.callee);
          const binding = imports.get(local);
          const method = binding?.source === '@nestjs/common' ? HTTP.get(binding.imported) : null;
          if (!method) continue;
          const methodPaths = call.arguments.length ? literalPaths(call.arguments[0]) : [''];
          const dynamicMethod = methodPaths === null;
          const dynamic = dynamicController || dynamicMethod;
          if (dynamicMethod) reasons.push({ code: 'nest_dynamic_method_path', path: module.path });
          const methodGuards = guardSignals(graph, module, imports, methodNode.decorators);
          const publicOverrides = [...classPublic, ...publicSignals(module, imports, methodNode.decorators)];
          const select = (role) => {
            const localRole = signalsForRole(methodGuards, role);
            const inheritedRole = signalsForRole(classGuards, role);
            if (localRole.some((item) => item.exact)) return controlFromSignals(localRole, false, role);
            if (inheritedRole.some((item) => item.exact)) return controlFromSignals(inheritedRole, true, role);
            if (localRole.length) return controlFromSignals(localRole, false, role);
            if (inheritedRole.length) return controlFromSignals(inheritedRole, true, role);
            return controlFromSignals([], false, role);
          };
          const authentication = select('authentication');
          const authorization = select('authorization');
          const routeSignals = [...classGuards, ...methodGuards];
          const routeScopedControl = routeScopeFromSignals(
            routeSignals.filter((item) => item.role !== 'unknown'),
            [...unclassifiedSignals(routeSignals), ...publicOverrides],
          );
          const pathPairs = dynamic ? [[null, null]]
            : prefixes.flatMap((prefix) => methodPaths.map((methodPath) => [prefix, methodPath]));
          for (const [prefix, methodPath] of pathPairs) {
            const path = dynamic ? null : joinRoutePath(prefix, methodPath);
            routes.push(prioritizeRoute(routeRecord({ framework: 'nestjs', method, path,
              pathKind: pathKind(path, dynamic), location: sourceLocation(module.path, methodNode),
              handler: expressionName(methodNode.key), objectAddressed: objectAddressedPath(path),
              authentication, authorization, routeScopedControl,
              limitations: [dynamic ? 'dynamic-route-path' : null,
                publicOverrides.length ? 'public-override-requires-review' : null].filter(Boolean) })));
          }
        }
      }
    });
  }
  const frameworkReasons = reasons.filter((item) => item.path && graph.modules.has(item.path));
  return {
    routes,
    applicationControls: globalSignals,
    coverage: { framework: 'nestjs', status: frameworkReasons.length ? 'partial' : eligible ? 'completed' : 'not_applicable',
      counts: { discovered: graph.modules.size, eligible, parsed: eligible, incomplete: new Set(frameworkReasons.map((item) => item.path)).size },
      reasons: aggregateReasons(frameworkReasons) },
  };
}
