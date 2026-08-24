import { posix } from 'node:path';
import { routeRecord } from '../route-security-model.mjs';
import { signalForPrimitive, signalsForRole, unclassifiedSignals } from '../route-control-registry.mjs';
import { prioritizeRoute } from '../route-security-priority.mjs';
import {
  aggregateReasons, controlFromSignals, expressionName, importedBindings, objectAddressedPath,
  pathKind, routeScopeFromSignals, sourceLocation, structuralGraphReasons, walkJsTsAst,
} from './route-extractor-helpers.mjs';

const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']);

function nextRoutePath(modulePath) {
  const parts = modulePath.split('/');
  const routeIndex = parts.length - 1;
  if (!/^route\.[cm]?[jt]sx?$/.test(parts[routeIndex])) return null;
  const appIndex = parts.lastIndexOf('app', routeIndex - 1);
  const monorepoApp = appIndex >= 2 && ['apps', 'packages'].includes(parts[appIndex - 2]);
  if (appIndex < 0 || (appIndex > 0 && parts[appIndex - 1] !== 'src' && !monorepoApp)) return null;
  const segments = parts.slice(appIndex + 1, routeIndex);
  if (segments.some((segment) => segment.startsWith('_'))) {
    return { path: null, reason: 'next_private_route_segment' };
  }
  if (segments.some((segment) => /^\(\.\.?.*\)/.test(segment))) {
    return { path: null, reason: 'next_intercepting_route_unresolved' };
  }
  const visible = segments.filter((segment) => !(segment.startsWith('(') && segment.endsWith(')'))
    && !segment.startsWith('@'));
  return { path: `/${visible.join('/')}`.replace(/\/{2,}/g, '/') || '/', reason: null };
}

function exportedHandlers(module) {
  const declarations = new Map();
  const exported = [];
  for (const node of module.ast.body) {
    const declaration = node.type === 'ExportNamedDeclaration' ? node.declaration : node;
    if (declaration?.type === 'FunctionDeclaration' && declaration.id?.name) declarations.set(declaration.id.name, declaration);
    for (const item of declaration?.declarations || []) if (item.id?.type === 'Identifier') declarations.set(item.id.name, item.init);
    if (node.type !== 'ExportNamedDeclaration') continue;
    if (declaration?.type === 'FunctionDeclaration' && METHODS.has(declaration.id?.name)) {
      exported.push({ method: declaration.id.name, node: declaration });
    }
    for (const item of declaration?.declarations || []) {
      if (item.id?.type === 'Identifier' && METHODS.has(item.id.name)) exported.push({ method: item.id.name, node: item.init || item });
    }
    for (const specifier of node.specifiers || []) {
      const method = expressionName(specifier.exported);
      const local = expressionName(specifier.local);
      if (METHODS.has(method) && declarations.has(local)) exported.push({ method, node: declarations.get(local) });
    }
  }
  return exported;
}

function handlerSignals(module, handler, imports) {
  const signals = [];
  walkJsTsAst(handler, (node) => {
    if (node.type !== 'CallExpression') return;
    const name = expressionName(node.callee);
    if (!name) return;
    const root = name.split('.')[0];
    const binding = imports.get(root);
    const imported = name.includes('.') ? name.split('.').slice(1).join('.') : binding?.imported;
    const exact = binding ? signalForPrimitive(binding.source, imported,
      sourceLocation(module.path, node)) : null;
    if (exact) signals.push(exact);
    else if (/^(?:auth|getSession|requireAuth|currentUser)$/.test(name)) {
      signals.push({ kind: 'next-custom-auth-candidate', origin: name,
        location: sourceLocation(module.path, node), exact: false, role: 'unknown' });
    }
  });
  return signals;
}

export function extractNextAppRoutes(graph) {
  const routes = [];
  const reasons = [...structuralGraphReasons(graph)];
  let eligible = 0;
  for (const module of graph.modules.values()) {
    const routePath = nextRoutePath(module.path);
    if (!routePath) continue;
    eligible += 1;
    if (!module.ast) continue;
    if (routePath.reason) {
      reasons.push({ code: routePath.reason, path: module.path });
      continue;
    }
    const imports = importedBindings(module);
    const handlers = exportedHandlers(module);
    if (!handlers.length) reasons.push({ code: 'next_route_handler_export_unresolved', path: module.path });
    for (const handler of handlers) {
      const signals = handlerSignals(module, handler.node, imports);
      const authentication = controlFromSignals(signalsForRole(signals, 'authentication'));
      const authorization = controlFromSignals(signalsForRole(signals, 'authorization'), false, 'authorization');
      const routeScopedControl = routeScopeFromSignals(
        signals.filter((item) => item.role !== 'unknown'), unclassifiedSignals(signals),
      );
      routes.push(prioritizeRoute(routeRecord({ framework: 'next-app', method: handler.method, path: routePath.path,
        pathKind: pathKind(routePath.path), location: sourceLocation(module.path, handler.node),
        handler: handler.method, objectAddressed: objectAddressedPath(routePath.path),
        authentication, authorization, routeScopedControl })));
    }
  }
  const frameworkReasons = reasons.filter((item) => item.path && graph.modules.has(item.path));
  return {
    routes,
    coverage: { framework: 'next-app', status: frameworkReasons.length ? 'partial' : eligible ? 'completed' : 'not_applicable',
      counts: { discovered: graph.modules.size, eligible, parsed: eligible, incomplete: new Set(frameworkReasons.map((item) => item.path)).size },
      reasons: aggregateReasons(frameworkReasons) },
  };
}
