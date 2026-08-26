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
    const imported = name.includes('.') && binding
      ? `${binding.imported}.${name.split('.').slice(1).join('.')}` : binding?.imported;
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

function applicationModule(modulePath) {
  const match = /(?:^|\/)(middleware|proxy)\.[cm]?[jt]sx?$/.exec(modulePath);
  return match?.[1] || null;
}

function propertyName(node) {
  if (node?.type !== 'ObjectProperty') return null;
  return expressionName(node.key) || (node.key?.type === 'StringLiteral' ? node.key.value : null);
}

function staticMatcher(module) {
  let config = null;
  for (const raw of module.ast?.body || []) {
    const declaration = raw.type === 'ExportNamedDeclaration' ? raw.declaration : null;
    for (const item of declaration?.declarations || []) {
      if (item.id?.type === 'Identifier' && item.id.name === 'config') config = item.init;
    }
  }
  if (!config) return { state: 'absent', values: [] };
  if (config.type !== 'ObjectExpression') return { state: 'unresolved', values: [] };
  const matcher = config.properties.find((property) => propertyName(property) === 'matcher');
  if (!matcher) return { state: 'absent', values: [] };
  if (matcher.value?.type === 'StringLiteral') return { state: 'static', values: [matcher.value.value] };
  if (matcher.value?.type === 'ArrayExpression'
      && matcher.value.elements.every((item) => item?.type === 'StringLiteral')) {
    return { state: 'static', values: matcher.value.elements.map((item) => item.value) };
  }
  return { state: 'unresolved', values: [] };
}

function nextApplicationContext(module) {
  const surface = applicationModule(module.path);
  if (!surface || !module.ast) return { controls: [], reasons: [], applicable: false };
  const imports = importedBindings(module);
  const signals = handlerSignals(module, module.ast, imports);
  for (const node of module.ast.body || []) {
    if (!node.source || node.source.value !== 'next-auth/middleware') continue;
    const signal = signalForPrimitive('next-auth/middleware', 'default', sourceLocation(module.path, node));
    if (signal) signals.push(signal);
  }
  const matcher = staticMatcher(module);
  const reasons = [];
  if (matcher.state === 'unresolved') {
    reasons.push({ code: 'next_middleware_matcher_unresolved', path: module.path });
  }
  const unique = signals.filter((signal, index, items) => items.findIndex((candidate) =>
    candidate.kind === signal.kind && candidate.location.line === signal.location.line) === index);
  if (!unique.length) {
    unique.push({ kind: `next-${surface}-candidate`, origin: surface,
      location: sourceLocation(module.path, module.ast), exact: false, role: 'unknown' });
    reasons.push({ code: 'next_application_control_unclassified', path: module.path });
  }
  const matcherText = matcher.state === 'static'
    ? ` Static matcher evidence: ${matcher.values.join(', ') || '(empty)'}.`
    : matcher.state === 'unresolved' ? ' The matcher shape was not statically resolved.'
      : ' No explicit static matcher was declared.';
  return {
    controls: unique.map((signal) => ({
      kind: signal.kind, origin: signal.origin, role: signal.role,
      location: signal.location,
      boundary: `A Next.js ${surface} application surface was observed.${matcherText} This is application context only; route applicability, denial behavior and runtime enforcement are not proved.`,
    })),
    reasons,
    applicable: true,
  };
}

export function extractNextAppRoutes(graph) {
  const routes = [];
  const applicationControls = [];
  const reasons = [...structuralGraphReasons(graph)];
  let eligible = 0;
  for (const module of graph.modules.values()) {
    const application = nextApplicationContext(module);
    if (application.applicable) {
      eligible += 1;
      applicationControls.push(...application.controls);
      reasons.push(...application.reasons);
    }
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
    applicationControls,
    coverage: { framework: 'next-app', status: frameworkReasons.length ? 'partial' : eligible ? 'completed' : 'not_applicable',
      counts: { discovered: graph.modules.size, eligible, parsed: eligible, incomplete: new Set(frameworkReasons.map((item) => item.path)).size },
      reasons: aggregateReasons(frameworkReasons) },
  };
}
