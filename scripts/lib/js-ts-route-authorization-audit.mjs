import { walkJsTsAst } from './js-ts-ast-parser.mjs';
import { expressionName } from './js-ts-module-graph.mjs';
import { analyzeAccessPaths, createAccessPathBudget } from './js-ts-access-path.mjs';
import { analyzeIdentityEvidence } from './js-ts-identity-evidence.mjs';
import { importedBindings } from './frameworks/route-extractor-helpers.mjs';
import { extractSelectorEvidence } from './js-ts-selector-evidence.mjs';
import { prioritizeRoute } from './route-security-priority.mjs';
import { accessChainRecord } from './route-security-model.mjs';

export const ROUTE_AUTHORIZATION_RULE_ID = 'js-route-object-authorization-review';

const FUNCTION_TYPES = new Set([
  'ArrowFunctionExpression', 'FunctionDeclaration', 'FunctionExpression', 'ClassMethod',
  'ClassPrivateMethod', 'ObjectMethod',
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

function declarations(module) {
  const values = new Map();
  const duplicates = new Set();
  walkJsTsAst(module.ast, (node, parent) => {
    let name = null;
    let value = null;
    if (node.type === 'FunctionDeclaration' && node.id?.name) {
      name = node.id.name;
      value = node;
    } else if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier') {
      name = node.id.name;
      value = unwrap(node.init);
    } else if (FUNCTION_TYPES.has(node.type) && ['ClassBody', 'ObjectExpression'].includes(parent?.type)) {
      name = safeName(node.key);
      value = node;
    }
    if (!name || !value) return;
    if (values.has(name) && values.get(name) !== value) duplicates.add(name);
    else values.set(name, value);
  });
  for (const name of duplicates) values.delete(name);
  return values;
}

function resolveFunction(node, values) {
  const current = unwrap(node);
  if (FUNCTION_TYPES.has(current?.type)) return current;
  if (current?.type === 'Identifier' && FUNCTION_TYPES.has(values.get(current.name)?.type)) {
    return values.get(current.name);
  }
  return null;
}

function handlerForRoute(module, route) {
  const values = declarations(module);
  if (route.framework === 'nestjs') {
    let exact = null;
    walkJsTsAst(module.ast, (node) => {
      if (!['ClassMethod', 'ClassPrivateMethod'].includes(node.type)) return;
      if (node.loc?.start?.line === route.location.line && safeName(node.key) === route.handler) exact = node;
    });
    return exact;
  }
  if (route.framework === 'next-app') {
    let exact = null;
    walkJsTsAst(module.ast, (node) => {
      if (FUNCTION_TYPES.has(node.type) && node.loc?.start?.line === route.location.line) exact = node;
    });
    return exact || resolveFunction(values.get(route.handler), values);
  }
  if (route.framework === 'express') {
    if (route.handler && route.handler !== '<inline>') {
      const named = resolveFunction(values.get(route.handler), values);
      if (named) return named;
    }
    let exact = null;
    walkJsTsAst(module.ast, (node) => {
      if (node.type !== 'CallExpression' || node.loc?.start?.line !== route.location.line) return;
      const candidate = resolveFunction(node.arguments.at(-1), values);
      if (candidate) exact = candidate;
    });
    return exact;
  }
  return null;
}

function directAccessChains(graph, module, route, handler, budget) {
  const identity = analyzeIdentityEvidence(graph, module, handler);
  const selected = extractSelectorEvidence({
    module, handler, framework: route.framework, routePath: route.path, entryKind: 'route',
    imports: importedBindings(module), principalAliases: identity.principalAliases,
  });
  const objectSelectors = selected.selectors.filter((selector) => selector.origin === 'request_selected');
  const paths = analyzeAccessPaths({
    graph, module, handler, entry: { kind: 'route', id: route.id,
      name: route.handler || route.id, module },
    identity: identity.identity, selectorGroups: selected.selectorGroups,
    principalAliases: identity.principalAliases, tenantAliases: identity.tenantAliases, budget,
  });
  const pathChains = paths.chains.map(accessChainRecord);
  const selectorIncomplete = selected.limitations.length > 0;
  const unresolvedSelectors = selected.selectors.some((selector) => selector.origin === 'unknown')
    ? selected.selectors.filter((selector) => selector.origin === 'unknown')
    : objectSelectors.map((selector) => ({ ...selector, origin: 'unknown' }));
  const selectorIncompleteChain = selectorIncomplete && !pathChains.length && unresolvedSelectors.length
    ? [accessChainRecord({
      entryKind: 'route', entryId: route.id, status: 'partial', outcome: 'incomplete',
      identity: identity.identity,
      objectSelectors: unresolvedSelectors,
      callEdges: [], dataOperation: null, reason: 'selector_source_unresolved',
      limitations: selected.limitations.map((item) => item.code),
      evidenceBoundary: 'A dynamic or ambiguous request selector was observed, but its exact field or value origin could not be established. No object-authorization conclusion is available.',
    })] : [];
  return {
    chains: [...pathChains, ...selectorIncompleteChain],
    operations: paths.operations,
    limitations: [...selected.limitations.map((item) => item.code),
      ...paths.limitations,
      ...paths.chains.map((item) => item.reason).filter(Boolean)],
    coverageReasons: paths.coverage.reasons,
    selectors: selected.selectors,
  };
}

function aggregateReasons(items) {
  const grouped = new Map();
  for (const item of items) {
    const entry = grouped.get(item.code) || { code: item.code, count: 0, samplePaths: [] };
    entry.count += 1;
    if (item.path && entry.samplePaths.length < 10 && !entry.samplePaths.includes(item.path)) {
      entry.samplePaths.push(item.path);
    }
    grouped.set(item.code, entry);
  }
  return [...grouped.values()].sort((left, right) => left.code.localeCompare(right.code));
}

export function auditJsTsRouteAuthorization(graph, routes) {
  const reasons = [...graph.reasons];
  const accessBudget = createAccessPathBudget();
  const reviewedRoutes = [];
  let scanned = 0;
  let eligible = 0;
  for (const route of routes) {
    if (!route.path) {
      reviewedRoutes.push(route);
      continue;
    }
    const module = graph.modules.get(route.location.path);
    if (!module?.ast) {
      if (route.objectAddressed) {
        eligible += 1;
        reasons.push({ code: 'route_handler_source_incomplete', path: route.location.path });
        reviewedRoutes.push({ ...route, limitations: [...new Set([
          ...route.limitations, 'route-object-authorization-analysis-incomplete',
        ])].sort() });
      } else reviewedRoutes.push(route);
      continue;
    }
    const handler = handlerForRoute(module, route);
    if (!handler) {
      if (route.objectAddressed) {
        eligible += 1;
        reasons.push({ code: 'route_handler_unresolved', path: route.location.path });
        reviewedRoutes.push({ ...route, limitations: [...new Set([
          ...route.limitations, 'route-object-authorization-analysis-incomplete',
        ])].sort() });
      } else reviewedRoutes.push(route);
      continue;
    }
    const access = directAccessChains(graph, module, route, handler, accessBudget);
    if (!route.objectAddressed && !access.selectors.length) {
      reviewedRoutes.push(route);
      continue;
    }
    eligible += 1;
    scanned += 1;
    for (const code of access.limitations.filter((item) => item.startsWith('selector_'))) {
      reasons.push({ code, path: route.location.path });
    }
    for (const code of access.coverageReasons) reasons.push({ code, path: route.location.path });
    const operations = access.operations.map((item) => `${item.provider}-${item.operation}`);
    const limitations = [...route.limitations];
    limitations.push(...access.limitations);
    if (access.operations.some((item) => item.principalConstraint === 'observed'
        || item.tenantConstraint === 'observed')) {
      limitations.push('principal-constraint-observed-not-validated');
    }
    reviewedRoutes.push(prioritizeRoute({ ...route, objectAddressed: true,
      accessChains: [...(route.accessChains || []), ...access.chains],
      operations: [...new Set([...route.operations, ...operations])].sort(),
      limitations: [...new Set(limitations)].sort(),
    }));
  }
  const uniqueReasons = reasons.filter((item, index, items) =>
    items.findIndex((candidate) => candidate.code === item.code && candidate.path === item.path) === index);
  const status = !eligible ? 'not_applicable' : uniqueReasons.length ? 'partial' : 'completed';
  return {
    routes: reviewedRoutes,
    coverage: {
      id: `source-${ROUTE_AUTHORIZATION_RULE_ID}`,
      adapterId: 'builtin-source',
      ruleId: ROUTE_AUTHORIZATION_RULE_ID,
      ruleRevision: '1',
      status,
      counts: {
        discovered: routes.length,
        eligible,
        scanned,
        excluded: routes.length - eligible,
        skipped: eligible - scanned,
        truncated: 0,
        errors: uniqueReasons.length,
      },
      reasons: aggregateReasons(uniqueReasons),
    },
  };
}
