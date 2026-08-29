import { walkJsTsAst } from './js-ts-ast-parser.mjs';
import { expressionName } from './js-ts-module-graph.mjs';
import { analyzeDataOperations } from './js-ts-data-operation-evidence.mjs';
import { analyzeIdentityEvidence } from './js-ts-identity-evidence.mjs';
import { analyzeOneHopAccess } from './js-ts-one-hop-access.mjs';
import { importedBindings } from './frameworks/route-extractor-helpers.mjs';
import { prioritizeRoute } from './route-security-priority.mjs';
import { accessChainRecord } from './route-security-model.mjs';
import { isPrincipalExpressionName, isPrincipalOrTenantKey } from './access-control-vocabulary.mjs';

export const ROUTE_AUTHORIZATION_RULE_ID = 'js-route-object-authorization-review';

const FUNCTION_TYPES = new Set([
  'ArrowFunctionExpression', 'FunctionDeclaration', 'FunctionExpression', 'ClassMethod',
  'ClassPrivateMethod', 'ObjectMethod',
]);
const ID_ROUTE_PARAM = /(?:^|[_-])id$|Id$/;

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
  if (!property || !['ObjectProperty', 'ObjectMethod'].includes(property.type)) return null;
  return safeName(property.key);
}

function functionBodyNodes(root, visit) {
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

function routeParameterNames(path) {
  const names = [];
  const pattern = /:([A-Za-z_$][\w$]*)|\[(?:\.\.\.)?([^\]]+)\]/g;
  for (const match of String(path || '').matchAll(pattern)) {
    const name = match[1] || match[2];
    if (ID_ROUTE_PARAM.test(name)) names.push(name);
  }
  return [...new Set(names)];
}

function objectPatternBindings(pattern, allowedKeys) {
  const bindings = [];
  if (pattern?.type !== 'ObjectPattern') return bindings;
  for (const property of pattern.properties) {
    if (property.type !== 'ObjectProperty') continue;
    const key = propertyName(property);
    if (!allowedKeys.has(key)) continue;
    const value = unwrap(property.value);
    if (value?.type === 'Identifier') bindings.push(value.name);
    if (value?.type === 'AssignmentPattern' && value.left?.type === 'Identifier') bindings.push(value.left.name);
  }
  return bindings;
}

function nestParamAliases(handler, imports, names, aliases, containers) {
  for (const rawParameter of handler.params || []) {
    const parameter = rawParameter.type === 'TSParameterProperty' ? rawParameter.parameter : rawParameter;
    for (const decorator of parameter.decorators || []) {
      const call = decorator.expression?.type === 'CallExpression' ? decorator.expression : null;
      const local = safeName(call?.callee);
      const binding = imports.get(local);
      if (binding?.source !== '@nestjs/common' || binding.imported !== 'Param') continue;
      const selected = call.arguments[0]?.type === 'StringLiteral' ? call.arguments[0].value : null;
      if (selected && names.includes(selected) && parameter.type === 'Identifier') aliases.add(parameter.name);
      if (!selected && parameter.type === 'Identifier') {
        containers.add(parameter.name);
        for (const name of names) aliases.add(`${parameter.name}.${name}`);
      }
    }
  }
}

function initialRouteAliases(route, handler, imports) {
  const names = routeParameterNames(route.path);
  const aliases = new Set();
  const containers = new Set();
  if (!names.length) return { names, aliases, containers };
  if (route.framework === 'express') {
    const request = unwrap(handler.params?.[0]);
    if (request?.type === 'Identifier') {
      containers.add(`${request.name}.params`);
      for (const name of names) aliases.add(`${request.name}.params.${name}`);
    } else if (request?.type === 'ObjectPattern') {
      const params = objectPatternBindings(request, new Set(['params']));
      for (const local of params) {
        containers.add(local);
        for (const name of names) aliases.add(`${local}.${name}`);
      }
    }
  } else if (route.framework === 'next-app') {
    const context = unwrap(handler.params?.[1]);
    if (context?.type === 'Identifier') {
      containers.add(`${context.name}.params`);
      for (const name of names) aliases.add(`${context.name}.params.${name}`);
    } else if (context?.type === 'ObjectPattern') {
      const params = objectPatternBindings(context, new Set(['params']));
      for (const local of params) {
        containers.add(local);
        for (const name of names) aliases.add(`${local}.${name}`);
      }
    }
  } else if (route.framework === 'nestjs') nestParamAliases(handler, imports, names, aliases, containers);
  return { names, aliases, containers };
}

function routeExpression(node, aliases) {
  const current = unwrap(node);
  const name = safeName(current);
  if (name && aliases.has(name)) return true;
  if (current?.type === 'CallExpression' && ['String', 'Number', 'parseInt'].includes(safeName(current.callee))) {
    return routeExpression(current.arguments[0], aliases);
  }
  return false;
}

function containsRouteExpression(node, aliases) {
  const stack = [unwrap(node)];
  let visited = 0;
  while (stack.length && visited < 2_000) {
    const current = stack.pop();
    if (!current || typeof current !== 'object') continue;
    visited += 1;
    if (routeExpression(current, aliases)) return true;
    if (FUNCTION_TYPES.has(current.type)) continue;
    for (const [key, value] of Object.entries(current)) {
      if (['loc', 'start', 'end', 'extra', 'comments'].includes(key)) continue;
      if (Array.isArray(value)) stack.push(...value);
      else if (value && typeof value === 'object') stack.push(value);
    }
  }
  return false;
}

function delegatedSelectorObserved(handler, aliases) {
  let observed = false;
  functionBodyNodes(handler, (node) => {
    if (observed || node.type !== 'CallExpression') return;
    const callee = safeName(node.callee);
    if (!callee?.includes('.') || /^(?:res|response|console)\./.test(callee)) return;
    if (node.arguments.some((argument) => containsRouteExpression(argument, aliases))) observed = true;
  });
  return observed;
}

function collectLocalFacts(handler, routeFacts) {
  const objectValues = new Map();
  const principalAliases = new Set();
  const variableNodes = [];
  functionBodyNodes(handler, (node) => {
    if (node.type === 'VariableDeclarator') variableNodes.push(node);
  });
  for (let pass = 0; pass < 4; pass += 1) {
    let changed = false;
    for (const declaration of variableNodes) {
      const init = unwrap(declaration.init);
      if (declaration.id?.type === 'Identifier') {
        if (init?.type === 'ObjectExpression') objectValues.set(declaration.id.name, init);
        if (routeExpression(init, routeFacts.aliases) && !routeFacts.aliases.has(declaration.id.name)) {
          routeFacts.aliases.add(declaration.id.name);
          changed = true;
        }
        if (isPrincipalExpression(init, principalAliases) && !principalAliases.has(declaration.id.name)) {
          principalAliases.add(declaration.id.name);
          changed = true;
        }
      }
      if (declaration.id?.type !== 'ObjectPattern') continue;
      const initName = safeName(init);
      if (routeFacts.containers.has(initName)) {
        for (const local of objectPatternBindings(declaration.id, new Set(routeFacts.names))) {
          if (!routeFacts.aliases.has(local)) {
            routeFacts.aliases.add(local);
            changed = true;
          }
        }
      }
      const authCall = init?.type === 'CallExpression'
        && /(?:^|\.)(?:auth|getSession|getServerSession|currentUser)$/.test(safeName(init.callee) || '');
      if (authCall) {
        for (const property of declaration.id.properties) {
          if (property.type !== 'ObjectProperty'
              || !isPrincipalOrTenantKey(propertyName(property))) continue;
          const local = safeName(property.value);
          if (local && !principalAliases.has(local)) {
            principalAliases.add(local);
            changed = true;
          }
        }
      }
    }
    if (!changed) break;
  }
  return { objectValues, principalAliases };
}

function isPrincipalExpression(node, aliases = new Set()) {
  return isPrincipalExpressionName(safeName(node), aliases);
}

function directAccessChains(graph, module, route, handler) {
  const routeFacts = initialRouteAliases(route, handler, importedBindings(module));
  collectLocalFacts(handler, routeFacts);
  const identity = analyzeIdentityEvidence(graph, module, handler);
  const analyzed = analyzeDataOperations(graph, module, handler, {
    objectAliases: routeFacts.aliases,
    principalAliases: identity.principalAliases,
  });
  const objectSelectors = routeFacts.names.map((name) => ({
    kind: 'route-parameter', name, location: route.location,
  }));
  const directChains = analyzed.operations.map((dataOperation) => {
    const constrained = dataOperation.principalConstraint === 'observed'
      || dataOperation.tenantConstraint === 'observed';
    const outcome = constrained ? 'principal_constraint_observed'
      : dataOperation.externalPolicy === 'external_policy_required'
        ? 'external_policy_required' : 'principal_constraint_not_observed';
    return accessChainRecord({
      entryKind: 'route', entryId: route.id, status: 'completed', outcome,
      identity: identity.identity, objectSelectors, callEdges: [], dataOperation,
      evidenceBoundary: dataOperation.externalPolicy === 'external_policy_required'
        ? 'The request-selected object reaches a supported Supabase operation. Query constraints are static evidence only, and database row-level security must be checked separately.'
        : 'The request-selected object reaches a supported same-handler data operation. Visible query constraints do not prove runtime authorization, and missing visible constraints do not prove a vulnerability.',
    });
  });
  const incompleteChains = analyzed.incomplete.map((reason) => accessChainRecord({
    entryKind: 'route', entryId: route.id, status: 'partial', outcome: 'incomplete',
    identity: identity.identity, objectSelectors, callEdges: [], dataOperation: null,
    reason: reason.code === 'prisma_client_identity_unresolved'
      ? 'data_client_unresolved' : 'module_or_parser_evidence_incomplete',
    limitations: [reason.code],
    evidenceBoundary: `A Prisma-shaped data operation was observed at ${reason.location.path}:${reason.location.line || '?'} but the client identity could not be resolved to an imported PrismaClient. No authorization conclusion is available.`,
  }));
  const oneHop = analyzeOneHopAccess({
    graph, module, handler, entry: { kind: 'route', id: route.id,
      name: route.handler || route.id, module },
    identity: identity.identity, objectAliases: routeFacts.aliases,
    principalAliases: identity.principalAliases, objectSelectors,
  });
  const delegatedUnresolved = !directChains.length && !incompleteChains.length && !oneHop.length
    && delegatedSelectorObserved(handler, routeFacts.aliases);
  return {
    chains: [...directChains, ...incompleteChains, ...oneHop.map(accessChainRecord)],
    operations: [...analyzed.operations, ...oneHop.map((item) => item.dataOperation).filter(Boolean)],
    limitations: [...analyzed.incomplete.map((item) => item.code),
      ...(delegatedUnresolved ? ['delegated-object-authorization-unresolved'] : []),
      ...oneHop.map((item) => item.reason).filter(Boolean)],
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
  const reviewedRoutes = [];
  let scanned = 0;
  const eligibleRoutes = routes.filter((route) => route.objectAddressed && route.path);
  for (const route of routes) {
    if (!route.objectAddressed || !route.path) {
      reviewedRoutes.push(route);
      continue;
    }
    const module = graph.modules.get(route.location.path);
    if (!module?.ast) {
      reasons.push({ code: 'route_handler_source_incomplete', path: route.location.path });
      reviewedRoutes.push({ ...route, limitations: [...new Set([
        ...route.limitations, 'route-object-authorization-analysis-incomplete',
      ])].sort() });
      continue;
    }
    const handler = handlerForRoute(module, route);
    if (!handler) {
      reasons.push({ code: 'route_handler_unresolved', path: route.location.path });
      reviewedRoutes.push({ ...route, limitations: [...new Set([
        ...route.limitations, 'route-object-authorization-analysis-incomplete',
      ])].sort() });
      continue;
    }
    scanned += 1;
    const access = directAccessChains(graph, module, route, handler);
    const operations = access.operations.map((item) => `${item.provider}-${item.operation}`);
    const limitations = [...route.limitations];
    limitations.push(...access.limitations);
    if (access.operations.some((item) => item.principalConstraint === 'observed'
        || item.tenantConstraint === 'observed')) {
      limitations.push('principal-constraint-observed-not-validated');
    }
    reviewedRoutes.push(prioritizeRoute({ ...route,
      accessChains: [...(route.accessChains || []), ...access.chains],
      operations: [...new Set([...route.operations, ...operations])].sort(),
      limitations: [...new Set(limitations)].sort(),
    }));
  }
  const uniqueReasons = reasons.filter((item, index, items) =>
    items.findIndex((candidate) => candidate.code === item.code && candidate.path === item.path) === index);
  const status = !eligibleRoutes.length ? 'not_applicable' : uniqueReasons.length ? 'partial' : 'completed';
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
        eligible: eligibleRoutes.length,
        scanned,
        excluded: routes.length - eligibleRoutes.length,
        skipped: eligibleRoutes.length - scanned,
        truncated: 0,
        errors: uniqueReasons.length,
      },
      reasons: aggregateReasons(uniqueReasons),
    },
  };
}
