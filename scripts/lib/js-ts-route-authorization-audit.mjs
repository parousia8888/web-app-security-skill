import { walkJsTsAst } from './js-ts-ast-parser.mjs';
import { expressionName } from './js-ts-module-graph.mjs';
import { analyzeDataOperations } from './js-ts-data-operation-evidence.mjs';
import { analyzeIdentityEvidence } from './js-ts-identity-evidence.mjs';
import { analyzeOneHopAccess } from './js-ts-one-hop-access.mjs';
import { importedBindings } from './frameworks/route-extractor-helpers.mjs';
import { prioritizeRoute } from './route-security-priority.mjs';
import { accessChainRecord } from './route-security-model.mjs';

export const ROUTE_AUTHORIZATION_RULE_ID = 'js-route-object-authorization-review';

const FUNCTION_TYPES = new Set([
  'ArrowFunctionExpression', 'FunctionDeclaration', 'FunctionExpression', 'ClassMethod',
  'ClassPrivateMethod', 'ObjectMethod',
]);
const PRISMA_OPERATIONS = new Set([
  'findUnique', 'findUniqueOrThrow', 'findFirst', 'findFirstOrThrow', 'findMany',
  'update', 'updateMany', 'delete', 'deleteMany', 'upsert',
]);
const PRINCIPAL_KEYS = /^(?:owner|user|tenant|organization|account|member)Id$/i;
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
          if (property.type !== 'ObjectProperty' || !PRINCIPAL_KEYS.test(propertyName(property) || '')) continue;
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
  const name = safeName(node);
  if (!name) return false;
  if (aliases.has(name)) return true;
  if (PRINCIPAL_KEYS.test(name)) return true;
  return /^(?:req|request|ctx|context|session|auth|principal|user)(?:\.[A-Za-z_$][\w$]*)*\.(?:id|userId|ownerId|tenantId|organizationId|accountId|memberId)$/i.test(name);
}

function resolveObject(node, objectValues) {
  const current = unwrap(node);
  if (current?.type === 'ObjectExpression') return current;
  if (current?.type === 'Identifier') return objectValues.get(current.name) || null;
  return null;
}

function objectPropertyValue(object, name, objectValues) {
  for (const property of object?.properties || []) {
    if (property.type === 'SpreadElement') continue;
    if (propertyName(property) === name) return resolveObject(property.value, objectValues) || unwrap(property.value);
  }
  return null;
}

function objectContains(object, predicate, objectValues, depth = 0) {
  if (!object || depth > 8) return false;
  for (const property of object.properties || []) {
    if (property.type === 'SpreadElement') continue;
    if (predicate(propertyName(property), unwrap(property.value))) return true;
    const nested = resolveObject(property.value, objectValues);
    if (nested && objectContains(nested, predicate, objectValues, depth + 1)) return true;
    if (property.value?.type === 'ArrayExpression') {
      for (const element of property.value.elements) {
        const child = resolveObject(element, objectValues);
        if (child && objectContains(child, predicate, objectValues, depth + 1)) return true;
      }
    }
  }
  return false;
}

function prismaClients(module) {
  const imports = importedBindings(module);
  const constructors = new Set();
  for (const [local, binding] of imports) {
    if (binding.source !== '@prisma/client') continue;
    if (binding.imported === 'PrismaClient') constructors.add(local);
    if (binding.imported === '*') constructors.add(`${local}.PrismaClient`);
  }
  const clients = new Set();
  walkJsTsAst(module.ast, (node) => {
    let target = null;
    let init = null;
    if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier') {
      target = node.id.name;
      init = unwrap(node.init);
    } else if (['ClassProperty', 'ClassPrivateProperty'].includes(node.type)) {
      target = `this.${safeName(node.key)}`;
      init = unwrap(node.value);
    }
    if (target && init?.type === 'NewExpression' && constructors.has(safeName(init.callee))) clients.add(target);
  });
  return clients;
}

function prismaOperation(call, clients) {
  const name = safeName(call?.callee);
  if (!name) return null;
  for (const client of clients) {
    if (!name.startsWith(`${client}.`)) continue;
    const parts = name.slice(client.length + 1).split('.');
    if (parts.length === 2 && PRISMA_OPERATIONS.has(parts[1])) {
      return { model: parts[0], operation: parts[1] };
    }
  }
  return null;
}

function nodeContainsRouteExpression(node, aliases) {
  let matched = false;
  const stack = [unwrap(node)];
  let visited = 0;
  while (stack.length && !matched && visited < 2_000) {
    const current = stack.pop();
    if (!current || typeof current !== 'object') continue;
    visited += 1;
    if (routeExpression(current, aliases)) {
      matched = true;
      break;
    }
    if (!FUNCTION_TYPES.has(current.type)) {
      for (const [key, value] of Object.entries(current)) {
        if (['loc', 'start', 'end', 'extra', 'comments'].includes(key)) continue;
        if (Array.isArray(value)) stack.push(...value);
        else if (value && typeof value === 'object') stack.push(value);
      }
    }
  }
  return matched;
}

function operationEvidence(module, route, handler, clients) {
  const imports = importedBindings(module);
  const routeFacts = initialRouteAliases(route, handler, imports);
  const { objectValues, principalAliases } = collectLocalFacts(handler, routeFacts);
  const operations = [];
  const delegated = [];
  functionBodyNodes(handler, (node) => {
    if (node.type !== 'CallExpression') return;
    const prisma = prismaOperation(node, clients);
    if (prisma) {
      const options = resolveObject(node.arguments[0], objectValues);
      const where = objectPropertyValue(options, 'where', objectValues);
      const whereObject = resolveObject(where, objectValues);
      if (!whereObject || !objectContains(whereObject,
        (_key, value) => routeExpression(value, routeFacts.aliases), objectValues)) return;
      const principalConstraint = objectContains(whereObject,
        (key, value) => PRINCIPAL_KEYS.test(key || '') && isPrincipalExpression(value, principalAliases),
        objectValues);
      operations.push({ ...prisma, call: node, principalConstraint });
      return;
    }
    if (['String', 'Number', 'parseInt'].includes(safeName(node.callee))) return;
    if (node.arguments.some((argument) => nodeContainsRouteExpression(argument, routeFacts.aliases))) {
      delegated.push(node);
    }
  });
  return { operations, delegated };
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
  const oneHop = analyzeOneHopAccess({
    graph, module, handler, entry: { kind: 'route', id: route.id,
      name: route.handler || route.id, module },
    identity: identity.identity, objectAliases: routeFacts.aliases,
    principalAliases: identity.principalAliases, objectSelectors,
  });
  return {
    chains: [...directChains, ...oneHop.map(accessChainRecord)],
    operations: [...analyzed.operations, ...oneHop.map((item) => item.dataOperation).filter(Boolean)],
    limitations: oneHop.map((item) => item.reason).filter(Boolean),
  };
}

function rawFinding(route, operation) {
  const line = operation.call.loc?.start?.line ?? route.location.line;
  const construct = `prisma_${operation.operation}_route_identifier`;
  const subject = `${route.framework}:${route.method}:${route.path}:${route.location.path}:${line}:${construct}`;
  return {
    ruleId: ROUTE_AUTHORIZATION_RULE_ID,
    title: 'Direct route-ID database operation needs object-authorization review',
    severity: 'high',
    state: 'suspected',
    discriminator: subject,
    summary: 'A request-selected route identifier reaches a direct Prisma operation, and this bounded check did not observe a supported owner or tenant constraint in the same operation.',
    location: { path: route.location.path, line },
    evidence: {
      subject, line, construct, framework: route.framework, method: route.method,
      routePath: route.path, dataOperation: `prisma.${operation.model}.${operation.operation}`,
      principalConstraintObserved: false,
    },
    remediation: 'Review the actual authorization boundary before changing code. If this operation owns the boundary, require the authenticated principal or tenant in the query or in an equivalent centrally enforced policy.',
    retest: 'Use two owned users or tenants to verify cross-owner access is rejected, verify legitimate and privileged workflows, then rerun the route audit.',
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
  const findings = [];
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
    const evidence = operationEvidence(module, route, handler, prismaClients(module));
    const access = directAccessChains(graph, module, route, handler);
    for (const operation of evidence.operations) {
      if (!operation.principalConstraint) findings.push(rawFinding(route, operation));
    }
    const operations = [...evidence.operations.map((item) => `prisma-${item.operation.replace(/[A-Z]/g,
      (character) => `-${character.toLowerCase()}`)}`),
    ...access.operations.map((item) => `${item.provider}-${item.operation}`)];
    const limitations = [...route.limitations];
    limitations.push(...access.limitations);
    if (evidence.operations.some((item) => item.principalConstraint)) {
      limitations.push('principal-constraint-observed-not-validated');
    }
    if (!evidence.operations.length && evidence.delegated.length) {
      limitations.push('delegated-object-authorization-unresolved');
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
    findings,
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
