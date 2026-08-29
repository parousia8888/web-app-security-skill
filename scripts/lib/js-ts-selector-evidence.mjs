import { expressionName } from './js-ts-module-graph.mjs';

const FUNCTION_TYPES = new Set([
  'ArrowFunctionExpression', 'FunctionDeclaration', 'FunctionExpression', 'ClassMethod',
  'ClassPrivateMethod', 'ObjectMethod',
]);
const CONVERSIONS = new Set(['String', 'Number', 'parseInt']);
const REQUEST_FIELDS = new Set(['params', 'query', 'body']);
const NEST_DECORATORS = new Map([
  ['Param', 'nest-path-param'],
  ['Query', 'nest-query-field'],
  ['Body', 'nest-body-field'],
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

function literalString(node) {
  const current = unwrap(node);
  if (current?.type === 'StringLiteral') return current.value;
  if (current?.type === 'TemplateLiteral' && current.expressions.length === 0) {
    return current.quasis.map((item) => item.value.cooked ?? item.value.raw).join('');
  }
  return null;
}

function sourceLocation(path, node) {
  return { path, line: node?.loc?.start?.line ?? null };
}

function candidateName(name) {
  return typeof name === 'string' && /^(?:id|.*Id|.*_id)$/.test(name);
}

function routeParameterNames(path) {
  const names = [];
  const pattern = /:([A-Za-z_$][\w$]*)|\[(?:\.\.\.)?([^\]]+)\]/g;
  for (const match of String(path || '').matchAll(pattern)) {
    const name = match[1] || match[2];
    if (candidateName(name)) names.push(name);
  }
  return [...new Set(names)];
}

function parameterNode(raw) {
  const parameter = raw?.type === 'TSParameterProperty' ? raw.parameter : raw;
  return parameter?.type === 'AssignmentPattern' ? parameter.left : parameter;
}

function staticPropertyName(node) {
  if (!['MemberExpression', 'OptionalMemberExpression'].includes(node?.type)) return null;
  if (!node.computed) return safeName(node.property);
  return literalString(node.property);
}

function objectPropertyName(property) {
  if (property?.type !== 'ObjectProperty') return null;
  if (property.computed) return literalString(property.key);
  return safeName(property.key);
}

function sameFact(left, right) {
  return left.origin === right.origin && left.kind === right.kind && left.name === right.name;
}

function localWalk(root, visit) {
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

function descriptor(kind, name, origin, path, node) {
  return { kind, name, origin, location: sourceLocation(path, node) };
}

export function extractSelectorEvidence(input) {
  const { module, handler, framework = null, routePath = null, entryKind = 'route' } = input;
  const imports = input.imports || new Map();
  const principalSeeds = new Set(input.principalAliases || []);
  const facts = new Map();
  const nodeFacts = new Map();
  const containers = new Map();
  const requestRoots = new Map();
  const contextRoots = new Set();
  const actionRoots = new Set();
  const selectors = new Map();
  const limitations = new Map();
  const declarations = [];
  const assignments = [];
  const sourceNodes = [];
  const writes = new Map();
  const pathNames = routeParameterNames(routePath);

  const limit = (code, node = handler) => {
    if (!limitations.has(code)) limitations.set(code, {
      code, path: module.path, location: sourceLocation(module.path, node),
    });
  };
  const addSelector = (item) => {
    const key = [item.kind, item.name, item.origin].join('\0');
    if (!selectors.has(key)) selectors.set(key, item);
  };
  const addNodeFact = (node, item, source = false) => {
    if (!node) return false;
    const existing = nodeFacts.get(node);
    if (existing && sameFact(existing, item)) {
      if (source && ['request_selected', 'unknown'].includes(item.origin)) addSelector(item);
      return false;
    }
    nodeFacts.set(node, existing ? { ...item, origin: 'unknown' } : item);
    if (existing) limit('selector_alias_ambiguous', node);
    if (source) addSelector(nodeFacts.get(node));
    return !existing;
  };
  const addFact = (alias, item, source = false) => {
    if (!alias) return false;
    const existing = facts.get(alias);
    if (existing && sameFact(existing, item)) {
      if (source && ['request_selected', 'unknown'].includes(item.origin)) addSelector(item);
      return false;
    }
    if (existing && !sameFact(existing, item)) {
      const unknown = { ...item, origin: 'unknown' };
      facts.set(alias, unknown);
      limit('selector_alias_ambiguous');
      if (source) addSelector(unknown);
      return true;
    }
    facts.set(alias, item);
    if (source && ['request_selected', 'unknown'].includes(item.origin)) addSelector(item);
    return true;
  };
  const addContainer = (alias, item) => {
    if (!alias) return false;
    const existing = containers.get(alias);
    if (existing && existing.surface === item.surface && existing.kind === item.kind
        && existing.origin === item.origin) return false;
    if (existing) {
      containers.set(alias, { ...item, origin: 'unknown' });
      limit('selector_alias_ambiguous');
      return true;
    }
    containers.set(alias, item);
    return true;
  };

  function bindPattern(pattern, container, node = pattern) {
    const current = parameterNode(pattern);
    if (current?.type !== 'ObjectPattern') return false;
    let changed = false;
    for (const property of current.properties) {
      if (property.type === 'RestElement') {
        limit('selector_destructuring_ambiguous', property);
        continue;
      }
      if (property.type !== 'ObjectProperty') continue;
      const field = objectPropertyName(property);
      if (!field) {
        limit('selector_dynamic_field_unresolved', property);
        continue;
      }
      const value = parameterNode(property.value);
      if (container.surface === 'request-root' && REQUEST_FIELDS.has(field)) {
        const nested = {
          surface: field, kind: container.kind === 'express'
            ? `express-${field === 'params' ? 'path-param' : `${field}-field`}`
            : `${container.kind}-${field}`,
          origin: container.origin,
          allowedNames: field === 'params' ? new Set(pathNames) : null,
          location: sourceLocation(module.path, property),
        };
        if (value?.type === 'ObjectPattern') changed = bindPattern(value, nested, property) || changed;
        else if (value?.type === 'Identifier') changed = addContainer(value.name, nested) || changed;
        else limit('selector_destructuring_ambiguous', property);
        continue;
      }
      if (container.surface === 'next-context' && field === 'params') {
        const nested = {
          surface: 'params', kind: 'next-route-param', origin: container.origin,
          allowedNames: new Set(pathNames), location: sourceLocation(module.path, property),
        };
        if (value?.type === 'ObjectPattern') changed = bindPattern(value, nested, property) || changed;
        else if (value?.type === 'Identifier') changed = addContainer(value.name, nested) || changed;
        else limit('selector_destructuring_ambiguous', property);
        continue;
      }
      if (container.surface === 'url' && field === 'searchParams') {
        const nested = { surface: 'search-params', kind: 'next-search-param',
          origin: container.origin, allowedNames: null,
          location: sourceLocation(module.path, property) };
        if (value?.type === 'Identifier') changed = addContainer(value.name, nested) || changed;
        else limit('selector_destructuring_ambiguous', property);
        continue;
      }
      if (value?.type === 'ObjectPattern') {
        const nested = { ...container, surface: `${container.surface}.${field}` };
        changed = bindPattern(value, nested, property) || changed;
        continue;
      }
      if (value?.type !== 'Identifier') {
        limit('selector_destructuring_ambiguous', property);
        continue;
      }
      const allowed = container.allowedNames?.has(field) || candidateName(field);
      if (!allowed) continue;
      const item = descriptor(container.kind, field, container.origin, module.path, property || node);
      changed = addFact(value.name, item, true) || changed;
    }
    return changed;
  }

  function containerFor(node) {
    const current = unwrap(node);
    const name = safeName(current);
    if (name && containers.has(name)) return containers.get(name);
    const root = requestRoots.get(name);
    if (root) return { surface: 'request-root',
      kind: root.kind === 'express-request' ? 'express' : 'next-request',
      origin: 'request_selected', allowedNames: null, location: sourceLocation(module.path, current) };
    if (contextRoots.has(name)) return { surface: 'next-context', kind: 'next-route-param',
      origin: 'request_selected', allowedNames: new Set(pathNames),
      location: sourceLocation(module.path, current) };
    if (current?.type === 'CallExpression' && isRequestJsonCall(current)) {
      return { surface: 'json', kind: 'next-json-field',
        origin: repeatedJson ? 'unknown' : 'request_selected', allowedNames: null,
        location: sourceLocation(module.path, current) };
    }
    if (current && containsRequestJson(current)) {
      limit('selector_transform_unresolved', current);
      return { surface: 'json', kind: 'next-json-field', origin: 'unknown',
        allowedNames: null, location: sourceLocation(module.path, current) };
    }
    if (current?.type === 'NewExpression' && isRequestUrl(current.arguments?.[0])) {
      return { surface: 'url', kind: 'next-search-param', origin: 'request_selected',
        allowedNames: null, location: sourceLocation(module.path, current) };
    }
    if (!['MemberExpression', 'OptionalMemberExpression'].includes(current?.type)) return null;
    const field = staticPropertyName(current);
    const rootName = safeName(current.object);
    const request = requestRoots.get(rootName);
    if (request && REQUEST_FIELDS.has(field)) {
      return { surface: field, kind: request.kind === 'express-request'
        ? `express-${field === 'params' ? 'path-param' : `${field}-field`}`
        : field === 'params' ? 'next-route-param' : `next-${field}-field`,
      origin: 'request_selected', allowedNames: field === 'params' ? new Set(pathNames) : null,
      location: sourceLocation(module.path, current) };
    }
    if (contextRoots.has(rootName) && field === 'params') {
      return { surface: 'params', kind: 'next-route-param', origin: 'request_selected',
        allowedNames: new Set(pathNames), location: sourceLocation(module.path, current) };
    }
    const base = containerFor(current.object);
    if (base?.surface === 'url' && field === 'searchParams') {
      return { surface: 'search-params', kind: 'next-search-param', origin: base.origin,
        allowedNames: null, location: sourceLocation(module.path, current) };
    }
    if (request?.kind === 'next-request' && field === 'nextUrl') {
      return { surface: 'url', kind: 'next-search-param', origin: 'request_selected',
        allowedNames: null, location: sourceLocation(module.path, current) };
    }
    return null;
  }

  function isRequestUrl(node) {
    const current = unwrap(node);
    if (!['MemberExpression', 'OptionalMemberExpression'].includes(current?.type)
        || staticPropertyName(current) !== 'url') return false;
    return requestRoots.get(safeName(current.object))?.kind === 'next-request';
  }

  function isRequestJsonCall(node) {
    const current = unwrap(node);
    if (current?.type !== 'CallExpression' || current.arguments.length) return false;
    if (!['MemberExpression', 'OptionalMemberExpression'].includes(current.callee?.type)
        || staticPropertyName(current.callee) !== 'json') return false;
    return requestRoots.get(safeName(current.callee.object))?.kind === 'next-request';
  }

  function containsRequestJson(node) {
    const stack = [{ node: unwrap(node), root: true }];
    let visited = 0;
    while (stack.length && visited < 2_000) {
      const item = stack.pop();
      const current = item.node;
      if (!current || typeof current !== 'object') continue;
      visited += 1;
      if (isRequestJsonCall(current)) return true;
      if (!item.root && FUNCTION_TYPES.has(current.type)) continue;
      for (const [key, value] of Object.entries(current)) {
        if (['loc', 'start', 'end', 'extra', 'errors', 'comments', 'tokens'].includes(key)) continue;
        if (Array.isArray(value)) {
          for (const child of value) stack.push({ node: child, root: false });
        } else if (value && typeof value === 'object') stack.push({ node: value, root: false });
      }
    }
    return false;
  }

  function classifyCall(node) {
    const current = unwrap(node);
    if (current?.type !== 'CallExpression') return null;
    const called = safeName(current.callee);
    if (CONVERSIONS.has(called) && current.arguments.length) return classifyExpression(current.arguments[0]);
    if (!['MemberExpression', 'OptionalMemberExpression'].includes(current.callee?.type)
        || staticPropertyName(current.callee) !== 'get') return null;
    const receiverName = safeName(current.callee.object);
    const receiver = containerFor(current.callee.object);
    const action = entryKind === 'server-action' && actionRoots.has(receiverName);
    const search = receiver?.surface === 'search-params';
    if (!action && !search) return null;
    const field = literalString(current.arguments[0]);
    const kind = action ? 'form-data-field' : 'next-search-param';
    if (!field) {
      limit('selector_dynamic_field_unresolved', current);
      const item = descriptor(kind, 'unknown', 'unknown', module.path, current);
      addNodeFact(current, item, true);
      return item;
    }
    if (!candidateName(field)) return null;
    const item = descriptor(kind, field, 'request_selected', module.path, current);
    addNodeFact(current, item, true);
    return item;
  }

  function classifyExpression(node) {
    const current = unwrap(node);
    if (!current) return null;
    if (nodeFacts.has(current)) return nodeFacts.get(current);
    const name = safeName(current);
    if (name && facts.has(name)) return facts.get(name);
    if (name && principalSeeds.has(name)) {
      return descriptor('principal-value', name.split('.').at(-1), 'principal_derived', module.path, current);
    }
    if (['StringLiteral', 'NumericLiteral', 'BooleanLiteral', 'NullLiteral', 'BigIntLiteral'].includes(current.type)
        || (current.type === 'TemplateLiteral' && current.expressions.length === 0)) {
      return descriptor('literal-value', 'constant', 'constant', module.path, current);
    }
    if (current.type === 'CallExpression') return classifyCall(current);
    if (!['MemberExpression', 'OptionalMemberExpression'].includes(current.type)) return null;
    const container = containerFor(current.object);
    if (!container) return null;
    const field = staticPropertyName(current);
    if (!field) {
      limit('selector_dynamic_field_unresolved', current);
      const item = descriptor(container.kind, 'unknown', 'unknown', module.path, current);
      addSelector(item);
      return item;
    }
    if (!(container.allowedNames?.has(field) || candidateName(field))) return null;
    const item = descriptor(container.kind, field, container.origin, module.path, current);
    addFact(safeName(current), item, true);
    return item;
  }

  function seedParameters() {
    if (entryKind === 'server-action') {
      for (const raw of handler.params || []) {
        const parameter = parameterNode(raw);
        if (parameter?.type === 'Identifier') {
          actionRoots.add(parameter.name);
          if (candidateName(parameter.name)) {
            addFact(parameter.name, descriptor('action-parameter', parameter.name,
              'request_selected', module.path, parameter), true);
          }
        } else if (parameter?.type === 'ObjectPattern') {
          bindPattern(parameter, { surface: 'action-parameter', kind: 'action-parameter',
            origin: 'request_selected', allowedNames: null });
        }
      }
      return;
    }
    if (framework === 'express') {
      const request = parameterNode(handler.params?.[0]);
      if (request?.type === 'Identifier') requestRoots.set(request.name, { kind: 'express-request' });
      else if (request?.type === 'ObjectPattern') bindPattern(request, {
        surface: 'request-root', kind: 'express', origin: 'request_selected', allowedNames: null,
      });
      return;
    }
    if (framework === 'next-app') {
      const request = parameterNode(handler.params?.[0]);
      if (request?.type === 'Identifier') requestRoots.set(request.name, { kind: 'next-request' });
      const context = parameterNode(handler.params?.[1]);
      if (context?.type === 'Identifier') contextRoots.add(context.name);
      else if (context?.type === 'ObjectPattern') bindPattern(context, {
        surface: 'next-context', kind: 'next-route-param', origin: 'request_selected',
        allowedNames: new Set(pathNames),
      });
      return;
    }
    if (framework !== 'nestjs') return;
    for (const raw of handler.params || []) {
      const parameter = parameterNode(raw);
      for (const decorator of parameter?.decorators || []) {
        const call = decorator.expression?.type === 'CallExpression' ? decorator.expression : null;
        const local = safeName(call?.callee);
        const binding = imports.get(local);
        const kind = binding?.source === '@nestjs/common'
          ? NEST_DECORATORS.get(binding.imported) : null;
        if (!kind) continue;
        const selected = literalString(call.arguments[0]);
        if (call.arguments.length && selected === null) {
          limit('selector_dynamic_field_unresolved', call);
          if (parameter?.type === 'Identifier') {
            addFact(parameter.name, descriptor(kind, 'unknown', 'unknown', module.path, parameter), true);
          }
          continue;
        }
        if (selected !== null) {
          const allowed = kind === 'nest-path-param' ? pathNames.includes(selected) || candidateName(selected)
            : candidateName(selected);
          if (allowed && parameter?.type === 'Identifier') {
            addFact(parameter.name, descriptor(kind, selected, 'request_selected', module.path, parameter), true);
          }
          continue;
        }
        const container = { surface: kind, kind, origin: 'request_selected',
          allowedNames: kind === 'nest-path-param' ? new Set(pathNames) : null,
          location: sourceLocation(module.path, parameter) };
        if (parameter?.type === 'Identifier') addContainer(parameter.name, container);
        else if (parameter?.type === 'ObjectPattern') bindPattern(parameter, container);
      }
    }
  }

  seedParameters();
  localWalk(handler, (node) => {
    if (node.type === 'VariableDeclarator') {
      declarations.push(node);
      if (node.id?.type === 'Identifier' && node.init) {
        writes.set(node.id.name, (writes.get(node.id.name) || 0) + 1);
      }
    }
    if (node.type === 'AssignmentExpression') {
      assignments.push(node);
      if (node.left?.type === 'Identifier') writes.set(node.left.name, (writes.get(node.left.name) || 0) + 1);
    }
    if (['MemberExpression', 'OptionalMemberExpression', 'CallExpression'].includes(node.type)) {
      sourceNodes.push(node);
    }
  });
  for (let pass = 0; pass < 4; pass += 1) {
    let changed = false;
    for (const declaration of declarations) {
      if (declaration.id?.type !== 'Identifier') continue;
      const initName = safeName(declaration.init);
      if (requestRoots.has(initName) && !requestRoots.has(declaration.id.name)) {
        requestRoots.set(declaration.id.name, requestRoots.get(initName));
        changed = true;
      }
      if (contextRoots.has(initName) && !contextRoots.has(declaration.id.name)) {
        contextRoots.add(declaration.id.name);
        changed = true;
      }
      if (actionRoots.has(initName) && !actionRoots.has(declaration.id.name)) {
        actionRoots.add(declaration.id.name);
        changed = true;
      }
    }
    if (!changed) break;
  }
  const jsonCalls = sourceNodes.filter((node) => node.type === 'CallExpression' && isRequestJsonCall(node));
  const repeatedJson = jsonCalls.length > 1;
  if (repeatedJson) limit('selector_body_parse_repeated', jsonCalls[1]);

  for (let pass = 0; pass < 6; pass += 1) {
    let changed = false;
    for (const declaration of declarations) {
      const init = unwrap(declaration.init);
      const id = parameterNode(declaration.id);
      if (id?.type === 'Identifier') {
        const initName = safeName(init);
        if (requestRoots.has(initName) && !requestRoots.has(id.name)) {
          requestRoots.set(id.name, requestRoots.get(initName));
          changed = true;
        }
        if (contextRoots.has(initName) && !contextRoots.has(id.name)) {
          contextRoots.add(id.name);
          changed = true;
        }
        if (actionRoots.has(initName) && !actionRoots.has(id.name)) {
          actionRoots.add(id.name);
          changed = true;
        }
        const container = containerFor(init);
        if (container) changed = addContainer(id.name, container) || changed;
        const item = classifyExpression(init);
        if (item) changed = addFact(id.name, item) || changed;
      } else if (id?.type === 'ObjectPattern') {
        const container = containerFor(init);
        if (container) changed = bindPattern(id, container, declaration) || changed;
      }
    }
    for (const node of sourceNodes) {
      if (node.type === 'CallExpression') classifyCall(node);
      else classifyExpression(node);
    }
    for (const assignment of assignments) {
      if (assignment.left?.type !== 'Identifier') continue;
      const item = classifyExpression(assignment.right);
      if (item) changed = addFact(assignment.left.name, item) || changed;
    }
    if (!changed) break;
  }

  for (const [name, count] of writes) {
    if (count <= 1 || !facts.has(name)) continue;
    facts.set(name, { ...facts.get(name), origin: 'unknown' });
    limit('selector_alias_ambiguous');
  }
  for (const [name, fact] of facts) {
    if (fact.origin === 'request_selected' && writes.get(name) > 1) facts.set(name, { ...fact, origin: 'unknown' });
  }

  const publicSelectors = [...selectors.values()].map((item) => ({
    kind: item.kind, name: item.name, origin: item.origin, location: item.location,
  })).sort((left, right) => [left.location.path, left.location.line ?? 0, left.kind, left.name]
    .join('\0').localeCompare([right.location.path, right.location.line ?? 0, right.kind, right.name].join('\0')));
  const objectAliases = new Set([...facts].filter(([, fact]) => fact.origin === 'request_selected')
    .map(([name]) => name));
  const objectNodes = new Set([...nodeFacts].filter(([, fact]) => fact.origin === 'request_selected')
    .map(([node]) => node));
  const origins = Object.fromEntries(['request_selected', 'constant', 'principal_derived', 'unknown']
    .map((origin) => [origin, new Set([...facts].filter(([, fact]) => fact.origin === origin)
      .map(([name]) => name))]));
  const selectorGroups = publicSelectors.filter((selector) => selector.origin === 'request_selected')
    .map((selector) => ({
      selector,
      aliases: new Set([...facts].filter(([, fact]) => sameFact(fact, selector))
        .map(([name]) => name)),
      nodes: new Set([...nodeFacts].filter(([, fact]) => sameFact(fact, selector))
        .map(([node]) => node)),
    }));
  return {
    selectors: publicSelectors,
    objectAliases,
    objectNodes,
    facts,
    nodeFacts,
    origins,
    selectorGroups,
    limitations: [...limitations.values()],
  };
}
