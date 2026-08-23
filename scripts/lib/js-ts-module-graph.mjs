import { posix } from 'node:path';
import { parseJsTsAst, walkJsTsAst } from './js-ts-ast-parser.mjs';

const EXTENSIONS = ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts'];

export function literalString(node) {
  if (node?.type === 'StringLiteral') return node.value;
  if (node?.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis.map((item) => item.value.cooked ?? item.value.raw).join('');
  }
  return null;
}

export function expressionName(node) {
  if (!node) return null;
  if (node.type === 'ThisExpression') return 'this';
  if (node.type === 'Identifier') return node.name;
  if ((node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') && !node.computed) {
    const left = expressionName(node.object);
    const right = expressionName(node.property);
    return left && right ? `${left}.${right}` : null;
  }
  if ((node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') && node.computed) {
    const property = literalString(node.property);
    const left = expressionName(node.object);
    return left && property ? `${left}.${property}` : null;
  }
  return null;
}

function safeModulePath(path) {
  const normalized = posix.normalize(path.replace(/\\/g, '/'));
  return !normalized.startsWith('../') && normalized !== '..' && !posix.isAbsolute(normalized)
    ? normalized : null;
}

function resolveLocal(fromPath, specifier, files) {
  if (!specifier.startsWith('.')) return null;
  const base = safeModulePath(posix.join(posix.dirname(fromPath), specifier));
  if (!base) return { path: null, reason: 'module_path_escape' };
  const candidates = [base];
  if (!EXTENSIONS.some((extension) => base.endsWith(extension))) {
    for (const extension of EXTENSIONS) candidates.push(`${base}${extension}`);
    for (const extension of EXTENSIONS) candidates.push(posix.join(base, `index${extension}`));
  }
  const matches = candidates.filter((candidate) => files.has(candidate));
  if (matches.length === 1) return { path: matches[0], reason: null };
  return { path: null, reason: matches.length ? 'module_resolution_ambiguous' : 'module_resolution_missing' };
}

function patternBindings(pattern) {
  if (pattern?.type === 'Identifier') return [{ local: pattern.name, imported: 'default', kind: 'CommonJSDefault' }];
  if (pattern?.type !== 'ObjectPattern') return [];
  return pattern.properties.flatMap((property) => {
    if (property.type !== 'ObjectProperty') return [];
    const imported = expressionName(property.key);
    const local = expressionName(property.value);
    return imported && local ? [{ local, imported, kind: 'CommonJSNamed' }] : [];
  });
}

function collectModule(path, text, files, limits) {
  const parsed = parseJsTsAst(path, text);
  if (parsed.error) return { path, text, ast: null, imports: [], exports: [], reasons: [parsed.error.code] };
  const imports = [];
  const exports = [];
  const reasons = [];
  const walked = walkJsTsAst(parsed.ast, (node, parent) => {
    if (node.type === 'ImportDeclaration') {
      const source = literalString(node.source);
      const bindings = node.specifiers.map((specifier) => ({
        local: specifier.local?.name || null,
        imported: specifier.type === 'ImportDefaultSpecifier' ? 'default'
          : specifier.type === 'ImportNamespaceSpecifier' ? '*'
            : expressionName(specifier.imported),
        kind: specifier.type,
      }));
      const resolution = source ? resolveLocal(path, source, files) : null;
      imports.push({ source, bindings, resolution });
      if (resolution?.reason) reasons.push(resolution.reason);
    }
    if (node.type === 'CallExpression' && expressionName(node.callee) === 'require'
        && node.arguments.length === 1) {
      const source = literalString(node.arguments[0]);
      if (source) {
        const bindings = parent?.type === 'VariableDeclarator' ? patternBindings(parent.id) : [];
        const resolution = resolveLocal(path, source, files);
        imports.push({ source, bindings, resolution });
        if (resolution?.reason) reasons.push(resolution.reason);
      }
    }
    if (node.type === 'CallExpression' && node.callee?.type === 'Import') reasons.push('dynamic_import_unresolved');
    if (node.type === 'ExportDefaultDeclaration') {
      exports.push({ exported: 'default', local: expressionName(node.declaration), node: node.declaration });
    }
    if (node.type === 'ExportNamedDeclaration') {
      if (node.source) {
        const source = literalString(node.source);
        const bindings = node.specifiers.map((specifier) => ({
          local: expressionName(specifier.exported), imported: expressionName(specifier.local),
          kind: 'ExportNamedReexport',
        }));
        const resolution = source ? resolveLocal(path, source, files) : null;
        imports.push({ source, bindings, resolution });
        if (resolution?.reason) reasons.push(resolution.reason);
      }
      if (node.declaration?.id?.name) exports.push({ exported: node.declaration.id.name, local: node.declaration.id.name, node: node.declaration });
      for (const declaration of node.declaration?.declarations || []) {
        if (declaration.id?.name) exports.push({ exported: declaration.id.name, local: declaration.id.name, node: declaration });
      }
      for (const specifier of node.specifiers || []) {
        exports.push({ exported: expressionName(specifier.exported), local: expressionName(specifier.local), node: specifier });
      }
    }
    if (node.type === 'AssignmentExpression') {
      const left = expressionName(node.left);
      if (left === 'module.exports') exports.push({ exported: 'default', local: expressionName(node.right), node: node.right });
      else if (left?.startsWith('exports.')) exports.push({ exported: left.slice(8), local: expressionName(node.right), node: node.right });
    }
  }, { maxNodes: limits.maxNodesPerFile });
  if (!walked.completed) reasons.push(walked.reason);
  return { path, text, ast: parsed.ast, imports, exports, reasons: [...new Set(reasons)] };
}

export function buildJsTsModuleGraph(sourceFiles, options = {}) {
  const limits = {
    maxModules: options.maxModules ?? 5_000,
    maxEdges: options.maxEdges ?? 20_000,
    maxNodesPerFile: options.maxNodesPerFile ?? 250_000,
  };
  const fileMap = new Map();
  const reasons = [];
  for (const file of sourceFiles) {
    const path = safeModulePath(file.path);
    if (!path) {
      reasons.push({ code: 'source_path_escape', path: '<unsafe-source-path>' });
      continue;
    }
    if (fileMap.has(path)) reasons.push({ code: 'duplicate_source_path', path });
    else fileMap.set(path, file.text);
  }
  const modules = new Map();
  let edgeCount = 0;
  for (const [path, text] of fileMap) {
    if (modules.size >= limits.maxModules) {
      reasons.push({ code: 'module_graph_module_limit', path });
      break;
    }
    const module = collectModule(path, text, fileMap, limits);
    edgeCount += module.imports.length;
    if (edgeCount > limits.maxEdges) {
      module.reasons.push('module_graph_edge_limit');
      reasons.push({ code: 'module_graph_edge_limit', path });
    }
    modules.set(path, module);
    for (const reason of module.reasons) reasons.push({ code: reason, path });
  }
  return {
    modules,
    completed: reasons.length === 0,
    reasons,
    counts: { discovered: sourceFiles.length, parsed: [...modules.values()].filter((item) => item.ast).length,
      incomplete: new Set(reasons.map((item) => item.path)).size, edges: edgeCount },
  };
}
