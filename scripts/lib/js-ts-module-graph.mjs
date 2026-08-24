import { posix } from 'node:path';
import { parseJsTsAst, walkJsTsAst } from './js-ts-ast-parser.mjs';

const EXTENSIONS = ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts'];
const CONFIG_NAMES = new Set(['tsconfig.json', 'jsconfig.json']);

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

function resolveBase(base, files, reasons = {}) {
  if (!base) return { path: null, reason: reasons.escape || 'module_path_escape' };
  const candidates = [base];
  if (!EXTENSIONS.some((extension) => base.endsWith(extension))) {
    for (const extension of EXTENSIONS) candidates.push(`${base}${extension}`);
    for (const extension of EXTENSIONS) candidates.push(posix.join(base, `index${extension}`));
  }
  const matches = [...new Set(candidates.filter((candidate) => files.has(candidate)))];
  if (matches.length === 1) return { path: matches[0], reason: null };
  return { path: null, reason: matches.length
    ? (reasons.ambiguous || 'module_resolution_ambiguous')
    : (reasons.missing || 'module_resolution_missing') };
}

function stripJsonComments(text) {
  let output = '';
  let string = false;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let index = 0; index < text.length; index += 1) {
    const current = text[index];
    const next = text[index + 1];
    if (lineComment) {
      if (current === '\n' || current === '\r') {
        lineComment = false;
        output += current;
      } else output += ' ';
      continue;
    }
    if (blockComment) {
      if (current === '*' && next === '/') {
        output += '  ';
        index += 1;
        blockComment = false;
      } else output += current === '\n' || current === '\r' ? current : ' ';
      continue;
    }
    if (string) {
      output += current;
      if (escaped) escaped = false;
      else if (current === '\\') escaped = true;
      else if (current === '"') string = false;
      continue;
    }
    if (current === '"') {
      string = true;
      output += current;
    } else if (current === '/' && next === '/') {
      output += '  ';
      index += 1;
      lineComment = true;
    } else if (current === '/' && next === '*') {
      output += '  ';
      index += 1;
      blockComment = true;
    } else output += current;
  }
  if (string || blockComment) throw new Error('unterminated JSONC token');
  return output;
}

function removeTrailingJsonCommas(text) {
  let output = '';
  let string = false;
  let escaped = false;
  for (let index = 0; index < text.length; index += 1) {
    const current = text[index];
    if (string) {
      output += current;
      if (escaped) escaped = false;
      else if (current === '\\') escaped = true;
      else if (current === '"') string = false;
      continue;
    }
    if (current === '"') {
      string = true;
      output += current;
      continue;
    }
    if (current === ',') {
      let cursor = index + 1;
      while (/\s/.test(text[cursor] || '')) cursor += 1;
      if (text[cursor] === '}' || text[cursor] === ']') continue;
    }
    output += current;
  }
  return output;
}

function parseJsonConfig(text) {
  return JSON.parse(removeTrailingJsonCommas(stripJsonComments(text)));
}

function aliasPatternMatch(pattern, specifier) {
  const first = pattern.indexOf('*');
  if (first < 0) return pattern === specifier ? { wildcard: '', specificity: pattern.length + 10_000 } : null;
  if (first !== pattern.lastIndexOf('*')) return null;
  const prefix = pattern.slice(0, first);
  const suffix = pattern.slice(first + 1);
  if (!specifier.startsWith(prefix) || !specifier.endsWith(suffix)
      || specifier.length < prefix.length + suffix.length) return null;
  return { wildcard: specifier.slice(prefix.length, specifier.length - suffix.length),
    specificity: prefix.length + suffix.length };
}

function configRecords(configFiles, reasons, limits) {
  const records = [];
  for (const input of (configFiles || []).slice(0, limits.maxResolutionConfigs)) {
    const path = safeModulePath(input.path);
    if (!path || !CONFIG_NAMES.has(posix.basename(path))) continue;
    try {
      const parsed = parseJsonConfig(input.text);
      const compiler = parsed?.compilerOptions;
      if (!compiler || typeof compiler !== 'object' || Array.isArray(compiler)) continue;
      const configDirectory = posix.dirname(path);
      const baseUrl = compiler.baseUrl === undefined ? '.' : compiler.baseUrl;
      if (typeof baseUrl !== 'string') {
        reasons.push({ code: 'module_config_base_url_invalid', path });
        continue;
      }
      const base = safeModulePath(posix.join(configDirectory, baseUrl));
      if (!base) {
        reasons.push({ code: 'module_config_path_escape', path });
        continue;
      }
      const aliases = [];
      if (compiler.paths !== undefined && (!compiler.paths || typeof compiler.paths !== 'object'
          || Array.isArray(compiler.paths))) {
        reasons.push({ code: 'module_config_paths_invalid', path });
        continue;
      }
      for (const [pattern, targets] of Object.entries(compiler.paths || {})) {
        if (typeof pattern !== 'string' || !Array.isArray(targets)
            || targets.some((target) => typeof target !== 'string')
            || (pattern.match(/\*/g) || []).length > 1
            || targets.some((target) => (target.match(/\*/g) || []).length > 1)) {
          reasons.push({ code: 'module_config_alias_invalid', path });
          continue;
        }
        aliases.push({ pattern, targets });
      }
      records.push({ path, directory: configDirectory, base, aliases });
    } catch {
      reasons.push({ code: 'module_config_parse_error', path });
    }
  }
  if ((configFiles || []).length > limits.maxResolutionConfigs) {
    reasons.push({ code: 'module_config_limit', path: '<module-configs>' });
  }
  return records;
}

function nearestConfig(fromPath, configs) {
  const directory = posix.dirname(fromPath);
  const applicable = configs.filter((config) => config.directory === '.'
    || directory === config.directory || directory.startsWith(`${config.directory}/`));
  applicable.sort((left, right) => right.directory.length - left.directory.length
    || (posix.basename(left.path) === 'tsconfig.json' ? -1 : 1));
  return applicable[0] || null;
}

function resolveAlias(fromPath, specifier, files, configs) {
  const config = nearestConfig(fromPath, configs);
  if (!config) return null;
  const matches = config.aliases.map((alias) => ({ alias,
    match: aliasPatternMatch(alias.pattern, specifier) })).filter((item) => item.match)
    .sort((left, right) => right.match.specificity - left.match.specificity);
  if (!matches.length) return null;
  const selected = matches[0];
  const resolved = [];
  let escaped = false;
  for (const target of selected.alias.targets) {
    const value = target.includes('*') ? target.replace('*', selected.match.wildcard) : target;
    const base = safeModulePath(posix.join(config.base, value));
    if (!base) {
      escaped = true;
      continue;
    }
    const candidate = resolveBase(base, files, {
      missing: 'module_alias_resolution_missing', ambiguous: 'module_alias_resolution_ambiguous',
      escape: 'module_alias_path_escape',
    });
    if (candidate.path) resolved.push(candidate.path);
    else if (candidate.reason === 'module_alias_resolution_ambiguous') {
      return { path: null, reason: candidate.reason };
    }
  }
  const unique = [...new Set(resolved)];
  if (unique.length === 1) return { path: unique[0], reason: null };
  if (unique.length > 1) return { path: null, reason: 'module_alias_resolution_ambiguous' };
  return { path: null, reason: escaped ? 'module_alias_path_escape' : 'module_alias_resolution_missing' };
}

function packageNameFor(specifier) {
  if (!specifier || specifier.startsWith('.') || specifier.startsWith('/') || specifier.startsWith('#')) return null;
  const parts = specifier.split('/');
  return specifier.startsWith('@') ? parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null : parts[0];
}

function stringTargets(value) {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(stringTargets);
  if (!value || typeof value !== 'object') return [];
  return ['import', 'default', 'require', 'types'].flatMap((key) => stringTargets(value[key]));
}

function exportTargets(exportsField, subpath) {
  if (typeof exportsField === 'string' || Array.isArray(exportsField)) {
    return subpath === '.' ? stringTargets(exportsField) : [];
  }
  if (!exportsField || typeof exportsField !== 'object') return [];
  const entries = Object.entries(exportsField);
  if (!entries.some(([key]) => key.startsWith('.'))) return subpath === '.' ? stringTargets(exportsField) : [];
  if (Object.hasOwn(exportsField, subpath)) return stringTargets(exportsField[subpath]);
  const matches = entries.flatMap(([pattern, value]) => {
    const matched = aliasPatternMatch(pattern, subpath);
    if (!matched || !pattern.includes('*')) return [];
    return stringTargets(value).map((target) => target.includes('*')
      ? target.replace('*', matched.wildcard) : target);
  });
  return matches;
}

function workspaceRecords(packageManifests, reasons, limits) {
  const byName = new Map();
  for (const input of (packageManifests || []).slice(0, limits.maxResolutionPackages)) {
    const path = safeModulePath(input.path);
    const manifest = input.manifest;
    if (!path || posix.basename(path) !== 'package.json' || !manifest
        || typeof manifest.name !== 'string') continue;
    const record = { path, directory: posix.dirname(path), manifest };
    if (!byName.has(manifest.name)) byName.set(manifest.name, []);
    byName.get(manifest.name).push(record);
  }
  if ((packageManifests || []).length > limits.maxResolutionPackages) {
    reasons.push({ code: 'workspace_package_limit', path: '<package-manifests>' });
  }
  return byName;
}

function resolveWorkspace(specifier, files, packages) {
  const name = packageNameFor(specifier);
  const records = name ? packages.get(name) : null;
  if (!records) return null;
  if (records.length !== 1) return { path: null, reason: 'workspace_package_ambiguous' };
  const record = records[0];
  const suffix = specifier.slice(name.length);
  const subpath = suffix ? `.${suffix}` : '.';
  let targets = exportTargets(record.manifest.exports, subpath);
  if (!targets.length && record.manifest.exports === undefined) {
    if (subpath === '.') targets = [record.manifest.module, record.manifest.main, './index']
      .filter((value) => typeof value === 'string');
    else targets = [subpath.slice(1)];
  }
  const resolved = [];
  let escaped = false;
  for (const target of targets) {
    const clean = target.replace(/^\.\//, '');
    const base = safeModulePath(posix.join(record.directory, clean));
    if (!base) {
      escaped = true;
      continue;
    }
    const candidate = resolveBase(base, files, {
      missing: 'workspace_export_resolution_missing', ambiguous: 'workspace_export_resolution_ambiguous',
      escape: 'workspace_export_path_escape',
    });
    if (candidate.path) resolved.push(candidate.path);
    else if (candidate.reason === 'workspace_export_resolution_ambiguous') {
      return { path: null, reason: candidate.reason };
    }
  }
  const unique = [...new Set(resolved)];
  if (unique.length === 1) return { path: unique[0], reason: null };
  if (unique.length > 1) return { path: null, reason: 'workspace_export_resolution_ambiguous' };
  return { path: null, reason: escaped ? 'workspace_export_path_escape'
    : 'workspace_export_resolution_missing' };
}

function resolveLocal(fromPath, specifier, files, context) {
  if (!specifier.startsWith('.')) {
    return resolveAlias(fromPath, specifier, files, context.configs)
      || resolveWorkspace(specifier, files, context.packages);
  }
  const base = safeModulePath(posix.join(posix.dirname(fromPath), specifier));
  return resolveBase(base, files);
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

function collectModule(path, text, files, limits, context) {
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
      const resolution = source ? resolveLocal(path, source, files, context) : null;
      imports.push({ source, bindings, resolution });
      if (resolution?.reason) reasons.push(resolution.reason);
    }
    if (node.type === 'CallExpression' && expressionName(node.callee) === 'require'
        && node.arguments.length === 1) {
      const source = literalString(node.arguments[0]);
      if (source) {
        const bindings = parent?.type === 'VariableDeclarator' ? patternBindings(parent.id) : [];
        const resolution = resolveLocal(path, source, files, context);
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
        const resolution = source ? resolveLocal(path, source, files, context) : null;
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
    maxResolutionConfigs: options.maxResolutionConfigs ?? 250,
    maxResolutionPackages: options.maxResolutionPackages ?? 1_000,
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
  const context = {
    configs: configRecords(options.configFiles || [], reasons, limits),
    packages: workspaceRecords(options.packageManifests || [], reasons, limits),
  };
  for (const [path, text] of fileMap) {
    if (modules.size >= limits.maxModules) {
      reasons.push({ code: 'module_graph_module_limit', path });
      break;
    }
    const module = collectModule(path, text, fileMap, limits, context);
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
