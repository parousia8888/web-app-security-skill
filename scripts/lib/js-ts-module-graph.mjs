import { posix } from 'node:path';
import { parseJsTsAst, walkJsTsAst } from './js-ts-ast-parser.mjs';
import {
  prismaGeneratorRecords, resolveGeneratedProviderImport,
} from './prisma-generator-evidence.mjs';

const EXTENSIONS = ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts'];
const CONFIG_NAMES = new Set(['tsconfig.json', 'jsconfig.json']);
const VITE_CONFIG_NAME = /^vite\.config\.[cm]?[jt]s$/i;
const MAX_EXPRESSION_NAME_DEPTH = 64;

export function literalString(node) {
  if (node?.type === 'StringLiteral') return node.value;
  if (node?.type === 'TemplateLiteral' && node.expressions.length === 0) {
    return node.quasis.map((item) => item.value.cooked ?? item.value.raw).join('');
  }
  return null;
}

export function expressionName(node, depth = 0) {
  if (!node) return null;
  if (depth >= MAX_EXPRESSION_NAME_DEPTH) return null;
  if (node.type === 'ThisExpression') return 'this';
  if (node.type === 'Identifier') return node.name;
  if ((node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') && !node.computed) {
    const left = expressionName(node.object, depth + 1);
    const right = expressionName(node.property, depth + 1);
    return left && right ? `${left}.${right}` : null;
  }
  if ((node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') && node.computed) {
    const property = literalString(node.property);
    const left = expressionName(node.object, depth + 1);
    return left && property ? `${left}.${property}` : null;
  }
  return null;
}

function expressionNameDepthExceeded(node) {
  const pending = [{ node, depth: 0 }];
  while (pending.length) {
    const current = pending.pop();
    if (!current.node) continue;
    const member = current.node.type === 'MemberExpression'
      || current.node.type === 'OptionalMemberExpression';
    if (!member) continue;
    if (current.depth >= MAX_EXPRESSION_NAME_DEPTH) return true;
    pending.push({ node: current.node.object, depth: current.depth + 1 });
    if (!current.node.computed) pending.push({ node: current.node.property, depth: current.depth + 1 });
  }
  return false;
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

function unwrapExpression(node) {
  let current = node;
  while (['TSAsExpression', 'TSSatisfiesExpression', 'TypeCastExpression',
    'TSNonNullExpression', 'ParenthesizedExpression'].includes(current?.type)) current = current.expression;
  return current;
}

function staticObjectKey(property) {
  if (property?.type !== 'ObjectProperty' || property.computed) return null;
  return property.key?.type === 'Identifier' ? property.key.name : literalString(property.key);
}

function exactObjectValue(object, key) {
  if (object?.type !== 'ObjectExpression') return null;
  let value = null;
  for (const property of object.properties) {
    if (property.type === 'SpreadElement') {
      if (value !== null) return null;
      continue;
    }
    if (staticObjectKey(property) === key) value = unwrapExpression(property.value);
  }
  return value;
}

function topLevelDeclarations(ast) {
  const values = new Map();
  for (const statement of ast?.body || []) {
    if (statement.type !== 'VariableDeclaration') continue;
    for (const declaration of statement.declarations) {
      if (declaration.id?.type === 'Identifier' && declaration.init) {
        values.set(declaration.id.name, unwrapExpression(declaration.init));
      }
    }
  }
  return values;
}

function functionDeclarations(node) {
  const values = new Map();
  if (node?.body?.type !== 'BlockStatement') return values;
  for (const statement of node.body.body) {
    if (statement.type !== 'VariableDeclaration') continue;
    for (const declaration of statement.declarations) {
      if (declaration.id?.type === 'Identifier' && declaration.init) {
        values.set(declaration.id.name, unwrapExpression(declaration.init));
      }
    }
  }
  return values;
}

function returnedObject(callback) {
  const body = unwrapExpression(callback?.body);
  if (body?.type === 'ObjectExpression') return body;
  if (body?.type !== 'BlockStatement') return null;
  const returns = body.body.filter((statement) => statement.type === 'ReturnStatement');
  if (returns.length !== 1) return null;
  const returned = unwrapExpression(returns[0].argument);
  return returned?.type === 'ObjectExpression' ? returned : null;
}

function configObject(ast) {
  const defineBindings = new Set();
  for (const statement of ast?.body || []) {
    if (statement.type !== 'ImportDeclaration'
        || !['vite', 'vitest/config'].includes(literalString(statement.source))) continue;
    for (const specifier of statement.specifiers || []) {
      if (specifier.type === 'ImportSpecifier' && expressionName(specifier.imported) === 'defineConfig') {
        defineBindings.add(specifier.local?.name);
      }
    }
  }
  const candidates = [];
  walkJsTsAst(ast, (node) => {
    if (node.type !== 'CallExpression' || !defineBindings.has(expressionName(node.callee))
        || node.arguments.length !== 1) return;
    const argument = unwrapExpression(node.arguments[0]);
    if (argument?.type === 'ObjectExpression') candidates.push({ object: argument, declarations: new Map() });
    else if (['ArrowFunctionExpression', 'FunctionExpression'].includes(argument?.type)) {
      const object = returnedObject(argument);
      if (object) candidates.push({ object, declarations: functionDeclarations(argument) });
    }
  });
  return candidates.length === 1 ? candidates[0] : null;
}

function pathBindings(ast) {
  const direct = new Set();
  const namespaces = new Set();
  for (const statement of ast?.body || []) {
    if (statement.type !== 'ImportDeclaration'
        || !['path', 'node:path'].includes(literalString(statement.source))) continue;
    for (const specifier of statement.specifiers || []) {
      if (specifier.type === 'ImportSpecifier'
          && ['resolve', 'join'].includes(expressionName(specifier.imported))) direct.add(specifier.local?.name);
      if (specifier.type === 'ImportNamespaceSpecifier') namespaces.add(specifier.local?.name);
    }
  }
  return { direct, namespaces };
}

function exactSourcePath(node, directory, bindings) {
  const expression = unwrapExpression(node);
  const direct = literalString(expression);
  if (direct !== null) return safeModulePath(posix.join(directory, direct));
  if (expression?.type !== 'CallExpression') return null;
  const callee = expressionName(expression.callee);
  const accepted = bindings.direct.has(callee)
    || [...bindings.namespaces].some((name) => callee === `${name}.resolve` || callee === `${name}.join`);
  if (!accepted || expression.arguments.length < 2
      || expressionName(expression.arguments[0]) !== '__dirname') return null;
  const segments = expression.arguments.slice(1).map((argument) => literalString(unwrapExpression(argument)));
  if (segments.some((segment) => segment === null)) return null;
  return safeModulePath(posix.join(directory, ...segments));
}

function keyPattern(node, declarations, depth = 0) {
  if (!node || depth > 16) return null;
  const expression = unwrapExpression(node);
  const literal = literalString(expression);
  if (literal !== null) return [{ type: 'literal', value: literal }];
  if (expression?.type === 'Identifier' && declarations.has(expression.name)) {
    return keyPattern(declarations.get(expression.name), declarations, depth + 1);
  }
  if (expression?.type === 'TemplateLiteral') {
    const parts = [];
    for (let index = 0; index < expression.quasis.length; index += 1) {
      parts.push({ type: 'literal', value: expression.quasis[index].value.cooked
        ?? expression.quasis[index].value.raw });
      if (index < expression.expressions.length) parts.push({ type: 'dynamic' });
    }
    return parts;
  }
  if (expression?.type === 'BinaryExpression' && expression.operator === '+') {
    const left = keyPattern(expression.left, declarations, depth + 1);
    const right = keyPattern(expression.right, declarations, depth + 1);
    return left && right ? [...left, ...right] : null;
  }
  return null;
}

function patternMayEqual(parts, key) {
  if (!parts) return true;
  let source = '^';
  for (const part of parts) source += part.type === 'dynamic' ? '.*'
    : part.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`${source}$`, 'u').test(key);
}

function reduceCannotDefineKey(call, key) {
  const expression = unwrapExpression(call);
  if (expression?.type !== 'CallExpression' || expressionName(expression.callee?.property) !== 'reduce'
      || expression.arguments.length < 2) return false;
  const callback = unwrapExpression(expression.arguments[0]);
  const initial = unwrapExpression(expression.arguments[1]);
  const accumulator = callback?.params?.[0]?.name;
  if (!accumulator || callback.body?.type !== 'BlockStatement'
      || initial?.type !== 'ObjectExpression' || initial.properties.length !== 0) return false;
  const declarations = functionDeclarations(callback);
  let returned = false;
  for (const statement of callback.body.body) {
    if (statement.type === 'VariableDeclaration') continue;
    if (statement.type === 'ReturnStatement' && expressionName(statement.argument) === accumulator) {
      returned = true;
      continue;
    }
    const assignment = statement.type === 'ExpressionStatement'
      ? unwrapExpression(statement.expression) : null;
    if (assignment?.type !== 'AssignmentExpression' || assignment.operator !== '='
        || assignment.left?.type !== 'MemberExpression' || !assignment.left.computed
        || expressionName(assignment.left.object) !== accumulator
        || patternMayEqual(keyPattern(assignment.left.property, declarations), key)) return false;
  }
  return returned;
}

function spreadCannotDefineKey(node, key, declarations, depth = 0) {
  if (!node || depth > 16) return false;
  const expression = unwrapExpression(node);
  if (expression?.type === 'Identifier' && declarations.has(expression.name)) {
    return spreadCannotDefineKey(declarations.get(expression.name), key, declarations, depth + 1);
  }
  if (expression?.type === 'ObjectExpression') {
    return expression.properties.every((property) => property.type === 'SpreadElement'
      ? spreadCannotDefineKey(property.argument, key, declarations, depth + 1)
      : staticObjectKey(property) !== null && staticObjectKey(property) !== key);
  }
  return reduceCannotDefineKey(expression, key);
}

function exactInputValue(input, name, declarations) {
  if (input?.type !== 'ObjectExpression') return null;
  let value = null;
  for (const property of input.properties) {
    if (property.type === 'SpreadElement') {
      if (!spreadCannotDefineKey(property.argument, name, declarations)) value = null;
      continue;
    }
    if (staticObjectKey(property) === name) value = unwrapExpression(property.value);
  }
  return value;
}

function outputPatterns(output) {
  const values = output?.type === 'ArrayExpression' ? output.elements.map(unwrapExpression)
    : [unwrapExpression(output)];
  const patterns = [];
  for (const value of values) {
    if (value?.type !== 'ObjectExpression') return [];
    const pattern = literalString(exactObjectValue(value, 'entryFileNames'));
    if (pattern === null || (pattern.match(/\[name\]/g) || []).length !== 1
        || pattern.replace('[name]', '').match(/\[[^\]]+\]/)) return [];
    patterns.push(pattern);
  }
  return [...new Set(patterns)];
}

function buildEntryRecords(configFiles, limits) {
  const records = [];
  for (const input of (configFiles || []).slice(0, limits.maxResolutionConfigs)) {
    const path = safeModulePath(input.path);
    if (!path || !VITE_CONFIG_NAME.test(posix.basename(path))) continue;
    const parsed = parseJsTsAst(path, input.text);
    if (parsed.error) continue;
    const config = configObject(parsed.ast);
    if (!config) continue;
    const build = exactObjectValue(config.object, 'build');
    const rollup = exactObjectValue(build, 'rollupOptions');
    const inputObject = exactObjectValue(rollup, 'input');
    const patterns = outputPatterns(exactObjectValue(rollup, 'output'));
    const outDir = literalString(exactObjectValue(build, 'outDir')) ?? 'dist';
    if (inputObject?.type !== 'ObjectExpression' || !patterns.length || typeof outDir !== 'string') continue;
    const directory = posix.dirname(path);
    const outputDirectory = safeModulePath(posix.join(directory, outDir));
    if (!outputDirectory) continue;
    records.push({
      path, directory, outputDirectory, patterns, inputObject,
      declarations: new Map([...topLevelDeclarations(parsed.ast), ...config.declarations]),
      pathBindings: pathBindings(parsed.ast),
    });
  }
  return records;
}

function builtWorkspaceSource(record, target, files, builds) {
  const clean = target.replace(/^\.\//, '');
  const outputPath = safeModulePath(posix.join(record.directory, clean));
  if (!outputPath) return { paths: [], escaped: true };
  const paths = [];
  for (const build of builds.filter((candidate) => candidate.directory === record.directory)) {
    if (outputPath !== build.outputDirectory
        && !outputPath.startsWith(`${build.outputDirectory}/`)) continue;
    const relative = posix.relative(build.outputDirectory, outputPath);
    for (const pattern of build.patterns) {
      const [prefix, suffix] = pattern.split('[name]');
      if (!relative.startsWith(prefix) || !relative.endsWith(suffix)
          || relative.length < prefix.length + suffix.length) continue;
      const name = relative.slice(prefix.length, relative.length - suffix.length);
      const value = exactInputValue(build.inputObject, name, build.declarations);
      const source = exactSourcePath(value, build.directory, build.pathBindings);
      if (source && files.has(source)) paths.push(source);
    }
  }
  return { paths: [...new Set(paths)], escaped: false };
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

function resolveWorkspace(specifier, files, packages, builds) {
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
    } else {
      const built = builtWorkspaceSource(record, target, files, builds);
      resolved.push(...built.paths);
      escaped = escaped || built.escaped;
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
      || resolveWorkspace(specifier, files, context.packages, context.builds);
  }
  const base = safeModulePath(posix.join(posix.dirname(fromPath), specifier));
  const resolved = resolveBase(base, files);
  if (resolved.path) return resolved;
  return resolveGeneratedProviderImport(fromPath, specifier, context.generatedProviders) || resolved;
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
    if ((node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression')
        && expressionNameDepthExceeded(node)) reasons.push('expression_name_depth_limit');
    if (node.type === 'ImportDeclaration') {
      const source = literalString(node.source);
      const bindings = node.specifiers.map((specifier) => ({
        local: specifier.local?.name || null,
        imported: specifier.type === 'ImportDefaultSpecifier' ? 'default'
          : specifier.type === 'ImportNamespaceSpecifier' ? '*'
            : expressionName(specifier.imported),
        kind: specifier.type,
        typeOnly: node.importKind === 'type' || specifier.importKind === 'type',
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
          typeOnly: node.exportKind === 'type' || specifier.exportKind === 'type',
        }));
        const resolution = source ? resolveLocal(path, source, files, context) : null;
        imports.push({ source, bindings, resolution });
        if (resolution?.reason) reasons.push(resolution.reason);
      }
      if (node.declaration?.id?.name) exports.push({
        exported: node.declaration.id.name,
        local: node.declaration.id.name,
        node: node.declaration,
        typeOnly: node.exportKind === 'type',
      });
      for (const declaration of node.declaration?.declarations || []) {
        if (declaration.id?.name) exports.push({
          exported: declaration.id.name,
          local: declaration.id.name,
          node: declaration,
          typeOnly: node.exportKind === 'type',
        });
      }
      for (const specifier of node.specifiers || []) {
        exports.push({
          exported: expressionName(specifier.exported),
          local: expressionName(specifier.local),
          node: specifier,
          typeOnly: node.exportKind === 'type' || specifier.exportKind === 'type',
        });
      }
    }
    if (node.type === 'ExportAllDeclaration') {
      const source = literalString(node.source);
      const resolution = source ? resolveLocal(path, source, files, context) : null;
      imports.push({ source, bindings: [], resolution });
      if (resolution?.reason) reasons.push(resolution.reason);
    }
    if (node.type === 'AssignmentExpression') {
      const left = expressionName(node.left);
      if (left === 'module.exports') exports.push({
        exported: 'default', local: expressionName(node.right), node: node.right, typeOnly: false,
      });
      else if (left?.startsWith('exports.')) exports.push({
        exported: left.slice(8), local: expressionName(node.right), node: node.right, typeOnly: false,
      });
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
    builds: buildEntryRecords(options.configFiles || [], limits),
    generatedProviders: prismaGeneratorRecords(options.providerFiles || []),
  };
  for (const [path, text] of fileMap) {
    if (modules.size >= limits.maxModules) {
      reasons.push({ code: 'module_graph_module_limit', path });
      break;
    }
    let module;
    try {
      module = collectModule(path, text, fileMap, limits, context);
    } catch {
      module = {
        path, text, ast: null, imports: [], exports: [], reasons: ['js_ts_module_analysis_failed'],
      };
    }
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
