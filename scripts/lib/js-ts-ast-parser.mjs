import { parse } from '../vendor/js-ts-parser.bundle.mjs';

const EXTENSION = /\.([cm]?[jt]sx?)$/i;

function parserPlugins(path) {
  const extension = EXTENSION.exec(path)?.[1]?.toLowerCase() || '';
  const plugins = [];
  if (extension.includes('t')) plugins.push('typescript');
  if (extension.endsWith('x')) plugins.push('jsx');
  if (extension.includes('t')) plugins.push('decorators-legacy');
  return plugins;
}

export function parseJsTsAst(path, text) {
  try {
    const ast = parse(text, {
      sourceType: 'unambiguous',
      sourceFilename: path,
      errorRecovery: false,
      allowAwaitOutsideFunction: true,
      allowReturnOutsideFunction: true,
      plugins: parserPlugins(path),
    });
    return { ast: ast.program, error: null };
  } catch (error) {
    return {
      ast: null,
      error: {
        code: 'js_ts_ast_parse_error',
        line: Number.isInteger(error?.loc?.line) ? error.loc.line : null,
      },
    };
  }
}

export function walkJsTsAst(root, visit, limits = {}) {
  const maxNodes = limits.maxNodes ?? 250_000;
  const stack = [{ node: root, parent: null, key: null }];
  let visited = 0;
  while (stack.length) {
    const { node, parent, key } = stack.pop();
    if (!node || typeof node !== 'object') continue;
    if (typeof node.type === 'string') {
      visited += 1;
      if (visited > maxNodes) return { completed: false, visited, reason: 'js_ts_ast_node_limit' };
      visit(node, parent, key);
    }
    for (const [key, value] of Object.entries(node)) {
      if (['loc', 'start', 'end', 'extra', 'errors', 'comments', 'tokens'].includes(key)) continue;
      if (Array.isArray(value)) {
        for (let index = value.length - 1; index >= 0; index -= 1) {
          stack.push({ node: value[index], parent: node, key });
        }
      } else if (value && typeof value === 'object') stack.push({ node: value, parent: node, key });
    }
  }
  return { completed: true, visited, reason: null };
}
