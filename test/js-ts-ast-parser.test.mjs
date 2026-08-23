import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { parseJsTsAst, walkJsTsAst } from '../scripts/lib/js-ts-ast-parser.mjs';

for (const [path, source] of [
  ['src/app.js', 'export const value = { ok: true };'],
  ['src/view.jsx', 'export const View = () => <main>{value}</main>;'],
  ['src/model.ts', 'export interface Model { id: string };'],
  ['src/controller.tsx', '@sealed\nclass Controller { render(): JSX.Element { return <main />; } }'],
  ['src/nest-controller.ts', "class Controller { method(@Param('id') id: string) {} }"],
]) {
  const parsed = parseJsTsAst(path, source);
  assert.equal(parsed.error, null, `${path}: ${JSON.stringify(parsed.error)}`);
  let nodes = 0;
  const walked = walkJsTsAst(parsed.ast, () => { nodes += 1; });
  assert.equal(walked.completed, true);
  assert.ok(nodes > 1);
}

assert.equal(parseJsTsAst('src/broken.ts', 'const value: =').error.code, 'js_ts_ast_parse_error');
const limited = parseJsTsAst('src/large.js', 'const value = { nested: { ok: true } };');
assert.equal(walkJsTsAst(limited.ast, () => {}, { maxNodes: 1 }).reason, 'js_ts_ast_node_limit');

const manifest = JSON.parse(readFileSync(new URL(
  '../scripts/vendor/js-ts-parser.manifest.json', import.meta.url), 'utf8'));
const bundle = readFileSync(new URL('../scripts/vendor/js-ts-parser.bundle.mjs', import.meta.url));
assert.equal(manifest.component, '@babel/parser');
assert.equal(manifest.version, '7.28.4');
assert.equal(manifest.license, 'MIT');
assert.equal(createHash('sha256').update(bundle).digest('hex'), manifest.sha256);

console.log('js/ts ast parser ok: js, jsx, ts, tsx, fail-closed errors, node limit and bundle digest');
