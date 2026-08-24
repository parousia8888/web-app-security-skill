import assert from 'node:assert/strict';
import { buildJsTsModuleGraph } from '../scripts/lib/js-ts-module-graph.mjs';

const graph = buildJsTsModuleGraph([
  { path: 'src/app.ts', text: "import router from './routes'; import { auth as guard } from '@scope/auth'; export default router;" },
  { path: 'src/routes/index.ts', text: "export const router = {}; export default router;" },
  { path: 'src/cjs.js', text: "const value = require('./routes'); module.exports = value;" },
]);
assert.equal(graph.modules.size, 3);
assert.equal(graph.modules.get('src/app.ts').imports[0].resolution.path, 'src/routes/index.ts');
assert.equal(graph.modules.get('src/app.ts').imports[1].resolution, null);
assert.equal(graph.modules.get('src/cjs.js').imports[0].bindings[0].local, 'value');
assert.equal(graph.modules.get('src/cjs.js').exports[0].exported, 'default');
assert.equal(graph.completed, true);

const aliases = buildJsTsModuleGraph([
  { path: 'apps/web/app/route.ts', text: "import { auth } from '@/auth'; import { helper } from '@workspace/security/helper';" },
  { path: 'apps/web/auth.ts', text: 'export const auth = () => true;' },
  { path: 'packages/security/src/helper.ts', text: 'export function helper() {}' },
], {
  configFiles: [{ path: 'apps/web/tsconfig.json', text: `{
    // JSONC is valid for TypeScript configuration.
    "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["./*"] }, },
  }` }],
  packageManifests: [{ path: 'packages/security/package.json', manifest: {
    name: '@workspace/security', exports: { './*': './src/*.ts' },
  } }],
});
assert.equal(aliases.modules.get('apps/web/app/route.ts').imports[0].resolution.path,
  'apps/web/auth.ts');
assert.equal(aliases.modules.get('apps/web/app/route.ts').imports[1].resolution.path,
  'packages/security/src/helper.ts');

const boundedAliases = buildJsTsModuleGraph([
  { path: 'src/app.ts', text: "import value from '@/same'; import external from 'external';" },
  { path: 'src/same.ts', text: 'export default 1;' },
  { path: 'src/same.js', text: 'export default 2;' },
], { configFiles: [{ path: 'tsconfig.json', text: '{"compilerOptions":{"paths":{"@/*":["src/*"]}}}' }] });
assert.equal(boundedAliases.modules.get('src/app.ts').imports[0].resolution.reason,
  'module_alias_resolution_ambiguous');
assert.equal(boundedAliases.modules.get('src/app.ts').imports[1].resolution, null);

const broken = buildJsTsModuleGraph([
  { path: 'src/broken.ts', text: 'const value: =' },
  { path: 'src/dynamic.ts', text: 'const module = import(name);' },
]);
assert.equal(broken.completed, false);
assert.ok(broken.reasons.some((item) => item.code === 'js_ts_ast_parse_error'));
assert.ok(broken.reasons.some((item) => item.code === 'dynamic_import_unresolved'));

const ambiguous = buildJsTsModuleGraph([
  { path: 'src/app.ts', text: "import value from './same';" },
  { path: 'src/same.ts', text: 'export default 1;' },
  { path: 'src/same.js', text: 'export default 2;' },
]);
assert.equal(ambiguous.modules.get('src/app.ts').imports[0].resolution.reason,
  'module_resolution_ambiguous');
assert.ok(ambiguous.reasons.some((item) => item.code === 'module_resolution_ambiguous'));

const limited = buildJsTsModuleGraph([
  { path: 'src/a.ts', text: "import './b';" }, { path: 'src/b.ts', text: 'export default 1;' },
], { maxEdges: 0 });
assert.ok(limited.reasons.some((item) => item.code === 'module_graph_edge_limit'));

const escaped = buildJsTsModuleGraph([
  { path: '../outside.ts', text: 'export default 1;' },
  { path: 'src/safe.ts', text: 'export default 2;' },
]);
assert.equal(escaped.modules.has('../outside.ts'), false);
assert.ok(escaped.reasons.some((item) => item.code === 'source_path_escape'));

console.log('js/ts module graph ok: ESM bindings, local resolution, ambiguity and fail-closed limits');
