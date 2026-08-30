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

const nodeExportWildcards = buildJsTsModuleGraph([
  {
    path: 'apps/web/route.ts',
    text: "import value from '@workspace/pattern/features/a$b/c.d';",
  },
  {
    path: 'packages/pattern/src/a$b/c.d/entry.a$b/c.d.js',
    text: 'export default true;',
  },
], {
  packageManifests: [{ path: 'packages/pattern/package.json', manifest: {
    name: '@workspace/pattern',
    exports: { './features/*': './src/*/entry.*.js' },
  } }],
});
assert.equal(nodeExportWildcards.modules.get('apps/web/route.ts').imports[0].resolution.path,
  'packages/pattern/src/a$b/c.d/entry.a$b/c.d.js',
  'Node package exports replace every RHS wildcard with the same captured subpath');

const conditionalExports = buildJsTsModuleGraph([
  { path: 'apps/web/same.ts', text: "import value from '@workspace/same';" },
  { path: 'packages/same/src/index.ts', text: 'export default true;' },
  { path: 'apps/web/different.ts', text: "import value from '@workspace/different';" },
  { path: 'packages/different/src/node.ts', text: 'export default true;' },
  { path: 'packages/different/src/browser.ts', text: 'export default true;' },
  { path: 'apps/web/fallback.ts', text: "import value from '@workspace/fallback';" },
  { path: 'packages/fallback/src/index.ts', text: 'export default true;' },
], {
  packageManifests: [
    { path: 'packages/same/package.json', manifest: {
      name: '@workspace/same', exports: { '.': {
        node: './src/index.ts', custom: './src/index.ts', default: './src/index.ts',
      } },
    } },
    { path: 'packages/different/package.json', manifest: {
      name: '@workspace/different', exports: { '.': {
        node: { import: './src/node.ts' }, custom: './src/browser.ts',
      } },
    } },
    { path: 'packages/fallback/package.json', manifest: {
      name: '@workspace/fallback', exports: { '.': [null, './missing.ts', './src/index.ts'] },
    } },
  ],
});
assert.equal(conditionalExports.modules.get('apps/web/same.ts').imports[0].resolution.path,
  'packages/same/src/index.ts', 'different conditions resolving to one source remain exact');
assert.equal(conditionalExports.modules.get('apps/web/different.ts').imports[0].resolution.reason,
  'workspace_export_resolution_ambiguous',
  'unknown runtime conditions resolving to different sources fail closed');
assert.equal(conditionalExports.modules.get('apps/web/fallback.ts').imports[0].resolution.path,
  'packages/fallback/src/index.ts', 'array fallback retains the one existing exact target');

const invalidTypeScriptWildcard = buildJsTsModuleGraph([
  { path: 'src/app.ts', text: "import value from '@/feature';" },
  { path: 'src/feature/entry/feature.ts', text: 'export default true;' },
], {
  configFiles: [{ path: 'tsconfig.json', text: JSON.stringify({
    compilerOptions: { paths: { '@/*': ['src/*/entry/*'] } },
  }) }],
});
assert.equal(invalidTypeScriptWildcard.modules.get('src/app.ts').imports[0].resolution, null,
  'TypeScript path targets with more than one wildcard stay outside the supported contract');
assert.ok(invalidTypeScriptWildcard.reasons.some((item) => item.code === 'module_config_alias_invalid'));

const replacementTextAlias = buildJsTsModuleGraph([
  { path: 'src/app.ts', text: "import value from '@/a$b';" },
  { path: 'src/a$b.ts', text: 'export default true;' },
], {
  configFiles: [{ path: 'tsconfig.json', text: JSON.stringify({
    compilerOptions: { paths: { '@/*': ['src/*'] } },
  }) }],
});
assert.equal(replacementTextAlias.modules.get('src/app.ts').imports[0].resolution.path,
  'src/a$b.ts', 'TypeScript one-wildcard replacement treats dollar text literally');

const builtWorkspace = buildJsTsModuleGraph([
  { path: 'apps/web/route.ts', text: "import { prisma } from '@workspace/database';" },
  { path: 'packages/database/src/index.ts', text: 'export const prisma = {};' },
], {
  packageManifests: [{ path: 'packages/database/package.json', manifest: {
    name: '@workspace/database', exports: { '.': {
      import: './dist/index.js', require: './dist/index.cjs', types: './dist/index.d.ts',
    } },
  } }],
  configFiles: [{ path: 'packages/database/vite.config.ts', text: `
import { resolve } from 'node:path';
import { defineConfig } from 'vite';
const generated = ['migration/a.ts'].reduce((acc, file) => {
  const entryName = \`\${file}/migration\`;
  acc[entryName] = resolve(__dirname, file);
  return acc;
}, {});
export default defineConfig(async () => ({
  build: { rollupOptions: {
    input: { index: resolve(__dirname, 'src/index.ts'), ...generated },
    output: [{ entryFileNames: '[name].js' }, { entryFileNames: '[name].cjs' }],
  } },
}));
` }],
});
assert.equal(builtWorkspace.modules.get('apps/web/route.ts').imports[0].resolution.path,
  'packages/database/src/index.ts');

const ambiguousBuiltWorkspace = buildJsTsModuleGraph([
  { path: 'apps/web/route.ts', text: "import { prisma } from '@workspace/database';" },
  { path: 'packages/database/src/index.ts', text: 'export const prisma = {};' },
], {
  packageManifests: [{ path: 'packages/database/package.json', manifest: {
    name: '@workspace/database', exports: './dist/index.js',
  } }],
  configFiles: [{ path: 'packages/database/vite.config.ts', text: `
import { resolve } from 'node:path';
import { defineConfig } from 'vite';
export default defineConfig({ build: { rollupOptions: {
  input: { index: resolve(__dirname, 'src/index.ts'), ...unknownEntries },
  output: { entryFileNames: '[name].js' },
} } });
` }],
});
assert.equal(ambiguousBuiltWorkspace.modules.get('apps/web/route.ts').imports[0].resolution.reason,
  'workspace_export_resolution_missing');

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

const exportAll = buildJsTsModuleGraph([
  { path: 'src/barrel.ts', text: "export * from './target';" },
  { path: 'src/target.ts', text: 'export function target() {}' },
]);
assert.equal(exportAll.modules.get('src/barrel.ts').imports[0].resolution.path, 'src/target.ts');

const typeOnly = buildJsTsModuleGraph([
  { path: 'src/consumer.ts', text: "import type { Client } from './types';" },
  { path: 'src/types.ts', text: 'export type Client = unknown;' },
]);
assert.equal(typeOnly.modules.get('src/consumer.ts').imports[0].bindings[0].typeOnly, true);
assert.equal(typeOnly.modules.get('src/types.ts').exports[0].typeOnly, true);

const escaped = buildJsTsModuleGraph([
  { path: '../outside.ts', text: 'export default 1;' },
  { path: 'src/safe.ts', text: 'export default 2;' },
]);
assert.equal(escaped.modules.has('../outside.ts'), false);
assert.ok(escaped.reasons.some((item) => item.code === 'source_path_escape'));

console.log('js/ts module graph ok: ESM bindings, local resolution, ambiguity and fail-closed limits');
