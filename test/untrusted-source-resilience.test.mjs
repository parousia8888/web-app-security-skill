#!/usr/bin/env node
import assert from 'node:assert/strict';
import { buildJsTsModuleGraph, expressionName } from '../scripts/lib/js-ts-module-graph.mjs';

let expression = { type: 'Identifier', name: 'root' };
for (let index = 0; index < 20_000; index += 1) {
  expression = {
    type: 'MemberExpression', computed: false, object: expression,
    property: { type: 'Identifier', name: `p${index}` },
  };
}
assert.doesNotThrow(() => expressionName(expression));
assert.equal(expressionName(expression), null);

const source = `export const value = root${'.child'.repeat(100)};`;
const graph = buildJsTsModuleGraph([{ path: 'src/deep.ts', text: source }]);
assert.equal(graph.completed, false);
assert.ok(graph.modules.has('src/deep.ts'));
assert.ok(graph.reasons.some((reason) => reason.code === 'expression_name_depth_limit'
  && reason.path === 'src/deep.ts'));

const neighbor = buildJsTsModuleGraph([
  { path: 'src/deep.ts', text: source },
  { path: 'src/route.ts', text: "import express from 'express'; const app = express(); app.get('/ok', handler);" },
]);
assert.ok(neighbor.modules.get('src/route.ts')?.ast, 'a hostile neighboring file must not abort the graph');

console.log('untrusted source resilience ok: bounded expression naming and per-module continuity');
