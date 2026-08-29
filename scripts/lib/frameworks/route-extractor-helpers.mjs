import { posix } from 'node:path';
import { walkJsTsAst } from '../js-ts-ast-parser.mjs';
import { expressionName, literalString } from '../js-ts-module-graph.mjs';
import { controlEvidence, routeScopedControlEvidence } from '../route-security-model.mjs';

export { expressionName, literalString, walkJsTsAst };

export function importedBindings(module) {
  const bindings = new Map();
  for (const item of module.imports) {
    for (const binding of item.bindings) {
      if (!binding.local) continue;
      bindings.set(binding.local, {
        source: item.source,
        imported: binding.imported,
        resolvedPath: item.resolution?.path || null,
        resolutionReason: item.resolution?.reason || null,
        generatedProvider: item.resolution?.generatedProvider || null,
        providerEvidencePath: item.resolution?.providerEvidencePath || null,
        typeOnly: Boolean(binding.typeOnly),
      });
    }
  }
  return bindings;
}

export function callName(node) {
  return node?.type === 'CallExpression' || node?.type === 'OptionalCallExpression'
    ? expressionName(node.callee) : null;
}

export function functionName(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if (['FunctionExpression', 'ArrowFunctionExpression', 'FunctionDeclaration'].includes(node.type)) {
    return node.id?.name || '<inline>';
  }
  return expressionName(node);
}

export function sourceLocation(path, node) {
  return { path, line: node?.loc?.start?.line ?? null };
}

export function joinRoutePath(...parts) {
  const usable = parts.filter((part) => typeof part === 'string' && part.length);
  if (!usable.length) return '/';
  return `/${usable.map((part) => part.replace(/^\/+|\/+$/g, '')).filter(Boolean).join('/')}`
    .replace(/\/{2,}/g, '/') || '/';
}

export function pathKind(path, dynamic = false) {
  if (dynamic) return 'dynamic';
  if (!path) return 'unknown';
  return /:\w+|\[[^\]]+\]|\*/.test(path) ? 'parameterized' : 'static';
}

export function objectAddressedPath(path) {
  return Boolean(path && (/:((?:id|.*Id))(?:\/|$)/i.test(path)
    || /\[(?:\.\.\.)?(?:id|.*Id)\]/i.test(path)));
}

export function controlFromSignals(signals, inherited = false, role = 'authentication') {
  const label = role === 'authorization' ? 'authorization' : 'authentication';
  if (!signals.length) return controlEvidence('not_observed', [],
    `No supported ${label} control signal was observed within this static boundary.`);
  const exact = signals.filter((signal) => signal.exact);
  const chosen = exact.length ? exact : signals;
  const state = exact.length ? (inherited ? 'inherited_observed' : 'local_observed') : 'candidate_observed';
  return controlEvidence(state, chosen.map(({ exact: _exact, role: _role, ...signal }) => signal), exact.length
    ? `A supported static ${label} construct was observed; runtime enforcement and correctness are not proved.`
    : `A structurally relevant ${label} candidate is visible, but runtime behavior was not resolved.`);
}

export function routeScopeFromSignals(classifiedSignals, unknownSignals) {
  return routeScopedControlEvidence(classifiedSignals, unknownSignals);
}

export function aggregateReasons(items) {
  const grouped = new Map();
  for (const item of items) {
    const entry = grouped.get(item.code) || { code: item.code, count: 0, samplePaths: [] };
    entry.count += 1;
    if (item.path && entry.samplePaths.length < 10 && !entry.samplePaths.includes(item.path)) {
      entry.samplePaths.push(item.path);
    }
    grouped.set(item.code, entry);
  }
  return [...grouped.values()].sort((a, b) => a.code.localeCompare(b.code));
}

const RELATION_ONLY_GRAPH_REASONS = new Set([
  'module_resolution_missing', 'module_resolution_ambiguous', 'dynamic_import_unresolved',
  'module_alias_resolution_missing', 'module_alias_resolution_ambiguous',
  'workspace_export_resolution_missing', 'workspace_export_resolution_ambiguous',
  'module_alias_path_escape', 'module_config_alias_invalid', 'module_config_base_url_invalid',
  'module_config_limit', 'module_config_parse_error', 'module_config_path_escape',
  'module_config_paths_invalid', 'workspace_export_path_escape', 'workspace_package_ambiguous',
  'workspace_package_limit',
]);

export function structuralGraphReasons(graph) {
  return graph.reasons.filter((item) => !RELATION_ONLY_GRAPH_REASONS.has(item.code));
}

export function localModuleExport(graph, modulePath, imported) {
  const module = graph.modules.get(modulePath);
  if (!module) return null;
  const match = module.exports.find((item) => item.exported === imported && !item.typeOnly);
  return match?.local || null;
}

export function safeRelativeImportPath(path) {
  const normalized = posix.normalize(path);
  return normalized.startsWith('../') || posix.isAbsolute(normalized) ? null : normalized;
}
