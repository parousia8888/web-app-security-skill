import { createHash } from 'node:crypto';
import { lstatSync, realpathSync, readdirSync, statSync } from 'node:fs';
import { isAbsolute, posix, relative, resolve, sep } from 'node:path';

export const MANDATORY_EXCLUDED_DIRECTORIES = Object.freeze([
  '.git', '.webapp-security',
]);

export const DEFAULT_EXCLUDED_DIRECTORIES = Object.freeze([
  '.git', '.hg', '.svn', '.next', '.nuxt', '.output', '.webapp-security', 'build',
  'coverage', 'dist', 'node_modules', 'target', 'vendor', '__pycache__', '.venv', 'venv',
]);

const MAX_ROOTS = 128;
const MAX_EXCLUSIONS = 256;

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, stableValue(item)]));
  }
  return value;
}

function digestValue(value) {
  return createHash('sha256').update(JSON.stringify(stableValue(value))).digest('hex');
}

function normalizeRelative(value, label, { root = false } = {}) {
  if (typeof value !== 'string' || !value || value.length > 4096 || isAbsolute(value)
      || /[\u0000-\u001f\u007f\\]/.test(value)) throw new Error(`${label} is invalid`);
  if (root && value === '.') return value;
  if (value === '.' || value === '..' || value.startsWith('../') || value.includes('//')
      || value.endsWith('/') || posix.normalize(value) !== value
      || value.split('/').some((segment) => !segment || segment === '.' || segment === '..')) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function uniqueBounded(values, label, limit, normalize) {
  if (!Array.isArray(values) || !values.length && label === 'sourceRoots'
      || values.length > limit) throw new Error(`${label} must be a bounded array`);
  const normalized = values.map((value) => normalize(value));
  if (new Set(normalized).size !== normalized.length) throw new Error(`${label} contains duplicates`);
  return normalized;
}

function inside(root, candidate) {
  const path = relative(root, candidate);
  return path === '' || (path !== '..' && !path.startsWith(`..${sep}`) && !isAbsolute(path));
}

function relativePath(value) {
  return value.split(sep).join('/');
}

export function normalizedAuditBoundary(auditBoundary) {
  if (!auditBoundary || typeof auditBoundary !== 'object' || Array.isArray(auditBoundary)) {
    throw new Error('audit boundary is invalid');
  }
  const sourceRoots = uniqueBounded(auditBoundary.sourceRoots, 'sourceRoots', MAX_ROOTS,
    (value) => normalizeRelative(value, 'source root', { root: true }));
  const recordedExclusions = uniqueBounded(
    auditBoundary.excludedDirectories || [], 'excludedDirectories', MAX_EXCLUSIONS,
    (value) => {
      const normalized = normalizeRelative(value, 'excluded directory');
      if (normalized.includes('/')) throw new Error('excluded directory must be a basename');
      return normalized;
    },
  );
  const excludedDirectories = [...recordedExclusions];
  for (const value of MANDATORY_EXCLUDED_DIRECTORIES) {
    if (!excludedDirectories.includes(value)) excludedDirectories.push(value);
  }
  return { ...auditBoundary, sourceRoots, excludedDirectories };
}

export function compileAuditScope(projectRoot, auditBoundary) {
  const root = realpathSync(resolve(projectRoot));
  if (!statSync(root).isDirectory()) throw new Error('scope project root is not a directory');
  const boundary = normalizedAuditBoundary(auditBoundary);
  const recordedExclusions = new Set(auditBoundary.excludedDirectories || []);
  const exclusions = new Set(boundary.excludedDirectories);
  const roots = [];
  for (const path of boundary.sourceRoots) {
    const absolute = resolve(root, path);
    if (!inside(root, absolute)) throw new Error(`source root escapes project: ${path}`);
    let real;
    try {
      if (lstatSync(absolute).isSymbolicLink()) throw new Error('symlink root');
      real = realpathSync(absolute);
      if (!inside(root, real) || !statSync(real).isDirectory()) throw new Error('outside project');
      readdirSync(real);
    } catch {
      throw new Error(`source root is unavailable: ${path}`);
    }
    const normalized = relativePath(relative(root, real)) || '.';
    if (normalized.split('/').some((segment) => exclusions.has(segment))) {
      throw new Error(`source root is excluded: ${path}`);
    }
    roots.push({ path: normalized, absolute: real });
  }
  roots.sort((left, right) => left.path.length - right.path.length || left.path.localeCompare(right.path));
  const effectiveRoots = roots.filter((candidate, index) => !roots.slice(0, index).some((parent) =>
    parent.path === '.' || candidate.path === parent.path || candidate.path.startsWith(`${parent.path}/`)));

  const classify = (input) => {
    let path;
    try { path = normalizeRelative(input, 'scope path', { root: true }); } catch {
      return { included: false, reason: 'scope_path_invalid', path: null };
    }
    const segments = path === '.' ? [] : path.split('/');
    const excluded = segments.find((segment) => exclusions.has(segment));
    if (excluded) return {
      included: false,
      reason: recordedExclusions.has(excluded)
        ? 'scope_excluded_directory' : 'mandatory_engine_exclusion',
      path,
      excludedDirectory: excluded,
    };
    const included = effectiveRoots.some((sourceRoot) => sourceRoot.path === '.'
      || path === sourceRoot.path || path.startsWith(`${sourceRoot.path}/`));
    return { included, reason: included ? 'scope_included' : 'outside_source_roots', path };
  };

  const governingInputs = (manifests = [], lockfiles = []) => {
    const output = [];
    for (const input of [...manifests, ...lockfiles]) {
      const classified = classify(input);
      if (classified.included) {
        output.push({ path: classified.path, mode: 'source_input' });
        continue;
      }
      let normalized;
      try { normalized = normalizeRelative(input, 'governing input'); } catch { continue; }
      if (normalized.split('/').some((segment) => exclusions.has(segment))) continue;
      const directory = posix.dirname(normalized);
      const governs = effectiveRoots.some((sourceRoot) => sourceRoot.path !== '.'
        && (directory === '.' || sourceRoot.path === directory
          || sourceRoot.path.startsWith(`${directory}/`)));
      if (governs) output.push({ path: normalized, mode: 'governing_input' });
    }
    return [...new Map(output.map((entry) => [entry.path, entry])).values()]
      .sort((left, right) => left.path.localeCompare(right.path));
  };

  return Object.freeze({
    projectRoot: root,
    boundary: Object.freeze(boundary),
    roots: Object.freeze(effectiveRoots.map((entry) => Object.freeze({ ...entry }))),
    excludedDirectoryNames: Object.freeze([...exclusions]),
    recordedExcludedDirectoryNames: Object.freeze([...recordedExclusions]),
    includes: (path) => classify(path).included,
    classify,
    governingInputs,
    scopeDigest: digestValue(boundary),
    restricted: !(effectiveRoots.length === 1 && effectiveRoots[0].path === '.'
      && DEFAULT_EXCLUDED_DIRECTORIES.every((value) => exclusions.has(value))
      && exclusions.size === DEFAULT_EXCLUDED_DIRECTORIES.length),
  });
}
