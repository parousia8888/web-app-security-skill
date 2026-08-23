import { existsSync, mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';

const MAX_GIT_OUTPUT = 32 * 1024 * 1024;
const LOCKFILE_NAMES = new Set([
  'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock',
  'bun.lockb', 'uv.lock', 'poetry.lock', 'Pipfile.lock',
]);
const PATH_LEVEL_RULES = new Set(['sensitive-env-file-present', 'tracked-sensitive-env-file']);
const GLOBAL_INTEGRITY_REASONS = new Set([
  'directory_unreadable', 'depth_limit_reached', 'entry_limit_reached', 'file_limit_reached',
]);

const posix = (value) => value.split(sep).join('/');

function git(cwd, args, options = {}) {
  const result = spawnSync('git', args, {
    cwd, encoding: options.encoding || 'utf8', maxBuffer: MAX_GIT_OUTPUT,
  });
  if (result.error) throw new Error(`Git could not run: ${result.error.message}`);
  if (result.status !== 0) {
    const detail = String(result.stderr || result.stdout || '').trim().split('\n')[0];
    throw new Error(detail || `Git exited ${result.status}`);
  }
  return result.stdout;
}

function safeRef(ref) {
  if (!ref || ref.startsWith('-') || ref.length > 512 || /[\u0000-\u001f\u007f]/.test(ref)) {
    throw new Error('--since requires a non-option Git ref without control characters');
  }
  return ref;
}

function parseNameStatus(output) {
  const fields = output.split('\0');
  if (fields.at(-1) === '') fields.pop();
  const changes = [];
  for (let index = 0; index < fields.length;) {
    const status = fields[index++];
    if (!/^(?:[ACDMRTUXB][0-9]{0,3}|[ACDMRTUXB])$/.test(status)) {
      throw new Error(`Git returned an unsupported diff status: ${status || '(empty)'}`);
    }
    const renamed = /^[RC]/.test(status);
    const previousPath = renamed ? fields[index++] : null;
    const path = fields[index++];
    if (!path || (renamed && !previousPath)) throw new Error('Git returned an incomplete changed path');
    changes.push({ status, path: posix(path), previousPath: previousPath ? posix(previousPath) : null });
  }
  return changes;
}

function hunkRanges(patch) {
  const added = [];
  let deletedLines = 0;
  for (const line of patch.split('\n')) {
    const match = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(line);
    if (!match) continue;
    deletedLines += Number(match[2] ?? 1);
    const start = Number(match[3]);
    const count = Number(match[4] ?? 1);
    if (count > 0) added.push({ start, end: start + count - 1 });
  }
  return { added, deletedLines };
}

function insideRoot(root, target) {
  const rel = relative(root, target);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..');
}

function diffArgs(kind, baseCommit, tail) {
  return ['diff', ...(kind === 'staged' ? ['--cached'] : []), ...tail, baseCommit, '--', '.'];
}

export function createGitDiffScope(projectRoot, options) {
  const root = realpathSync(resolve(projectRoot));
  const kind = options?.mode;
  if (!['since', 'staged'].includes(kind)) throw new Error('diff mode must be since or staged');
  if (git(root, ['rev-parse', '--is-inside-work-tree']).trim() !== 'true') {
    throw new Error('diff-scoped audit requires a Git working tree');
  }
  const repositoryRoot = realpathSync(resolve(git(root, ['rev-parse', '--show-toplevel']).trim()));
  if (!insideRoot(repositoryRoot, root)) throw new Error('project root is outside the Git working tree');
  const baseExpression = kind === 'since' ? `${safeRef(options.ref)}^{commit}` : 'HEAD^{commit}';
  const baseCommit = git(root, ['rev-parse', '--verify', '--end-of-options', baseExpression]).trim();
  if (!/^[a-f0-9]{40,64}$/.test(baseCommit)) throw new Error('Git did not resolve an immutable base commit');

  const statusOutput = git(root, diffArgs(kind, baseCommit, [
    '--name-status', '-z', '--find-renames', '--no-ext-diff', '--relative',
  ]));
  const changes = parseNameStatus(statusOutput);
  let addedLineCount = 0;
  for (const change of changes) {
    if (change.status.startsWith('D')) {
      change.added = [];
      change.contentChanged = true;
      continue;
    }
    if (change.status === 'R100' || change.status === 'C100') {
      change.added = [];
      change.contentChanged = false;
      continue;
    }
    const patch = git(root, [
      'diff', ...(kind === 'staged' ? ['--cached'] : []), '--unified=0', '--no-color',
      '--no-ext-diff', '--find-renames', baseCommit, '--',
      ...(change.previousPath ? [change.previousPath] : []), change.path,
    ]);
    const hunks = hunkRanges(patch);
    change.added = hunks.added;
    change.contentChanged = hunks.added.length > 0 || hunks.deletedLines > 0 || !change.status.startsWith('R');
    addedLineCount += hunks.added.reduce((count, range) => count + range.end - range.start + 1, 0);
  }

  let auditRoot = root;
  let temporaryRoot = null;
  if (kind === 'staged') {
    temporaryRoot = mkdtempSync(join(tmpdir(), 'web-app-security-index-'));
    git(repositoryRoot, ['checkout-index', '--all', `--prefix=${temporaryRoot}${sep}`]);
    const projectRelative = relative(repositoryRoot, root);
    auditRoot = projectRelative ? join(temporaryRoot, projectRelative) : temporaryRoot;
    if (!existsSync(auditRoot)) {
      rmSync(temporaryRoot, { recursive: true, force: true });
      throw new Error('the Git index contains no files in the selected project');
    }
  }

  const untrackedFilesExcluded = kind === 'since'
    ? git(root, ['ls-files', '--others', '--exclude-standard', '-z', '--', '.'])
      .split('\0').filter(Boolean).length
    : 0;
  const byPath = new Map(changes.map((change) => [change.path, change]));
  return {
    auditRoot,
    selection: {
      mode: kind,
      baseCommit,
      snapshotKind: kind === 'staged' ? 'git_index' : 'working_tree',
      changedFileCount: changes.length,
      addedLineCount,
      untrackedFilesExcluded,
    },
    changes,
    byPath,
    cleanup() {
      if (temporaryRoot) rmSync(temporaryRoot, { recursive: true, force: true });
    },
  };
}

function lineAdded(change, line) {
  return Number.isInteger(line) && change.added.some((range) => line >= range.start && line <= range.end);
}

function isDependencyInput(path) {
  const name = basename(path);
  return name === 'package.json' || name === 'pyproject.toml' || name === 'pnpm-workspace.yaml'
    || LOCKFILE_NAMES.has(name);
}

function dependencyInputAffects(manifestPath, changedPath) {
  if (!isDependencyInput(changedPath)) return false;
  if (changedPath === manifestPath) return true;
  const inputDirectory = posix(dirname(changedPath));
  const manifestDirectory = posix(dirname(manifestPath));
  return inputDirectory === '.' || manifestDirectory === inputDirectory
    || manifestDirectory.startsWith(`${inputDirectory}/`);
}

function integrityRelevant(audit, changedPaths) {
  return (audit.integrityIssues || []).some((issue) =>
    GLOBAL_INTEGRITY_REASONS.has(issue.code) || changedPaths.has(issue.path));
}

export function selectDiffFindings(audit, diffScope) {
  const changedPaths = new Set(diffScope.changes.filter((change) => !change.status.startsWith('D'))
    .map((change) => change.path));
  return audit.findings.filter((finding) => {
    if (finding.ruleId === 'source-evidence-incomplete') return integrityRelevant(audit, changedPaths);
    if (finding.ruleId === 'source-stack-unsupported') return diffScope.changes.length > 0;
    if (finding.ruleId === 'dependency-lockfile-missing') {
      const manifestPath = finding.location?.path || finding.evidence?.subject;
      return diffScope.changes.some((change) => dependencyInputAffects(manifestPath, change.path));
    }
    const path = finding.location?.path;
    if (!path) return false;
    const change = diffScope.byPath.get(path);
    if (!change || change.status.startsWith('D') || !change.contentChanged) return false;
    if (PATH_LEVEL_RULES.has(finding.ruleId)) return true;
    return lineAdded(change, finding.location?.line);
  });
}

export function selectDiffRoutes(routes, diffScope) {
  const changedPaths = new Set(diffScope.changes.filter((change) =>
    !change.status.startsWith('D') && change.contentChanged).map((change) => change.path));
  return routes.filter((route) => {
    if (changedPaths.has(route.location?.path)) return true;
    for (const control of [route.authentication, route.authorization]) {
      if ((control?.signals || []).some((signal) => changedPaths.has(signal.location?.path))) return true;
    }
    return false;
  });
}
