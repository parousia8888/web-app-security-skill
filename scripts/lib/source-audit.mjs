import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { createFinding } from './evidence.mjs';
import {
  classifyJsTsSource, inspectJsTsSource, JS_TS_SOURCE_RULE_IDS,
} from './js-ts-source-audit.mjs';
import {
  classifyPythonSource, inspectPythonSource, PYTHON_SOURCE_RULE_IDS,
} from './python-source-audit.mjs';
import { DEFAULT_SOURCE_TRAVERSAL_LIMITS, sourceTraversalLimits } from './project-identity.mjs';
import { createSourceAnalysisSession, sourceAnalysisLimits } from './source-analysis-budget.mjs';
import { analyzeRouteSecurity, ROUTE_INTEGRITY_RULE_ID } from './route-security-audit.mjs';
import { SOURCE_RULES } from './source-rules.mjs';

const IGNORED = new Set([
  '.git', '.hg', '.svn', '.next', '.nuxt', '.output', '.webapp-security', 'build', 'coverage',
  'dist', 'node_modules', 'target', 'vendor', '__pycache__', '.venv', 'venv',
]);
const CONFIG_FILES = /^(?:next|vite|nuxt|svelte|astro)\.config\.(?:js|mjs|cjs|ts)$/;
const ENV_FILE = /^\.env(?:\.[a-z0-9_-]+)?$/i;
const ENV_TEMPLATE = /^\.env\.(?:example|sample|template|dist|defaults)$/i;
const MAX_REASON_SAMPLES = 10;
const SOURCE_RULE_IDS = SOURCE_RULES.map((rule) => rule.id);
const ANALYSIS_LIMIT_CODES = new Set([
  'source_token_limit', 'source_operation_limit', 'source_global_operation_limit',
]);

const posix = (value) => value.split(sep).join('/');

function samplePath(value) {
  const clean = posix(value || '.').replace(/^\.\//, '').replace(/[\u0000-\u001f\u007f]/g, '?');
  return clean.length > 160 ? `${clean.slice(0, 143)}-${Buffer.from(clean).toString('hex').slice(-16)}` : clean;
}

function addReason(tracker, code, path) {
  let reason = tracker.reasonMap.get(code);
  if (!reason) {
    reason = { code, count: 0, samplePaths: [] };
    tracker.reasonMap.set(code, reason);
  }
  reason.count += 1;
  const sample = samplePath(path);
  if (reason.samplePaths.length < MAX_REASON_SAMPLES && !reason.samplePaths.includes(sample)) {
    reason.samplePaths.push(sample);
  }
}

function tracker() {
  return {
    counts: { discovered: 0, eligible: 0, scanned: 0, excluded: 0, skipped: 0, truncated: 0, errors: 0 },
    reasonMap: new Map(),
    statusOverride: null,
  };
}

function account(trackerState, outcome, code, path) {
  trackerState.counts.discovered += 1;
  if (outcome === 'excluded') {
    trackerState.counts.excluded += 1;
  } else {
    trackerState.counts.eligible += 1;
    trackerState.counts[outcome] += 1;
  }
  if (code) addReason(trackerState, code, path);
}

function resultFor(trackerState) {
  const incomplete = trackerState.counts.skipped + trackerState.counts.truncated + trackerState.counts.errors;
  return {
    status: trackerState.statusOverride
      || (incomplete ? (trackerState.counts.scanned ? 'partial' : 'unavailable') : 'completed'),
    counts: trackerState.counts,
    reasons: [...trackerState.reasonMap.values()].sort((left, right) => left.code.localeCompare(right.code)),
  };
}

function trackedSensitiveEnvFiles(root) {
  const options = { encoding: 'utf8', timeout: 5000, maxBuffer: 4 * 1024 * 1024, windowsHide: true };
  const identity = spawnSync('git', ['-C', root, 'rev-parse', '--is-inside-work-tree'], options);
  if (identity.error) {
    return { status: 'unavailable', code: identity.error.code === 'ETIMEDOUT'
      ? 'git_identity_timeout' : 'git_command_unavailable', paths: [] };
  }
  if (identity.status !== 0 || identity.stdout.trim() !== 'true') {
    if (identity.status === 128) return { status: 'not_applicable', code: 'not_git_repository', paths: [] };
    return { status: 'unavailable', code: 'git_identity_failed', paths: [] };
  }
  const listed = spawnSync('git', ['-C', root, 'ls-files', '-z', '--cached', '--', '.'], options);
  if (listed.error) {
    return { status: 'unavailable', code: listed.error.code === 'ETIMEDOUT'
      ? 'git_index_timeout' : 'git_index_unavailable', paths: [] };
  }
  if (listed.status !== 0) return { status: 'unavailable', code: 'git_index_failed', paths: [] };
  const paths = listed.stdout.split('\0').filter(Boolean).map(posix).filter((path) => {
    const name = path.split('/').at(-1);
    return ENV_FILE.test(name) && !ENV_TEMPLATE.test(name);
  });
  return { status: 'completed', code: null, paths: [...new Set(paths)].sort() };
}

function walk(root, limits) {
  const files = [];
  const events = [];
  let entriesSeen = 0;
  let stopped = false;

  function event(outcome, code, path) {
    events.push({ outcome, code, path: samplePath(path) });
  }

  function visit(directory, depth) {
    if (stopped) return;
    let entries;
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      event('errors', 'directory_unreadable', posix(relative(root, directory)) || '.');
      return;
    }
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
      const absolute = join(directory, entry.name);
      const path = posix(relative(root, absolute));
      entriesSeen += 1;
      if (entriesSeen > limits.maxEntries) {
        event('truncated', 'entry_limit_reached', path);
        stopped = true;
        break;
      }
      if (entry.isSymbolicLink()) {
        event('excluded', 'symlink_not_followed', path);
        continue;
      }
      if (entry.isDirectory()) {
        if (IGNORED.has(entry.name)) {
          event('excluded', 'policy_excluded_directory', path);
        } else if (depth >= limits.maxDepth) {
          event('truncated', 'depth_limit_reached', path);
        } else {
          visit(absolute, depth + 1);
        }
      } else if (entry.isFile()) {
        if (files.length >= limits.maxFiles) {
          event('truncated', 'file_limit_reached', path);
          stopped = true;
          break;
        }
        files.push({ absolute, path, name: entry.name });
      } else {
        event('excluded', 'unsupported_file_type', path);
      }
    }
  }
  visit(root, 0);
  return { files, events, entriesSeen: Math.min(entriesSeen, limits.maxEntries), stopped };
}

function readText(file, maxFileBytes) {
  try {
    if (statSync(file.absolute).size > maxFileBytes) {
      return { outcome: 'truncated', code: 'file_size_limit', text: null };
    }
    const bytes = readFileSync(file.absolute);
    if (bytes.includes(0)) return { outcome: 'skipped', code: 'unsupported_encoding', text: null };
    return { outcome: 'scanned', code: null, text: new TextDecoder('utf-8', { fatal: true }).decode(bytes) };
  } catch (error) {
    return error?.code === 'EACCES' || error?.code === 'EPERM'
      ? { outcome: 'errors', code: 'file_unreadable', text: null }
      : error instanceof TypeError
        ? { outcome: 'skipped', code: 'unsupported_encoding', text: null }
        : { outcome: 'errors', code: 'file_read_error', text: null };
  }
}

function lineOf(text, index) {
  return text.slice(0, index).split('\n').length;
}

function patchLine(path, text, match, replacement) {
  const line = text.slice(0, match.index).split('\n').length;
  const before = match[0];
  const after = before.replace(match[1], replacement);
  return `--- a/${path}\n+++ b/${path}\n@@ line ${line} @@\n-${before}\n+${after}\n`;
}

function workspacePatterns(manifest) {
  if (Array.isArray(manifest.workspaces)) return manifest.workspaces;
  if (Array.isArray(manifest.workspaces?.packages)) return manifest.workspaces.packages;
  return [];
}

function yamlContentBeforeComment(value) {
  let quote = null;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (quote === '"' && character === '\\') {
      index += 1;
      continue;
    }
    if (quote && character === quote) quote = null;
    else if (!quote && (character === "'" || character === '"')) quote = character;
    else if (!quote && character === '#') return value.slice(0, index);
  }
  if (quote) throw new Error('unterminated quoted scalar');
  return value;
}

function pnpmWorkspaceScalar(value) {
  const clean = yamlContentBeforeComment(value).trim();
  if (!clean) throw new Error('empty workspace pattern');
  if (clean.startsWith("'")) {
    if (!clean.endsWith("'") || clean.length < 2) throw new Error('invalid single-quoted pattern');
    return clean.slice(1, -1).replace(/''/g, "'");
  }
  if (clean.startsWith('"')) {
    const parsed = JSON.parse(clean);
    if (typeof parsed !== 'string') throw new Error('workspace pattern must be a string');
    return parsed;
  }
  if (/^[\[\]{}>,|&*@`]/.test(clean) || /:\s/.test(clean)) {
    throw new Error('unsupported workspace pattern syntax');
  }
  return clean;
}

function parsePnpmWorkspacePatterns(text) {
  const lines = text.split(/\r?\n/);
  let packagesIndent = null;
  const patterns = [];
  for (const rawLine of lines) {
    if (/^\s*#/.test(rawLine) || !rawLine.trim()) continue;
    if (/^ *\t/.test(rawLine)) throw new Error('tab indentation is unsupported');
    const indentation = /^ */.exec(rawLine)[0].length;
    if (packagesIndent === null) {
      if (indentation !== 0) continue;
      const match = /^packages\s*:\s*(.*)$/.exec(rawLine);
      if (!match) continue;
      packagesIndent = indentation;
      const inlineValue = yamlContentBeforeComment(match[1]).trim();
      if (inlineValue) {
        if (inlineValue === '[]') return [];
        const inline = JSON.parse(inlineValue);
        if (!Array.isArray(inline) || inline.some((value) => typeof value !== 'string')) {
          throw new Error('packages must be a string list');
        }
        return inline;
      }
      continue;
    }
    const content = yamlContentBeforeComment(rawLine.slice(indentation)).trim();
    if (!content) continue;
    if (indentation < packagesIndent || (indentation === packagesIndent && !content.startsWith('-'))) break;
    const match = /^-\s+(.+)$/.exec(content);
    if (!match) throw new Error('packages must contain only string list items');
    patterns.push(pnpmWorkspaceScalar(match[1]));
  }
  return patterns;
}

function globMatchesPath(pattern, path) {
  if (typeof pattern !== 'string') return false;
  const escaped = pattern.replace(/^!/, '').replace(/\\/g, '/').replace(/^\.\//, '').replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const expression = escaped.replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\u0000/g, '.*');
  return new RegExp(`^${expression}/?$`).test(path);
}

function workspaceIncludes(patterns, path) {
  return patterns.some((pattern) => !pattern.startsWith('!') && globMatchesPath(pattern, path))
    && !patterns.some((pattern) => pattern.startsWith('!') && globMatchesPath(pattern, path));
}

function coveredByWorkspace(manifest, parsedPackages, pnpmWorkspaces, lockRoots) {
  const manifestRoot = posix(dirname(manifest.path));
  if (manifestRoot === '.' || lockRoots.has(manifestRoot)) {
    return { covered: lockRoots.has(manifestRoot), uncertainty: null };
  }
  const segments = manifestRoot.split('/');
  let uncertainty = null;
  for (let depth = segments.length - 1; depth >= 0; depth -= 1) {
    const ancestor = depth ? segments.slice(0, depth).join('/') : '.';
    if (!lockRoots.has(ancestor)) continue;
    const ancestorManifestPath = ancestor === '.' ? 'package.json' : `${ancestor}/package.json`;
    const parsed = parsedPackages.get(ancestorManifestPath);
    const relativeRoot = ancestor === '.' ? manifestRoot : manifestRoot.slice(ancestor.length + 1);
    if (parsed && workspaceIncludes(workspacePatterns(parsed), relativeRoot)) {
      return { covered: true, uncertainty: null };
    }
    const pnpm = pnpmWorkspaces.get(ancestor);
    if (pnpm?.outcome === 'scanned' && workspaceIncludes(pnpm.patterns, relativeRoot)) {
      return { covered: true, uncertainty: null };
    }
    if (pnpm && pnpm.outcome !== 'scanned') uncertainty ||= pnpm;
  }
  return { covered: false, uncertainty };
}

export function auditSource(projectRoot, limits = DEFAULT_SOURCE_TRAVERSAL_LIMITS, evidenceOptions = {}) {
  const root = resolve(projectRoot);
  if (!existsSync(root) || !statSync(root).isDirectory()) throw new Error(`project root is invalid: ${projectRoot}`);
  const effectiveLimits = sourceTraversalLimits(limits);
  const effectiveAnalysisLimits = sourceAnalysisLimits(evidenceOptions.analysisLimits);
  const analysisSession = createSourceAnalysisSession(effectiveAnalysisLimits);
  const recordedLimits = { ...effectiveLimits, sourceAnalysis: effectiveAnalysisLimits };
  const traversal = walk(root, effectiveLimits);
  const { files } = traversal;
  const findings = [];
  const trackers = Object.fromEntries(SOURCE_RULE_IDS.map((ruleId) => [ruleId, tracker()]));
  const integrityIssues = new Map();
  const exclusions = traversal.events.filter((event) => event.outcome === 'excluded');
  const traversalIssues = traversal.events.filter((event) => event.outcome !== 'excluded');
  const noteIntegrity = (outcome, code, path) => {
    const key = `${outcome}\0${code}\0${samplePath(path)}`;
    if (!integrityIssues.has(key)) integrityIssues.set(key, { outcome, code, path: samplePath(path) });
  };
  for (const ruleId of SOURCE_RULE_IDS.filter((id) => id !== 'source-evidence-incomplete')) {
    for (const event of exclusions) account(trackers[ruleId], 'excluded', event.code, event.path);
    for (const event of traversalIssues) {
      account(trackers[ruleId], event.outcome, event.code, event.path);
      noteIntegrity(event.outcome, event.code, event.path);
    }
  }
  const manifests = files.filter((file) => file.name === 'package.json' || file.name === 'pyproject.toml' || /^requirements.*\.txt$/i.test(file.name));
  const lockCheckedManifests = manifests.filter((file) => file.name === 'package.json' || file.name === 'pyproject.toml');
  const lockNames = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb', 'uv.lock', 'poetry.lock', 'Pipfile.lock']);
  const lockRoots = new Set(files.filter((file) => lockNames.has(file.name)).map((file) => posix(dirname(file.path))));
  const textCache = new Map();
  const load = (file) => {
    if (!textCache.has(file.path)) textCache.set(file.path, readText(file, effectiveLimits.maxFileBytes));
    return textCache.get(file.path);
  };
  const packageResults = new Map();
  for (const file of files.filter((item) => item.name === 'package.json')) {
    const loaded = load(file);
    if (loaded.outcome !== 'scanned') {
      packageResults.set(file.path, loaded);
      continue;
    }
    try {
      packageResults.set(file.path, { ...loaded, parsed: JSON.parse(loaded.text) });
    } catch {
      packageResults.set(file.path, { outcome: 'errors', code: 'manifest_parse_error', text: null, parsed: null });
    }
  }
  const parsedPackages = new Map([...packageResults.entries()]
    .filter(([, result]) => result.outcome === 'scanned').map(([path, result]) => [path, result.parsed]));
  const routeInputIssues = [];
  const moduleConfigFiles = [];
  for (const file of files.filter((item) => item.name === 'tsconfig.json' || item.name === 'jsconfig.json')) {
    const loaded = load(file);
    if (loaded.outcome === 'scanned') moduleConfigFiles.push({ path: file.path, text: loaded.text });
    else routeInputIssues?.push?.({ code: loaded.code, path: file.path });
  }
  const pnpmWorkspaces = new Map();
  for (const file of files.filter((item) => item.name === 'pnpm-workspace.yaml')) {
    const workspaceRoot = posix(dirname(file.path));
    const loaded = load(file);
    if (loaded.outcome !== 'scanned') {
      pnpmWorkspaces.set(workspaceRoot, { ...loaded, path: file.path });
      continue;
    }
    try {
      pnpmWorkspaces.set(workspaceRoot, {
        outcome: 'scanned', code: null, path: file.path,
        patterns: parsePnpmWorkspacePatterns(loaded.text),
      });
    } catch {
      pnpmWorkspaces.set(workspaceRoot, {
        outcome: 'errors', code: 'pnpm_workspace_parse_error', path: file.path,
      });
    }
  }

  const trackedEnvironment = trackedSensitiveEnvFiles(resolve(evidenceOptions.gitRoot || root));
  if (trackedEnvironment.status === 'not_applicable') {
    account(trackers['tracked-sensitive-env-file'], 'excluded', trackedEnvironment.code, '.');
    trackers['tracked-sensitive-env-file'].statusOverride = 'not_applicable';
  } else if (trackedEnvironment.status === 'unavailable') {
    account(trackers['tracked-sensitive-env-file'], 'errors', trackedEnvironment.code, '.');
    noteIntegrity('errors', trackedEnvironment.code, '.');
  } else {
    account(trackers['tracked-sensitive-env-file'], 'scanned', null, '.');
    for (const path of trackedEnvironment.paths) {
      findings.push(createFinding({
        ruleId: 'tracked-sensitive-env-file',
        title: 'Sensitive environment filename is tracked by Git',
        severity: 'medium',
        state: 'confirmed',
        discriminator: path,
        summary: 'Git confirms that an environment-named file is tracked. The audit did not read it and does not claim that it contains a valid credential.',
        location: { path, line: 1 },
        evidence: { subject: path, observed: 'tracked in current Git index', contentsRead: false },
        remediation: 'Privately verify whether the file contains sensitive values, rotate any exposed credential, remove it from current and relevant historical source, and keep only a placeholder example.',
        retest: 'Use Git index and history checks without printing values, then rerun the source audit and confirm this tracking fact is absent.',
      }));
    }
  }

  const routeSources = [];
  for (const file of files) {
    const classification = classifyJsTsSource(file.path);
    if (!classification.eligible) {
      for (const ruleId of JS_TS_SOURCE_RULE_IDS) {
        account(trackers[ruleId], 'excluded', classification.reason, file.path);
      }
      continue;
    }
    const loaded = load(file);
    if (loaded.outcome !== 'scanned') {
      routeInputIssues.push({ code: loaded.code, path: file.path });
      for (const ruleId of JS_TS_SOURCE_RULE_IDS) {
        account(trackers[ruleId], loaded.outcome, loaded.code, file.path);
      }
      noteIntegrity(loaded.outcome, loaded.code, file.path);
      continue;
    }
    const inspected = inspectJsTsSource(file.path, loaded.text, { analysisSession });
    if (inspected.error) {
      const outcome = ANALYSIS_LIMIT_CODES.has(inspected.error.code) ? 'truncated' : 'errors';
      routeInputIssues.push({ code: inspected.error.code, path: file.path });
      for (const ruleId of JS_TS_SOURCE_RULE_IDS) {
        account(trackers[ruleId], outcome, inspected.error.code, file.path);
      }
      noteIntegrity(outcome, inspected.error.code, file.path);
      continue;
    }
    routeSources.push({ path: file.path, text: loaded.text });
    for (const ruleId of JS_TS_SOURCE_RULE_IDS) account(trackers[ruleId], 'scanned', null, file.path);
    for (const finding of inspected.findings) findings.push(createFinding(finding));
  }

  const routeAnalysis = analyzeRouteSecurity(routeSources, {
    inputIssues: routeInputIssues,
    packageManifests: [...parsedPackages.values()],
    packageManifestRecords: [...parsedPackages.entries()].map(([path, manifest]) => ({ path, manifest })),
    configFiles: moduleConfigFiles,
    graphLimits: { maxModules: effectiveLimits.maxFiles },
  });
  if (['partial', 'unavailable'].includes(routeAnalysis.reportCoverage.status)) {
    findings.push(createFinding({
      ruleId: ROUTE_INTEGRITY_RULE_ID,
      title: 'Framework route-security evidence is incomplete',
      severity: 'high',
      state: 'unknown',
      summary: 'One or more supported route inputs or relationships could not be analyzed, so the route inventory and control review are incomplete.',
      evidence: {
        subject: 'route-security-coverage',
        status: routeAnalysis.reportCoverage.status,
        reasons: Object.fromEntries(routeAnalysis.reportCoverage.reasons.map((reason) =>
          [reason.code, reason.count])),
      },
      remediation: 'Review the bounded route coverage reasons, restore parsable source or resolve the relationship, then rerun before treating the route review as complete.',
      retest: 'Rerun the built-in audit until route-security coverage reports completed, then review the routes and controls that become visible.',
    }));
  }

  for (const file of files) {
    const classification = classifyPythonSource(file.path);
    if (!classification.eligible) {
      for (const ruleId of PYTHON_SOURCE_RULE_IDS) {
        account(trackers[ruleId], 'excluded', classification.reason, file.path);
      }
      continue;
    }
    const loaded = load(file);
    if (loaded.outcome !== 'scanned') {
      for (const ruleId of PYTHON_SOURCE_RULE_IDS) {
        account(trackers[ruleId], loaded.outcome, loaded.code, file.path);
      }
      noteIntegrity(loaded.outcome, loaded.code, file.path);
      continue;
    }
    const inspected = inspectPythonSource(file.path, loaded.text, { analysisSession });
    if (inspected.error) {
      const outcome = ANALYSIS_LIMIT_CODES.has(inspected.error.code) ? 'truncated' : 'errors';
      for (const ruleId of PYTHON_SOURCE_RULE_IDS) {
        account(trackers[ruleId], outcome, inspected.error.code, file.path);
      }
      noteIntegrity(outcome, inspected.error.code, file.path);
      continue;
    }
    for (const ruleId of PYTHON_SOURCE_RULE_IDS) account(trackers[ruleId], 'scanned', null, file.path);
    for (const finding of inspected.findings) findings.push(createFinding(finding));
  }

  for (const manifest of lockCheckedManifests) {
    const result = manifest.name === 'package.json'
      ? packageResults.get(manifest.path)
      : { outcome: 'scanned', code: null };
    if (result.outcome !== 'scanned') {
      account(trackers['dependency-lockfile-missing'], result.outcome, result.code, manifest.path);
      noteIntegrity(result.outcome, result.code, manifest.path);
      continue;
    }
    const manifestRoot = posix(dirname(manifest.path));
    const workspace = manifest.name === 'package.json'
      ? coveredByWorkspace(manifest, parsedPackages, pnpmWorkspaces, lockRoots)
      : { covered: lockRoots.has(manifestRoot), uncertainty: null };
    if (workspace.uncertainty) {
      account(trackers['dependency-lockfile-missing'], workspace.uncertainty.outcome,
        workspace.uncertainty.code, manifest.path);
      noteIntegrity(workspace.uncertainty.outcome, workspace.uncertainty.code, workspace.uncertainty.path);
      continue;
    }
    account(trackers['dependency-lockfile-missing'], 'scanned', null, manifest.path);
    if (!workspace.covered) {
      findings.push(createFinding({
        ruleId: 'dependency-lockfile-missing',
        title: 'Dependency manifest has no adjacent lockfile',
        severity: 'low',
        state: 'confirmed',
        summary: 'The project manifest is present, but no supported lockfile was found in the same project root. Dependency resolution is not reproducible from the recorded source alone.',
        location: { path: manifest.path, line: 1 },
        evidence: { subject: manifest.path, observed: 'no adjacent supported lockfile' },
        remediation: 'Generate and commit the package-manager lockfile used by CI and deployment.',
        retest: `Run the source audit again and confirm ${manifest.path} has an adjacent supported lockfile.`,
      }));
    }
  }

  for (const file of files) {
    if (ENV_FILE.test(file.name) && !ENV_TEMPLATE.test(file.name)) {
      account(trackers['sensitive-env-file-present'], 'scanned', null, file.path);
      findings.push(createFinding({
        ruleId: 'sensitive-env-file-present',
        title: 'Sensitive environment file requires repository and artifact review',
        severity: 'medium',
        state: 'suspected',
        summary: 'An environment-named file exists in the source tree. Its presence does not prove that it is tracked or publicly served, and its contents were not read.',
        location: { path: file.path, line: 1 },
        evidence: { subject: file.path, observed: 'filename only', contentsRead: false },
        remediation: 'Keep secrets outside source control and build artifacts; use an example file containing placeholders when documentation is needed.',
        retest: 'Verify repository tracking and built/deployed artifacts without printing secret values, then rerun this audit.',
      }));
      continue;
    }
    if (file.name === 'package.json') {
      const result = packageResults.get(file.path);
      account(trackers['node-inspector-public-bind'], result.outcome, result.code, file.path);
      if (result.outcome !== 'scanned') {
        noteIntegrity(result.outcome, result.code, file.path);
        continue;
      }
      const { text, parsed: manifest } = result;
      for (const [scriptName, command] of Object.entries(manifest.scripts || {})) {
        if (typeof command !== 'string') continue;
        const match = /--inspect(?:-brk)?(?:=|\s+)(0\.0\.0\.0|\[::\])(?::\d+)?/.exec(command);
        if (!match) continue;
        findings.push(createFinding({
          ruleId: 'node-inspector-public-bind',
          title: 'Node inspector is configured to bind on every interface',
          severity: 'high',
          state: 'suspected',
          discriminator: scriptName,
          summary: `The ${scriptName} script configures the Node inspector on a non-loopback address. Runtime use and network exposure still require confirmation.`,
          location: { path: file.path, line: lineOf(text, text.indexOf(command)) },
          evidence: { subject: `${file.path}#scripts.${scriptName}`, observed: match[0], runtimeReachability: 'unknown' },
          remediation: 'Bind the inspector to loopback and never enable it in an externally reachable production process.',
          retest: 'Run the source audit again, then verify the deployed process has no public inspector listener.',
          patch: `# Review manually: change ${match[1]} to 127.0.0.1 in package.json script ${scriptName}.\n`,
        }));
      }
    }
    if (CONFIG_FILES.test(file.name)) {
      const result = load(file);
      account(trackers['production-source-map-enabled'], result.outcome, result.code, file.path);
      if (result.outcome !== 'scanned') {
        noteIntegrity(result.outcome, result.code, file.path);
        continue;
      }
      const { text } = result;
      for (const pattern of [
        /productionBrowserSourceMaps\s*:\s*(true)/,
        /sourcemap\s*:\s*(true|['"](?:inline|hidden)['"])/,
        /sourceMap\s*:\s*(true|['"](?:inline|hidden)['"])/,
      ]) {
        const match = pattern.exec(text);
        if (!match) continue;
        findings.push(createFinding({
          ruleId: 'production-source-map-enabled',
          title: 'Production source maps are enabled in build configuration',
          severity: 'medium',
          state: 'suspected',
          summary: 'The build configuration enables production source maps. This is a lead until the deployed artifact or origin confirms public map delivery.',
          location: { path: file.path, line: lineOf(text, match.index) },
          evidence: { subject: file.path, observed: match[0], publicDelivery: 'unknown' },
          remediation: 'Disable public production source maps or upload them only to an access-controlled error-monitoring service.',
          retest: 'Rebuild, confirm no public .map artifact is emitted or served, and rerun the source audit.',
          patch: patchLine(file.path, text, match, 'false'),
        }));
        break;
      }
    }
  }

  if (manifests.length) {
    for (const manifest of manifests) account(trackers['source-stack-unsupported'], 'scanned', null, manifest.path);
  } else {
    account(trackers['source-stack-unsupported'], 'scanned', null, '.');
  }
  if (!manifests.length) {
    findings.push(createFinding({
      ruleId: 'source-stack-unsupported',
      title: 'No supported source manifest was available',
      severity: 'info',
      state: 'unknown',
      summary: 'The deterministic source rules could not establish a supported Node or Python project boundary.',
      evidence: { subject: '.', observed: 'no supported manifest' },
      remediation: 'Record the stack manually and use the agent-guided methodology for the project framework.',
      retest: 'Provide a supported manifest or an explicit, reviewable stack adapter and rerun.',
    }));
  }

  const integrity = trackers['source-evidence-incomplete'];
  account(integrity, 'scanned', null, '.');
  for (const event of exclusions) account(integrity, 'excluded', event.code, event.path);
  for (const issue of integrityIssues.values()) account(integrity, issue.outcome, issue.code, issue.path);
  if (integrityIssues.size) {
    const reasons = [...integrityIssues.values()].reduce((counts, item) => {
      counts[item.code] = (counts[item.code] || 0) + 1;
      return counts;
    }, {});
    findings.push(createFinding({
      ruleId: 'source-evidence-incomplete',
      title: 'Source evidence is incomplete',
      severity: 'high',
      state: 'unknown',
      summary: 'One or more eligible source inputs could not be traversed or inspected, so the absence of other findings is not a complete result.',
      evidence: { subject: 'source-traversal', reasons, effectiveLimits: recordedLimits },
      remediation: 'Review the bounded coverage reasons, restore readable supported inputs, reduce pathological or generated input, or adjust a documented traversal boundary before rerunning.',
      retest: 'Rerun with the same subject and scope until every required source rule has completed coverage.',
    }));
  }

  const coverage = Object.fromEntries(Object.entries(trackers).map(([ruleId, state]) =>
    [ruleId, resultFor(state)]));
  coverage[ROUTE_INTEGRITY_RULE_ID] = routeAnalysis.reportCoverage;
  return {
    findings,
    integrityIssues: [...integrityIssues.values()],
    coverage,
    routeAnalysis,
    traversal: {
      effectiveLimits: recordedLimits,
      analysis: analysisSession.snapshot(),
      entriesSeen: traversal.entriesSeen,
      filesDiscovered: files.length,
      stopped: traversal.stopped,
    },
  };
}

export function renderPatch(findings) {
  const patches = findings.filter((finding) => finding.patch).map((finding) =>
    `# ${finding.id}: ${finding.title}\n${finding.patch.trim()}\n`);
  return patches.length
    ? `# Proposed changes only. Review and apply manually; this file does not prove a fix.\n\n${patches.join('\n')}\n`
    : '# No deterministic patch proposal was produced. Findings still require review.\n';
}
