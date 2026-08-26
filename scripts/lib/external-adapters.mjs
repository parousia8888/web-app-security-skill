import { createHash } from 'node:crypto';
import {
  chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync,
  realpathSync, statSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  CHECKOV_ADAPTER, CHECKOV_RULES, GITLEAKS_ADAPTER, GITLEAKS_RULES, OPENGREP_ADAPTER,
  OPENGREP_RULE_ID_MAP, OPENGREP_RULES, OPENGREP_RULESET, OSV_ADAPTER, OSV_RULES,
} from './adapter-definitions.mjs';
import { sourceRuleRegistryEntry } from './source-rule-registry.mjs';

const MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const digest = (value) => createHash('sha256').update(String(value)).digest('hex');
const posix = (value) => value.split(sep).join('/');

function safeProjectPath(projectRoot, value) {
  if (typeof value !== 'string' || !value) return null;
  const absolute = isAbsolute(value) ? resolve(value) : resolve(projectRoot, value);
  const path = posix(relative(projectRoot, absolute));
  if (!path || path === '..' || path.startsWith('../') || isAbsolute(path)) return null;
  return path.slice(0, 160);
}

function safeCheckovPath(projectRoot, value) {
  if (typeof value !== 'string' || !value || value.includes('\\') || value.includes('\0')) return null;
  const relativePath = value.replace(/^\/+/, '');
  if (!relativePath) return null;
  const path = safeProjectPath(projectRoot, relativePath);
  if (!path) return null;
  const absolute = resolve(projectRoot, path);
  try {
    if (!existsSync(absolute) || lstatSync(absolute).isSymbolicLink()) return null;
  } catch {
    return null;
  }
  return path;
}

function containedProjectFile(projectRoot, value) {
  if (typeof value !== 'string' || !value || value.length > 4096 || isAbsolute(value)
      || /[\u0000-\u001f\u007f\\]/.test(value)) return { path: null, reason: 'adapter_input_path_unsafe' };
  const absolute = resolve(projectRoot, value);
  const lexical = relative(resolve(projectRoot), absolute);
  if (!lexical || lexical === '..' || lexical.startsWith(`..${sep}`) || isAbsolute(lexical)) {
    return { path: null, reason: 'adapter_input_path_unsafe' };
  }
  try {
    const realRoot = realpathSync(projectRoot);
    const realFile = realpathSync(absolute);
    const contained = relative(realRoot, realFile);
    if (!contained || contained === '..' || contained.startsWith(`..${sep}`) || isAbsolute(contained)
        || !statSync(realFile).isFile()) return { path: null, reason: 'adapter_input_path_unsafe' };
    return { path: absolute, reason: null };
  } catch {
    return { path: null, reason: 'adapter_input_path_unavailable' };
  }
}

function counts({
  discovered = 1, eligible = 1, scanned = 0, excluded = 0, skipped = 0, errors = 0,
} = {}) {
  return { discovered, eligible, scanned, excluded, skipped, truncated: 0, errors };
}

function coverage(adapter, rule, status, countValues, reasons = []) {
  return {
    id: `${adapter.id}-${rule.id}`,
    adapterId: adapter.id,
    ruleId: rule.id,
    ruleRevision: rule.revision,
    status,
    counts: counts(countValues),
    reasons,
  };
}

function unknownFinding(adapter, rule, reasonCode, detail = {}) {
  return {
    adapterId: adapter.id,
    ruleId: rule.id,
    title: `${adapter.id} evidence unavailable`,
    severity: rule.severity,
    state: 'unknown',
    summary: `${adapter.id} could not complete this check (${reasonCode}).`,
    location: null,
    evidence: { subject: rule.id, reasonCode, ...detail },
    remediation: `Run webapp-security doctor, install the tested ${adapter.id} version, and rerun the same adapter selection.`,
    retest: `Repeat this audit with ${adapter.id}@${adapter.version} and the same project scope.`,
  };
}

function run(binary, args, { cwd, timeoutSeconds, env }) {
  const result = spawnSync(binary, args, {
    cwd,
    encoding: 'utf8',
    env: env ? { ...process.env, ...env } : process.env,
    timeout: timeoutSeconds * 1000,
    maxBuffer: MAX_OUTPUT_BYTES,
    windowsHide: true,
  });
  if (result.error?.code === 'ENOENT') return { kind: 'missing' };
  if (result.error?.code === 'ENOBUFS') return { kind: 'output_limit' };
  if (result.error?.code === 'ETIMEDOUT' || result.signal === 'SIGTERM') return { kind: 'timeout' };
  if (result.error) return { kind: 'internal_error' };
  return { kind: 'completed', status: result.status, stdout: result.stdout || '' };
}

function version(binary, args, adapter, timeoutSeconds, parser, env) {
  const result = run(binary, args, { timeoutSeconds, env });
  if (result.kind !== 'completed') return { status: result.kind, expectedVersion: adapter.version };
  if (result.status !== 0) return { status: 'internal_error', expectedVersion: adapter.version };
  const observedVersion = parser(result.stdout);
  if (!observedVersion) return { status: 'malformed_version', expectedVersion: adapter.version };
  return {
    status: observedVersion === adapter.version ? 'available' : 'unsupported_version',
    expectedVersion: adapter.version,
    observedVersion,
  };
}

export function probeGitleaks(binary, timeoutSeconds) {
  return version(binary, ['version'], GITLEAKS_ADAPTER, timeoutSeconds,
    (stdout) => /^(\d+\.\d+\.\d+)\s*$/m.exec(stdout)?.[1]);
}

export function probeOsv(binary, timeoutSeconds) {
  return version(binary, ['--version'], OSV_ADAPTER, timeoutSeconds,
    (stdout) => /osv-scanner version:\s*(\d+\.\d+\.\d+)/.exec(stdout)?.[1]);
}

function withCheckovState(callback) {
  const stateDir = mkdtempSync(resolve(tmpdir(), 'webapp-security-checkov-'));
  chmodSync(stateDir, 0o700);
  const home = resolve(stateDir, 'home');
  const temp = resolve(stateDir, 'tmp');
  const config = resolve(stateDir, 'empty-config.yml');
  for (const directory of [home, temp]) mkdirSync(directory, { mode: 0o700 });
  writeFileSync(config, '{}\n', { mode: 0o600, flag: 'wx' });
  const env = {
    HOME: home,
    XDG_CACHE_HOME: resolve(home, '.cache'),
    TMPDIR: temp,
    CHECKOV_CONFIG_FILE: config,
  };
  try {
    return callback(env);
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
}

export function probeCheckov(binary, timeoutSeconds, stateEnv = null) {
  const probe = (env) => version(binary, ['--version'], CHECKOV_ADAPTER, timeoutSeconds,
    (stdout) => /^(\d+\.\d+\.\d+)\s*$/m.exec(stdout)?.[1], env);
  return stateEnv ? probe(stateEnv) : withCheckovState(probe);
}

function withOpengrepState(callback) {
  const stateDir = mkdtempSync(resolve(tmpdir(), 'webapp-security-opengrep-'));
  chmodSync(stateDir, 0o700);
  const env = {
    SEMGREP_LOG_FILE: resolve(stateDir, 'semgrep.log'),
    SEMGREP_SETTINGS_FILE: resolve(stateDir, 'settings.yml'),
    OPENGREP_VERSION_CACHE_PATH: resolve(stateDir, 'version-check.json'),
  };
  try {
    return callback(env);
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
  }
}

export function probeOpengrep(binary, timeoutSeconds, stateEnv = null) {
  const probe = (env) => version(binary, ['--version'], OPENGREP_ADAPTER, timeoutSeconds,
    (stdout) => /^(\d+\.\d+\.\d+)\s*$/m.exec(stdout)?.[1], env);
  return stateEnv ? probe(stateEnv) : withOpengrepState(probe);
}

export function verifyOpengrepRuleset(
  rulesPath = resolve(ROOT, OPENGREP_RULESET.relativePath),
  expectedDigest = OPENGREP_RULESET.sha256,
) {
  try {
    if (!existsSync(rulesPath) || lstatSync(rulesPath).isSymbolicLink()) return { status: 'unavailable' };
    const observedDigest = createHash('sha256').update(readFileSync(rulesPath)).digest('hex');
    return {
      status: observedDigest === expectedDigest ? 'available' : 'digest_mismatch',
      expectedDigest,
      observedDigest,
    };
  } catch {
    return { status: 'unavailable', expectedDigest };
  }
}

export function parseGitleaksJson(stdout, projectRoot, scanMode) {
  let parsed;
  try { parsed = JSON.parse(stdout || '[]'); } catch { throw new Error('malformed_json'); }
  if (!Array.isArray(parsed)) throw new Error('malformed_output');
  const findings = parsed.map((item) => {
    if (!item || typeof item.RuleID !== 'string' || !item.RuleID
        || !Number.isInteger(item.StartLine) || item.StartLine < 1) throw new Error('malformed_output');
    const path = safeProjectPath(projectRoot, item.File);
    if (!path) throw new Error('unsafe_path');
    const toolFingerprintDigest = digest(item.Fingerprint || `${path}:${item.StartLine}:${item.RuleID}`);
    return {
      adapterId: GITLEAKS_ADAPTER.id,
      ruleId: scanMode === 'history' ? GITLEAKS_RULES[0].id : GITLEAKS_RULES[1].id,
      title: `Secret pattern lead from ${item.RuleID}`,
      severity: 'high',
      state: 'suspected',
      summary: `Gitleaks matched rule ${item.RuleID} in ${scanMode === 'history' ? 'committed history' : 'the working tree'}; credential validity and exposure were not inferred.`,
      location: { path, line: item.StartLine },
      evidence: {
        subject: `${scanMode}:${path}:${item.StartLine}:${item.RuleID}:${toolFingerprintDigest}`,
        scanMode,
        externalRuleId: item.RuleID,
        toolFingerprintDigest,
        ...(scanMode === 'history' && /^[a-f0-9]{40,64}$/i.test(item.Commit || '')
          ? { commit: item.Commit.toLowerCase() } : {}),
      },
      remediation: 'Revoke any live credential, remove it from the current tree and history as appropriate, and add a narrowly scoped prevention or suppression control.',
      retest: `Rerun the Gitleaks ${scanMode} adapter and confirm this fingerprint is absent or covered by an approved suppression.`,
    };
  });
  return [...new Map(findings.map((finding) => [finding.evidence.subject, finding])).values()];
}

function unavailable(adapter, rules, reasonCode, detail = {}) {
  return {
    findings: rules.map((rule) => unknownFinding(adapter, rule, reasonCode, detail)),
    coverage: rules.map((rule) => coverage(adapter, rule, 'unavailable', { errors: 1 }, [
      { code: reasonCode, count: 1, samplePaths: [] },
    ])),
  };
}

export function runGitleaks(projectRoot, { binary = 'gitleaks', timeoutSeconds = 120 } = {}) {
  const gitApplicable = existsSync(resolve(projectRoot, '.git'))
    && !lstatSync(resolve(projectRoot, '.git')).isSymbolicLink();
  const identity = probeGitleaks(binary, timeoutSeconds);
  if (identity.status !== 'available') {
    const reason = `adapter_${identity.status}`;
    const detail = identity.observedVersion ? { observedVersion: identity.observedVersion } : {};
    return {
      adapter: GITLEAKS_ADAPTER,
      identity,
      findings: [
        ...(gitApplicable ? [unknownFinding(GITLEAKS_ADAPTER, GITLEAKS_RULES[0], reason, detail)] : []),
        unknownFinding(GITLEAKS_ADAPTER, GITLEAKS_RULES[1], reason, detail),
      ],
      coverage: [
        ...(gitApplicable
          ? [coverage(GITLEAKS_ADAPTER, GITLEAKS_RULES[0], 'unavailable', { errors: 1 }, [
            { code: reason, count: 1, samplePaths: [] },
          ])]
          : [coverage(GITLEAKS_ADAPTER, GITLEAKS_RULES[0], 'not_applicable', {
            discovered: 1, eligible: 0, excluded: 1,
          }, [{ code: 'not_git_repository', count: 1, samplePaths: [] }])]),
        coverage(GITLEAKS_ADAPTER, GITLEAKS_RULES[1], 'unavailable', { errors: 1 }, [
          { code: reason, count: 1, samplePaths: [] },
        ]),
      ],
      networkAccessPerformed: false,
    };
  }
  const modes = [
    { mode: 'history', rule: GITLEAKS_RULES[0], applicable: gitApplicable, command: 'git' },
    { mode: 'working-tree', rule: GITLEAKS_RULES[1], applicable: true, command: 'dir' },
  ];
  const findings = [];
  const coverageEntries = [];
  for (const item of modes) {
    if (!item.applicable) {
      coverageEntries.push(coverage(GITLEAKS_ADAPTER, item.rule, 'not_applicable', {
        discovered: 1, eligible: 0, excluded: 1,
      }, [{ code: 'not_git_repository', count: 1, samplePaths: [] }]));
      continue;
    }
    const result = run(binary, [item.command, '--no-banner', '--no-color', '--redact=100',
      '--log-level', 'error', '--timeout', String(timeoutSeconds), '--report-format', 'json',
      '--report-path', '-', projectRoot], { cwd: projectRoot, timeoutSeconds });
    if (result.kind !== 'completed' || ![0, 1].includes(result.status)) {
      const reason = result.kind === 'completed' ? 'adapter_internal_error' : `adapter_${result.kind}`;
      findings.push(unknownFinding(GITLEAKS_ADAPTER, item.rule, reason));
      coverageEntries.push(coverage(GITLEAKS_ADAPTER, item.rule, 'unavailable', { errors: 1 }, [
        { code: reason, count: 1, samplePaths: [] },
      ]));
      continue;
    }
    try {
      const parsed = parseGitleaksJson(result.stdout, projectRoot, item.mode);
      if ((result.status === 1) !== (parsed.length > 0)) throw new Error('inconsistent_exit');
      findings.push(...parsed);
      coverageEntries.push(coverage(GITLEAKS_ADAPTER, item.rule, 'completed', { scanned: 1 }));
    } catch (error) {
      const reason = `adapter_${error.message}`;
      findings.push(unknownFinding(GITLEAKS_ADAPTER, item.rule, reason));
      coverageEntries.push(coverage(GITLEAKS_ADAPTER, item.rule, 'unavailable', { errors: 1 }, [
        { code: reason, count: 1, samplePaths: [] },
      ]));
    }
  }
  return { adapter: GITLEAKS_ADAPTER, identity, findings, coverage: coverageEntries, networkAccessPerformed: false };
}

export function parseOsvJson(stdout, projectRoot) {
  let parsed;
  try { parsed = JSON.parse(stdout || '{}'); } catch { throw new Error('malformed_json'); }
  if (!parsed || !Array.isArray(parsed.results)) throw new Error('malformed_output');
  const findings = [];
  for (const result of parsed.results) {
    const sourcePath = safeProjectPath(projectRoot, result?.source?.path);
    if (!sourcePath) throw new Error('unsafe_path');
    if (!Array.isArray(result?.packages)) throw new Error('malformed_packages');
    for (const item of result.packages) {
      const pkg = item?.package;
      if (!pkg || typeof pkg.name !== 'string' || typeof pkg.version !== 'string'
          || typeof pkg.ecosystem !== 'string' || !Array.isArray(item.groups)) throw new Error('malformed_package');
      for (const group of item.groups) {
        if (!Array.isArray(group?.ids) || !group.ids.length
            || group.ids.some((id) => typeof id !== 'string' || !id)) throw new Error('malformed_group');
        const advisoryIds = [...new Set(group.ids)].sort();
        const aliases = Array.isArray(group.aliases)
          ? [...new Set(group.aliases.filter((value) => typeof value === 'string' && value))].sort()
          : [];
        findings.push({
          adapterId: OSV_ADAPTER.id,
          ruleId: OSV_RULES[0].id,
          title: `OSV advisory match for ${pkg.ecosystem}:${pkg.name}`,
          severity: 'info',
          state: 'suspected',
          summary: `OSV-Scanner matched ${pkg.ecosystem}:${pkg.name}@${pkg.version} to ${advisoryIds.join(', ')}. Local impact and priority were not inferred.`,
          location: { path: sourcePath, line: null },
          evidence: {
            subject: `${pkg.ecosystem}:${pkg.name}:${pkg.version}:${advisoryIds.join(',')}`,
            ecosystem: pkg.ecosystem,
            packageName: pkg.name,
            installedVersion: pkg.version,
            advisoryIds,
            aliases,
            upstreamMaxSeverity: typeof group.max_severity === 'string' ? group.max_severity : null,
            sourceType: typeof result.source.type === 'string' ? result.source.type : 'unknown',
          },
          remediation: 'Review the named advisory in project context, update or replace the dependency where applicable, and document any time-bounded suppression.',
          retest: 'Rerun OSV-Scanner with the same dependency inputs and confirm the advisory identity is absent or explicitly suppressed.',
        });
      }
    }
  }
  return findings;
}

export function parseOpengrepJson(stdout, projectRoot) {
  let parsed;
  try { parsed = JSON.parse(stdout || '{}'); } catch { throw new Error('malformed_json'); }
  if (!parsed || !Array.isArray(parsed.results) || !Array.isArray(parsed.errors)
      || !parsed.paths || !Array.isArray(parsed.paths.scanned)) throw new Error('malformed_output');
  if (parsed.version !== OPENGREP_ADAPTER.version) throw new Error('output_version_mismatch');
  if (parsed.errors.length) throw new Error('scan_errors');
  if (parsed.paths.scanned.some((path) => !safeProjectPath(projectRoot, path))) throw new Error('unsafe_path');
  const findings = parsed.results.map((item) => {
    const localRuleId = OPENGREP_RULE_ID_MAP.get(item?.check_id);
    if (!localRuleId || !Number.isInteger(item?.start?.line) || item.start.line < 1
        || !Number.isInteger(item?.start?.col) || item.start.col < 1
        || item?.extra?.engine_kind !== 'OSS') throw new Error('malformed_output');
    const path = safeProjectPath(projectRoot, item.path);
    if (!path) throw new Error('unsafe_path');
    const rule = sourceRuleRegistryEntry(OPENGREP_ADAPTER.id, localRuleId);
    return {
      adapterId: OPENGREP_ADAPTER.id,
      ruleId: localRuleId,
      title: rule.technicalTerm,
      severity: rule.severity,
      state: 'suspected',
      summary: `Opengrep matched local rule ${item.check_id} at ${path}:${item.start.line}. ${rule.confidenceBoundary}`,
      location: { path, line: item.start.line },
      evidence: {
        subject: `${item.check_id}:${path}:${item.start.line}:${item.start.col}`,
        externalRuleId: item.check_id,
        engineKind: item.extra.engine_kind,
        column: item.start.col,
        rulesetSha256: OPENGREP_RULESET.sha256,
      },
      remediation: rule.proposal.summary,
      retest: rule.securityRetest,
    };
  });
  const unique = new Map();
  for (const finding of findings) unique.set(finding.evidence.subject, finding);
  return [...unique.values()].sort((left, right) => left.evidence.subject.localeCompare(right.evidence.subject));
}

const CHECKOV_RULE_MAP = new Map([
  ['CKV_DOCKER_8', 'checkov-dockerfile-root-user'],
  ['CKV_DOCKER_2', 'checkov-dockerfile-healthcheck-missing'],
  ['CKV2_GHA_1', 'checkov-github-actions-write-all'],
]);
const CHECKOV_FRAMEWORKS = new Set(['dockerfile', 'github_actions']);

export function parseCheckovJson(stdout, projectRoot, allowedPaths = null) {
  let parsed;
  try { parsed = JSON.parse(stdout || '{}'); } catch { throw new Error('malformed_json'); }
  const reports = Array.isArray(parsed) ? parsed : [parsed];
  if (!reports.length || reports.some((report) => !report || typeof report !== 'object')) {
    throw new Error('malformed_output');
  }
  const findings = [];
  const frameworkEvidence = new Map();
  for (const report of reports) {
    const framework = report.check_type;
    const summary = report.summary;
    const results = report.results;
    if (!CHECKOV_FRAMEWORKS.has(framework) || frameworkEvidence.has(framework)
        || !summary || summary.checkov_version !== CHECKOV_ADAPTER.version
        || !Number.isInteger(summary.parsing_errors) || summary.parsing_errors !== 0
        || !results || !Array.isArray(results.passed_checks)
        || !Array.isArray(results.failed_checks) || !Array.isArray(results.skipped_checks)) {
      throw new Error(summary?.parsing_errors > 0 ? 'scan_errors' : 'malformed_output');
    }
    const selectedEvidence = new Map([...CHECKOV_RULE_MAP.keys()]
      .filter((ruleId) => (ruleId.startsWith('CKV_DOCKER_') ? 'dockerfile' : 'github_actions') === framework)
      .map((ruleId) => [ruleId, { passed: [], failed: [], skipped: [] }]));
    frameworkEvidence.set(framework, {
      failed: results.failed_checks.length,
      skipped: results.skipped_checks.length,
      selectedEvidence,
    });
    for (const item of results.passed_checks) {
      const evidence = selectedEvidence.get(item?.check_id);
      if (evidence) {
        const path = safeCheckovPath(projectRoot, item.file_path);
        if (!path) throw new Error('unsafe_path');
        if (allowedPaths && !allowedPaths.has(path)) throw new Error('unexpected_input_path');
        evidence.passed.push({ path });
      }
    }
    for (const item of results.failed_checks) {
      if (!CHECKOV_RULE_MAP.has(item?.check_id)) throw new Error('unknown_rule');
      const expectedFramework = item.check_id.startsWith('CKV_DOCKER_') ? 'dockerfile' : 'github_actions';
      if (framework !== expectedFramework) throw new Error('malformed_output');
      const path = safeCheckovPath(projectRoot, item.file_path);
      if (!path || !Array.isArray(item.file_line_range) || item.file_line_range.length !== 2
          || item.file_line_range.some((line) => !Number.isInteger(line) || line < 1)
          || item.file_line_range[1] < item.file_line_range[0]) throw new Error('unsafe_path');
      if (allowedPaths && !allowedPaths.has(path)) throw new Error('unexpected_input_path');
      selectedEvidence.get(item.check_id).failed.push({ path, line: item.file_line_range[0] });
      const localRuleId = CHECKOV_RULE_MAP.get(item.check_id);
      findings.push({
        adapterId: CHECKOV_ADAPTER.id,
        ruleId: localRuleId,
        title: `Deployment-policy lead from ${item.check_id}`,
        severity: CHECKOV_RULES.find((rule) => rule.id === localRuleId).severity,
        state: 'suspected',
        summary: `Checkov matched deployment-policy rule ${item.check_id} at ${path}:${item.file_line_range[0]}; deployed runtime context and practical impact were not inferred.`,
        location: { path, line: item.file_line_range[0] },
        evidence: {
          subject: `${item.check_id}:${path}:${item.file_line_range[0]}:${item.file_line_range[1]}`,
          externalRuleId: item.check_id,
          framework,
          lineEnd: item.file_line_range[1],
        },
        remediation: `Review ${item.check_id} in deployment context, choose the narrowest configuration change, and test the recorded operational side effects before rollout.`,
        retest: `Rerun Checkov ${item.check_id}, then verify the built image or workflow behavior in the owned deployment path.`,
      });
    }
    for (const item of results.skipped_checks) {
      const evidence = selectedEvidence.get(item?.check_id);
      if (!evidence) throw new Error('unknown_rule');
      const path = safeCheckovPath(projectRoot, item.file_path);
      if (!path || !Array.isArray(item.file_line_range) || item.file_line_range.length !== 2
          || item.file_line_range.some((line) => !Number.isInteger(line) || line < 1)
          || item.file_line_range[1] < item.file_line_range[0]) throw new Error('unsafe_path');
      if (allowedPaths && !allowedPaths.has(path)) throw new Error('unexpected_input_path');
      evidence.skipped.push({ path, line: item.file_line_range[0] });
    }
  }
  const unique = new Map();
  for (const finding of findings) unique.set(finding.evidence.subject, finding);
  return {
    findings: [...unique.values()].sort((left, right) => left.evidence.subject.localeCompare(right.evidence.subject)),
    frameworkEvidence,
  };
}

function checkovInputs(projectRoot) {
  const dockerfiles = existsSync(resolve(projectRoot, 'Dockerfile'))
    && !lstatSync(resolve(projectRoot, 'Dockerfile')).isSymbolicLink() ? ['Dockerfile'] : [];
  const workflows = [];
  const workflowRoot = resolve(projectRoot, '.github', 'workflows');
  if (existsSync(workflowRoot) && !lstatSync(workflowRoot).isSymbolicLink()
      && statSync(workflowRoot).isDirectory()) {
    for (const name of readdirSync(workflowRoot).sort()) {
      const full = resolve(workflowRoot, name);
      if (/\.ya?ml$/i.test(name) && !lstatSync(full).isSymbolicLink() && statSync(full).isFile()) {
        workflows.push(`.github/workflows/${name}`);
      }
    }
  }
  return { dockerfiles, workflows };
}

export function runCheckov(projectRoot, { binary = 'checkov', timeoutSeconds = 120 } = {}) {
  projectRoot = resolve(projectRoot);
  const inputs = checkovInputs(projectRoot);
  const allInputs = [...inputs.dockerfiles, ...inputs.workflows];
  const applicableRules = CHECKOV_RULES.filter((rule) => (rule.id.startsWith('checkov-dockerfile-')
    ? inputs.dockerfiles.length : inputs.workflows.length));
  const notApplicableRules = CHECKOV_RULES.filter((rule) => !applicableRules.includes(rule));
  if (!allInputs.length) {
    return {
      adapter: CHECKOV_ADAPTER,
      identity: { status: 'not_applicable', expectedVersion: CHECKOV_ADAPTER.version },
      findings: [],
      coverage: CHECKOV_RULES.map((rule) => coverage(CHECKOV_ADAPTER, rule, 'not_applicable', {
        discovered: 1, eligible: 0, excluded: 1,
      }, [{ code: rule.id.startsWith('checkov-dockerfile-') ? 'no_dockerfile_input' : 'no_github_actions_input', count: 1, samplePaths: [] }])),
      networkAccessPerformed: false,
    };
  }
  return withCheckovState((stateEnv) => {
    const identity = probeCheckov(binary, timeoutSeconds, stateEnv);
    const notApplicableCoverage = notApplicableRules.map((rule) => coverage(
      CHECKOV_ADAPTER, rule, 'not_applicable', { discovered: 1, eligible: 0, excluded: 1 },
      [{ code: rule.id.startsWith('checkov-dockerfile-') ? 'no_dockerfile_input' : 'no_github_actions_input', count: 1, samplePaths: [] }],
    ));
    if (identity.status !== 'available') {
      return {
        adapter: CHECKOV_ADAPTER, identity,
        ...unavailable(CHECKOV_ADAPTER, applicableRules, `adapter_${identity.status}`,
          identity.observedVersion ? { observedVersion: identity.observedVersion } : {}),
        coverage: [
          ...unavailable(CHECKOV_ADAPTER, applicableRules, `adapter_${identity.status}`).coverage,
          ...notApplicableCoverage,
        ],
        networkAccessPerformed: identity.status !== 'missing',
      };
    }
    const result = run(binary, [
      '-f', ...allInputs,
      '--framework', 'dockerfile', 'github_actions',
      '--check', 'CKV_DOCKER_8,CKV_DOCKER_2,CKV2_GHA_1',
      '--output', 'json', '--skip-download', '--compact',
    ], { cwd: projectRoot, timeoutSeconds, env: stateEnv });
    if (result.kind !== 'completed' || ![0, 1].includes(result.status)) {
      const reason = result.kind === 'completed' ? 'adapter_internal_error' : `adapter_${result.kind}`;
      const failed = unavailable(CHECKOV_ADAPTER, applicableRules, reason);
      return {
        adapter: CHECKOV_ADAPTER, identity, findings: failed.findings,
        coverage: [...failed.coverage, ...notApplicableCoverage], networkAccessPerformed: true,
      };
    }
    try {
      const parsed = parseCheckovJson(result.stdout, projectRoot, new Set(allInputs));
      for (const framework of parsed.frameworkEvidence.keys()) {
        if ((framework === 'dockerfile' && !inputs.dockerfiles.length)
            || (framework === 'github_actions' && !inputs.workflows.length)) {
          throw new Error('unexpected_input_framework');
        }
      }
      if ((result.status === 1) !== (parsed.findings.length > 0)) throw new Error('inconsistent_exit');
      for (const rule of applicableRules) {
        const framework = rule.id.startsWith('checkov-dockerfile-') ? 'dockerfile' : 'github_actions';
        const externalRuleId = [...CHECKOV_RULE_MAP.entries()]
          .find(([, localRuleId]) => localRuleId === rule.id)?.[0];
        const evidence = parsed.frameworkEvidence.get(framework)?.selectedEvidence.get(externalRuleId);
        const paths = rule.id.startsWith('checkov-dockerfile-') ? inputs.dockerfiles : inputs.workflows;
        const observedPaths = new Set([
          ...(evidence?.passed || []), ...(evidence?.failed || []), ...(evidence?.skipped || []),
        ].map((item) => item.path));
        if (!evidence || paths.some((path) => !observedPaths.has(path))) {
          throw new Error('incomplete_framework_evidence');
        }
      }
      return {
        adapter: CHECKOV_ADAPTER, identity, findings: [
          ...parsed.findings,
          ...applicableRules.flatMap((rule) => {
            const framework = rule.id.startsWith('checkov-dockerfile-') ? 'dockerfile' : 'github_actions';
            const externalRuleId = [...CHECKOV_RULE_MAP.entries()]
              .find(([, localRuleId]) => localRuleId === rule.id)?.[0];
            const evidence = parsed.frameworkEvidence.get(framework).selectedEvidence.get(externalRuleId);
            return evidence.skipped.length ? [unknownFinding(CHECKOV_ADAPTER, rule, 'adapter_rule_suppressed', {
              externalRuleId,
              suppressions: evidence.skipped,
            })] : [];
          }),
        ],
        coverage: [
          ...applicableRules.map((rule) => {
            const paths = rule.id.startsWith('checkov-dockerfile-') ? inputs.dockerfiles : inputs.workflows;
            const framework = rule.id.startsWith('checkov-dockerfile-') ? 'dockerfile' : 'github_actions';
            const externalRuleId = [...CHECKOV_RULE_MAP.entries()]
              .find(([, localRuleId]) => localRuleId === rule.id)?.[0];
            const evidence = parsed.frameworkEvidence.get(framework).selectedEvidence.get(externalRuleId);
            return coverage(CHECKOV_ADAPTER, rule, evidence.skipped.length ? 'unavailable' : 'completed', {
              discovered: paths.length, eligible: paths.length,
              scanned: evidence.skipped.length ? Math.max(0, paths.length - evidence.skipped.length) : paths.length,
              skipped: evidence.skipped.length,
              errors: evidence.skipped.length ? 1 : 0,
            }, evidence.skipped.length ? [{
              code: 'adapter_rule_suppressed', count: evidence.skipped.length,
              samplePaths: evidence.skipped.map((item) => item.path).slice(0, 5),
            }] : []);
          }),
          ...notApplicableCoverage,
        ],
        networkAccessPerformed: true,
      };
    } catch (error) {
      const failed = unavailable(CHECKOV_ADAPTER, applicableRules, `adapter_${error.message}`);
      return {
        adapter: CHECKOV_ADAPTER, identity, findings: failed.findings,
        coverage: [...failed.coverage, ...notApplicableCoverage], networkAccessPerformed: true,
      };
    }
  });
}

export function runOpengrep(projectRoot, {
  binary = 'opengrep', timeoutSeconds = 120,
  rulesPath = resolve(ROOT, OPENGREP_RULESET.relativePath),
  rulesetSha256 = OPENGREP_RULESET.sha256,
} = {}) {
  projectRoot = resolve(projectRoot);
  return withOpengrepState((stateEnv) => {
    const identity = probeOpengrep(binary, timeoutSeconds, stateEnv);
    if (identity.status !== 'available') {
      return { adapter: OPENGREP_ADAPTER, identity, ...unavailable(
        OPENGREP_ADAPTER, OPENGREP_RULES, `adapter_${identity.status}`,
        identity.observedVersion ? { observedVersion: identity.observedVersion } : {},
      ), networkAccessPerformed: false };
    }
    const ruleset = verifyOpengrepRuleset(rulesPath, rulesetSha256);
    if (ruleset.status !== 'available') {
      return {
        adapter: OPENGREP_ADAPTER, identity,
        ...unavailable(OPENGREP_ADAPTER, OPENGREP_RULES, `adapter_ruleset_${ruleset.status}`),
        networkAccessPerformed: false,
      };
    }
    const result = run(binary, [
      'scan', '--config', rulesPath, '--json', '--disable-version-check', '--no-git-ignore',
      '--no-rewrite-rule-ids', '--jobs', '1', '--timeout', String(Math.min(timeoutSeconds, 30)),
      '--max-target-bytes', '1048576',
      '--exclude', '.git', '--exclude', '.hg', '--exclude', '.svn',
      '--exclude', '.next', '--exclude', '.nuxt', '--exclude', '.output',
      '--exclude', '.webapp-security', '--exclude', 'build', '--exclude', 'coverage',
      '--exclude', 'dist', '--exclude', 'node_modules', '--exclude', 'target',
      '--exclude', 'vendor', '--exclude', '__pycache__', '--exclude', '.venv', '--exclude', 'venv',
      '--error', projectRoot,
    ], { cwd: projectRoot, timeoutSeconds, env: stateEnv });
    if (result.kind !== 'completed' || ![0, 1].includes(result.status)) {
      const reason = result.kind === 'completed' ? 'adapter_internal_error' : `adapter_${result.kind}`;
      return {
        adapter: OPENGREP_ADAPTER, identity,
        ...unavailable(OPENGREP_ADAPTER, OPENGREP_RULES, reason),
        networkAccessPerformed: false,
      };
    }
    try {
      const findings = parseOpengrepJson(result.stdout, projectRoot);
      if ((result.status === 1) !== (findings.length > 0)) throw new Error('inconsistent_exit');
      let parsed;
      try { parsed = JSON.parse(result.stdout); } catch { throw new Error('malformed_json'); }
      const scannedPaths = [...new Set(parsed.paths.scanned.map((path) => safeProjectPath(projectRoot, path)))];
      const pathsForRule = (rule) => scannedPaths.filter((path) => {
        if (rule.id.startsWith('opengrep-python-')) return /\.py$/i.test(path);
        return /\.(?:cjs|cts|js|jsx|mjs|mts|ts|tsx)$/i.test(path);
      });
      return {
        adapter: OPENGREP_ADAPTER, identity, findings,
        coverage: OPENGREP_RULES.map((rule) => {
          const eligible = pathsForRule(rule).length;
          return coverage(OPENGREP_ADAPTER, rule, eligible ? 'completed' : 'not_applicable', {
            discovered: eligible || 1, eligible, scanned: eligible, excluded: eligible ? 0 : 1,
          }, eligible ? [] : [{ code: 'no_supported_source_input', count: 1, samplePaths: [] }]);
        }),
        networkAccessPerformed: false,
      };
    } catch (error) {
      return {
        adapter: OPENGREP_ADAPTER, identity,
        ...unavailable(OPENGREP_ADAPTER, OPENGREP_RULES, `adapter_${error.message}`),
        networkAccessPerformed: false,
      };
    }
  });
}

export function runOsv(projectRoot, lockfiles, { binary = 'osv-scanner', timeoutSeconds = 120 } = {}) {
  if (!lockfiles.length) {
    return {
      adapter: OSV_ADAPTER,
      identity: { status: 'not_applicable', expectedVersion: OSV_ADAPTER.version },
      findings: [],
      coverage: [coverage(OSV_ADAPTER, OSV_RULES[0], 'not_applicable', {
        discovered: 1, eligible: 0, excluded: 1,
      }, [{ code: 'no_supported_dependency_input', count: 1, samplePaths: [] }])],
      networkAccessPerformed: false,
    };
  }
  const identity = probeOsv(binary, timeoutSeconds);
  if (identity.status !== 'available') {
    return { adapter: OSV_ADAPTER, identity, ...unavailable(
      OSV_ADAPTER, OSV_RULES, `adapter_${identity.status}`,
      identity.observedVersion ? { observedVersion: identity.observedVersion } : {},
    ), networkAccessPerformed: false };
  }
  const resolvedLockfiles = lockfiles.map((lockfile) => containedProjectFile(projectRoot, lockfile));
  const invalidInput = resolvedLockfiles.find((item) => item.reason);
  if (invalidInput) {
    return {
      adapter: OSV_ADAPTER, identity,
      ...unavailable(OSV_ADAPTER, OSV_RULES, invalidInput.reason),
      networkAccessPerformed: false,
    };
  }
  const args = [
    'scan', 'source', '--format', 'json', '--verbosity', 'error',
    '--no-call-analysis', 'go', '--no-call-analysis', 'rust',
  ];
  for (const lockfile of resolvedLockfiles) args.push('--lockfile', lockfile.path);
  const result = run(binary, args, { cwd: projectRoot, timeoutSeconds });
  if (result.kind !== 'completed' || ![0, 1].includes(result.status)) {
    const reason = result.kind === 'completed' ? 'adapter_internal_error' : `adapter_${result.kind}`;
    return {
      adapter: OSV_ADAPTER, identity,
      ...unavailable(OSV_ADAPTER, OSV_RULES, reason),
      networkAccessPerformed: result.kind !== 'missing',
    };
  }
  try {
    const findings = parseOsvJson(result.stdout, projectRoot);
    if ((result.status === 1) !== (findings.length > 0)) throw new Error('inconsistent_exit');
    return {
      adapter: OSV_ADAPTER, identity, findings,
      coverage: [coverage(OSV_ADAPTER, OSV_RULES[0], 'completed', {
        discovered: lockfiles.length, eligible: lockfiles.length, scanned: lockfiles.length,
      })],
      networkAccessPerformed: true,
    };
  } catch (error) {
    const reason = `adapter_${error.message}`;
    return {
      adapter: OSV_ADAPTER, identity,
      ...unavailable(OSV_ADAPTER, OSV_RULES, reason),
      networkAccessPerformed: true,
    };
  }
}

export function runExternalAdapters(projectRoot, lockfiles, selected, options = {}) {
  const results = [];
  if (selected.includes('checkov')) results.push(runCheckov(projectRoot, {
    binary: process.env.WEBAPP_SECURITY_CHECKOV_BIN || 'checkov',
    timeoutSeconds: options.timeoutSeconds,
  }));
  if (selected.includes('gitleaks')) results.push(runGitleaks(projectRoot, {
    binary: process.env.WEBAPP_SECURITY_GITLEAKS_BIN || 'gitleaks',
    timeoutSeconds: options.timeoutSeconds,
  }));
  if (selected.includes('opengrep')) results.push(runOpengrep(projectRoot, {
    binary: process.env.WEBAPP_SECURITY_OPENGREP_BIN || 'opengrep',
    timeoutSeconds: options.timeoutSeconds,
  }));
  if (selected.includes('osv')) results.push(runOsv(projectRoot, lockfiles, {
    binary: process.env.WEBAPP_SECURITY_OSV_SCANNER_BIN || 'osv-scanner',
    timeoutSeconds: options.timeoutSeconds,
  }));
  return results;
}
