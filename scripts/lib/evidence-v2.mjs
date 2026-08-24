import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { digestValue, stableValue } from './project-identity.mjs';
import {
  sha256, validateReportV2,
  V2_BASELINE_STATES, V2_DOMAINS, V2_RESULT_STATES,
} from './report-v2-contract.mjs';
import {
  BUILTIN_SOURCE_ADAPTER, sourceRule, sourceRuleset,
} from './source-rules.mjs';
import { adapterRulesetDigest } from './ruleset-v2.mjs';
import { sanitizeEvidence, sanitizedJson, writeAtomicEvidenceBundle } from './evidence-writer.mjs';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const severityRank = new Map(SEVERITIES.map((severity, index) => [severity, index]));

export const DEFAULT_POLICY = {
  thresholds: [
    { domain: 'security_exposure', failOn: 'high' },
    { domain: 'supply_chain', failOn: 'high' },
    { domain: 'search_discoverability', failOn: 'never' },
    { domain: 'reliability', failOn: 'never' },
    { domain: 'evidence_integrity', failOn: 'never' },
  ],
  gateStates: ['confirmed', 'suspected'],
  precedence: 'actionable_threshold_before_incomplete',
};

export function policyForFailOn(failOn, domainOverrides = []) {
  if (!['critical', 'high', 'medium', 'low', 'never'].includes(failOn)) {
    throw new Error(`invalid fail-on threshold: ${failOn}`);
  }
  const overrides = new Map();
  for (const value of domainOverrides) {
    const [domain, threshold, extra] = String(value).split('=');
    if (extra !== undefined || !V2_DOMAINS.includes(domain)
        || !['critical', 'high', 'medium', 'low', 'never'].includes(threshold)) {
      throw new Error(`invalid domain threshold: ${value}; expected <domain>=<critical|high|medium|low|never>`);
    }
    if (overrides.has(domain)) throw new Error(`duplicate domain threshold: ${domain}`);
    overrides.set(domain, threshold);
  }
  return {
    thresholds: DEFAULT_POLICY.thresholds.map((threshold) => ({
      ...threshold,
      failOn: overrides.get(threshold.domain)
        || (['security_exposure', 'supply_chain'].includes(threshold.domain)
          ? failOn
          : threshold.failOn),
    })),
    gateStates: [...DEFAULT_POLICY.gateStates],
    precedence: DEFAULT_POLICY.precedence,
  };
}

function findingFingerprint({ rule, location, evidence }) {
  return digestValue({
    version: 2,
    ruleId: rule.id,
    ruleRevision: rule.revision,
    location: location?.path || null,
    discriminator: evidence?.subject || null,
  });
}

function movementFingerprint(finding) {
  if (!finding.location?.path || typeof finding.evidence?.construct !== 'string') return null;
  const { subject: _subject, line: _line, ...pathIndependentEvidence } = finding.evidence;
  return digestValue({
    version: 1,
    ruleId: finding.rule.id,
    ruleRevision: finding.rule.revision,
    adapterId: finding.adapter.id,
    evidence: stableValue(pathIndependentEvidence),
  });
}

function uniqueMovementMatches(currentFindings, previousFindings) {
  const previousFingerprints = new Set(previousFindings.map((finding) => finding.fingerprint));
  const currentFingerprints = new Set(currentFindings.map((finding) => finding.fingerprint));
  const group = (findings, excluded) => {
    const groups = new Map();
    for (const finding of findings) {
      if (excluded.has(finding.fingerprint)) continue;
      const key = movementFingerprint(finding);
      if (!key) continue;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(finding);
    }
    return groups;
  };
  const currentGroups = group(currentFindings, previousFingerprints);
  const previousGroups = group(previousFindings, currentFingerprints);
  const matches = new Map();
  for (const [key, current] of currentGroups) {
    const previous = previousGroups.get(key);
    if (current.length === 1 && previous?.length === 1) {
      matches.set(current[0].fingerprint, previous[0]);
    }
  }
  return matches;
}

function emptyBaseline(state = 'new', coverage = null) {
  return {
    state,
    priorFingerprint: null,
    compatibility: state === 'new' ? 'not_attempted' : 'compatible',
    currentCheck: coverage?.status === 'completed' ? 'completed' : coverage ? 'incomplete' : 'not_run',
    coverageRef: coverage?.id || null,
    reasonCode: state === 'new' ? 'no_comparable_prior_finding' : null,
  };
}

export function createFindingV2({
  ruleset, adapterId, rule, title, severity, state, summary, location = null,
  evidence = {}, remediation, retest,
}) {
  const adapter = ruleset.adapters.find((item) => item.id === adapterId);
  if (!adapter) throw new Error(`finding references unregistered adapter: ${adapterId}`);
  if (rule.severity && severity !== rule.severity) {
    throw new Error(`finding severity differs from rule taxonomy: ${rule.id} expected ${rule.severity}, received ${severity}`);
  }
  const cleanLocation = location ? sanitizeEvidence(location) : null;
  const cleanEvidence = sanitizeEvidence(evidence);
  const core = {
    schemaVersion: 2,
    fingerprintVersion: 2,
    rule: { id: rule.id, revision: rule.revision },
    adapter: { id: adapter.id, version: adapter.version, rulesetDigest: adapter.rulesetDigest },
    domain: rule.domain,
    title: sanitizeEvidence(title),
    severity,
    state,
    summary: sanitizeEvidence(summary),
    location: cleanLocation,
    evidence: stableValue(cleanEvidence),
    remediation: sanitizeEvidence(remediation),
    retest: sanitizeEvidence(retest),
    baseline: emptyBaseline(),
  };
  const fingerprint = findingFingerprint(core);
  return { ...core, id: `${rule.id}-f${fingerprint.slice(0, 12)}`, fingerprint };
}

export function sourceFindingV2(legacyFinding, ruleset = sourceRuleset()) {
  return createFindingV2({
    ruleset,
    adapterId: BUILTIN_SOURCE_ADAPTER.id,
    rule: sourceRule(legacyFinding.ruleId),
    title: legacyFinding.title,
    severity: legacyFinding.severity,
    state: legacyFinding.state,
    summary: legacyFinding.summary,
    location: legacyFinding.location || null,
    evidence: legacyFinding.evidence || {},
    remediation: legacyFinding.remediation,
    retest: legacyFinding.retest,
  });
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function coverageMap(coverage) {
  return new Map(coverage.map((entry) => [entry.ruleId, entry]));
}

function completed(entry) {
  return entry?.status === 'completed';
}

function baselineFor(state, previous, coverage, reasonCode) {
  if (state === 'new') return {
    ...emptyBaseline('new'),
    coverageRef: coverage?.id || null,
  };
  if (state === 'unchanged' || state === 'regressed') return {
    state,
    priorFingerprint: previous.fingerprint,
    compatibility: 'compatible',
    currentCheck: 'completed',
    coverageRef: coverage.id,
    reasonCode: reasonCode
      || (state === 'regressed' ? 'condition_reappeared_after_fixed' : 'same_condition_still_present'),
  };
  if (state === 'fixed') return {
    state,
    priorFingerprint: previous.fingerprint,
    compatibility: 'compatible',
    currentCheck: 'completed',
    coverageRef: coverage.id,
    reasonCode: 'condition_absent_after_completed_check',
  };
  if (state === 'unretested') return {
    state,
    priorFingerprint: previous.fingerprint,
    compatibility: 'compatible',
    currentCheck: coverage ? 'incomplete' : 'not_run',
    coverageRef: coverage?.id || null,
    reasonCode,
  };
  return {
    state: 'not_comparable',
    priorFingerprint: previous?.fingerprint || null,
    compatibility: 'not_comparable',
    currentCheck: completed(coverage) ? 'completed' : coverage ? 'incomplete' : 'not_run',
    coverageRef: coverage?.id || null,
    reasonCode,
  };
}

export function compareFindingsV2(currentFindings, currentCoverage, baselineReport, currentRuleset) {
  const coverage = coverageMap(currentCoverage);
  const previousByFingerprint = new Map(baselineReport.findings.map((finding) => [finding.fingerprint, finding]));
  const previousCoverage = coverageMap(baselineReport.coverage);
  const movedPrevious = uniqueMovementMatches(currentFindings, baselineReport.findings);
  const matchedPreviousFingerprints = new Set();
  const compared = currentFindings.map((finding) => {
    const check = coverage.get(finding.rule.id);
    const oldCheck = previousCoverage.get(finding.rule.id);
    const exactPrevious = previousByFingerprint.get(finding.fingerprint);
    const previous = exactPrevious || movedPrevious.get(finding.fingerprint);
    if (previous) matchedPreviousFingerprints.add(previous.fingerprint);
    const currentAdapter = currentRuleset.adapters.find((item) => item.id === check?.adapterId);
    const previousAdapter = baselineReport.ruleset.adapters.find((item) => item.id === oldCheck?.adapterId);
    if (!oldCheck) return { ...clone(finding), baseline: baselineFor('new', null, check) };
    if (!currentAdapter || !previousAdapter || currentAdapter.version !== previousAdapter.version) {
      return { ...clone(finding), baseline: baselineFor('not_comparable', previous, check, 'adapter_version_changed') };
    }
    if (oldCheck.ruleRevision !== check?.ruleRevision) {
      return { ...clone(finding), baseline: baselineFor('not_comparable', previous, check, 'rule_revision_changed') };
    }
    if (!completed(check)) {
      return { ...clone(finding), baseline: previous
        ? baselineFor('unretested', previous, check, 'current_check_incomplete')
        : baselineFor('not_comparable', null, check, 'current_check_incomplete') };
    }
    if (!previous) return { ...clone(finding), baseline: baselineFor('new', null, check) };
    const state = previous.baseline?.state === 'fixed' ? 'regressed' : 'unchanged';
    const reasonCode = !exactPrevious && state === 'unchanged' ? 'condition_moved' : null;
    return { ...clone(finding), baseline: baselineFor(state, previous, check, reasonCode) };
  });

  for (const previous of baselineReport.findings) {
    if (matchedPreviousFingerprints.has(previous.fingerprint)) continue;
    const check = coverage.get(previous.rule.id);
    const oldCheck = previousCoverage.get(previous.rule.id);
    const currentAdapter = currentRuleset.adapters.find((item) => item.id === check?.adapterId);
    const previousAdapter = baselineReport.ruleset.adapters.find((item) => item.id === oldCheck?.adapterId);
    const retained = clone(previous);
    if (!check) {
      retained.baseline = baselineFor('unretested', previous, null, 'rule_not_run');
    } else if (!currentAdapter || !previousAdapter || currentAdapter.version !== previousAdapter.version) {
      retained.baseline = baselineFor('not_comparable', previous, check, 'adapter_version_changed');
    } else if (!oldCheck || oldCheck.ruleRevision !== check.ruleRevision) {
      retained.baseline = baselineFor('not_comparable', previous, check, 'rule_revision_changed');
    } else if (!completed(check)) {
      retained.baseline = baselineFor('unretested', previous, check, 'current_check_incomplete');
    } else {
      const adapter = currentRuleset.adapters.find((item) => item.id === check.adapterId);
      if (adapter) retained.adapter = {
        id: adapter.id, version: adapter.version, rulesetDigest: adapter.rulesetDigest,
      };
      retained.baseline = baselineFor('fixed', previous, check);
    }
    compared.push(retained);
  }
  return compared;
}

export function initializeFindingsV2(currentFindings, currentCoverage) {
  const coverage = coverageMap(currentCoverage);
  return currentFindings.map((finding) => {
    const check = coverage.get(finding.rule.id);
    if (!check || check.ruleRevision !== finding.rule.revision) {
      throw new Error(`cannot initialize finding without compatible coverage: ${finding.rule.id}`);
    }
    return { ...clone(finding), baseline: emptyBaseline('new', check) };
  });
}

export function assertComparableBaseline(currentSubject, baselineReport, rawBytes) {
  const errors = validateRuntimeReportV2(baselineReport);
  if (errors.length) throw new Error(`invalid v2 baseline ${errors.join('; ')}`);
  if (baselineReport.subject.binding !== 'persisted') throw new Error('baseline subject is not persisted and cannot be compared');
  if (currentSubject.binding !== 'persisted') throw new Error('retest requires a persisted current subject');
  if (baselineReport.subject.id !== currentSubject.id) throw new Error('baseline subject does not match the current project');
  if (baselineReport.subject.scopeDigest !== currentSubject.scopeDigest) throw new Error('baseline scope does not match the current scope');
  return {
    sourceDigest: sha256(rawBytes),
    sourceSchemaVersion: 2,
    subjectId: baselineReport.subject.id,
    scopeDigest: baselineReport.subject.scopeDigest,
    rulesetDigest: baselineReport.ruleset.digest,
    compatibility: 'compatible',
    reasonCode: null,
  };
}

export function summarizeV2(findings) {
  const bySeverity = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
  const byState = Object.fromEntries(V2_RESULT_STATES.map((state) => [state, 0]));
  const byBaseline = Object.fromEntries(V2_BASELINE_STATES.map((state) => [state, 0]));
  const byDomain = Object.fromEntries(V2_DOMAINS.map((domain) => [domain, {
    total: 0,
    byState: Object.fromEntries(V2_RESULT_STATES.map((state) => [state, {
      total: 0,
      bySeverity: Object.fromEntries(SEVERITIES.map((severity) => [severity, 0])),
    }])),
  }]));
  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
    byState[finding.state] += 1;
    byDomain[finding.domain].total += 1;
    byDomain[finding.domain].byState[finding.state].total += 1;
    byDomain[finding.domain].byState[finding.state].bySeverity[finding.severity] += 1;
    if (finding.baseline.state) byBaseline[finding.baseline.state] += 1;
  }
  return { total: findings.length, byDomain, bySeverity, byState, byBaseline };
}

export function createReportV2({
  version, generatedAt, mode, subject, ruleset, scope, coverage, findings, limitations,
  baseline = null, migration = null, policy = DEFAULT_POLICY,
}) {
  for (const finding of findings) {
    if (JSON.stringify(sanitizeEvidence(finding)) !== JSON.stringify(finding)) {
      throw new Error(`finding contains unsanitized or oversized evidence: ${finding.id || 'unknown'}`);
    }
  }
  const report = {
    schemaVersion: 2,
    tool: { name: 'Web App Security Skill', version },
    generatedAt,
    mode,
    subject: sanitizeEvidence(subject),
    ruleset: sanitizeEvidence(ruleset),
    scope: sanitizeEvidence(scope),
    policy: sanitizeEvidence(policy),
    coverage: sanitizeEvidence(coverage),
    summary: summarizeV2(findings),
    findings: [...findings].sort((left, right) =>
      (severityRank.get(left.severity) - severityRank.get(right.severity)) || left.id.localeCompare(right.id)),
    limitations: sanitizeEvidence(limitations),
    baseline: sanitizeEvidence(baseline),
    migration: sanitizeEvidence(migration),
  };
  const errors = validateRuntimeReportV2(report);
  if (errors.length) throw new Error(`invalid v2 report:\n${errors.map((error) => `- ${error}`).join('\n')}`);
  return report;
}

function expectedRuleset(report) {
  const adapters = report.ruleset.adapters.map((adapter) => {
    const rules = report.coverage.filter((entry) => entry.adapterId === adapter.id)
      .map((entry) => ({ id: entry.ruleId, revision: entry.ruleRevision }));
    return { ...adapter, rulesetDigest: adapterRulesetDigest(adapter, rules) };
  });
  return { digest: digestValue({ fingerprintVersion: 2, adapters }), adapters };
}

export function validateRuntimeReportV2(report) {
  const errors = validateReportV2(report);
  if (report?.tool?.name !== 'Web App Security Skill' || typeof report?.tool?.version !== 'string') errors.push('report.tool is invalid');
  if (Number.isNaN(Date.parse(report?.generatedAt))) errors.push('report.generatedAt is invalid');
  if (!Array.isArray(report?.limitations)) errors.push('report.limitations must be an array');
  const adapterIds = new Set();
  for (const adapter of report?.ruleset?.adapters || []) {
    if (adapterIds.has(adapter.id)) errors.push(`duplicate ruleset adapter ${adapter.id}`);
    adapterIds.add(adapter.id);
  }
  const coverageKeys = new Set();
  for (const entry of report?.coverage || []) {
    if (!entry.ruleId || !entry.ruleRevision) errors.push('coverage requires rule identity');
    const key = `${entry.adapterId}:${entry.ruleId}`;
    if (coverageKeys.has(key)) errors.push(`duplicate coverage rule ${key}`);
    coverageKeys.add(key);
    if (!adapterIds.has(entry.adapterId)) errors.push(`coverage references absent adapter ${entry.adapterId}`);
  }
  if (report?.ruleset?.adapters && report?.coverage) {
    const expected = expectedRuleset(report);
    for (const adapter of report.ruleset.adapters) {
      const calculated = expected.adapters.find((item) => item.id === adapter.id)?.rulesetDigest;
      if (adapter.rulesetDigest !== calculated) errors.push(`adapter ruleset digest is invalid: ${adapter.id}`);
    }
    if (report.ruleset.digest !== expected.digest) errors.push('report ruleset digest is invalid');
  }
  const ids = new Set();
  const fingerprints = new Set();
  for (const finding of report?.findings || []) {
    if (ids.has(finding.id)) errors.push(`duplicate finding id ${finding.id}`);
    ids.add(finding.id);
    if (fingerprints.has(finding.fingerprint)) errors.push(`duplicate finding fingerprint ${finding.fingerprint}`);
    fingerprints.add(finding.fingerprint);
    if (finding.fingerprint !== findingFingerprint(finding)) errors.push(`finding fingerprint is invalid: ${finding.id}`);
    const adapter = report.ruleset?.adapters?.find((item) => item.id === finding.adapter?.id);
    const check = report.coverage?.find((item) => item.adapterId === finding.adapter?.id && item.ruleId === finding.rule?.id);
    const retained = ['unretested', 'not_comparable'].includes(finding.baseline?.state);
    if (!adapter && !retained) errors.push(`finding adapter is absent from ruleset: ${finding.id}`);
    if (adapter && finding.adapter.rulesetDigest !== adapter.rulesetDigest && !retained) {
      errors.push(`finding adapter digest is inconsistent: ${finding.id}`);
    }
    if (check && check.ruleRevision !== finding.rule.revision && !retained) {
      errors.push(`finding rule revision is inconsistent: ${finding.id}`);
    }
  }
  if (report?.findings && JSON.stringify(report.summary) !== JSON.stringify(summarizeV2(report.findings))) {
    errors.push('report summary is inconsistent');
  }
  return [...new Set(errors)];
}

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[character]);
const escapeXml = escapeHtml;

function domainSummaryLines(report) {
  return V2_DOMAINS.flatMap((domain) => {
    const summary = report.summary.byDomain[domain];
    if (!summary.total) return [];
    const states = V2_RESULT_STATES.flatMap((state) => {
      const stateSummary = summary.byState[state];
      if (!stateSummary.total) return [];
      const severities = SEVERITIES.filter((severity) => stateSummary.bySeverity[severity])
        .map((severity) => `${severity}=${stateSummary.bySeverity[severity]}`).join(', ');
      return `${state}=${stateSummary.total} (${severities})`;
    }).join('; ');
    return [`${domain}: total=${summary.total}; ${states}`];
  });
}

export function renderMarkdownV2(report) {
  const adapterLines = report.ruleset.adapters.map((adapter) =>
    `- \`${adapter.id}@${adapter.version}\` (${adapter.maturity}); ruleset \`${adapter.rulesetDigest}\``);
  const coverageLines = report.coverage.flatMap((entry) => {
    const counts = Object.entries(entry.counts).map(([key, value]) => `${key}=${value}`).join(', ');
    const reasons = entry.reasons.length
      ? `; reasons: ${entry.reasons.map((reason) => `${reason.code}=${reason.count}${reason.samplePaths.length ? ` [${reason.samplePaths.join(', ')}]` : ''}`).join('; ')}`
      : '';
    return [`- \`${entry.adapterId}/${entry.ruleId}@${entry.ruleRevision}\`: ${entry.status}; ${counts}${reasons}`];
  });
  const traversal = report.scope?.traversal
    ? [`- Traversal: entries=${report.scope.traversal.entriesSeen}, files=${report.scope.traversal.filesDiscovered}, stopped=${report.scope.traversal.stopped}; limits=${JSON.stringify(report.scope.traversal.effectiveLimits)}`]
    : [];
  const lines = [
    '# Web App Security report', '',
    `- Schema: \`v${report.schemaVersion}\``,
    `- Mode: \`${report.mode}\``,
    `- Subject: \`${report.subject.id}\` (${report.subject.binding})`,
    `- Generated: ${report.generatedAt}`,
    `- Findings: ${report.summary.total}`,
    '', '## Risk summary', '',
    ...domainSummaryLines(report).map((line) => `- ${line}`),
    ...(report.summary.total ? [] : ['No findings were produced by the checks that ran.']),
    '', '## Adapters', '',
    ...adapterLines,
    '', '## Coverage', '',
    ...traversal,
    ...coverageLines,
    '', '## Findings', '',
  ];
  if (!report.findings.length) lines.push('No findings were produced by the checks that ran.', '');
  for (const finding of report.findings) {
    lines.push(
      `### ${finding.id}: ${finding.title}`, '',
      `**${finding.domain} / ${finding.severity} / ${finding.state} / ${finding.baseline.state || 'none'}**`, '',
      finding.summary, '',
      finding.location ? `Location: \`${finding.location.path}${finding.location.line ? `:${finding.location.line}` : ''}\`` : 'Location: project-wide', '',
      `Evidence: \`${JSON.stringify(finding.evidence)}\``, '',
      `Remediation: ${finding.remediation}`, '',
      `Retest: ${finding.retest}`, '',
    );
  }
  lines.push('## Limitations', '', ...report.limitations.map((item) => `- ${item}`), '');
  return `${lines.join('\n')}\n`;
}

export function renderHtmlV2(report) {
  const adapters = report.ruleset.adapters.map((adapter) =>
    `<li><code>${escapeHtml(`${adapter.id}@${adapter.version}`)}</code> (${escapeHtml(adapter.maturity)}); ruleset <code>${escapeHtml(adapter.rulesetDigest)}</code></li>`).join('');
  const rows = report.findings.map((finding) => `<article data-finding-id="${escapeHtml(finding.id)}">
<h2>${escapeHtml(finding.title)}</h2>
<p><strong>${escapeHtml(`${finding.domain} / ${finding.severity} / ${finding.state} / ${finding.baseline.state || 'none'}`)}</strong></p>
<p>${escapeHtml(finding.summary)}</p>
<dl><dt>ID</dt><dd><code>${escapeHtml(finding.id)}</code></dd><dt>Location</dt><dd><code>${escapeHtml(finding.location ? `${finding.location.path}${finding.location.line ? `:${finding.location.line}` : ''}` : 'project-wide')}</code></dd><dt>Evidence</dt><dd><code>${escapeHtml(JSON.stringify(finding.evidence))}</code></dd><dt>Remediation</dt><dd>${escapeHtml(finding.remediation)}</dd><dt>Retest</dt><dd>${escapeHtml(finding.retest)}</dd></dl>
</article>`).join('\n');
  const coverage = report.coverage.map((entry) => {
    const counts = Object.entries(entry.counts).map(([key, value]) => `${key}=${value}`).join(', ');
    const reasons = entry.reasons.length
      ? `; reasons: ${entry.reasons.map((reason) => `${reason.code}=${reason.count}${reason.samplePaths.length ? ` [${reason.samplePaths.join(', ')}]` : ''}`).join('; ')}`
      : '';
    return `<li><code>${escapeHtml(`${entry.adapterId}/${entry.ruleId}@${entry.ruleRevision}`)}</code>: ${escapeHtml(`${entry.status}; ${counts}${reasons}`)}</li>`;
  }).join('');
  const traversal = report.scope?.traversal
    ? `<p>Traversal: <code>${escapeHtml(JSON.stringify(report.scope.traversal))}</code></p>`
    : '';
  const summary = domainSummaryLines(report).map((line) => `<li>${escapeHtml(line)}</li>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Web App Security report</title><style>body{font:16px/1.5 system-ui;max-width:960px;margin:40px auto;padding:0 20px;color:#171717}article{border-top:1px solid #bbb;padding:16px 0}code{overflow-wrap:anywhere}dt{font-weight:700;margin-top:8px}</style></head><body><h1>Web App Security report</h1><p>Mode: ${escapeHtml(report.mode)} · Findings: ${report.summary.total}</p><p>Subject: <code>${escapeHtml(report.subject.id)}</code></p><h2>Risk summary</h2>${summary ? `<ul>${summary}</ul>` : '<p>No findings were produced by the checks that ran.</p>'}<h2>Adapters</h2><ul>${adapters}</ul><h2>Coverage</h2>${traversal}<ul>${coverage}</ul><h2>Findings</h2>${rows || '<p>No findings were produced by the checks that ran.</p>'}<h2>Limitations</h2><ul>${report.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul></body></html>\n`;
}

export function renderSarifV2(report) {
  const rules = [...new Map(report.findings.map((finding) => [finding.rule.id, {
    id: finding.rule.id,
    shortDescription: { text: finding.title },
    help: { text: `${finding.remediation}\n\nRetest: ${finding.retest}` },
  }])).values()];
  const level = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
  return `${JSON.stringify({
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'Web App Security Skill', version: report.tool.version, rules },
        extensions: report.ruleset.adapters.map((adapter) => ({
          name: adapter.id, version: adapter.version,
          semanticVersion: /^\d+\.\d+\.\d+$/.test(adapter.version) ? adapter.version : undefined,
          properties: { maturity: adapter.maturity, rulesetDigest: adapter.rulesetDigest },
        })) },
      properties: {
        adapterCoverage: report.coverage.map((entry) => ({
          id: entry.id, adapterId: entry.adapterId, ruleId: entry.ruleId,
          ruleRevision: entry.ruleRevision, status: entry.status, counts: entry.counts,
        })),
      },
      results: report.findings.filter((finding) => finding.baseline.state !== 'fixed').map((finding) => ({
        ruleId: finding.rule.id,
        level: level[finding.severity],
        message: { text: `[${finding.state}] ${finding.summary}` },
        fingerprints: { webAppSecurityFingerprint: finding.fingerprint },
        properties: { domain: finding.domain, evidenceState: finding.state, baselineState: finding.baseline.state },
        ...(finding.location ? { locations: [{ physicalLocation: {
          artifactLocation: { uri: finding.location.path },
          ...(finding.location.line ? { region: { startLine: finding.location.line } } : {}),
        } }] } : {}),
      })),
    }],
  }, null, 2)}\n`;
}

export function renderJunitV2(report) {
  const failures = report.findings.filter((finding) => finding.state === 'confirmed' && finding.baseline.state !== 'fixed').length;
  const skipped = report.findings.length - failures;
  const cases = report.findings.map((finding) => {
    const attrs = `classname="web-app-security.${escapeXml(finding.rule.id)}" name="${escapeXml(finding.id)}"`;
    const properties = `<properties><property name="domain" value="${escapeXml(finding.domain)}"/><property name="evidenceState" value="${escapeXml(finding.state)}"/><property name="baselineState" value="${escapeXml(finding.baseline.state)}"/></properties>`;
    if (finding.baseline.state === 'fixed') return `<testcase ${attrs}>${properties}<skipped message="fixed in retest"/></testcase>`;
    if (finding.state !== 'confirmed') return `<testcase ${attrs}>${properties}<skipped message="${escapeXml(finding.state)}"/></testcase>`;
    return `<testcase ${attrs}>${properties}<failure message="${escapeXml(`${finding.severity}: ${finding.title}`)}">${escapeXml(finding.summary)}</failure></testcase>`;
  }).join('');
  const adapterProperties = report.ruleset.adapters.map((adapter) =>
    `<property name="adapter.${escapeXml(adapter.id)}.version" value="${escapeXml(adapter.version)}"/><property name="adapter.${escapeXml(adapter.id)}.rulesetDigest" value="${escapeXml(adapter.rulesetDigest)}"/>`).join('');
  const coverageProperties = report.coverage.map((entry) =>
    `<property name="coverage.${escapeXml(entry.id)}.status" value="${escapeXml(entry.status)}"/><property name="coverage.${escapeXml(entry.id)}.counts" value="${escapeXml(JSON.stringify(entry.counts))}"/>`).join('');
  return `<?xml version="1.0" encoding="UTF-8"?><testsuite name="Web App Security Skill" tests="${report.findings.length}" failures="${failures}" skipped="${skipped}"><properties>${adapterProperties}${coverageProperties}</properties>${cases}</testsuite>\n`;
}

export function writeReportBundleV2(report, directory, name = 'report', { additionalFiles = [], hooks = {} } = {}) {
  if (!/^[a-zA-Z0-9._-]+$/.test(name)) throw new Error('report name contains unsupported characters');
  const errors = validateRuntimeReportV2(report);
  if (errors.length) throw new Error(`refusing invalid report bundle: ${errors.join('; ')}`);
  const jsonBytes = `${JSON.stringify(report, null, 2)}\n`;
  const entries = [
    { key: 'json', name: `${name}.json`, content: jsonBytes, validate: (bytes) => JSON.parse(bytes.toString('utf8')) },
    { key: 'markdown', name: `${name}.md`, content: renderMarkdownV2(report) },
    { key: 'html', name: `${name}.html`, content: renderHtmlV2(report) },
    { key: 'sarif', name: `${name}.sarif`, content: renderSarifV2(report), validate: (bytes) => JSON.parse(bytes.toString('utf8')) },
    { key: 'junit', name: `${name}.junit.xml`, content: renderJunitV2(report) },
    { key: 'digest', name: `${name}.sha256`, content: `${sha256(jsonBytes)}  ${name}.json\n` },
    ...additionalFiles.map((file) => {
      const content = file.json === undefined
        ? (file.sanitize === false ? file.content : sanitizeEvidence(file.content))
        : (file.sanitize === false
          ? `${JSON.stringify(file.json, null, 2)}\n`
          : sanitizedJson(file.json));
      return {
        key: file.key || file.name,
        name: file.name,
        content,
        ...(file.json === undefined ? {} : { validate: (bytes) => JSON.parse(bytes.toString('utf8')) }),
      };
    }),
  ];
  return writeAtomicEvidenceBundle(directory, entries, hooks);
}

export function readReportV2(path) {
  const rawBytes = readFileSync(path);
  let report;
  try { report = JSON.parse(rawBytes.toString('utf8')); } catch { throw new Error(`invalid report JSON: ${basename(path)}`); }
  const errors = validateRuntimeReportV2(report);
  if (errors.length) throw new Error(`invalid v2 report ${basename(path)}:\n${errors.join('\n')}`);
  return { report, rawBytes };
}

export function readBaselineV2(path) {
  const loaded = readReportV2(path);
  const digestPath = join(dirname(path), `${basename(path, '.json')}.sha256`);
  let recorded;
  try {
    const line = readFileSync(digestPath, 'utf8').trim();
    const match = /^([a-f0-9]{64})  ([a-zA-Z0-9._-]+\.json)$/.exec(line);
    if (!match || match[2] !== basename(path)) throw new Error();
    recorded = match[1];
  } catch {
    throw new Error(`baseline digest sidecar is missing or invalid: ${basename(digestPath)}`);
  }
  if (sha256(loaded.rawBytes) !== recorded) throw new Error('baseline bytes do not match the recorded digest');
  return { ...loaded, sourceDigest: recorded };
}

export function failsThresholdV2(report) {
  const thresholds = new Map(report.policy.thresholds.map((entry) => [entry.domain, entry.failOn]));
  const gateStates = new Set(Array.isArray(report.policy.gateStates)
    ? report.policy.gateStates
    : ['confirmed']);
  return report.findings.some((finding) => {
    const failOn = thresholds.get(finding.domain) || 'never';
    if (failOn === 'never' || !gateStates.has(finding.state) || finding.baseline.state === 'fixed') return false;
    return severityRank.get(finding.severity) <= severityRank.get(failOn);
  });
}

export function hasIncompleteEvidenceV2(report) {
  return report.findings.some((finding) => finding.state === 'unknown'
      && finding.baseline.state !== 'fixed')
    || report.coverage.some((entry) => ['partial', 'unavailable'].includes(entry.status));
}

export function exitCodeV2(report) {
  if (failsThresholdV2(report)) return 1;
  if (hasIncompleteEvidenceV2(report)) return 3;
  return 0;
}

export function reportDigest(report) {
  return createHash('sha256').update(`${JSON.stringify(report, null, 2)}\n`).digest('hex');
}
