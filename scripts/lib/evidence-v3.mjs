import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import {
  assertComparableBaseline, compareFindingsV2, createFindingV2, createReportV2, exitCodeV2,
  initializeFindingsV2, readBaselineV2, sourceFindingV2, validateRuntimeReportV2,
} from './evidence-v2.mjs';
import { sanitizeEvidence, sanitizedJson, writeAtomicEvidenceBundle } from './evidence-writer.mjs';
import { BUILTIN_SOURCE_ADAPTER, sourceRule } from './source-rules.mjs';
import { sourceRuleExplanation, sourceRuleHelpUri } from './source-rule-registry.mjs';
import {
  downgradeFindingV3, downgradeReportV3, validateExplanationV3, validateReportV3,
} from './report-v3-contract.mjs';
import { sha256 } from './report-v2-contract.mjs';
import { markdownCodeSpan } from './markdown-escaping.mjs';

const severityRank = new Map(['critical', 'high', 'medium', 'low', 'info']
  .map((severity, index) => [severity, index]));

function defaultExplanation(finding) {
  const unavailable = finding.state === 'unknown';
  const notApplicable = finding.state === 'not_applicable';
  return {
    technicalTerm: finding.title,
    plainLanguage: finding.summary,
    consequence: unavailable
      ? 'The audit cannot determine whether this condition is safe until the missing evidence is available.'
      : notApplicable
        ? 'The recorded component or condition is outside this project scope, so no product impact is asserted.'
        : 'If the observed condition is reachable in production, it may affect the confidentiality, integrity or availability described by this finding.',
    evidenceBoundary: unavailable
      ? 'The required check did not complete. This result is an evidence gap and does not prove the project is vulnerable or safe.'
      : finding.state === 'suspected'
        ? 'The audit observed a source or scanner lead. Runtime reachability and exploitability have not been established.'
        : finding.state === 'confirmed'
          ? 'The stated condition was reproduced by the named check with sanitized evidence; broader exploitability is limited to the recorded scope.'
          : 'The check recorded that this rule does not apply to the current scope.',
    standards: [],
    proposal: {
      status: notApplicable ? 'not_applicable' : unavailable ? 'review_required' : 'ready_for_review',
      summary: finding.remediation,
    },
    alternatives: [],
    sideEffects: [
      unavailable
        ? 'Collecting the missing evidence may require installing a pinned local tool or expanding the reviewed source scope.'
        : 'The proposed change may alter existing application or deployment behavior; review the affected component before applying it.',
    ],
    securityRetest: finding.retest,
    functionalRetest: 'Run the project-native tests and the affected user journey after applying the proposal.',
    rollback: 'Revert the reviewed change if the affected user journey or project-native tests regress, then reassess the proposal with the observed behavior.',
    userDecisions: [],
  };
}

export function explanationForFindingV3(finding, explanation = null) {
  const clean = sanitizeEvidence(explanation || defaultExplanation(finding));
  const errors = validateExplanationV3(clean);
  if (errors.length) throw new Error(`invalid v3 explanation: ${errors.join('; ')}`);
  return clean;
}

export function createFindingV3(options) {
  const v2 = createFindingV2(options);
  const explanation = explanationForFindingV3(v2, options.explanation);
  return { ...v2, schemaVersion: 3, explanation, disposition: { status: 'active' } };
}

export function upgradeFindingV2(finding, explanation = null) {
  if (finding.schemaVersion === 3) return {
    ...structuredClone(finding), disposition: finding.disposition || { status: 'active' },
  };
  if (finding.schemaVersion !== 2) throw new Error('only v2 findings can be upgraded to v3');
  return {
    ...structuredClone(finding), schemaVersion: 3,
    explanation: explanationForFindingV3(finding, explanation), disposition: { status: 'active' },
  };
}

export function sourceFindingV3(legacyFinding, ruleset, explanation = null) {
  const v2 = sourceFindingV2(legacyFinding, ruleset);
  return upgradeFindingV2(v2, explanation || sourceRuleExplanation(
    BUILTIN_SOURCE_ADAPTER.id, legacyFinding.ruleId, v2,
  ));
}

function upgradeReportFindings(report, explanationProvider = null) {
  if (report.schemaVersion === 3) return structuredClone(report);
  if (report.schemaVersion !== 2) throw new Error('only v2 reports can be upgraded for v3 comparison');
  return {
    ...structuredClone(report),
    schemaVersion: 3,
    findings: report.findings.map((finding) => upgradeFindingV2(
      finding, explanationProvider ? explanationProvider(finding) : null,
    )),
  };
}

export function initializeFindingsV3(findings, coverage) {
  return initializeFindingsV2(findings, coverage);
}

export function compareFindingsV3(current, coverage, baselineReport, currentRuleset, explanationProvider = null) {
  const upgradedBaseline = upgradeReportFindings(baselineReport, explanationProvider);
  return compareFindingsV2(current, coverage, upgradedBaseline, currentRuleset)
    .map((finding) => finding.schemaVersion === 3 ? finding : upgradeFindingV2(finding));
}

export function assertComparableBaselineV3(currentSubject, baselineReport, rawBytes) {
  if (baselineReport.schemaVersion === 2) return assertComparableBaseline(currentSubject, baselineReport, rawBytes);
  const errors = validateRuntimeReportV3(baselineReport);
  if (errors.length) throw new Error(`invalid v3 baseline ${errors.join('; ')}`);
  if (baselineReport.subject.binding !== 'persisted') throw new Error('baseline subject is not persisted and cannot be compared');
  if (currentSubject.binding !== 'persisted') throw new Error('retest requires a persisted current subject');
  if (baselineReport.subject.id !== currentSubject.id) throw new Error('baseline subject does not match the current project');
  if (baselineReport.subject.scopeDigest !== currentSubject.scopeDigest) throw new Error('baseline scope does not match the current scope');
  return {
    sourceDigest: sha256(rawBytes),
    sourceSchemaVersion: 3,
    subjectId: baselineReport.subject.id,
    scopeDigest: baselineReport.subject.scopeDigest,
    rulesetDigest: baselineReport.ruleset.digest,
    compatibility: 'compatible',
    reasonCode: null,
  };
}

export function createReportV3(options) {
  const cleanFindings = options.findings.map((finding) => ({
    ...structuredClone(finding),
    explanation: explanationForFindingV3(finding, finding.explanation),
    disposition: finding.disposition || { status: 'active' },
  }));
  const base = createReportV2({
    ...options,
    findings: cleanFindings.map(downgradeFindingV3),
    baseline: options.baseline?.sourceSchemaVersion === 3
      ? { ...options.baseline, sourceSchemaVersion: 2 }
      : options.baseline,
  });
  const findingById = new Map(cleanFindings.map((finding) => [finding.id, finding]));
  const report = {
    ...base,
    schemaVersion: 3,
    findings: base.findings.map((finding) => findingById.get(finding.id)),
    baseline: sanitizeEvidence(options.baseline ?? null),
  };
  const suppressedTotal = report.findings.filter((finding) =>
    finding.disposition.status === 'suppressed').length;
  report.summary = {
    ...report.summary,
    activeTotal: report.summary.total - suppressedTotal,
    suppressedTotal,
    byDisposition: { active: report.summary.total - suppressedTotal, suppressed: suppressedTotal },
  };
  const errors = validateRuntimeReportV3(report);
  if (errors.length) throw new Error(`invalid v3 report:\n${errors.map((error) => `- ${error}`).join('\n')}`);
  return report;
}

export function validateRuntimeReportV3(report) {
  const errors = validateReportV3(report);
  const downgraded = downgradeReportV3(report);
  errors.push(...validateRuntimeReportV2(downgraded));
  return [...new Set(errors)];
}

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (character) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[character]);
const escapeXml = escapeHtml;
const evidenceLabels = {
  confirmed: 'reproduced in the recorded scope',
  suspected: 'a lead that still needs context or reproduction',
  unknown: 'the required evidence was unavailable; this is not a pass',
  not_applicable: 'outside the recorded scope',
};
const proposalLabels = {
  ready_for_review: 'specific proposal ready for human review',
  review_required: 'missing context or a user decision before application',
  no_safe_automatic_change: 'no safe automatic change was identified',
  not_applicable: 'no repair applies to this result',
};

function listLines(values, fallback = 'None recorded.') {
  return values.length ? values.map((value) => `- ${value}`) : [fallback];
}

function domainSummaryLines(report) {
  return Object.entries(report.summary.byDomain).flatMap(([domain, summary]) => {
    if (!summary.total) return [];
    const states = Object.entries(summary.byState).flatMap(([state, stateSummary]) => {
      if (!stateSummary.total) return [];
      const severities = Object.entries(stateSummary.bySeverity)
        .filter(([, count]) => count)
        .map(([severity, count]) => `${severity}=${count}`).join(', ');
      return `${state}=${stateSummary.total}${severities ? ` (${severities})` : ''}`;
    }).join('; ');
    return [`${domain}: total=${summary.total}${states ? `; ${states}` : ''}`];
  });
}

function coverageLine(entry) {
  const counts = Object.entries(entry.counts).map(([key, value]) => `${key}=${value}`).join(', ');
  const reasons = entry.reasons.length
    ? `; reasons: ${entry.reasons.map((reason) => `${reason.code}=${reason.count}${reason.samplePaths.length ? ` [${reason.samplePaths.join(', ')}]` : ''}`).join('; ')}`
    : '';
  return `${entry.status}; ${counts}${reasons}`;
}

export function renderFindingMarkdownV3(finding, { technical = false } = {}) {
  const explanation = finding.explanation;
  const lines = [
    `### ${finding.id}: ${finding.title}`, '',
    `**${finding.domain} / ${finding.severity} / ${finding.state} (${evidenceLabels[finding.state]}) / ${finding.baseline.state || 'none'}**`, '',
    ...(finding.disposition.status === 'suppressed' ? [
      `**SUPPRESSED (${finding.disposition.suppressionId})${finding.disposition.expiresAt ? ` until ${finding.disposition.expiresAt}` : ''}:** ${finding.disposition.reason}`, '',
    ] : []),
    `**Professional term:** ${explanation.technicalTerm}`, '',
    `**What this means:** ${explanation.plainLanguage}`, '',
    `**What could happen:** ${explanation.consequence}`, '',
    `**What the evidence proves:** ${explanation.evidenceBoundary}`, '',
    `**Proposed change (${explanation.proposal.status}: ${proposalLabels[explanation.proposal.status]}):** ${explanation.proposal.summary}`, '',
    '**Alternatives:**', '', ...listLines(explanation.alternatives), '',
    '**Possible side effects:**', '', ...listLines(explanation.sideEffects), '',
    `**Security retest:** ${explanation.securityRetest}`, '',
    `**Functional retest:** ${explanation.functionalRetest}`, '',
    `**Rollback:** ${explanation.rollback}`, '',
    '**Decisions needed from you:**', '', ...listLines(explanation.userDecisions), '',
  ];
  if (explanation.standards.length) {
    lines.push('**Standards:**', '', ...explanation.standards.map((item) => `- [${item.id}](${item.url})`), '');
  }
  if (technical) lines.push(
    '**Technical evidence:**', '',
    `- Rule: ${markdownCodeSpan(`${finding.rule.id}@${finding.rule.revision}`)}`,
    `- Adapter: ${markdownCodeSpan(`${finding.adapter.id}@${finding.adapter.version}`)}`,
    `- Location: ${finding.location ? markdownCodeSpan(`${finding.location.path}${finding.location.line ? `:${finding.location.line}` : ''}`) : 'project-wide'}`,
    `- Evidence: ${markdownCodeSpan(JSON.stringify(finding.evidence))}`, '',
  );
  return lines;
}

export function renderMarkdownV3(report, options = {}) {
  const adapterLines = report.ruleset.adapters.map((adapter) =>
    `- \`${adapter.id}@${adapter.version}\` (${adapter.maturity}); ruleset \`${adapter.rulesetDigest}\``);
  const traversal = report.scope?.traversal
    ? [`- Traversal: entries=${report.scope.traversal.entriesSeen}, files=${report.scope.traversal.filesDiscovered}, stopped=${report.scope.traversal.stopped}; limits=${JSON.stringify(report.scope.traversal.effectiveLimits)}`]
    : [];
  const selection = report.scope?.selection
    ? [`- Selection: mode=${report.scope.selection.mode}; base=${report.scope.selection.baseCommit}; snapshot=${report.scope.selection.snapshotKind}; changedFiles=${report.scope.selection.changedFileCount}; addedLines=${report.scope.selection.addedLineCount}; untrackedExcluded=${report.scope.selection.untrackedFilesExcluded}`]
    : [];
  const lines = [
    '# Web App Security report', '',
    `- Schema: \`v${report.schemaVersion}\``,
    `- Mode: \`${report.mode}\``,
    `- Subject: \`${report.subject.id}\` (${report.subject.binding})`,
    `- Generated: ${report.generatedAt}`,
    `- Findings: ${report.summary.total} (active=${report.summary.activeTotal}, suppressed=${report.summary.suppressedTotal})`, '',
    '## Risk summary', '',
    ...domainSummaryLines(report).map((line) => `- ${line}`),
    ...(report.summary.total ? [] : ['No findings were produced by the checks that ran.']),
    '', '## Adapters', '',
    ...adapterLines,
    '', '## Coverage', '',
    ...selection,
    ...traversal,
    ...report.coverage.map((entry) =>
      `- \`${entry.adapterId}/${entry.ruleId}@${entry.ruleRevision}\`: ${coverageLine(entry)}`),
    '',
    '## Findings', '',
  ];
  if (!report.findings.length) lines.push('No findings were produced by the checks that ran.', '');
  for (const finding of report.findings) lines.push(...renderFindingMarkdownV3(finding, options));
  lines.push('## Limitations', '', ...report.limitations.map((item) => `- ${item}`), '');
  return `${lines.join('\n')}\n`;
}

export function renderHtmlV3(report) {
  const adapters = report.ruleset.adapters.map((adapter) =>
    `<li><code>${escapeHtml(`${adapter.id}@${adapter.version}`)}</code> (${escapeHtml(adapter.maturity)}); ruleset <code>${escapeHtml(adapter.rulesetDigest)}</code></li>`).join('');
  const coverage = report.coverage.map((entry) =>
    `<li><code>${escapeHtml(`${entry.adapterId}/${entry.ruleId}@${entry.ruleRevision}`)}</code>: ${escapeHtml(coverageLine(entry))}</li>`).join('');
  const traversal = report.scope?.traversal
    ? `<p>Traversal: <code>${escapeHtml(JSON.stringify(report.scope.traversal))}</code></p>`
    : '';
  const selection = report.scope?.selection
    ? `<p>Selection: <code>${escapeHtml(JSON.stringify(report.scope.selection))}</code></p>`
    : '';
  const summary = domainSummaryLines(report).map((line) => `<li>${escapeHtml(line)}</li>`).join('');
  const rows = report.findings.map((finding) => {
    const x = finding.explanation;
    const list = (values) => values.length
      ? `<ul>${values.map((value) => `<li>${escapeHtml(value)}</li>`).join('')}</ul>`
      : '<p>None recorded.</p>';
    const standards = x.standards.length
      ? `<ul>${x.standards.map((item) => `<li><a href="${escapeHtml(item.url)}">${escapeHtml(item.id)}</a></li>`).join('')}</ul>`
      : '<p>None recorded.</p>';
    const disposition = finding.disposition.status === 'suppressed'
      ? `<p><strong>SUPPRESSED (${escapeHtml(finding.disposition.suppressionId)})${finding.disposition.expiresAt ? ` until ${escapeHtml(finding.disposition.expiresAt)}` : ''}:</strong> ${escapeHtml(finding.disposition.reason)}</p>` : '';
    return `<article data-finding-id="${escapeHtml(finding.id)}"><h2>${escapeHtml(finding.title)}</h2><p><strong>${escapeHtml(`${finding.domain} / ${finding.severity} / ${finding.state} (${evidenceLabels[finding.state]}) / ${finding.baseline.state || 'none'}`)}</strong></p>${disposition}<dl><dt>Professional term</dt><dd>${escapeHtml(x.technicalTerm)}</dd><dt>What this means</dt><dd>${escapeHtml(x.plainLanguage)}</dd><dt>What could happen</dt><dd>${escapeHtml(x.consequence)}</dd><dt>What the evidence proves</dt><dd>${escapeHtml(x.evidenceBoundary)}</dd><dt>Proposed change (${escapeHtml(`${x.proposal.status}: ${proposalLabels[x.proposal.status]}`)})</dt><dd>${escapeHtml(x.proposal.summary)}</dd><dt>Alternatives</dt><dd>${list(x.alternatives)}</dd><dt>Possible side effects</dt><dd>${list(x.sideEffects)}</dd><dt>Security retest</dt><dd>${escapeHtml(x.securityRetest)}</dd><dt>Functional retest</dt><dd>${escapeHtml(x.functionalRetest)}</dd><dt>Rollback</dt><dd>${escapeHtml(x.rollback)}</dd><dt>Decisions needed from you</dt><dd>${list(x.userDecisions)}</dd><dt>Standards</dt><dd>${standards}</dd></dl></article>`;
  }).join('\n');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Web App Security report</title><style>body{font:16px/1.5 system-ui;max-width:960px;margin:40px auto;padding:0 20px;color:#171717}article{border-top:1px solid #bbb;padding:16px 0}code{overflow-wrap:anywhere}dt{font-weight:700;margin-top:12px}dd{margin-left:0}</style></head><body><h1>Web App Security report</h1><p>Mode: ${escapeHtml(report.mode)} · Findings: ${report.summary.total} (active=${report.summary.activeTotal}, suppressed=${report.summary.suppressedTotal})</p><h2>Risk summary</h2>${summary ? `<ul>${summary}</ul>` : '<p>No findings were produced by the checks that ran.</p>'}<h2>Adapters</h2><ul>${adapters}</ul><h2>Coverage</h2>${selection}${traversal}<ul>${coverage}</ul><h2>Findings</h2>${rows || '<p>No findings were produced by the checks that ran.</p>'}<h2>Limitations</h2><ul>${report.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul></body></html>\n`;
}

export function renderSarifV3(report) {
  const rules = [...new Map(report.findings.map((finding) => [finding.rule.id, {
    id: finding.rule.id,
    name: finding.explanation.technicalTerm,
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.explanation.plainLanguage },
    help: { text: `${finding.explanation.consequence}\n\nProposal: ${finding.explanation.proposal.summary}\n\nPossible side effects: ${finding.explanation.sideEffects.join('; ')}\n\nSecurity retest: ${finding.explanation.securityRetest}\n\nFunctional retest: ${finding.explanation.functionalRetest}\n\nRollback: ${finding.explanation.rollback}` },
    ...(sourceRuleHelpUri(finding.adapter.id, finding.rule.id)
      ? { helpUri: sourceRuleHelpUri(finding.adapter.id, finding.rule.id) } : {}),
    properties: { standards: finding.explanation.standards.map((item) => item.id) },
  }])).values()];
  const level = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
  return `${JSON.stringify({
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: {
        driver: { name: 'Web App Security Skill', version: report.tool.version, rules },
        extensions: report.ruleset.adapters.map((adapter) => ({
          name: adapter.id, version: adapter.version,
          semanticVersion: /^\d+\.\d+\.\d+$/.test(adapter.version) ? adapter.version : undefined,
          properties: { maturity: adapter.maturity, rulesetDigest: adapter.rulesetDigest },
        })),
      },
      properties: {
        adapterCoverage: report.coverage.map((entry) => ({
          id: entry.id, adapterId: entry.adapterId, ruleId: entry.ruleId,
          ruleRevision: entry.ruleRevision, status: entry.status, counts: entry.counts,
        })),
      },
      results: report.findings.filter((finding) => finding.baseline.state !== 'fixed').map((finding) => ({
        ruleId: finding.rule.id,
        level: level[finding.severity],
        message: { text: `[${finding.state}] ${finding.explanation.plainLanguage}` },
        fingerprints: { webAppSecurityFingerprint: finding.fingerprint },
        properties: {
          domain: finding.domain, evidenceState: finding.state, baselineState: finding.baseline.state,
          proposalStatus: finding.explanation.proposal.status,
        },
        ...(finding.disposition.status === 'suppressed' ? { suppressions: [{
          kind: 'external', status: 'accepted', justification: finding.disposition.reason,
        }] } : {}),
        ...(finding.location ? { locations: [{ physicalLocation: {
          artifactLocation: { uri: finding.location.path },
          ...(finding.location.line ? { region: { startLine: finding.location.line } } : {}),
        } }] } : {}),
      })),
    }],
  }, null, 2)}\n`;
}

export function renderJunitV3(report) {
  const failures = report.findings.filter((finding) => finding.state === 'confirmed'
    && finding.baseline.state !== 'fixed' && finding.disposition.status !== 'suppressed').length;
  const skipped = report.findings.length - failures;
  const cases = report.findings.map((finding) => {
    const attrs = `classname="web-app-security.${escapeXml(finding.rule.id)}" name="${escapeXml(finding.id)}"`;
    const properties = `<properties><property name="domain" value="${escapeXml(finding.domain)}"/><property name="evidenceState" value="${escapeXml(finding.state)}"/><property name="baselineState" value="${escapeXml(finding.baseline.state)}"/><property name="technicalTerm" value="${escapeXml(finding.explanation.technicalTerm)}"/><property name="proposalStatus" value="${escapeXml(finding.explanation.proposal.status)}"/></properties>`;
    if (finding.baseline.state === 'fixed') return `<testcase ${attrs}>${properties}<skipped message="fixed in retest"/></testcase>`;
    if (finding.disposition.status === 'suppressed') return `<testcase ${attrs}>${properties}<skipped message="suppressed: ${escapeXml(finding.disposition.suppressionId)}"/></testcase>`;
    if (finding.state !== 'confirmed') return `<testcase ${attrs}>${properties}<skipped message="${escapeXml(finding.state)}"/></testcase>`;
    return `<testcase ${attrs}>${properties}<failure message="${escapeXml(`${finding.severity}: ${finding.title}`)}">${escapeXml(`${finding.explanation.plainLanguage}\n\n${finding.explanation.consequence}`)}</failure></testcase>`;
  }).join('');
  const adapterProperties = report.ruleset.adapters.map((adapter) =>
    `<property name="adapter.${escapeXml(adapter.id)}.version" value="${escapeXml(adapter.version)}"/><property name="adapter.${escapeXml(adapter.id)}.rulesetDigest" value="${escapeXml(adapter.rulesetDigest)}"/>`).join('');
  const coverageProperties = report.coverage.map((entry) =>
    `<property name="coverage.${escapeXml(entry.id)}.status" value="${escapeXml(entry.status)}"/><property name="coverage.${escapeXml(entry.id)}.counts" value="${escapeXml(JSON.stringify(entry.counts))}"/>`).join('');
  return `<?xml version="1.0" encoding="UTF-8"?><testsuite name="Web App Security Skill" tests="${report.findings.length}" failures="${failures}" skipped="${skipped}"><properties>${adapterProperties}${coverageProperties}</properties>${cases}</testsuite>\n`;
}

export function writeReportBundleV3(report, directory, name = 'report', { additionalFiles = [], hooks = {} } = {}) {
  if (!/^[a-zA-Z0-9._-]+$/.test(name)) throw new Error('report name contains unsupported characters');
  const errors = validateRuntimeReportV3(report);
  if (errors.length) throw new Error(`refusing invalid v3 report bundle: ${errors.join('; ')}`);
  const jsonBytes = `${JSON.stringify(report, null, 2)}\n`;
  const entries = [
    { key: 'json', name: `${name}.json`, content: jsonBytes, validate: (bytes) => JSON.parse(bytes.toString('utf8')) },
    { key: 'markdown', name: `${name}.md`, content: renderMarkdownV3(report) },
    { key: 'html', name: `${name}.html`, content: renderHtmlV3(report) },
    { key: 'sarif', name: `${name}.sarif`, content: renderSarifV3(report), validate: (bytes) => JSON.parse(bytes.toString('utf8')) },
    { key: 'junit', name: `${name}.junit.xml`, content: renderJunitV3(report) },
    { key: 'digest', name: `${name}.sha256`, content: `${sha256(jsonBytes)}  ${name}.json\n` },
    ...additionalFiles.map((file) => {
      const content = file.json === undefined
        ? (file.sanitize === false ? file.content : sanitizeEvidence(file.content))
        : (file.sanitize === false ? `${JSON.stringify(file.json, null, 2)}\n` : sanitizedJson(file.json));
      return { key: file.key || file.name, name: file.name, content,
        ...(file.validate ? { validate: file.validate }
          : file.json === undefined ? {} : { validate: (bytes) => JSON.parse(bytes.toString('utf8')) }) };
    }),
  ];
  return writeAtomicEvidenceBundle(directory, entries, hooks);
}

export function readReportV3(path) {
  const rawBytes = readFileSync(path);
  let report;
  try { report = JSON.parse(rawBytes.toString('utf8')); } catch { throw new Error(`invalid report JSON: ${basename(path)}`); }
  const errors = validateRuntimeReportV3(report);
  if (errors.length) throw new Error(`invalid v3 report ${basename(path)}:\n${errors.join('\n')}`);
  return { report, rawBytes };
}

export function readBaselineV3(path) {
  let header;
  try { header = JSON.parse(readFileSync(path, 'utf8')); } catch { throw new Error(`invalid report JSON: ${basename(path)}`); }
  if (header.schemaVersion === 2) return readBaselineV2(path);
  const loaded = readReportV3(path);
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

export function exitCodeV3(report) {
  const downgraded = downgradeReportV3(report);
  downgraded.findings = downgraded.findings.filter((_finding, index) =>
    report.findings[index]?.disposition?.status !== 'suppressed');
  const code = exitCodeV2(downgraded);
  if (code === 1) return 1;
  if (report.scope?.suppression?.status === 'unavailable') return 3;
  return code;
}

export function reportDigestV3(report) {
  return createHash('sha256').update(`${JSON.stringify(report, null, 2)}\n`).digest('hex');
}

export { BUILTIN_SOURCE_ADAPTER, sourceRule, severityRank };
