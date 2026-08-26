import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { markdownCodeSpan } from './markdown-escaping.mjs';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const RESULT_STATES = ['confirmed', 'suspected', 'unknown', 'not_applicable'];
export const BASELINE_STATES = ['new', 'fixed', 'unchanged', 'regressed'];
const severityRank = new Map(SEVERITIES.map((severity, index) => [severity, index]));

function hash(value) {
  return createHash('sha256').update(value).digest('hex');
}

function stableEvidence(value) {
  if (Array.isArray(value)) return value.map(stableEvidence);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => [key, stableEvidence(item)]));
  }
  return value;
}

export function createFinding(input) {
  const identity = JSON.stringify(stableEvidence({
    ruleId: input.ruleId,
    location: input.location?.path || null,
    discriminator: input.discriminator || input.evidence?.subject || null,
  }));
  const fingerprint = hash(identity);
  return {
    schemaVersion: 1,
    id: `${input.ruleId}-${fingerprint.slice(0, 12)}`,
    fingerprint,
    ruleId: input.ruleId,
    title: input.title,
    severity: input.severity,
    state: input.state,
    summary: input.summary,
    location: input.location || null,
    evidence: stableEvidence(input.evidence || {}),
    remediation: input.remediation,
    retest: input.retest,
    baselineState: input.baselineState || null,
    ...(input.patch ? { patch: input.patch } : {}),
  };
}

export function validateFinding(finding) {
  const errors = [];
  if (finding?.schemaVersion !== 1) errors.push('schemaVersion must be 1');
  for (const key of ['id', 'fingerprint', 'ruleId', 'title', 'summary', 'remediation', 'retest']) {
    if (typeof finding?.[key] !== 'string' || !finding[key]) errors.push(`${key} must be a non-empty string`);
  }
  if (!/^[a-f0-9]{64}$/.test(finding?.fingerprint || '')) errors.push('fingerprint must be sha256 hex');
  if (!SEVERITIES.includes(finding?.severity)) errors.push('severity is invalid');
  if (!RESULT_STATES.includes(finding?.state)) errors.push('state is invalid');
  if (finding?.baselineState !== null && !BASELINE_STATES.includes(finding?.baselineState)) errors.push('baselineState is invalid');
  if (!finding?.evidence || typeof finding.evidence !== 'object' || Array.isArray(finding.evidence)) errors.push('evidence must be an object');
  return errors;
}

export function validateReport(report) {
  const errors = [];
  if (report?.schemaVersion !== 1) errors.push('report schemaVersion must be 1');
  if (report?.tool?.name !== 'Web App Security Skill' || typeof report?.tool?.version !== 'string') errors.push('tool identity is invalid');
  if (!['audit', 'retest', 'demo-before', 'demo-after'].includes(report?.mode)) errors.push('mode is invalid');
  if (Number.isNaN(Date.parse(report?.generatedAt))) errors.push('generatedAt is invalid');
  if (!Array.isArray(report?.findings)) errors.push('findings must be an array');
  if (!Array.isArray(report?.limitations)) errors.push('limitations must be an array');
  const ids = new Set();
  const fingerprints = new Set();
  for (const [index, finding] of (report?.findings || []).entries()) {
    for (const error of validateFinding(finding)) errors.push(`findings[${index}]: ${error}`);
    if (ids.has(finding.id)) errors.push(`duplicate finding id ${finding.id}`);
    ids.add(finding.id);
    if (finding.baselineState !== 'fixed' && fingerprints.has(finding.fingerprint)) errors.push(`duplicate fingerprint ${finding.fingerprint}`);
    if (finding.baselineState !== 'fixed') fingerprints.add(finding.fingerprint);
  }
  return errors;
}

function cloneFinding(finding) {
  return JSON.parse(JSON.stringify(finding));
}

export function applyBaseline(current, baseline) {
  const baselineByFingerprint = new Map(baseline.findings.map((finding) => [finding.fingerprint, finding]));
  const currentFingerprints = new Set(current.map((finding) => finding.fingerprint));
  const compared = current.map((finding) => {
    const previous = baselineByFingerprint.get(finding.fingerprint);
    return { ...cloneFinding(finding), baselineState: previous ? (previous.baselineState === 'fixed' ? 'regressed' : 'unchanged') : 'new' };
  });
  for (const previous of baseline.findings) {
    if (previous.baselineState === 'fixed' || currentFingerprints.has(previous.fingerprint)) continue;
    compared.push({ ...cloneFinding(previous), baselineState: 'fixed' });
  }
  return compared;
}

export function summarize(findings) {
  const bySeverity = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
  const byState = Object.fromEntries(RESULT_STATES.map((state) => [state, 0]));
  const byBaseline = Object.fromEntries(BASELINE_STATES.map((state) => [state, 0]));
  for (const finding of findings) {
    bySeverity[finding.severity]++;
    byState[finding.state]++;
    if (finding.baselineState) byBaseline[finding.baselineState]++;
  }
  return { total: findings.length, bySeverity, byState, byBaseline };
}

export function createReport({ version, generatedAt, mode, scope, findings, limitations, baseline = null }) {
  const report = {
    schemaVersion: 1,
    tool: { name: 'Web App Security Skill', version },
    generatedAt,
    mode,
    scope,
    baseline,
    summary: summarize(findings),
    findings: [...findings].sort((a, b) =>
      (severityRank.get(a.severity) - severityRank.get(b.severity)) || a.id.localeCompare(b.id)),
    limitations,
  };
  const errors = validateReport(report);
  if (errors.length) throw new Error(`invalid report:\n${errors.map((error) => `- ${error}`).join('\n')}`);
  return report;
}

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
})[char]);
const escapeXml = escapeHtml;

export function renderMarkdown(report) {
  const lines = [
    '# Web App Security report', '',
    `- Mode: \`${report.mode}\``,
    `- Generated: ${report.generatedAt}`,
    `- Findings: ${report.summary.total}`,
    `- Evidence states: ${RESULT_STATES.map((state) => `${state}=${report.summary.byState[state]}`).join(', ')}`,
    '', '## Findings', '',
  ];
  if (!report.findings.length) lines.push('No findings were produced by the checks that ran.', '');
  for (const finding of report.findings) {
    lines.push(
      `### ${finding.id}: ${finding.title}`, '',
      `**${finding.severity} / ${finding.state}${finding.baselineState ? ` / ${finding.baselineState}` : ''}**`, '',
      finding.summary, '',
      finding.location ? `Location: ${markdownCodeSpan(`${finding.location.path}${finding.location.line ? `:${finding.location.line}` : ''}`)}` : 'Location: project-wide', '',
      `Evidence: ${markdownCodeSpan(JSON.stringify(finding.evidence))}`, '',
      `Remediation: ${finding.remediation}`, '',
      `Retest: ${finding.retest}`, '',
    );
  }
  lines.push('## Limitations', '', ...report.limitations.map((item) => `- ${item}`), '');
  return `${lines.join('\n')}\n`;
}

export function renderHtml(report) {
  const rows = report.findings.map((finding) => `<article data-finding-id="${escapeHtml(finding.id)}">
<h2>${escapeHtml(finding.title)}</h2>
<p><strong>${escapeHtml(finding.severity)} / ${escapeHtml(finding.state)}${finding.baselineState ? ` / ${escapeHtml(finding.baselineState)}` : ''}</strong></p>
<p>${escapeHtml(finding.summary)}</p>
<dl><dt>ID</dt><dd><code>${escapeHtml(finding.id)}</code></dd><dt>Location</dt><dd><code>${escapeHtml(finding.location ? `${finding.location.path}${finding.location.line ? `:${finding.location.line}` : ''}` : 'project-wide')}</code></dd><dt>Evidence</dt><dd><code>${escapeHtml(JSON.stringify(finding.evidence))}</code></dd><dt>Remediation</dt><dd>${escapeHtml(finding.remediation)}</dd><dt>Retest</dt><dd>${escapeHtml(finding.retest)}</dd></dl>
</article>`).join('\n');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Web App Security report</title><style>body{font:16px/1.5 system-ui;max-width:960px;margin:40px auto;padding:0 20px;color:#171717}article{border-top:1px solid #bbb;padding:16px 0}code{overflow-wrap:anywhere}dt{font-weight:700;margin-top:8px}</style></head><body><h1>Web App Security report</h1><p>Mode: ${escapeHtml(report.mode)} · Findings: ${report.summary.total}</p><p>Scope: <code>${escapeHtml(JSON.stringify(report.scope))}</code></p>${rows || '<p>No findings were produced by the checks that ran.</p>'}<h2>Limitations</h2><ul>${report.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul></body></html>\n`;
}

export function renderSarif(report) {
  const rules = [...new Map(report.findings.map((finding) => [finding.ruleId, {
    id: finding.ruleId,
    shortDescription: { text: finding.title },
    help: { text: `${finding.remediation}\n\nRetest: ${finding.retest}` },
  }])).values()];
  const level = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
  return `${JSON.stringify({
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'Web App Security Skill', version: report.tool.version, rules } },
      results: report.findings.filter((finding) => finding.baselineState !== 'fixed').map((finding) => ({
        ruleId: finding.ruleId,
        level: level[finding.severity],
        message: { text: `[${finding.state}] ${finding.summary}` },
        fingerprints: { webAppSecurityFingerprint: finding.fingerprint },
        properties: { evidenceState: finding.state, baselineState: finding.baselineState },
        ...(finding.location ? { locations: [{ physicalLocation: {
          artifactLocation: { uri: finding.location.path },
          ...(finding.location.line ? { region: { startLine: finding.location.line } } : {}),
        } }] } : {}),
      })),
    }],
  }, null, 2)}\n`;
}

export function renderJunit(report) {
  const failures = report.findings.filter((finding) => finding.state === 'confirmed' && finding.baselineState !== 'fixed').length;
  const skipped = report.findings.filter((finding) => finding.state !== 'confirmed' || finding.baselineState === 'fixed').length;
  const cases = report.findings.map((finding) => {
    const attrs = `classname="web-app-security.${escapeXml(finding.ruleId)}" name="${escapeXml(finding.id)}"`;
    if (finding.baselineState === 'fixed') return `<testcase ${attrs}><skipped message="fixed in retest"/></testcase>`;
    if (finding.state !== 'confirmed') return `<testcase ${attrs}><skipped message="${escapeXml(finding.state)}"/></testcase>`;
    return `<testcase ${attrs}><failure message="${escapeXml(`${finding.severity}: ${finding.title}`)}">${escapeXml(finding.summary)}</failure></testcase>`;
  }).join('');
  return `<?xml version="1.0" encoding="UTF-8"?><testsuite name="Web App Security Skill" tests="${report.findings.length}" failures="${failures}" skipped="${skipped}">${cases}</testsuite>\n`;
}

export function writeReportBundle(report, directory, name = 'report') {
  mkdirSync(directory, { recursive: true });
  const files = {
    json: join(directory, `${name}.json`),
    markdown: join(directory, `${name}.md`),
    html: join(directory, `${name}.html`),
    sarif: join(directory, `${name}.sarif`),
    junit: join(directory, `${name}.junit.xml`),
  };
  writeFileSync(files.json, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  writeFileSync(files.markdown, renderMarkdown(report), { mode: 0o600 });
  writeFileSync(files.html, renderHtml(report), { mode: 0o600 });
  writeFileSync(files.sarif, renderSarif(report), { mode: 0o600 });
  writeFileSync(files.junit, renderJunit(report), { mode: 0o600 });
  return files;
}

export function readReport(path) {
  const report = JSON.parse(readFileSync(path, 'utf8'));
  const errors = validateReport(report);
  if (errors.length) throw new Error(`invalid baseline/report ${basename(path)}:\n${errors.join('\n')}`);
  return report;
}

export function failsThreshold(report, failOn) {
  if (failOn === 'never') return false;
  const threshold = severityRank.get(failOn);
  return report.findings.some((finding) =>
    finding.state === 'confirmed' && finding.baselineState !== 'fixed' && severityRank.get(finding.severity) <= threshold);
}
