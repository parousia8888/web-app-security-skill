import { validateFindingV2, validateReportV2 } from './report-v2-contract.mjs';

export const V3_EXPLANATION_FIELDS = [
  'technicalTerm', 'plainLanguage', 'consequence', 'evidenceBoundary', 'standards', 'proposal',
  'alternatives', 'sideEffects', 'securityRetest', 'functionalRetest', 'rollback', 'userDecisions',
];

export const V3_PROPOSAL_STATES = [
  'ready_for_review', 'review_required', 'no_safe_automatic_change', 'not_applicable',
];

const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const STANDARD = /^(?:CWE-[1-9][0-9]*|OWASP-TOP10-2025-A(?:0[1-9]|10)|OWASP-API-2023-API(?:[1-9]|10)|OWASP-ASVS-5\.0\.0-[1-9][0-9]*(?:\.[0-9]+){1,2}|NIST-SSDF-1\.1-[A-Z]{2}\.[0-9]+\.[0-9]+)$/;

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function text(value, label, errors, max = 4096) {
  if (typeof value !== 'string' || !value.trim()) errors.push(`${label} must be non-empty text`);
  else {
    if (value.length > max) errors.push(`${label} exceeds ${max} characters`);
    if (CONTROL.test(value)) errors.push(`${label} contains control characters`);
  }
}

function textList(value, label, errors, { min = 0 } = {}) {
  if (!Array.isArray(value) || value.length < min || value.length > 12) {
    errors.push(`${label} must contain ${min}..12 entries`);
    return;
  }
  value.forEach((item, index) => text(item, `${label}[${index}]`, errors));
}

export function downgradeFindingV3(finding) {
  const { explanation: _explanation, ...rest } = structuredClone(finding);
  return { ...rest, schemaVersion: 2 };
}

export function downgradeReportV3(report) {
  const copy = structuredClone(report);
  copy.schemaVersion = 2;
  copy.findings = (copy.findings || []).map(downgradeFindingV3);
  if (copy.baseline?.sourceSchemaVersion === 3) copy.baseline.sourceSchemaVersion = 2;
  return copy;
}

export function validateExplanationV3(explanation) {
  const errors = [];
  if (!object(explanation)) return ['finding.explanation must be an object'];
  for (const field of V3_EXPLANATION_FIELDS) {
    if (!(field in explanation)) errors.push(`finding.explanation.${field} is required`);
  }
  for (const field of Object.keys(explanation)) {
    if (!V3_EXPLANATION_FIELDS.includes(field)) errors.push(`finding.explanation.${field} is not allowed`);
  }
  text(explanation.technicalTerm, 'finding.explanation.technicalTerm', errors, 512);
  for (const field of ['plainLanguage', 'consequence', 'evidenceBoundary', 'securityRetest', 'functionalRetest', 'rollback']) {
    text(explanation[field], `finding.explanation.${field}`, errors);
  }
  textList(explanation.alternatives, 'finding.explanation.alternatives', errors);
  textList(explanation.sideEffects, 'finding.explanation.sideEffects', errors, { min: 1 });
  textList(explanation.userDecisions, 'finding.explanation.userDecisions', errors);
  if (!Array.isArray(explanation.standards) || explanation.standards.length > 12) {
    errors.push('finding.explanation.standards must contain 0..12 entries');
  } else {
    const ids = new Set();
    explanation.standards.forEach((standard, index) => {
      const label = `finding.explanation.standards[${index}]`;
      if (!object(standard) || Object.keys(standard).some((key) => !['id', 'url'].includes(key))) {
        errors.push(`${label} is invalid`);
        return;
      }
      if (!STANDARD.test(standard.id || '')) errors.push(`${label}.id is invalid`);
      if (typeof standard.url !== 'string' || !/^https:\/\/\S+$/.test(standard.url)
          || standard.url.length > 512) errors.push(`${label}.url is invalid`);
      if (ids.has(standard.id)) errors.push(`${label}.id is duplicated`);
      ids.add(standard.id);
    });
  }
  if (!object(explanation.proposal)) errors.push('finding.explanation.proposal must be an object');
  else {
    for (const key of Object.keys(explanation.proposal)) {
      if (!['status', 'summary'].includes(key)) errors.push(`finding.explanation.proposal.${key} is not allowed`);
    }
    if (!V3_PROPOSAL_STATES.includes(explanation.proposal.status)) {
      errors.push('finding.explanation.proposal.status is invalid');
    }
    text(explanation.proposal.summary, 'finding.explanation.proposal.summary', errors);
  }
  return errors;
}

export function validateFindingV3(finding) {
  const errors = [];
  if (!object(finding)) return ['finding must be an object'];
  const allowed = new Set([
    'schemaVersion', 'id', 'fingerprint', 'fingerprintVersion', 'rule', 'adapter', 'domain',
    'title', 'severity', 'state', 'summary', 'location', 'evidence', 'remediation', 'retest',
    'explanation', 'baseline',
  ]);
  for (const key of Object.keys(finding)) {
    if (!allowed.has(key)) errors.push(`finding.${key} is not allowed`);
  }
  if (finding?.schemaVersion !== 3) errors.push('finding.schemaVersion must be 3');
  errors.push(...validateFindingV2(downgradeFindingV3(finding)));
  errors.push(...validateExplanationV3(finding?.explanation));
  return [...new Set(errors)];
}

export function validateReportV3(report) {
  const errors = [];
  if (!object(report)) return ['report must be an object'];
  if (report?.schemaVersion !== 3) errors.push('report.schemaVersion must be 3');
  if (report?.baseline && ![1, 2, 3].includes(report.baseline.sourceSchemaVersion)) {
    errors.push('report.baseline.sourceSchemaVersion is invalid');
  }
  errors.push(...validateReportV2(downgradeReportV3(report)));
  for (const [index, finding] of (report?.findings || []).entries()) {
    errors.push(...validateFindingV3(finding).map((error) => `report.findings[${index}]: ${error}`));
  }
  return [...new Set(errors)];
}
