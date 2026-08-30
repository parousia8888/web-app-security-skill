import { createHash } from 'node:crypto';
import { existsSync, lstatSync, readFileSync, statSync } from 'node:fs';
import { isAbsolute, posix, relative, resolve, sep } from 'node:path';
import { sanitizeEvidence } from './evidence-writer.mjs';

export const SUPPRESSION_FILE = 'webapp-security.suppressions.json';
const MAX_BYTES = 256 * 1024;
const ID = /^[a-z0-9][a-z0-9._-]{1,127}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const ENTRY_FIELDS = new Set([
  'id', 'adapterId', 'ruleId', 'path', 'fingerprint', 'reason', 'owner', 'createdAt', 'expiresAt',
]);

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function timestamp(value, label) {
  if (typeof value !== 'string' || !value || Number.isNaN(Date.parse(value))) {
    throw new Error(`${label} is invalid`);
  }
  return new Date(value);
}

function relativePath(value) {
  if (typeof value !== 'string' || !value || value.length > 4096 || isAbsolute(value)
      || /[\u0000-\u001f\u007f\\]/.test(value) || value === '.' || value === '..'
      || value.startsWith('../') || value.includes('//') || posix.normalize(value) !== value) {
    throw new Error('suppression path is invalid');
  }
  return value;
}

function validateEntry(entry, ids) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)
      || Object.keys(entry).some((field) => !ENTRY_FIELDS.has(field))) {
    throw new Error('suppression entry contains unknown fields');
  }
  for (const field of ['id', 'adapterId', 'ruleId']) {
    if (!ID.test(entry[field] || '')) throw new Error(`suppression ${field} is invalid`);
  }
  if (ids.has(entry.id)) throw new Error('suppression IDs must be unique');
  ids.add(entry.id);
  const path = relativePath(entry.path);
  if (!SHA256.test(entry.fingerprint || '')) throw new Error('suppression fingerprint is invalid');
  if (typeof entry.reason !== 'string' || !entry.reason.trim() || entry.reason.length > 2048
      || /[\u0000-\u001f\u007f]/.test(entry.reason)) throw new Error('suppression reason is invalid');
  if (entry.owner !== undefined && (typeof entry.owner !== 'string' || !entry.owner.trim()
      || entry.owner.length > 256 || /[\u0000-\u001f\u007f]/.test(entry.owner))) {
    throw new Error('suppression owner is invalid');
  }
  const createdAt = timestamp(entry.createdAt, 'suppression createdAt');
  const expiresAt = entry.expiresAt === undefined ? null : timestamp(entry.expiresAt, 'suppression expiresAt');
  if (expiresAt && expiresAt <= createdAt) throw new Error('suppression expiresAt must follow createdAt');
  return sanitizeEvidence({ ...entry, path, reason: entry.reason.trim(), owner: entry.owner?.trim() });
}

export function readSuppressionPolicy(projectRoot, subjectId, now, {
  gateEnabled = false, policyPath = SUPPRESSION_FILE,
} = {}) {
  let recordedPath;
  let path;
  try {
    recordedPath = relativePath(policyPath);
    path = resolve(projectRoot, recordedPath);
    const fromRoot = relative(resolve(projectRoot), path);
    if (fromRoot === '..' || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot)) {
      throw new Error('suppression file escapes the project');
    }
  } catch (error) {
    return {
      status: 'unavailable', path: String(policyPath), digest: null, entries: [],
      diagnostics: [{ id: null, code: 'suppression_file_invalid', detail: error.message }],
    };
  }
  if (!existsSync(path)) return {
    status: 'not_configured', path: recordedPath, digest: null, entries: [], diagnostics: [],
  };
  try {
    if (lstatSync(path).isSymbolicLink() || !statSync(path).isFile() || statSync(path).size > MAX_BYTES) {
      throw new Error('suppression file is unsafe or too large');
    }
    const bytes = readFileSync(path);
    const parsed = JSON.parse(bytes.toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
        || Object.keys(parsed).some((field) => !['schemaVersion', 'subjectId', 'entries'].includes(field))
        || parsed.schemaVersion !== 1 || parsed.subjectId !== subjectId
        || !Array.isArray(parsed.entries) || parsed.entries.length > 1000) {
      throw new Error('suppression file contract is invalid');
    }
    const ids = new Set();
    const diagnostics = [];
    const entries = parsed.entries.map((entry) => validateEntry(entry, ids)).map((entry) => {
      const external = entry.adapterId !== 'builtin-source' && entry.adapterId !== 'builtin';
      const governanceRequired = gateEnabled || external;
      let eligibility = 'eligible';
      if (entry.expiresAt && new Date(entry.expiresAt) <= now) eligibility = 'expired';
      else if (governanceRequired && (!entry.owner || !entry.expiresAt)) eligibility = 'governance_incomplete';
      if (eligibility !== 'eligible') diagnostics.push({
        id: entry.id,
        code: eligibility === 'expired' ? 'suppression_expired' : 'suppression_governance_incomplete',
      });
      return { ...entry, eligibility };
    });
    return { status: 'completed', path: recordedPath, digest: digest(bytes), entries, diagnostics };
  } catch (error) {
    return {
      status: 'unavailable', path: recordedPath, digest: null, entries: [],
      diagnostics: [{ id: null, code: 'suppression_file_invalid', detail: error.message }],
    };
  }
}

export function applySuppressions(findings, policy) {
  const diagnostics = [...policy.diagnostics];
  const matched = new Set();
  const retained = findings.map((finding) => {
    const path = finding.location?.path || null;
    const entry = policy.entries.find((candidate) => candidate.eligibility === 'eligible'
      && (candidate.adapterId === finding.adapter.id
        || candidate.adapterId === 'builtin' && finding.adapter.id === 'builtin-source')
      && candidate.ruleId === finding.rule.id
      && candidate.path === path
      && candidate.fingerprint === finding.fingerprint);
    if (!entry) return { ...finding, disposition: { status: 'active' } };
    matched.add(entry.id);
    if (finding.state === 'unknown' || finding.domain === 'evidence_integrity') {
      diagnostics.push({ id: entry.id, code: 'suppression_target_not_suppressible' });
      return { ...finding, disposition: { status: 'active' } };
    }
    return {
      ...finding,
      disposition: sanitizeEvidence({
        status: 'suppressed', suppressionId: entry.id, reason: entry.reason,
        owner: entry.owner || null, expiresAt: entry.expiresAt || null,
      }),
    };
  });
  for (const entry of policy.entries) {
    if (entry.eligibility === 'eligible' && !matched.has(entry.id)) {
      diagnostics.push({ id: entry.id, code: 'suppression_target_not_found' });
    }
  }
  return { findings: retained, diagnostics };
}
