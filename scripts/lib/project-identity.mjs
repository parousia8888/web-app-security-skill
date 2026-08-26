import { createHash, randomBytes } from 'node:crypto';
import {
  existsSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync,
} from 'node:fs';
import { dirname, isAbsolute, join, posix, resolve } from 'node:path';

export const PROJECT_IDENTITY_FILE = '.webapp-security/project.json';
export const SUBJECT_ID = /^project-[a-f0-9]{32}$/;

export function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, stableValue(item)]));
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(stableValue(value));
}

export function digestValue(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

export const DEFAULT_SOURCE_TRAVERSAL_LIMITS = Object.freeze({
  maxDepth: 12,
  maxFiles: 20000,
  maxEntries: 50000,
  maxFileBytes: 1024 * 1024,
});

const SOURCE_TRAVERSAL_RANGES = Object.freeze({
  maxDepth: [1, 64],
  maxFiles: [1, 200000],
  maxEntries: [1, 500000],
  maxFileBytes: [1024, 16 * 1024 * 1024],
});

export function sourceTraversalLimits(overrides = {}) {
  const limits = { ...DEFAULT_SOURCE_TRAVERSAL_LIMITS, ...overrides };
  for (const [name, [minimum, maximum]] of Object.entries(SOURCE_TRAVERSAL_RANGES)) {
    if (!Number.isInteger(limits[name]) || limits[name] < minimum || limits[name] > maximum) {
      throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
    }
  }
  return limits;
}

export function sourceAuditBoundary(traversalLimits = DEFAULT_SOURCE_TRAVERSAL_LIMITS, adapterConfig = {}) {
  const limits = sourceTraversalLimits(traversalLimits);
  const adapters = adapterConfig.adapters || ['builtin'];
  const adapterTimeoutSeconds = adapterConfig.timeoutSeconds || 120;
  return {
    version: 2,
    sourceRoots: ['.'],
    excludedDirectories: [
      '.git', '.hg', '.svn', '.next', '.nuxt', '.output', '.webapp-security', 'build',
      'coverage', 'dist', 'node_modules', 'target', 'vendor', '__pycache__', '.venv', 'venv',
    ],
    checkModes: ['source', 'local', ...adapters.filter((adapter) => adapter !== 'builtin').map((adapter) => `adapter:${adapter}`)],
    networkAccess: adapters.includes('osv') || adapters.includes('checkov'),
    adapters,
    adapterTimeoutSeconds,
    traversalLimits: limits,
  };
}

export function scopeDigest(boundary) {
  return digestValue(boundary);
}

function validateIdentity(identity) {
  if (identity?.schemaVersion !== 1 || identity?.product !== 'Web App Security Skill'
      || !SUBJECT_ID.test(identity?.subjectId || '') || Number.isNaN(Date.parse(identity?.createdAt))) {
    throw new Error(`invalid project identity: ${PROJECT_IDENTITY_FILE}`);
  }
  return identity;
}

export function readProjectIdentity(projectRoot) {
  const path = join(projectRoot, PROJECT_IDENTITY_FILE);
  if (!existsSync(path)) return null;
  if (lstatSync(path).isSymbolicLink()) throw new Error(`project identity cannot be a symlink: ${path}`);
  try {
    return validateIdentity(JSON.parse(readFileSync(path, 'utf8')));
  } catch (error) {
    if (error.message.startsWith('invalid project identity:')) throw error;
    throw new Error(`invalid project identity: ${PROJECT_IDENTITY_FILE}`);
  }
}

export function writeProjectIdentity(projectRoot, identity) {
  validateIdentity(identity);
  const path = join(projectRoot, PROJECT_IDENTITY_FILE);
  const directory = dirname(path);
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  if (existsSync(path)) throw new Error(`project identity already exists: ${path}`);
  const temporary = join(directory, `.project-${process.pid}-${randomBytes(6).toString('hex')}.tmp`);
  try {
    writeFileSync(temporary, `${JSON.stringify(identity, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    renameSync(temporary, path);
  } finally {
    rmSync(temporary, { force: true });
  }
  return identity;
}

export function ensureProjectIdentity(projectRoot, generatedAt) {
  const existing = readProjectIdentity(projectRoot);
  if (existing) return existing;
  return writeProjectIdentity(projectRoot, {
    schemaVersion: 1,
    product: 'Web App Security Skill',
    subjectId: `project-${randomBytes(16).toString('hex')}`,
    createdAt: generatedAt,
    lineage: null,
  });
}

export function persistedSubject(identity, boundary = sourceAuditBoundary()) {
  validateIdentity(identity);
  return {
    id: identity.subjectId,
    binding: 'persisted',
    scopeDigest: scopeDigest(boundary),
    localPathIncluded: false,
  };
}

export function ephemeralSubject(boundary = sourceAuditBoundary()) {
  return {
    id: `project-${randomBytes(16).toString('hex')}`,
    binding: 'ephemeral',
    scopeDigest: scopeDigest(boundary),
    localPathIncluded: false,
  };
}

function validateAbsoluteScopePath(value, label) {
  if (typeof value !== 'string' || !value || value.length > 4096
      || /[\u0000-\u001f\u007f]/.test(value) || !isAbsolute(value) || resolve(value) !== value) {
    throw new Error(`scope target contains an invalid ${label}`);
  }
}

function validateRelativeScopePath(value, label, { allowRoot = false } = {}) {
  if (typeof value !== 'string' || !value || value.length > 4096
      || /[\u0000-\u001f\u007f\\]/.test(value) || isAbsolute(value)) {
    throw new Error(`scope target contains an invalid ${label}`);
  }
  const normalized = posix.normalize(value);
  if (normalized !== value || normalized === '..' || normalized.startsWith('../')
      || (!allowRoot && normalized === '.')) {
    throw new Error(`scope target contains an invalid ${label}`);
  }
}

function validateTargetPaths(target) {
  if (!target || typeof target !== 'object' || Array.isArray(target)) {
    throw new Error('scope does not contain a valid target');
  }
  validateAbsoluteScopePath(target.projectRoot, 'projectRoot');
  for (const field of ['manifests', 'lockfiles', 'deploymentSurfaces', 'configSurfaces']) {
    if (!Array.isArray(target[field])) throw new Error(`scope target contains an invalid ${field} list`);
    for (const value of target[field]) validateRelativeScopePath(value, field);
  }
  for (const field of ['frameworks', 'packageManagers']) {
    if (!Array.isArray(target[field])) throw new Error(`scope target contains an invalid ${field} list`);
    for (const item of target[field]) {
      if (!item || typeof item !== 'object' || Array.isArray(item)) {
        throw new Error(`scope target contains an invalid ${field} entry`);
      }
      validateRelativeScopePath(item.root, `${field} root`, { allowRoot: true });
    }
  }
}

export function validatePersistedScope(scope) {
  if (scope?.schemaVersion !== 2 || scope?.generatedBy?.product !== 'Web App Security Skill') {
    throw new Error('scope is not a Web App Security Skill v2 scope');
  }
  if (!SUBJECT_ID.test(scope?.subject?.id || '') || scope.subject.binding !== 'persisted'
      || scope.subject.localPathIncluded !== false) {
    throw new Error('scope does not contain a persisted subject identity');
  }
  if (scope.auditBoundary?.version !== 2 || !scope.auditBoundary?.traversalLimits) {
    throw new Error('scope predates the traversal ledger; create a new run with webapp-security start');
  }
  sourceTraversalLimits(scope.auditBoundary.traversalLimits);
  if ('adapters' in scope.auditBoundary) {
    if (!Array.isArray(scope.auditBoundary.adapters) || !scope.auditBoundary.adapters.length
        || scope.auditBoundary.adapters.some((adapter) => !['builtin', 'checkov', 'gitleaks', 'opengrep', 'osv'].includes(adapter))) {
      throw new Error('scope contains an invalid adapter selection');
    }
    if (!Number.isInteger(scope.auditBoundary.adapterTimeoutSeconds)
        || scope.auditBoundary.adapterTimeoutSeconds < 1 || scope.auditBoundary.adapterTimeoutSeconds > 600) {
      throw new Error('scope contains an invalid adapter timeout');
    }
  }
  validateTargetPaths(scope.target);
  const actualDigest = scopeDigest(scope.auditBoundary);
  if (scope.subject.scopeDigest !== actualDigest) throw new Error('scope digest does not match its audit boundary');
  return scope;
}
