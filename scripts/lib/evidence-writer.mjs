import { createHash, randomUUID } from 'node:crypto';
import {
  chmodSync, linkSync, lstatSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { basename, join, resolve } from 'node:path';

const MAX_STRING = 4096;
const MAX_ARRAY = 200;
const MAX_KEYS = 200;
const SECRET_KEY = /^(authorization|cookie|set-cookie|password|passwd|secret|token|api[-_]?key|access[-_]?key|private[-_]?key)$/i;
const SENSITIVE_ID_KEY = /^(account|accountId|user|userName|bucket|bucketName|securityGroup|groupId|arn)$/i;
const PRIVATE_PATH = /(?:\/(?:Users|home|private)\/[^\s"'<>),;\]}]+|[A-Za-z]:\\Users\\[^\s"'<>),;\]}]+)/g;

const digest = (value) => createHash('sha256').update(String(value)).digest('hex').slice(0, 16);

function pathExists(path) {
  try { lstatSync(path); return true; } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

function cleanString(input) {
  let value = String(input)
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/gi, '[REDACTED_PRIVATE_KEY]')
    .replace(/\b(authorization|cookie|set-cookie)\s*:\s*[^\r\n]+/gi, '$1: [REDACTED]')
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, '$1 [REDACTED]')
    .replace(/\b(password|passwd|secret|token|api[-_]?key|access[-_]?key)\s*[=:]\s*([^\s,;]+)/gi, '$1=[REDACTED]')
    .replace(/([?&](?:access_token|token|secret|password|api_key|key|code)=)[^&#\s]*/gi, '$1[REDACTED]')
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[REDACTED_EMAIL]')
    .replace(/\b\d{12}\b/g, '[REDACTED_AWS_ACCOUNT]');
  value = value.replace(PRIVATE_PATH, (path) => `[REDACTED_PRIVATE_PATH:${digest(path)}]`);
  if (value.length > MAX_STRING) value = `${value.slice(0, MAX_STRING)}...[TRUNCATED]`;
  return value;
}

function isAuthorizationEvidenceModel(key, entries) {
  if (!/^authorization$/i.test(key)) return false;
  const names = new Set(entries.map(([itemKey]) => itemKey));
  return ['state', 'signals', 'boundary'].every((name) => names.has(name))
    || ['status', 'basis', 'proof', 'note'].every((name) => names.has(name));
}

export function sanitizeEvidence(value, key = '') {
  if (typeof value === 'string') {
    if (SECRET_KEY.test(key)) return '[REDACTED]';
    if (SENSITIVE_ID_KEY.test(key) && !/(Digest|Ref)$/i.test(key)) {
      return `[REDACTED_${key.toUpperCase()}:${digest(value)}]`;
    }
    return cleanString(value);
  }
  if (Array.isArray(value)) return value.slice(0, MAX_ARRAY).map((item) => sanitizeEvidence(item, key));
  if (value && typeof value === 'object') {
    const entries = Object.entries(value).slice(0, MAX_KEYS);
    const inheritSensitiveKey = SECRET_KEY.test(key) && !isAuthorizationEvidenceModel(key, entries);
    return Object.fromEntries(entries
      .map(([itemKey, item]) => [
        cleanString(itemKey),
        sanitizeEvidence(item, inheritSensitiveKey ? key : itemKey),
      ]));
  }
  return value;
}

export function sanitizedJson(value) {
  return `${JSON.stringify(sanitizeEvidence(value), null, 2)}\n`;
}

function assertName(name) {
  if (typeof name !== 'string' || !name || basename(name) !== name || name === '.' || name === '..') {
    throw new Error(`evidence filename escapes the output directory: ${name}`);
  }
}

function privateDirectory(directory) {
  const target = resolve(directory);
  if (pathExists(target) && lstatSync(target).isSymbolicLink()) {
    throw new Error('refusing symlink evidence directory');
  }
  mkdirSync(target, { recursive: true, mode: 0o700 });
  if (!statSync(target).isDirectory()) throw new Error('evidence output is not a directory');
  chmodSync(target, 0o700);
  return target;
}

export function writeAtomicEvidenceBundle(directory, entries, hooks = {}) {
  if (!Array.isArray(entries) || !entries.length) throw new Error('evidence bundle must contain files');
  const names = new Set();
  const prepared = entries.map((entry) => {
    assertName(entry.name);
    if (names.has(entry.name)) throw new Error(`duplicate evidence filename: ${entry.name}`);
    names.add(entry.name);
    const bytes = Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(String(entry.content));
    if (entry.validate) entry.validate(bytes);
    return { ...entry, bytes };
  });
  const targetDirectory = privateDirectory(directory);
  const targets = prepared.map((entry) => ({ ...entry, target: join(targetDirectory, entry.name) }));
  const conflict = targets.find((entry) => pathExists(entry.target));
  if (conflict) throw new Error(`refusing to overwrite existing evidence: ${conflict.name}`);

  const nonce = `${process.pid}-${randomUUID()}`;
  const staged = [];
  const committed = [];
  try {
    for (const [index, entry] of targets.entries()) {
      const stage = join(targetDirectory, `.webapp-security-stage-${nonce}-${index}`);
      writeFileSync(stage, entry.bytes, { flag: 'wx', mode: 0o600 });
      chmodSync(stage, 0o600);
      if (!statSync(stage).isFile() || readFileSync(stage).length !== entry.bytes.length) {
        throw new Error(`staged evidence validation failed: ${entry.name}`);
      }
      staged.push({ ...entry, stage });
    }
    hooks.afterStage?.(staged.map((entry) => entry.stage));
    for (const entry of staged) {
      try {
        linkSync(entry.stage, entry.target);
      } catch (error) {
        if (error.code === 'EEXIST') throw new Error(`refusing to overwrite existing evidence: ${entry.name}`);
        throw error;
      }
      rmSync(entry.stage);
      committed.push(entry);
      hooks.afterCommit?.(entry.name, committed.length);
    }
    return Object.fromEntries(committed.map((entry) => [entry.key || entry.name, entry.target]));
  } catch (error) {
    for (const entry of staged) rmSync(entry.stage, { force: true });
    for (const entry of committed.reverse()) {
      try {
        const current = readFileSync(entry.target);
        if (current.equals(entry.bytes)) rmSync(entry.target, { force: true });
      } catch { /* preserve a path changed by another process */ }
    }
    throw error;
  }
}
