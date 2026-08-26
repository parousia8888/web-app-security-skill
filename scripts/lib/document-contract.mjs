import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';

const SKIP_DIRECTORIES = new Set(['.git', 'node_modules', 'test-results']);
const PLAN_DISPOSITIONS = new Set(['shipped_as', 'superseded', 'intentionally_omitted']);

function markdownFiles(root, directory = root) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && !SKIP_DIRECTORIES.has(entry.name)) {
      files.push(...markdownFiles(root, join(directory, entry.name)));
    } else if (entry.isFile() && entry.name.endsWith('.md')) files.push(join(directory, entry.name));
  }
  return files;
}

function localLinkTarget(documentPath, rawTarget) {
  const target = rawTarget.trim().replace(/^<|>$/g, '');
  if (!target || target.startsWith('#') || /^[a-z][a-z0-9+.-]*:/i.test(target)) return null;
  const path = decodeURIComponent(target.split('#', 1)[0].split('?', 1)[0]);
  return path ? resolve(dirname(documentPath), path) : null;
}

export function validateMarkdownLinks(root) {
  const errors = [];
  for (const documentPath of markdownFiles(root)) {
    const source = readFileSync(documentPath, 'utf8');
    const pattern = /\[[^\]]*\]\(([^)]+)\)/g;
    for (const match of source.matchAll(pattern)) {
      const raw = match[1].replace(/\s+["'][^"']*["']\s*$/, '');
      let target;
      try {
        target = localLinkTarget(documentPath, raw);
      } catch {
        errors.push(`${relative(root, documentPath)} has an invalid encoded link: ${raw}`);
        continue;
      }
      if (target && !existsSync(target)) {
        errors.push(`${relative(root, documentPath)} links to missing ${relative(root, target)}`);
      }
    }
  }
  return errors.sort();
}

function referencedImplementationPaths(source) {
  return [...source.matchAll(/`((?:scripts|test)\/[^`]+)`/g)]
    .map((match) => match[1])
    .filter((path) => !/[\s*]/.test(path));
}

export function validatePlanArtifactStatus(root, statusPath = 'docs/plan-artifact-status.json') {
  const errors = [];
  const absoluteStatus = resolve(root, statusPath);
  if (!existsSync(absoluteStatus)) return [`${statusPath} is missing`];
  let record;
  try {
    record = JSON.parse(readFileSync(absoluteStatus, 'utf8'));
  } catch (error) {
    return [`${statusPath} is invalid JSON: ${error.message}`];
  }
  if (record.schemaVersion !== 1 || !Array.isArray(record.plans)) {
    return [`${statusPath} must contain schemaVersion 1 and plans[]`];
  }
  for (const plan of record.plans) {
    if (!plan?.path || !existsSync(resolve(root, plan.path))) {
      errors.push(`plan record points to missing ${plan?.path || '<path>'}`);
      continue;
    }
    const source = readFileSync(resolve(root, plan.path), 'utf8');
    const mappings = new Map();
    for (const artifact of plan.artifacts || []) {
      if (!artifact?.plannedPath || mappings.has(artifact.plannedPath)) {
        errors.push(`${plan.path} has a missing or duplicate plannedPath`);
        continue;
      }
      mappings.set(artifact.plannedPath, artifact);
      if (!source.includes(`\`${artifact.plannedPath}\``)) {
        errors.push(`${artifact.plannedPath} is not named by ${plan.path}`);
      }
      if (!PLAN_DISPOSITIONS.has(artifact.disposition)) {
        errors.push(`${artifact.plannedPath} has invalid disposition ${artifact.disposition}`);
      }
      if (!artifact.rationale || !Array.isArray(artifact.asBuilt) || !artifact.asBuilt.length) {
        errors.push(`${artifact.plannedPath} lacks rationale or asBuilt evidence`);
      }
      for (const replacement of artifact.asBuilt || []) {
        if (!existsSync(resolve(root, replacement))) {
          errors.push(`${artifact.plannedPath} maps to missing ${replacement}`);
        }
      }
    }
    for (const path of referencedImplementationPaths(source)) {
      if (!existsSync(resolve(root, path)) && !mappings.has(path)) {
        errors.push(`${plan.path} names missing ${path} without an as-built disposition`);
      }
    }
  }
  return errors.sort();
}

export function validateDocumentContract(root) {
  return [...validateMarkdownLinks(root), ...validatePlanArtifactStatus(root)].sort();
}
