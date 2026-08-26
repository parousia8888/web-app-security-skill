import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, relative, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const STATES = ['passed', 'failed', 'skipped', 'not_run'];

function counts(items) {
  return Object.fromEntries(STATES.map((state) => [state,
    items.filter((item) => item.status === state).length]));
}

function declaredOutcome(path) {
  if (!existsSync(path)) return null;
  const value = JSON.parse(readFileSync(path, 'utf8'));
  if (value?.schemaVersion !== 1 || !STATES.includes(value.status)
      || !Array.isArray(value.surfaces)
      || value.surfaces.some((surface) => !surface?.id || !STATES.includes(surface.status))
      || (value.surfaces.some((surface) => surface.status === 'failed') && value.status !== 'failed')) {
    throw new Error('invalid declared test outcome');
  }
  return value;
}

export function runTestInventory({
  root, files, output, node = process.execPath, env = process.env, stream = true,
}) {
  const repository = resolve(root);
  const evidenceDirectory = mkdtempSync(`${tmpdir()}/web-app-security-test-outcomes-`);
  const results = [];
  let halted = false;
  try {
    for (const [index, input] of files.entries()) {
      const file = resolve(repository, input);
      const display = relative(repository, file).replaceAll('\\', '/');
      if (halted) {
        results.push({ file: display, status: 'not_run', exitCode: null,
          reasonCode: 'earlier_test_failed', surfaces: [] });
        continue;
      }
      if (stream) process.stdout.write(`\u2192 ${display}\n`);
      const declaredPath = resolve(evidenceDirectory, `${index}.json`);
      const result = spawnSync(node, [file], {
        cwd: repository,
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
        env: { ...env, WEBAPP_SECURITY_TEST_OUTCOME_FILE: declaredPath },
      });
      if (stream && result.stdout) process.stdout.write(result.stdout);
      if (stream && result.stderr) process.stderr.write(result.stderr);
      let declared = null;
      let declarationError = null;
      try {
        declared = declaredOutcome(declaredPath);
      } catch (error) {
        declarationError = error.message;
      }
      const failed = result.status !== 0 || declarationError || declared?.status === 'failed';
      const status = failed ? 'failed' : (declared?.status || 'passed');
      results.push({
        file: display,
        status,
        exitCode: result.status,
        reasonCode: declarationError ? 'invalid_outcome_record' : (declared?.reasonCode || null),
        surfaces: declared?.surfaces || [],
        ...(result.signal ? { signal: result.signal } : {}),
        ...(declarationError ? { detail: declarationError } : {}),
      });
      if (failed) halted = true;
    }
  } finally {
    rmSync(evidenceDirectory, { recursive: true, force: true });
  }

  const surfaces = results.flatMap((result) => result.surfaces.map((surface) => ({
    file: result.file,
    ...surface,
  })));
  const fileCounts = counts(results);
  const surfaceCounts = counts(surfaces);
  const state = fileCounts.failed || surfaceCounts.failed ? 'failed'
    : fileCounts.skipped || fileCounts.not_run || surfaceCounts.skipped || surfaceCounts.not_run
      ? 'partial' : 'passed';
  const record = {
    schemaVersion: 1,
    generatedBy: 'scripts/run-tests.mjs',
    state,
    summary: { files: fileCounts, surfaces: surfaceCounts },
    files: results,
    surfaces,
  };
  const destination = resolve(repository, output);
  mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
  writeFileSync(destination, `${JSON.stringify(record, null, 2)}\n`, { mode: 0o600 });
  return { record, exitCode: state === 'failed' ? 1 : 0, output: destination };
}
