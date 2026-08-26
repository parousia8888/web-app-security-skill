import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const STATES = new Set(['passed', 'failed', 'skipped', 'not_run']);

export function recordTestOutcome({ status = 'passed', reasonCode = null, surfaces = [] }) {
  const output = process.env.WEBAPP_SECURITY_TEST_OUTCOME_FILE;
  if (!output) return;
  if (!STATES.has(status)) throw new Error(`invalid test outcome status: ${status}`);
  for (const surface of surfaces) {
    if (!surface?.id || !STATES.has(surface.status)) {
      throw new Error('test outcome surfaces require id and a terminal status');
    }
  }
  const path = resolve(output);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, `${JSON.stringify({ schemaVersion: 1, status, reasonCode, surfaces }, null, 2)}\n`, {
    mode: 0o600,
  });
}
