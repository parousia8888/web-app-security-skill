#!/usr/bin/env node
import {
  chmodSync, lstatSync, readFileSync, renameSync, rmSync, writeFileSync,
} from 'node:fs';
import { dirname, resolve } from 'node:path';
import {
  beginActionPromotion, finalizeActionPromotion, validateActionPromotionState,
} from './lib/action-promotion-state.mjs';

const args = process.argv.slice(2);
const command = args.shift();

function take(name, required = false) {
  const index = args.indexOf(name);
  if (index < 0) {
    if (required) throw new Error(`${name} is required`);
    return null;
  }
  const value = args[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
  args.splice(index, 2);
  return value;
}

function writeState(path, value) {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('release state must be a regular file');
  const temporary = resolve(dirname(path), `.release-state-${process.pid}-${Date.now()}.tmp`);
  try {
    writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
    renameSync(temporary, path);
    chmodSync(path, stat.mode & 0o777);
  } finally {
    rmSync(temporary, { force: true });
  }
}

try {
  if (!['check', 'begin', 'finalize'].includes(command)) {
    throw new Error('usage: action-promotion-state.mjs <check|begin|finalize> --state <release-state.json> [options]');
  }
  const statePath = resolve(take('--state', true));
  const version = take('--version');
  const expectedSourceCommit = take('--expected-source');
  const priorTagObject = take('--prior-tag-object');
  const sourceCommit = take('--source-commit');
  if (args.length) throw new Error(`unknown option ${args[0]}`);
  const state = JSON.parse(readFileSync(statePath, 'utf8'));
  let next = state;
  if (command === 'begin') {
    if (!version || !expectedSourceCommit || !priorTagObject || sourceCommit) {
      throw new Error('begin requires --version, --expected-source and --prior-tag-object');
    }
    next = beginActionPromotion(state, { version, expectedSourceCommit, priorTagObject });
  } else if (command === 'finalize') {
    if (!sourceCommit || version || expectedSourceCommit || priorTagObject) {
      throw new Error('finalize requires only --source-commit');
    }
    next = finalizeActionPromotion(state, sourceCommit);
  } else if (version || expectedSourceCommit || priorTagObject || sourceCommit) {
    throw new Error('check accepts only --state');
  }
  const errors = validateActionPromotionState(next);
  if (errors.length) throw new Error(errors.join('; '));
  if (command !== 'check') writeState(statePath, next);
  console.log(`Action promotion state: ${next.stableAction.promotion.state}`);
} catch (error) {
  console.error(`Action promotion state: ${error.message}`);
  process.exit(1);
}
