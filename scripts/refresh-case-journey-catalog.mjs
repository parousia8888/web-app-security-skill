#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256Bytes, toolSourceIdentity } from './lib/journey-contract.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const HISTORICAL = join(ROOT, 'docs', 'case-studies', 'journeys', 'evidence.json');
const VERSION = readFileSync(join(ROOT, 'VERSION'), 'utf8').trim();
const RELEASE = `v${VERSION}`;
const DEFAULT_OUTPUT = join(ROOT, 'docs', 'case-studies', 'journeys', `evidence-${RELEASE}.json`);

function usage(code, message) {
  if (message) console.error(`error: ${message}`);
  console.log(`node scripts/refresh-case-journey-catalog.mjs [options]

Options:
  --initialize           Create a refresh-pending ${RELEASE} catalog from immutable historical metadata
  --observations <dir>   Promote <dir>/<journey-id>/observed-corpus.json into the active catalog
  --out <json>           Output path (default: docs/case-studies/journeys/evidence-${RELEASE}.json)

Initialization and promotion never modify the historical evidence.json snapshot.`);
  process.exit(code);
}

function take(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return null;
  if (!args[index + 1] || args[index + 1].startsWith('--')) usage(2, `${name} requires a value`);
  return args.splice(index, 2)[1];
}

function initialize() {
  const historicalBytes = readFileSync(HISTORICAL);
  const historical = JSON.parse(historicalBytes.toString('utf8'));
  const runDate = new Date().toISOString();
  return {
    schemaVersion: 3,
    release: RELEASE,
    status: 'refresh_pending',
    evidenceType: 'active_ordinary_project_journey_contract',
    historicalSource: {
      path: 'docs/case-studies/journeys/evidence.json',
      sha256: sha256Bytes(historicalBytes),
      qualifier: 'Immutable v2 historical snapshot; not an active current-tool reproduction gate.',
    },
    toolSource: toolSourceIdentity(ROOT),
    method: {
      ...historical.method,
      auditExitRecordedSeparately: true,
      byteAndSemanticDigestsSeparated: true,
      manualAnnotationIdentitySeparated: true,
      gitleaksHistoryBoundary: 'target_commit_reachable_history',
    },
    regressionInventory: historical.regressionInventory,
    journeys: historical.journeys.map((journey) => ({
      ...journey,
      adapterSelection: ['builtin', 'gitleaks', 'osv'],
      mutableAdapters: ['osv'],
      historyBoundary: {
        adapter: 'gitleaks',
        ref: journey.commit,
        semantics: 'commits_reachable_from_exact_target_commit',
      },
      corpus: {
        runDate,
        adapters: [],
      },
    })),
  };
}

function promote(catalog, directory) {
  const toolIdentities = new Set();
  const journeys = catalog.journeys.map((journey) => {
    const path = join(directory, journey.id, 'observed-corpus.json');
    if (!existsSync(path)) throw new Error(`missing observation: ${path}`);
    const observed = JSON.parse(readFileSync(path, 'utf8'));
    if (observed.id !== journey.id || observed.commit !== journey.commit) {
      throw new Error(`${journey.id} observation target identity changed`);
    }
    if (JSON.stringify(observed.discovery) !== JSON.stringify(journey.discovery)) {
      throw new Error(`${journey.id} discovery changed; review it before promotion`);
    }
    if (JSON.stringify(observed.historyBoundary) !== JSON.stringify(journey.historyBoundary)) {
      throw new Error(`${journey.id} Gitleaks history boundary changed`);
    }
    toolIdentities.add(JSON.stringify(observed.toolSource));
    return { ...journey, historyBoundary: observed.historyBoundary, corpus: observed.corpus };
  });
  if (toolIdentities.size !== 1) throw new Error('observations do not share one tool source identity');
  return {
    ...catalog,
    status: 'active',
    toolSource: JSON.parse([...toolIdentities][0]),
    journeys,
  };
}

const args = process.argv.slice(2);
if (args.includes('-h') || args.includes('--help')) usage(0);
const initializeRequested = args.includes('--initialize');
if (initializeRequested) args.splice(args.indexOf('--initialize'), 1);
const observations = take(args, '--observations');
const output = resolve(take(args, '--out') || DEFAULT_OUTPUT);
if (args.length || initializeRequested === Boolean(observations)) {
  usage(2, 'choose exactly one of --initialize or --observations');
}

try {
  const catalog = initializeRequested
    ? initialize()
    : promote(JSON.parse(readFileSync(output, 'utf8')), resolve(observations));
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, `${JSON.stringify(catalog, null, 2)}\n`);
  console.log(`journey catalog ${catalog.status}: ${catalog.journeys.length} projects -> ${output}`);
} catch (error) {
  usage(2, error.message);
}
