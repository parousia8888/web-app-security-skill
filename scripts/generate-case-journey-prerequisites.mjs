#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { renderJourneyPrerequisiteBlock } from './lib/journey-contract.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CATALOG = join(ROOT, 'docs', 'case-studies', 'journeys', 'evidence-v0.7.3.json');
const README = join(ROOT, 'docs', 'case-studies', 'journeys', 'README.md');
const START = '<!-- journey-prerequisites:start -->';
const END = '<!-- journey-prerequisites:end -->';
const check = process.argv.includes('--check');
if (process.argv.slice(2).some((item) => item !== '--check')) {
  console.error('usage: node scripts/generate-case-journey-prerequisites.mjs [--check]');
  process.exit(2);
}

const catalog = JSON.parse(readFileSync(CATALOG, 'utf8'));
const selections = new Set(catalog.journeys.map((journey) => JSON.stringify(journey.adapterSelection)));
if (selections.size !== 1) {
  console.error('active journeys do not share one documented adapter selection');
  process.exit(1);
}
const block = renderJourneyPrerequisiteBlock(JSON.parse([...selections][0]));
const current = readFileSync(README, 'utf8');
const start = current.indexOf(START);
const end = current.indexOf(END);
if (start === -1 || end < start) {
  console.error('journey README prerequisite markers are missing');
  process.exit(1);
}
const rendered = `${current.slice(0, start)}${block}${current.slice(end + END.length)}`;
if (check) {
  if (rendered !== current) {
    console.error('journey README prerequisites are stale');
    process.exit(1);
  }
  console.log('journey prerequisites current');
} else {
  writeFileSync(README, rendered);
  console.log('journey prerequisites generated');
}
