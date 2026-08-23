#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  ordinaryEvidenceSemanticProjection, ordinaryReportSemanticProjection, ordinarySemanticDigest,
} from './lib/ordinary-review-evidence.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const evidencePath = `${ROOT}/docs/case-studies/journeys/v0.5.0-evidence.json`;
const reviewPath = `${ROOT}/docs/case-studies/journeys/v0.5.0-review.md`;
const corpusPath = `${ROOT}/docs/stable-rule-corpus.json`;
const evidence = JSON.parse(readFileSync(evidencePath, 'utf8'));
const review = readFileSync(reviewPath, 'utf8');
const args = process.argv.slice(2);
let compareProjectId = null;
let compareReportPath = null;
if (args.length) {
  if (args.length !== 3 || args[0] !== '--report') {
    console.error('usage: node scripts/check-v050-ordinary-review.mjs [--report <project-id> <report.json>]');
    process.exit(2);
  }
  [, compareProjectId, compareReportPath] = args;
}
const classes = ['useful_lead', 'expected_benign_match', 'unknown', 'confirmed'];
const totals = Object.fromEntries(classes.map((name) => [name, 0]));
let findings = 0;
let confirmed = 0;
let suspected = 0;
let unknown = 0;

function fail(message) {
  console.error(`v0.5.0 ordinary review: ${message}`);
  process.exitCode = 1;
}

if (evidence.schemaVersion !== 1 || evidence.projects?.length !== 5) fail('expected five schema-v1 projects');
if (evidence.method?.hostedInstancesProbed !== false
    || evidence.method?.projectDependenciesExecuted !== false
    || evidence.method?.networkAccessPerformed !== false
    || evidence.method?.precisionRecallPublished !== false
    || evidence.method?.findingCountTreatedAsVulnerabilityCount !== false) {
  fail('method boundaries drifted');
}
// The review stays bound to its v0.5.0 corpus identity while the current corpus evolves.
if (evidence.stableRuleCorpus?.path !== 'docs/stable-rule-corpus.json'
    || !/^[a-f0-9]{64}$/.test(evidence.stableRuleCorpus?.semanticDigest || '')) {
  fail('stable rule corpus identity differs');
}
if (!/^[a-f0-9]{64}$/.test(evidence.rulesetDigest || '')) fail('ruleset digest is invalid');

for (const project of evidence.projects || []) {
  if (!/^[a-f0-9]{40}$/.test(project.commit || '') || !/^[a-f0-9]{64}$/.test(project.report?.sha256 || '')) {
    fail(`${project.id} immutable identity is invalid`);
  }
  const expectedSemanticDigest = ordinarySemanticDigest(ordinaryEvidenceSemanticProjection(evidence, project));
  if (project.report?.semanticDigest !== expectedSemanticDigest) {
    fail(`${project.id} semantic report digest differs from its reviewed evidence`);
  }
  const seen = new Set();
  for (const name of classes) {
    if (!Array.isArray(project.review?.[name])) fail(`${project.id} is missing ${name}`);
    for (const id of project.review?.[name] || []) {
      if (!/^[a-z0-9-]+-f[a-f0-9]{12}$/.test(id)) fail(`${project.id} has invalid finding ID ${id}`);
      if (seen.has(id)) fail(`${project.id} classifies ${id} more than once`);
      seen.add(id);
      totals[name] += 1;
    }
  }
  if (seen.size !== project.report?.summary?.total) fail(`${project.id} review does not cover every report finding`);
  if ((project.review.unknown?.length || 0) !== project.report?.summary?.unknown) fail(`${project.id} unknown review count differs`);
  if ((project.review.confirmed?.length || 0) !== project.report?.summary?.confirmed) fail(`${project.id} confirmed review count differs`);
  if ((project.review.useful_lead.length + project.review.expected_benign_match.length)
      !== project.report?.summary?.suspected) fail(`${project.id} suspected review count differs`);
  if (!project.reviewNotes?.length || !review.includes(`| ${project.project} |`)) fail(`${project.id} readable review is incomplete`);
  findings += project.report.summary.total;
  confirmed += project.report.summary.confirmed;
  suspected += project.report.summary.suspected;
  unknown += project.report.summary.unknown;
}

const aggregate = evidence.aggregate || {};
if (aggregate.reports !== evidence.projects.length || aggregate.findings !== findings
    || aggregate.reportStates?.confirmed !== confirmed || aggregate.reportStates?.suspected !== suspected
    || aggregate.reportStates?.unknown !== unknown) fail('aggregate report-state counts differ');
for (const name of classes) {
  if (aggregate.reviewClasses?.[name] !== totals[name]) fail(`aggregate ${name} count differs`);
}
for (const marker of ['not 43 vulnerabilities', 'No precision or recall percentage',
  'No configured pattern matched. This is not evidence that the application is secure.']) {
  if (!review.includes(marker)) fail(`readable review omits boundary: ${marker}`);
}
if (!existsSync(corpusPath)) fail('stable corpus is missing');
if (compareProjectId) {
  const project = evidence.projects.find((item) => item.id === compareProjectId);
  if (!project) fail(`unknown reproduction project: ${compareProjectId}`);
  else {
    try {
      const report = JSON.parse(readFileSync(compareReportPath, 'utf8'));
      const actual = ordinarySemanticDigest(ordinaryReportSemanticProjection(report));
      if (actual !== project.report.semanticDigest) fail(`${compareProjectId} reproduced report semantics differ`);
      else if (!process.exitCode) console.log(`${compareProjectId} reproduced report semantics match`);
    } catch (error) {
      fail(`unable to read reproduced report: ${error.message}`);
    }
  }
}
if (!process.exitCode) {
  console.log(`v0.5.0 ordinary review ok: ${findings} findings -> ${totals.useful_lead} useful leads, ${totals.expected_benign_match} expected benign, ${totals.unknown} unknown, ${totals.confirmed} confirmed facts`);
}
