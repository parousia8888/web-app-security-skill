import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { auditSource } from './source-audit.mjs';
import { inspectJsTsSource } from './js-ts-source-audit.mjs';
import { inspectPythonSource } from './python-source-audit.mjs';

const LIMITATION = 'Author-maintained synthetic rule-contract conformance suite; it verifies declared planted examples. It does not measure production-vulnerability precision, recall, reachability, exploitability or security coverage.';

export function collectRuleContractObservations(root) {
  const positive = new Map();
  const addPositive = (findings) => {
    for (const finding of findings) {
      const states = positive.get(finding.ruleId) || [];
      states.push(finding.state);
      positive.set(finding.ruleId, states);
    }
  };
  addPositive(inspectJsTsSource('src/vulnerable.tsx', readFileSync(
    join(root, 'test', 'fixtures', 'js-ts-rules', 'vulnerable.tsx'), 'utf8')).findings);
  addPositive(inspectPythonSource('src/vulnerable.py', readFileSync(
    join(root, 'test', 'fixtures', 'python-rules', 'vulnerable.py'), 'utf8')).findings);
  addPositive(auditSource(join(root, 'test', 'fixtures', 'audit-app')).findings);

  const temporary = mkdtempSync(join(tmpdir(), 'web-app-security-rule-contract-'));
  try {
    const tracked = join(temporary, 'tracked');
    mkdirSync(tracked);
    writeFileSync(join(tracked, '.env.production'), 'RULE_CONTRACT_PLACEHOLDER=true\n');
    for (const args of [['init', '-q'], ['add', '.env.production']]) {
      const result = spawnSync('git', args, { cwd: tracked, encoding: 'utf8' });
      if (result.status !== 0) throw new Error(`git fixture setup failed: ${result.stderr || result.stdout}`);
    }
    addPositive(auditSource(tracked).findings);
    const incomplete = join(temporary, 'incomplete');
    mkdirSync(join(incomplete, 'src'), { recursive: true });
    writeFileSync(join(incomplete, 'package.json'), '{"private":true,"dependencies":{"express":"1.0.0"}}\n');
    writeFileSync(join(incomplete, 'package-lock.json'), '{"lockfileVersion":3}\n');
    writeFileSync(join(incomplete, 'src', 'broken.ts'), 'const value = "unterminated');
    addPositive(auditSource(incomplete).findings);
    const unsupported = join(temporary, 'unsupported');
    mkdirSync(unsupported);
    writeFileSync(join(unsupported, 'README.txt'), 'no supported manifest\n');
    addPositive(auditSource(unsupported).findings);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }

  const negativeFindings = [
    ...inspectJsTsSource('src/safe.tsx', readFileSync(
      join(root, 'test', 'fixtures', 'js-ts-rules', 'safe.tsx'), 'utf8')).findings,
    ...inspectPythonSource('src/safe.py', readFileSync(
      join(root, 'test', 'fixtures', 'python-rules', 'safe.py'), 'utf8')).findings,
    ...auditSource(join(root, 'test', 'fixtures', 'next-app')).findings,
  ];
  return [...positive.keys()].map((ruleId) => ({
    ruleId,
    positiveFindingCount: positive.get(ruleId).length,
    positiveStates: [...new Set(positive.get(ruleId))].sort(),
    negativeFindingCount: negativeFindings.filter((finding) => finding.ruleId === ruleId).length,
  }));
}

function summary(results) {
  const positivePassed = results.filter((item) => item.positive.passed).length;
  const negativeFailed = results.filter((item) => !item.negative.passed).length;
  return {
    contracts: results.length,
    positivePassed,
    positiveFailed: results.length - positivePassed,
    negativePassed: results.length - negativeFailed,
    negativeFailed,
    stateMismatches: results.filter((item) => item.positive.findingCount > 0
      && !item.positive.stateMatched).length,
  };
}

export function buildRuleContractConformance(corpus, observations, release) {
  const observed = new Map(observations.map((item) => [item.ruleId, item]));
  const rules = corpus.rules.filter((rule) => rule.adapterType === 'built_in').map((rule) => {
    const item = observed.get(rule.ruleId) || {
      positiveFindingCount: 0, positiveStates: [], negativeFindingCount: 0,
    };
    const stateMatched = item.positiveStates.length === 1
      && item.positiveStates[0] === rule.expectedPositiveState;
    return {
      ruleId: rule.ruleId,
      kind: rule.kind,
      family: rule.family,
      positive: {
        fixtureIds: rule.positiveFixtures.map((fixture) => fixture.id),
        expectedState: rule.expectedPositiveState,
        observedStates: item.positiveStates,
        findingCount: item.positiveFindingCount,
        stateMatched,
        passed: item.positiveFindingCount > 0 && stateMatched,
      },
      negative: {
        fixtureIds: rule.negativeFixtures.map((fixture) => fixture.id),
        findingCount: item.negativeFindingCount,
        passed: item.negativeFindingCount === 0,
      },
    };
  });
  const risk = rules.filter((rule) => rule.kind === 'risk_detection');
  const integrity = rules.filter((rule) => rule.kind === 'evidence_integrity');
  return {
    schemaVersion: 1,
    release,
    evidenceType: 'synthetic_rule_contract_conformance',
    limitation: LIMITATION,
    rulesetSemanticDigest: corpus.rulesetSemanticDigest,
    summary: {
      risk: summary(risk),
      evidenceIntegrity: summary(integrity),
      combined: summary(rules),
    },
    rules,
  };
}

export function validateRuleContractConformance(conformance) {
  const errors = [];
  if (conformance?.schemaVersion !== 1) errors.push('conformance.schemaVersion must be 1');
  if (!/^v\d+\.\d+\.\d+$/.test(conformance?.release || '')) {
    errors.push('conformance.release must be a version label');
  }
  if (conformance?.evidenceType !== 'synthetic_rule_contract_conformance') {
    errors.push('conformance evidence type is invalid');
  }
  if (conformance?.limitation !== LIMITATION) errors.push('conformance limitation is missing or changed');
  for (const result of conformance?.rules || []) {
    if (!result.positive.passed) errors.push(`${result.ruleId} planted positive failed`);
    if (!result.negative.passed) errors.push(`${result.ruleId} planted negative produced a finding`);
    if (result.positive.findingCount > 0 && !result.positive.stateMatched) {
      errors.push(`${result.ruleId} planted positive used an unexpected evidence state`);
    }
  }
  for (const [group, expected] of [['risk', 25], ['evidenceIntegrity', 3], ['combined', 28]]) {
    const value = conformance?.summary?.[group];
    if (value?.contracts !== expected) {
      errors.push(`${group} contract count differs from the 25 risk + 3 integrity contract`);
    }
  }
  return [...new Set(errors)];
}

function summaryLine(label, value) {
  return `| ${label} | ${value.contracts} | ${value.positivePassed} | ${value.positiveFailed} | ${value.negativePassed} | ${value.negativeFailed} | ${value.stateMismatches} |`;
}

export function renderRuleContractMarkdown(conformance) {
  const lines = [
    `# ${conformance.release} rule-contract conformance`, '',
    `> ${conformance.limitation}`, '',
    `Ruleset semantic digest: \`${conformance.rulesetSemanticDigest}\``, '',
    '## Contract results', '',
    '| Group | Contracts | Positive passed | Positive failed | Negative passed | Negative failed | State mismatches |',
    '|---|---:|---:|---:|---:|---:|---:|',
    summaryLine('Risk detection', conformance.summary.risk),
    summaryLine('Evidence integrity', conformance.summary.evidenceIntegrity),
    summaryLine('Combined', conformance.summary.combined), '',
    'A positive passes when the declared planted example emits the named rule in its expected',
    'evidence state. A negative passes when the rule stays quiet on its declared safe neighbour.',
    'These outcomes are rule-contract checks, not vulnerability accuracy measurements.', '',
    '## Rule cases', '',
    '| Rule | Kind | Expected state | Positive | Negative |',
    '|---|---|---|---:|---:|',
    ...conformance.rules.map((rule) => `| \`${rule.ruleId}\` | ${rule.kind} | \`${rule.positive.expectedState}\` | ${rule.positive.passed ? 'pass' : 'fail'} | ${rule.negative.passed ? 'pass' : 'fail'} |`),
    '',
    'Regenerate with `npm run conformance:rules`. CI uses the same runner with `--check` to',
    'compare committed JSON and Markdown bytes.',
  ];
  return `${lines.join('\n')}\n`;
}
