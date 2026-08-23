#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (path) => readFileSync(`${ROOT}/${path}`, 'utf8');
const normalize = (value) => value.replace(/\s+/g, ' ').trim();
const contract = JSON.parse(read('docs/public-contract.json'));
const capabilities = JSON.parse(read('docs/capabilities.json'));
const demo = JSON.parse(read('docs/assets/demo.json')).result;
const en = read('README.md');
const zh = read('README.zh-CN.md');
const evidence = read('docs/demo-evidence.md');
const firstTrial = 'npx --yes web-app-security-skill audit . --fail-on never';

function fail(message) {
  console.error(`public surfaces: ${message}`);
  process.exitCode = 1;
}

if (contract.schemaVersion !== 1) fail('public contract schemaVersion must be 1');
if (contract.currentSourceRelease?.version !== '0.6.0'
    || contract.currentSourceRelease?.status !== 'published'
    || !existsSync(`${ROOT}/${contract.currentSourceRelease?.routeReview || ''}`)) {
  fail('published v0.6.0 route-review contract is missing or invalid');
}
if (JSON.stringify(contract.currentSourceRelease?.stableFrameworks) !== JSON.stringify([
  'express', 'nestjs', 'next-app',
])) fail('published v0.6.0 framework scope changed');
for (const path of [...(contract.projectJourneys || []), ...(contract.methodStudies || [])]) {
  if (!existsSync(`${ROOT}/${path}`)) fail(`public evidence document is missing: ${path}`);
}
const journeyCount = contract.projectJourneys?.length ?? 0;
const studyCount = contract.methodStudies?.length ?? 0;
if (!en.includes(`## ${journeyCount} ordinary project journeys`)) fail('English project-journey count is stale');
if (!zh.includes(`## ${journeyCount} 个普通项目旅程`)) fail('Chinese project-journey count is stale');
if (!en.includes(`${studyCount} earlier source methodology studies`)) fail('English methodology-study count is stale');
if (!zh.includes(`${studyCount} 个既有源码方法论案例`)) fail('Chinese methodology-study count is stale');

for (const [locale, text] of [['en', en], ['zh-CN', zh]]) {
  if (!normalize(text).includes(normalize(contract.firstTaskPrompt[locale]))) {
    fail(`${locale} first-task prompt differs from docs/public-contract.json`);
  }
}

const headingOrder = [
  ['README.md', en, ['## See the result', '## Install', '## Run the first project', '## Capability boundary', '## Deterministic tools', '## Trust and release evidence']],
  ['README.zh-CN.md', zh, ['## 查看结果', '## 安装', '## 执行第一个项目', '## 能力边界', '## 确定性工具', '## 信任与 release 证据']],
];
for (const [path, text, headings] of headingOrder) {
  let cursor = -1;
  for (const heading of headings) {
    const index = text.indexOf(heading);
    if (index === -1) fail(`${path} is missing ${heading}`);
    if (index <= cursor) fail(`${path} has an invalid outcome-to-trust section order`);
    cursor = index;
  }
}

for (const [path, text] of [['README.md', en], ['README.zh-CN.md', zh]]) {
  for (const anchor of text.matchAll(/<a href="#([^"]+)">/g)) {
    if (!text.includes(`id="${anchor[1]}"`) && !text.includes(`name="${anchor[1]}"`)) {
      const derived = [...text.matchAll(/^#{1,6} (.+)$/gm)].some((match) => match[1]
        .toLowerCase()
        .replace(/[^\p{L}\p{N}\s-]/gu, '')
        .trim()
        .replace(/\s+/g, '-') === anchor[1]);
      if (!derived) fail(`${path} navigation anchor does not resolve: #${anchor[1]}`);
    }
  }
}

for (const [path, text, releaseHeading, explanationMarkers] of [
  ['README.md', en, "## What's new in v0.6.0",
    ['plain-language explanation', 'what the evidence proves', 'likely product side effects', 'normal-behavior retests']],
  ['README.zh-CN.md', zh, '## v0.6.0 新增内容',
    ['白话解释', '当前证据证明了什么', '可能影响的正常功能', '功能复测']],
]) {
  const trialIndex = text.indexOf(firstTrial);
  const demoIndex = text.indexOf('docs/assets/demo.gif');
  const releaseIndex = text.indexOf(releaseHeading);
  if (trialIndex === -1 || trialIndex > demoIndex) fail(`${path} does not put the complete npx trial before the demo`);
  if (releaseIndex === -1 || releaseIndex < demoIndex) fail(`${path} puts release notes before first-use evidence`);
  for (const marker of explanationMarkers) {
    if (!text.slice(0, demoIndex).includes(marker)) fail(`${path} first screen is missing ${marker}`);
  }
}

const categories = Object.keys(capabilities.categories);
const maturities = Object.keys(capabilities.maturities);
const states = Object.keys(capabilities.resultStates);
for (const [path, text] of [['README.md', en], ['README.zh-CN.md', zh]]) {
  for (const state of states) if (!text.includes(`\`${state}\``)) fail(`${path} is missing ${state}`);
  for (const marker of path === 'README.md'
    ? ['Detection', 'Evidence and reporting', 'Lifecycle and distribution', 'Agent-guided methodology', 'stable', 'planned']
    : ['检测', '证据与报告', '生命周期与分发', 'Agent 方法论', 'stable', 'planned']) {
    if (!text.includes(marker)) fail(`${path} is missing capability taxonomy marker ${marker}`);
  }
}

const demoFacts = [demo?.before?.technicalTerm, demo?.before?.state, demo?.before?.severity,
  demo?.before?.evidenceBoundary, demo?.proposal?.summary, demo?.proposal?.sideEffects?.[0],
  demo?.securityRetest?.baselineState, demo?.functionalRetest?.status];
if (demoFacts.some((value) => !value)) fail('structured source demo facts are invalid');
for (const [path, text] of [['README.md', en], ['README.zh-CN.md', zh], ['docs/demo-evidence.md', evidence]]) {
  for (const marker of [demo.before.technicalTerm, demo.before.state, demo.securityRetest.baselineState,
    demo.functionalRetest.status]) if (!text.includes(marker)) fail(`${path} is missing source demo fact ${marker}`);
}

for (const [path, text] of [['README.md', en], ['README.zh-CN.md', zh]]) {
  if (/2 security HIGH|11 discoverability HIGH|13\s+(?:high|HIGH)/.test(text)) fail(`${path} retains stale crawl demo facts`);
  if (!text.includes('demo-result.json')) fail(`${path} does not name the structured demo fact source`);
  if (!text.includes('fail-on-domain')) fail(`${path} does not document domain policy`);
  if (!text.includes('docs/rule-taxonomy.md')) fail(`${path} does not link the rule taxonomy`);
  if (!text.includes('route-security.md')) fail(`${path} does not explain the route review artifact`);
  if (!text.includes('Object-level authorization')) fail(`${path} does not explain object authorization`);
}

const detectionCount = capabilities.capabilities.filter((item) =>
  item.category === 'detection' && item.maturity === 'stable').length;
for (const [path, text] of [
  ['README.md', en], ['README.zh-CN.md', zh], ['docs/demo-evidence.md', evidence],
  ['docs/launch-evidence.md', read('docs/launch-evidence.md')],
]) {
  if (new RegExp(`${capabilities.capabilities.length}\\s+(?:automated|automation|detection)`, 'i').test(text)) {
    fail(`${path} presents the aggregate capability count as detection coverage`);
  }
  if (path.includes('launch') && !text.includes(`${detectionCount} stable narrow detection families`)) {
    fail(`${path} is missing the category-scoped stable detection count`);
  }
}

if (/Replace the placeholder|替换占位符/.test(`${en}\n${zh}`)) fail('stale Action placeholder copy remains');
if (!process.exitCode) console.log(`public surfaces ok: ${journeyCount} journeys, ${studyCount} methodology studies, ${categories.length} categories, ${maturities.length} maturities, ${states.length} result states`);
