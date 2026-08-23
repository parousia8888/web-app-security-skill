#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const check = process.argv.includes('--check');
if (process.argv.slice(2).some((arg) => arg !== '--check')) {
  console.error('usage: node scripts/generate-adoption-assets.mjs [--check]');
  process.exit(2);
}

const read = (path) => readFileSync(join(ROOT, path), 'utf8');
const json = (path) => JSON.parse(read(path));
const publication = json('docs/adoption/publication.json');
const regressions = json('docs/adoption/regressions.json');
const metadata = json('docs/github-metadata.json');
const contract = json('docs/public-contract.json');
const capabilities = json('docs/capabilities.json');
const demo = json('docs/assets/demo.json').result;
const journeys = json('docs/case-studies/journeys/evidence.json');
const ordinaryReview = json('docs/case-studies/journeys/v0.5.0-evidence.json');
const ruleCorpus = json('docs/stable-rule-corpus.json');
const version = read('VERSION').trim();
const releaseState = json('docs/release-state.json');
const published = releaseState.publishedRelease;
const releaseEvidencePath = published.evidence;

function requireFact(condition, message) {
  if (!condition) throw new Error(message);
}

requireFact(publication.schemaVersion === 2, 'publication schemaVersion must be 2');
requireFact(regressions.schemaVersion === 1 && regressions.cases?.length === 4,
  'four structured correctness regressions are required');
requireFact(/^[a-f0-9]{40}$/.test(regressions.fixCommit || '')
  && existsSync(join(ROOT, regressions.releaseEvidence)), 'regression evidence is incomplete');
requireFact(regressions.cases.every((item) => item.id && item.title && item.reproduction
  && item.impact && item.repair && item.test && item.plantedFailure && item.remainingBoundary
  && existsSync(join(ROOT, item.test))), 'regression case evidence is incomplete');
requireFact(releaseState.schemaVersion === 1, 'release-state schemaVersion must be 1');
requireFact(metadata.repository === publication.repositoryUrl.replace('https://github.com/', ''), 'repository sources disagree');
requireFact(metadata.promise?.en && metadata.promise?.['zh-CN'], 'canonical promises are missing');
requireFact(existsSync(join(ROOT, releaseEvidencePath)), `published release evidence is missing for v${published.version}`);
requireFact(demo.boundary === 'owned-local-source-fixture-no-network', 'demo must remain an owned local source fixture');
requireFact(demo.before?.state === 'suspected' && demo.before?.ruleId
  && demo.before?.technicalTerm && demo.before?.plainLanguage && demo.before?.consequence
  && demo.before?.evidenceBoundary && demo.proposal?.status === 'review_required'
  && demo.proposal?.sideEffects?.length && demo.securityRetest?.baselineState === 'fixed'
  && demo.functionalRetest?.status === 'passed', 'source demo facts are invalid');
requireFact(journeys.journeys?.length === contract.projectJourneys?.length, 'ordinary journey sources disagree');
requireFact(contract.methodStudies?.length > 0, 'method studies are missing');
requireFact(journeys.journeys.every((journey) => /^[a-f0-9]{40}$/.test(journey.commit || '')), 'journeys must pin immutable commits');
requireFact(journeys.method?.hostedInstancesProbed === false
  && journeys.method?.projectDependenciesExecuted === false
  && journeys.method?.osvPublicAdvisoryNetwork === true,
  'journey source/network boundary drifted');
requireFact(ordinaryReview.projects?.length === journeys.journeys.length
  && ordinaryReview.method?.hostedInstancesProbed === false
  && ordinaryReview.method?.networkAccessPerformed === false,
  'v0.5.0 ordinary review boundary drifted');
requireFact(ruleCorpus.counts?.stableTotal
  === ruleCorpus.counts?.builtInRisk + ruleCorpus.counts?.builtInIntegrity
    + ruleCorpus.counts?.externalRisk,
'stable rule corpus count drifted');

const capabilityCount = (category, maturity) => capabilities.capabilities.filter((item) =>
  item.category === category && (!maturity || item.maturity === maturity)).length;
const categorizedCount = Object.keys(capabilities.categories).reduce((sum, category) =>
  sum + capabilityCount(category), 0);
requireFact(categorizedCount === capabilities.capabilities.length, 'capability categories are incomplete');
const facts = {
  product: publication.product,
  repo: publication.repositoryUrl,
  marketplace: publication.marketplaceUrl,
  promiseEn: metadata.promise.en,
  promiseZh: metadata.promise['zh-CN'],
  version,
  publishedVersion: published.version,
  npxCommand: `npx --yes web-app-security-skill@${published.version} audit . --fail-on never`,
  release: published.url,
  capabilities: capabilities.capabilities.length,
  stableDetection: capabilityCount('detection', 'stable'),
  plannedDetection: capabilityCount('detection', 'planned'),
  evidenceReporting: capabilityCount('evidence_reporting'),
  lifecycleDistribution: capabilityCount('lifecycle_distribution'),
  guided: capabilityCount('agent_guided_methodology'),
  demoFinding: demo.before.technicalTerm,
  demoState: demo.before.state,
  demoSeverity: demo.before.severity,
  demoBoundary: demo.before.evidenceBoundary,
  demoProposal: demo.proposal.summary,
  demoSideEffect: demo.proposal.sideEffects.join(' '),
  securityRetest: demo.securityRetest.baselineState,
  functionalRetest: demo.functionalRetest.status,
  stableRules: ruleCorpus.counts.stableTotal,
  builtInRisk: ruleCorpus.counts.builtInRisk,
  builtInIntegrity: ruleCorpus.counts.builtInIntegrity,
  externalRisk: ruleCorpus.counts.externalRisk,
  reviewFindings: ordinaryReview.aggregate.findings,
  reviewUseful: ordinaryReview.aggregate.reviewClasses.useful_lead,
  reviewBenign: ordinaryReview.aggregate.reviewClasses.expected_benign_match,
  reviewUnknown: ordinaryReview.aggregate.reviewClasses.unknown,
  reviewConfirmed: ordinaryReview.aggregate.reviewClasses.confirmed,
  journeys: journeys.journeys.length,
  studies: contract.methodStudies.length,
};
requireFact(publication.firstRun.command === facts.npxCommand,
  'first-run command must match the published release');
const demoEn = `${facts.demoFinding}, ${facts.demoState.toUpperCase()} ${facts.demoSeverity.toUpperCase()}`;
const demoZh = `${facts.demoFinding}，${facts.demoState} ${facts.demoSeverity.toUpperCase()}`;
const demoAfterEn = `security ${facts.securityRetest}; functional ${facts.functionalRetest}`;
const demoAfterZh = `security ${facts.securityRetest}；functional ${facts.functionalRetest}`;

const generatedNote = '<!-- Generated by scripts/generate-adoption-assets.mjs. Edit structured sources, not this file. -->';
const enLimits = publication.limitations.en.map((item) => `- ${item}`).join('\n');
const zhLimits = publication.limitations['zh-CN'].map((item) => `- ${item}`).join('\n');
const installLink = `${facts.repo}/blob/main/docs/verified-installation.md`;
const installZhLink = `${facts.repo}/blob/main/docs/verified-installation.zh-CN.md`;
const demoLink = `${facts.repo}/blob/main/docs/demo-evidence.md`;
const capabilityLink = `${facts.repo}/blob/main/docs/capabilities.md`;
const journeysLink = `${facts.repo}/blob/main/docs/case-studies/journeys/README.md`;
const reviewLink = `${facts.repo}/blob/main/docs/case-studies/journeys/v0.5.0-review.md`;
const launchEvidenceLink = `${facts.repo}/blob/main/docs/launch-evidence.md`;
const regressionArticleLink = `${facts.repo}/blob/main/docs/adoption/regression-accountability.md`;
const regressionReleaseLink = `${facts.repo}/blob/main/${regressions.releaseEvidence}`;

const outputs = new Map();
function add(path, lines) {
  outputs.set(path, `${Array.isArray(lines) ? lines.join('\n') : lines}\n`);
}

add('docs/adoption/launch-brief.md', [
  '# Web App Security Skill: evidence-led launch brief',
  '',
  generatedNote,
  '',
  facts.promiseEn,
  '',
  `**For:** ${publication.audience.en}`,
  '',
  `**What it is:** ${publication.positioning.en}`,
  '',
  '## The inspect-patch-retest loop',
  '',
  `The repository-owned local source demo begins with **${demoEn}**, explains what the pattern does and does not prove, proposes argument-separated execution, names a quoting/platform side effect, and records **${demoAfterEn}**. It sends no network request and does not execute project dependencies.`,
  '',
  `[Watch the generated demo and inspect its reports](${demoLink}).`,
  '',
  '## What is implemented',
  '',
  `The current source contract lists **${facts.stableDetection} stable narrow detection families** and **${facts.plannedDetection} planned detection capabilities**. Separately, it records **${facts.evidenceReporting} evidence/reporting**, **${facts.lifecycleDistribution} lifecycle/distribution**, and **${facts.guided} agent-guided** capabilities. Demo, report, installer and Action behavior are not counted as vulnerability detection.`,
  '',
  `[Review every capability and its evidence](${capabilityLink}).`,
  '',
  `The v0.5.0 built-in review classifies all **${facts.reviewFindings} findings** from **${facts.journeys} fixed-commit ordinary projects** as ${facts.reviewUseful} useful leads, ${facts.reviewBenign} expected benign matches, ${facts.reviewUnknown} unknown and ${facts.reviewConfirmed} confirmed missing-lockfile facts. This is not a vulnerability count or precision/recall claim. A separate ${facts.studies}-study corpus exercises broader source methodology.`,
  '',
  `[Review the v0.5.0 classification](${reviewLink}) and [historical journey method](${journeysLink}).`,
  '',
  '## Install and distribution',
  '',
  `Release [v${facts.publishedVersion}](${facts.release}) provides a signed tag, reproducible source archive, SPDX SBOM, checksums, release manifest and provenance. The supported one-command installer pins and verifies its bootstrap before execution, then verifies the selected release assets and metadata.`,
  '',
  `- [Verified installation](${installLink})`,
  `- [GitHub Marketplace Action](${facts.marketplace})`,
  `- [Generated launch evidence](${launchEvidenceLink})`,
  '',
  '## Limits to preserve when quoting',
  '',
  enLimits,
  '',
  `Community publication, independent user-session results and upstream validation remain \`${publication.externalState.communityPublication}\`. This brief is a publication kit, not evidence that any external post or validation has occurred.`,
]);

add('docs/adoption/launch-brief.zh-CN.md', [
  '# Web App Security Skill：证据型发布简报',
  '',
  generatedNote,
  '',
  facts.promiseZh,
  '',
  `**面向：**${publication.audience['zh-CN']}`,
  '',
  `**产品形态：**${publication.positioning['zh-CN']}`,
  '',
  '## 检查、补丁与复测闭环',
  '',
  `仓库自有本地源码 demo 的初始结果为 **${demoZh}**，随后说明 pattern 能证明和不能证明什么，提出参数分离的执行方式，列出 quoting/跨平台副作用，并记录 **${demoAfterZh}**。该 fixture 不访问网络，也不执行项目依赖。`,
  '',
  `[查看生成的 demo、报告与补丁](${demoLink})。`,
  '',
  '## 已实现范围',
  '',
  `版本化合同当前列出 **${facts.stableDetection} 个 stable 窄检测家族**和 **${facts.plannedDetection} 项 planned 检测能力**；另行记录 **${facts.evidenceReporting} 项证据/报告**、**${facts.lifecycleDistribution} 项生命周期/分发**与 **${facts.guided} 项 agent-guided** 能力。Demo、报告、安装器和 Action 不计入漏洞检测覆盖。`,
  '',
  `[逐项查看能力与证据](${capabilityLink})。`,
  '',
  `v0.5.0 built-in 复核把 **${facts.journeys} 个固定 commit 普通项目**中的 **${facts.reviewFindings} 条 finding**逐条归类为 ${facts.reviewUseful} 条有用线索、${facts.reviewBenign} 条预期良性命中、${facts.reviewUnknown} 条 unknown 和 ${facts.reviewConfirmed} 条已确认的缺 lockfile 事实。这不是漏洞数量或 precision/recall。另有 ${facts.studies} 个独立源码方法论案例。`,
  '',
  `[查看 v0.5.0 人工分类](${reviewLink})与[历史旅程方法](${journeysLink})。`,
  '',
  '## 安装与分发',
  '',
  `Release [v${facts.publishedVersion}](${facts.release}) 提供签名 tag、可复现源码归档、SPDX SBOM、校验和、release manifest 与 provenance。受支持的一条命令安装路径在执行前固定并校验 bootstrap，随后校验所选 release 的资产与元数据。`,
  '',
  `- [可信安装说明](${installZhLink})`,
  `- [GitHub Marketplace Action](${facts.marketplace})`,
  `- [生成式 launch evidence](${launchEvidenceLink})`,
  '',
  '## 引用时必须保留的限制',
  '',
  zhLimits,
  '',
  `社区发布、独立用户 session 结果和上游验证仍为 \`${publication.externalState.communityPublication}\`。本简报只是发布素材，不代表外部文章或验证已经发生。`,
]);

add('docs/adoption/channels/technical-long-form.md', [
  '# Technical long-form draft',
  '',
  generatedNote,
  '',
  '## Title',
  '',
  'A readable web-security first pass after AI-assisted coding',
  '',
  '## Draft',
  '',
  `After an AI coding session, run one local command from the project root:`,
  '',
  '```bash',
  facts.npxCommand,
  '```',
  '',
  `${facts.product} turns each actionable lead into five review questions: what is the security term, what could happen, what did the evidence actually prove, what change is proposed, and what normal behavior could that change break? It keeps security retesting separate from product-function testing and does not edit the project.`,
  '',
  `The owned demo shows ${demoEn}, a reviewable shell-free proposal, and ${demoAfterEn}. [Inspect the exact reports and patch](${demoLink}).`,
  '',
  `Four correctness regressions in v0.5.1 changed the test strategy: a broken human-readable summary, a false confirmed pnpm lockfile absence, incomplete nested-template coverage, and a rename that could look fixed. [The reproductions, repairs and remaining boundaries are recorded here](${regressionArticleLink}).`,
  '',
  `Current limits remain explicit: static matches are usually suspected leads, parser failures become unknown, diff mode reduces review noise without proving whole-repository safety, and the planted benchmark is not production precision or recall.`,
  '',
  `Repository: ${facts.repo}`,
  '',
  '### Limits',
  '',
  enLimits,
  '',
  '> Publication status: draft. No external publication or upstream endorsement is claimed.',
]);

add('docs/adoption/channels/show-hn.md', [
  '# Show HN draft',
  '',
  generatedNote,
  '',
  '## Title',
  '',
  'Show HN: Web App Security Skill - one command, readable findings, and retests',
  '',
  '## Submission text',
  '',
  `I built ${facts.product} for Web builders using AI coding agents who need a local security first pass they can actually review. From a project root:`,
  '',
  '```bash',
  facts.npxCommand,
  '```',
  '',
  'The report pairs the security term with a plain-language consequence, says what the evidence does not prove, proposes a change for review, names likely side effects, and asks for separate security and normal-behavior retests. It does not edit the project or contact a deployment.',
  '',
  `I also published how four correctness regressions were reproduced and turned into regression gates: ${regressionArticleLink}`,
  '',
  `Repository: ${facts.repo}`,
  '',
  'The built-in checks are a bounded first pass, mainly for JavaScript/TypeScript and Python. A clean report does not prove a project secure. I would value feedback on whether the explanations and evidence boundaries help non-specialists decide what to review next.',
  '',
  '> Publication status: draft; submitting to Hacker News remains an owner action.',
]);

add('docs/adoption/channels/reddit.md', [
  '# Reddit discussion draft',
  '',
  generatedNote,
  '',
  '## Suggested title',
  '',
  'I built a local Web-security first pass that explains findings before proposing changes',
  '',
  '## Post',
  '',
  `I am working on [${facts.product}](${facts.repo}) for people who build Web products with AI coding tools but do not have a dedicated AppSec workflow. The first run is:`,
  '',
  '```bash',
  facts.npxCommand,
  '```',
  '',
  'For each lead, the report gives the technical term, a plain explanation, a realistic consequence, the missing evidence, a reviewable proposal, alternatives, likely side effects, rollback, and separate security/product retests. Static matches stay suspected unless stronger evidence exists.',
  '',
  `The demo is owned and local: ${demoEn} -> ${demoAfterEn}. I also documented four correctness regressions and the tests added after them: ${regressionArticleLink}`,
  '',
  'Questions for review:',
  '',
  '- Does the ordinary-language explanation give enough information to review a proposed change?',
  '- Which side effects or retest instructions are still too generic?',
  '- Where would you expect a local first pass to stop and hand off to deeper tooling or a specialist?',
  '',
  'This is not positioned as a general scanner, a precision benchmark or proof that an application is secure.',
  '',
  '> Publication status: draft; subreddit selection and posting require a rule check at posting time.',
]);

const shortPost = `${facts.product}: local first pass after AI coding. Leads include evidence limits, patch side effects and security/product retests. No auto-edit. ${facts.npxCommand} ${facts.repo}`;
requireFact(shortPost.length <= 280, `short post exceeds 280 characters (${shortPost.length})`);
add('docs/adoption/channels/x-short-post.md', [
  '# X / short-post draft',
  '',
  generatedNote,
  '',
  shortPost,
  '',
  `Character count before platform URL shortening: ${shortPost.length}.`,
  '',
  '> Publication status: draft.',
]);

add('docs/adoption/channels/v2ex.md', [
  '# V2EX 发布草稿',
  '',
  generatedNote,
  '',
  '## 标题',
  '',
  '做了一个 Web App Security Skill：一条命令检查 AI coding 后的 Web 项目',
  '',
  '## 正文',
  '',
  '先给能直接运行的入口：',
  '',
  '```bash',
  facts.npxCommand,
  '```',
  '',
  '主要给使用 AI coding 工具做 Web 产品、但没有专门安全流程的人。报告不会只扔一个漏洞名，而是同时写清楚：行业术语、白话解释、问题成立时的后果、当前证据没有证明什么、准备怎么改、可能影响哪些正常功能，以及安全复测和功能复测分别怎么做。CLI 不会直接改项目。',
  '',
  `自有本地 demo 的结果是 ${demoZh}，修改提案后记录 ${demoAfterZh}。原始报告、补丁和生成脚本都能查看。`,
  '',
  `我也把 v0.5.1 中四个 correctness regression 的最小复现、修法、回归门和剩余边界整理成了一篇记录：${regressionArticleLink}`,
  '',
  `项目：${facts.repo}`,
  '',
  `Demo：${demoLink}`,
  '',
  '当前边界：内置源码深度主要在 JavaScript/TypeScript 与 Python；静态命中通常只是 suspected；diff 模式只减少噪音；fixture benchmark 不等于真实项目检出率。',
  '',
  '> 发布状态：草稿；节点选择、标题和发布时间需发布时检查。',
]);

add('docs/adoption/channels/chinese-developer-community.md', [
  '# 中文开发者社区长文草稿',
  '',
  generatedNote,
  '',
  '## 标题',
  '',
  'AI coding 后怎样做一次看得懂的 Web 安全检查',
  '',
  '## 摘要',
  '',
  `${facts.product} 是一个开源 Skill 与 CLI，用一条命令生成本地源码安全初检，再把每条线索翻译成能审查的修改和复测问题。`,
  '',
  '## 正文',
  '',
  '```bash',
  facts.npxCommand,
  '```',
  '',
  '第一次报告会同时给出安全术语和白话解释，并区分“代码里看到了什么”与“还没有证明什么”。修改建议默认只供审查，同时列出替代方案、可能副作用、回滚条件、安全复测和产品功能复测。',
  '',
  `仓库自有 demo 从 ${demoZh} 开始，应用待审查提案后记录 ${demoAfterZh}。它不访问部署实例，也不执行目标项目依赖；报告、补丁和生成方式都在仓库。`,
  '',
  `在 v0.5.2 之前，四个可复现的正确性问题暴露了证据链的薄弱处：报告摘要输出 [object Object]、pnpm workspace 被误判为 confirmed 缺锁文件、嵌套模板让整文件 coverage 变成 partial、纯改名让 retest 看起来成功。这四项的修复和测试门记录在：${regressionArticleLink}`,
  '',
  '现在仍有明确限制：静态规则通常只能给 suspected 线索；parser 遇到不支持的语法会 fail closed 为 unknown；diff clean 不代表全仓库安全；planted benchmark 也不是真实漏洞 precision/recall。',
  '',
  `- 项目：${facts.repo}`,
  `- Demo：${demoLink}`,
  `- 当前限制：${facts.repo}/blob/main/KNOWN_LIMITATIONS.md`,
  '',
  '### 需要保留的限制',
  '',
  zhLimits,
  '',
  '> 发布状态：草稿。没有声称已在任何中文社区发布，也没有声称获得第三方或上游验证。',
]);

add('docs/adoption/channels/zenn-ja.md', [
  '# Zenn 投稿ドラフト',
  '',
  generatedNote,
  '',
  '## タイトル',
  '',
  'AI コーディング後の Web セキュリティ確認を、レビューできる言葉にする',
  '',
  '## 本文',
  '',
  'AI コーディングで Web プロダクトを作った後、専門家でなくても最初の確認を始められるようにしたローカル CLI と Skill です。プロジェクトのルートで次を実行します。',
  '',
  '```bash',
  facts.npxCommand,
  '```',
  '',
  'レポートは検出名だけを並べません。業界用語、平易な説明、起こり得る影響、現在の証拠で未確認の点、レビュー用の修正案、副作用、ロールバック条件を一緒に示します。セキュリティの再テストと通常機能の確認も分けます。CLI はコードを自動変更しません。',
  '',
  `所有 fixture のデモは ${demoEn} から始まり、修正案の適用後に ${demoAfterEn} を記録します。デプロイ先には接続せず、対象プロジェクトの依存関係も実行しません。`,
  '',
  `v0.5.1 では、読みやすい要約の崩れ、pnpm workspace の誤った confirmed 判定、ネストした template literal の解析不足、ファイル名変更による誤った retest 成功という四つの correctness regression がありました。最小再現、修正、回帰テスト、残る限界を公開しています：${regressionArticleLink}`,
  '',
  '現在の内蔵チェックは JavaScript/TypeScript と Python を中心とした限定的な first pass です。suspected は確認済み脆弱性ではなく、diff の結果が clean でもリポジトリ全体の安全性は証明できません。',
  '',
  `- Repository: ${facts.repo}`,
  `- Demo evidence: ${demoLink}`,
  `- Known limitations: ${facts.repo}/blob/main/KNOWN_LIMITATIONS.md`,
  '',
  '> 公開状態：ドラフト。Zenn への投稿と公開日時は owner の判断事項です。',
]);

const regressionSections = regressions.cases.flatMap((item, index) => [
  `## ${index + 1}. ${item.title}`,
  '',
  `**Minimal reproduction:** ${item.reproduction}`,
  '',
  `**Why it mattered:** ${item.impact}`,
  '',
  `**Repair:** ${item.repair}`,
  '',
  `**Regression gate:** [\`${item.test}\`](${facts.repo}/blob/main/${item.test})`,
  '',
  `**Failure plant:** ${item.plantedFailure}`,
  '',
  `**Remaining boundary:** ${item.remainingBoundary}`,
  '',
]);
add('docs/adoption/regression-accountability.md', [
  '# Four correctness regressions and the gates added after them',
  '',
  generatedNote,
  '',
  'This is a source-backed maintenance record for four reproducible v0.5.1 correctness failures.',
  'It does not identify a reviewer, assign incident severity, or claim an independent security audit.',
  '',
  `All four repairs landed in [\`${regressions.fixCommit}\`](${facts.repo}/commit/${regressions.fixCommit})`,
  `and are recorded in the [v${regressions.fixedVersion} release evidence](${regressionReleaseLink}).`,
  '',
  ...regressionSections,
  '## What these repairs do not establish',
  '',
  '- Passing the gates does not establish production vulnerability precision or recall.',
  '- A human-readable report still requires review; presentation tests do not prove comprehension.',
  '- Fail-closed unknown or partial coverage is evidence of a limit, not a passing security result.',
  '- `condition_moved` records an equivalent condition elsewhere; it does not prove file identity or a Git move.',
  '',
  '> Publication status: repository maintenance record. No third-party identity or endorsement is claimed.',
]);

add('docs/adoption/github-release-lead.md', [
  `# Human-readable GitHub Release lead for v${facts.publishedVersion}`,
  '',
  generatedNote,
  '',
  '> Prepared copy only. Editing the live GitHub Release remains an owner-authorized external action.',
  '',
  '## Suggested lead',
  '',
  facts.promiseEn,
  '',
  `${facts.product} gives Web builders using AI coding agents a reviewable local security first pass. Run it without installing:`,
  '',
  '```bash',
  facts.npxCommand,
  '```',
  '',
  'The report explains each lead in security terms and ordinary language, states what the evidence',
  'does not prove, proposes a change for review, names likely product side effects, and separates',
  'security retesting from normal-behavior testing. The command does not edit the project or contact',
  'a deployment.',
  '',
  `v${facts.publishedVersion} adds a framework-aware route review for bounded Express, NestJS and`,
  'Next.js App Router syntax. It keeps authentication, route authorization and object authorization',
  'separate, records unresolved syntax as incomplete evidence and orders review without turning',
  'missing visible controls into confirmed vulnerabilities. The direct Prisma object-authorization',
  'lead remains experimental. These are bounded first-pass capabilities; they do not',
  'prove that a project is secure or establish production-vulnerability precision or recall.',
  '',
  '## Keep below this lead',
  '',
  'Retain the existing signed-tag, asset digest, SBOM, manifest, provenance, immutable Action and',
  'verified-installer evidence below the human-readable opening.',
]);

add('docs/adoption/citations.md', [
  '# Citation and fact sheet',
  '',
  generatedNote,
  '',
  'Quote the claims below with their evidence links and limits. Do not convert repository counts',
  'into a security score, precision estimate or universal coverage claim.',
  '',
  '| ID | Citable claim | Evidence | Required qualifier |',
  '|---|---|---|---|',
  `| \`product.workflow\` | ${facts.promiseEn} | [README](${facts.repo}#readme) | Agent-guided work still requires project context and review. |`,
  `| \`demo.before-after\` | The repository-owned local source fixture records ${demoEn}, a reviewable proposal and ${demoAfterEn}. | [Generated demo evidence](${demoLink}) | The lead is suspected; no exploitability or third-party coverage claim. |`,
  `| \`capabilities.contract\` | The current source contract lists ${facts.stableDetection} stable narrow detection families and ${facts.plannedDetection} planned detection capabilities, separately from ${facts.evidenceReporting} evidence/reporting, ${facts.lifecycleDistribution} lifecycle/distribution and ${facts.guided} agent-guided capabilities. | [Generated capability matrix](${capabilityLink}) | Supporting or guided capability counts are not vulnerability coverage or precision. |`,
  `| \`cases.ordinary\` | ${facts.journeys} ordinary project journeys use immutable source commits with no hosted instance probed. | [Journey evidence](${journeysLink}) | Source-only scope; zero, false-positive and unknown outcomes remain visible; no upstream validation claimed. |`,
  `| \`cases.method\` | ${facts.studies} separate fixed-commit studies exercise the source-review methodology. | [Case-study method](${facts.repo}/blob/main/docs/case-studies/README.md) | Not a CLI precision benchmark. |`,
  `| \`release.integrity\` | v${facts.publishedVersion} records a signed tag, reproducible archive, SPDX SBOM, checksums, manifest and provenance. | [Release evidence](${facts.repo}/blob/main/${releaseEvidencePath}) | Artifact identity/origin does not prove every security conclusion. |`,
  `| \`distribution.marketplace\` | The composite Action is listed in GitHub Marketplace. | [Marketplace](${facts.marketplace}) | Listing presence is not adoption or security evidence. |`,
  '',
  '## Machine-readable source',
  '',
  'Use [`share-metadata.json`](share-metadata.json) for the same current facts. It is regenerated',
  'and checked in normal repository lint.',
]);

const share = {
  schemaVersion: 2,
  generatedBy: 'scripts/generate-adoption-assets.mjs',
  product: facts.product,
  repository: facts.repo,
  marketplace: facts.marketplace,
  productVersion: facts.version,
  release: { version: facts.publishedVersion, url: facts.release, state: 'published' },
  promise: { en: facts.promiseEn, 'zh-CN': facts.promiseZh },
  firstRun: {
    command: facts.npxCommand,
    explanation: publication.firstRun,
  },
  capabilityContract: {
    total: facts.capabilities,
    stableDetection: facts.stableDetection,
    plannedDetection: facts.plannedDetection,
    evidenceReporting: facts.evidenceReporting,
    lifecycleDistribution: facts.lifecycleDistribution,
    agentGuided: facts.guided,
    evidence: capabilityLink,
  },
  ownedLocalDemo: {
    finding: { technicalTerm: facts.demoFinding, state: facts.demoState, severity: facts.demoSeverity },
    proposal: { summary: facts.demoProposal, sideEffect: facts.demoSideEffect },
    retest: { security: facts.securityRetest, functional: facts.functionalRetest },
    thirdPartyTarget: false,
    networkAccess: false,
    evidence: demoLink,
  },
  caseEvidence: {
    ordinaryFixedCommitJourneys: facts.journeys,
    methodologyStudies: facts.studies,
    hostedInstancesProbedInOrdinaryJourneys: false,
    upstreamValidationClaimed: false,
    v050Review: {
      findings: facts.reviewFindings,
      usefulLeads: facts.reviewUseful,
      expectedBenignMatches: facts.reviewBenign,
      unknown: facts.reviewUnknown,
      confirmedFacts: facts.reviewConfirmed,
    },
    evidence: journeysLink,
  },
  correctnessRegressions: {
    reviewedVersion: regressions.reviewedVersion,
    fixedVersion: regressions.fixedVersion,
    count: regressions.cases.length,
    ids: regressions.cases.map((item) => item.id),
    fixCommit: regressions.fixCommit,
    evidence: regressionArticleLink,
  },
  externalState: publication.externalState,
  prohibitedInferences: [
    'general scanner coverage',
    'precision percentage',
    'project is secure',
    'upstream validation',
    'external publication already occurred'
  ]
};
add('docs/adoption/share-metadata.json', JSON.stringify(share, null, 2));

let stale = false;
for (const [path, content] of outputs) {
  const target = join(ROOT, path);
  if (check) {
    if (!existsSync(target) || readFileSync(target, 'utf8') !== content) {
      console.error(`adoption assets: stale ${path}`);
      stale = true;
    }
  } else {
    mkdirSync(join(target, '..'), { recursive: true });
    writeFileSync(target, content);
  }
}
if (stale) process.exit(1);
console.log(`adoption assets ${check ? 'current' : 'generated'}: ${outputs.size} files, ${facts.capabilities} capabilities, ${facts.journeys} journeys, ${facts.studies} studies`);
