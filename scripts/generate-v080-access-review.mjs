#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { analyzeDataOperations } from './lib/js-ts-data-operation-evidence.mjs';
import { walkJsTsAst } from './lib/js-ts-ast-parser.mjs';
import { buildJsTsModuleGraph } from './lib/js-ts-module-graph.mjs';
import { routeSemanticDigest } from './generate-v070-access-review.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const EVALUATION_PATH = join(ROOT, 'docs/reviews/v0.8.0-access-control-evaluation.json');
const REVIEW_JSON = join(ROOT, 'docs/reviews/v0.8.0-access-control-review.json');
const REVIEW_MD = join(ROOT, 'docs/reviews/v0.8.0-access-control-review.md');
const PROVENANCE_JSON = join(ROOT, 'docs/reviews/v0.8.0-access-control-review-provenance.json');
const PROVENANCE_MD = join(ROOT, 'docs/reviews/v0.8.0-access-control-review-provenance.md');
const REGRESSION_JSON = join(ROOT,
  'docs/regressions/v0.8.0-access-control-real-world-regression.json');
const REGRESSION_MD = join(ROOT,
  'docs/regressions/v0.8.0-access-control-real-world-regression.md');

export const V080_TOOL_COMMIT = 'fa21f3e6e53b48a08ad40e3529353f245f516260';
export const V080_LEDGER_SHA256 =
  'b57a3e7e281e3d08ed88205004be3d6dc5c2e39549aa7c8953a1e48d23014ee6';
export const V080_LEDGER_FILE_SHA256 =
  '3221ede8b967a68b616dcd8671a550c1c61c55f1f22955dc088a9d6ad8d71879';

const PROJECTS = [
  {
    id: 'nestjs-boilerplate', repository: 'brocoders/nestjs-boilerplate',
    commit: '9620f159eefe38f47747d02ab162852367c5472c', license: 'MIT', target: '.',
    reportSha256: 'd2ff336f6eaa4195450dba5cc8891c0b67b51bad29693ac0748f65992b799b65',
    routeReportSha256: '80412569cbf6142f1e806500857a56e1a681b165f0d2e7192e54fbd9fc99c987',
    routeMarkdownSha256: 'e8f6d345deaecf2faa5bb8785b20c02798c2ec3c94ba49f2da4041c66e7c07fe',
    routeSemanticSha256: '548520986f86c7fa0f30efe87696c0dfa66565c182cfdd4ba9e23f90d37cc3b6',
    baselineMedianSeconds: 0.28, candidateMedianSeconds: 0.35,
  },
  {
    id: 'vercel-chatbot', repository: 'vercel/chatbot',
    commit: 'c2f8235e1f3ea903ad8b7f61447c4f74164b5c58', license: 'Apache-2.0', target: '.',
    reportSha256: 'a1062d8bb4d21572efefffe1b5a08e3de10a7d27a2fbe373f692e074a1943cc7',
    routeReportSha256: 'b8c92dd24bd3eb1fefee2c9df3c9337466c3cb705ce2838152e2255238e9b936',
    routeMarkdownSha256: 'e15089e2aa5a9f86f0fbb1f76a2fff03843f429feb772712fc02a804ce465bdb',
    routeSemanticSha256: '74385e3ed5385913006ef40a0083f5229f9d41e48f157109bf89f14dcd1541f8',
    baselineMedianSeconds: 0.49, candidateMedianSeconds: 0.54,
  },
  {
    id: 'formbricks', repository: 'formbricks/formbricks',
    commit: 'b66c1dd978af618a0e402bd3343b456bed68594c', license: 'AGPL-3.0', target: '.',
    reportSha256: '5415713d74a855e2cfefb7bbbf82d0a6b3c73995e085af7910049490965f9d06',
    routeReportSha256: 'f9ac3731d4d67dff28a421b8fa0c5cd1c0ae7ce757fc9ac01ad37de512c8a952',
    routeMarkdownSha256: '95227eaf7022d6e79bead5eb3458c9443597776e8a552fe361dc4b48de95dfdd',
    routeSemanticSha256: '7f5ea6fad817500a6333ab4eb78ee8d50c43c97739d6aa544928c2a474a18f18',
    baselineMedianSeconds: 4.32, candidateMedianSeconds: 6.07,
  },
  {
    id: 'documenso', repository: 'documenso/documenso',
    commit: '75330166cc00b29c14399bc2e391e4b4d8080c00', license: 'AGPL-3.0',
    target: 'apps/docs',
    reportSha256: 'c6e7a1e7ca339ad69879f38997cd76f3d87188ccbc80ae587470211d60b68f2b',
    routeReportSha256: '838a8154d407b5e8c9a68bc2a2865913294e595aa74630240fab846ec2c1ebdd',
    routeMarkdownSha256: 'd71aacafed02e0b1086c59fb42e7c03956687c1fa5fbba5dbda395a8097fefa3',
    routeSemanticSha256: '5a32b50d0ff6504c3560eb78d69ba670341b73dff984a35e7d031f5f8dd0f90c',
    baselineMedianSeconds: 0.16, candidateMedianSeconds: 0.19,
  },
];

const EXPECTED_COMPLETED_CHAIN_IDS = new Set(`
access-chain.00ec8fd0fa61214176dbe4f6
access-chain.011b2403cf773d3c669758be
access-chain.0197d53b028462e7660ea807
access-chain.019aebca02e575c6d1961f7d
access-chain.06a24c75a479d67cfd0702e2
access-chain.086b529b1369128fb156f92c
access-chain.0f62a492e4988aab515ef2d5
access-chain.14913a8fb2817afc80af0fc1
access-chain.18a9db0b97aedeb474c06796
access-chain.1bac50890a41ae86f189a0dc
access-chain.1bd9199f6af681b25577bc73
access-chain.1deaa9c1fa9bbe80350dc723
access-chain.211c8aa49551d2229d032a2c
access-chain.21c50ccfb61017e994c185ab
access-chain.22235dfe03cfd161db5a420e
access-chain.225a2db823098935b6cc7a90
access-chain.23da716977b7898e9cb8ea70
access-chain.32176f488f417542200c8548
access-chain.3288e88f6e473bd0ccf32b98
access-chain.35c45d28e89463ee96ab6099
access-chain.457629b876f88d4965c4db84
access-chain.4bfde2d33d9581e38429a68f
access-chain.52ae8b6f9aaf48a893e10a1c
access-chain.52cc45084d34e8f9651ebfa1
access-chain.52cc99d500ea93937eff6372
access-chain.5988926ffa4e94221c04231d
access-chain.5afde3a776f87319b7875656
access-chain.5ee240547868a98599a0c7c4
access-chain.70a0ded3b917a8ae28cb95fa
access-chain.73af73433c0ec757945b852c
access-chain.7594e9deb5091ff76bacd25f
access-chain.787eeaec2d29a9355f2506b5
access-chain.7929f4b79b7fee738fb4ba8a
access-chain.801b77c9ba7678ffe4a842cb
access-chain.8112a24bbefe2c0a5a0706bc
access-chain.815cba04d3891160289be55c
access-chain.8228fa18c87cea883da87db9
access-chain.835c79b0f745c709c3f9319f
access-chain.84b066ff8112c6aa0b0ebe35
access-chain.84e9877ca9504649abc920a8
access-chain.8cdff56c2be92bc3887bd40d
access-chain.92bd866cc6113493add7364a
access-chain.983093257fba950536e43eed
access-chain.985e9973855dd0dd2c65e730
access-chain.98d9d78bf52d0e72a1a11094
access-chain.9ca0b025b6b012170fdb2fee
access-chain.a3a6812cb9ab92c61563e6b7
access-chain.a49a4786cd1b3f028172ecac
access-chain.aa179da2144f661cf24bba16
access-chain.aac48098cfa0284c04eaffd0
access-chain.ad8a66e93f19137ca3736f5b
access-chain.bc8d77b63361bd1be89dfda7
access-chain.c3af826b23ef46f22dd718da
access-chain.ce91bde2cb8ec80630110475
access-chain.d021c20bb34537ba5f603014
access-chain.d3f497ae9ee89169474fd13d
access-chain.da2fd5b8186ad7c5334896a8
access-chain.e146885407e57f2c1a87656c
access-chain.e74b108c9e9d0ed948c9bdf1
access-chain.f2b90b2ab497d84a15ff5c93
access-chain.f43cf151024969065f7b0c4f
access-chain.f6fdc6e2cb6702bb24a1569c
access-chain.fedf4a98adb9ee92d8a1191a
`.trim().split('\n'));

const EXPECTED_LIMITED_COMPLETED = new Map([
  ['access-chain.98d9d78bf52d0e72a1a11094', ['return_mapping_unresolved']],
  ['access-chain.983093257fba950536e43eed', ['constraint_expression_unresolved']],
  ['access-chain.801b77c9ba7678ffe4a842cb', ['return_mapping_unresolved']],
  ['access-chain.4bfde2d33d9581e38429a68f', ['return_mapping_unresolved']],
]);

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function countBy(values) {
  return Object.fromEntries([...values.reduce((map, value) =>
    map.set(String(value), (map.get(String(value)) || 0) + 1), new Map())]
    .sort(([left], [right]) => left.localeCompare(right)));
}

function normalizeOperation(operation) {
  return operation?.replace(/[A-Z]/g, (match) => `-${match.toLowerCase()}`) || null;
}

function normalizedSourcePath(label) {
  return label.project === 'documenso'
    ? label.source.path.replace(/^apps\/docs\//, '') : label.source.path;
}

function locateEntry(document, label) {
  const path = normalizedSourcePath(label);
  if (label.entry.startsWith('ACTION ')) {
    const name = label.entry.slice('ACTION '.length);
    return (document.serverActions || []).find((entry) =>
      entry.name === name && entry.location.path === path) || null;
  }
  const [method, ...pathParts] = label.entry.split(' ');
  const routePath = pathParts.join(' ');
  return document.routes.find((entry) => entry.method === method && entry.path === routePath
    && entry.location.path === path) || null;
}

function chainMatchesFrozenOperation(label, chain) {
  const expected = label.expectedDataOperation;
  if (!label.eligibleForV080 || !expected || chain.status !== 'completed') return false;
  if (chain.dataOperation?.provider !== expected.provider
    || chain.dataOperation?.resource !== expected.resource
    || chain.dataOperation?.operation !== normalizeOperation(expected.operation)) return false;
  const selectorNames = new Set(label.selectorOrigin.field.split(','));
  return chain.objectSelectors.some((selector) => selectorNames.has(selector.name));
}

function summarizeChain(project, entry, chain, frozenLabelId = null) {
  let disposition = 'frozen_expectation_completed';
  if (!frozenLabelId) {
    if (chain.outcome === 'authorization_constraint_observed') {
      disposition = 'additional_constraint_observed_review_path';
    } else if (chain.outcome === 'incomplete') {
      disposition = 'additional_incomplete_authorization_review_path';
    } else {
      disposition = 'additional_constraint_not_observed_review_path';
    }
  }
  return {
    id: chain.id,
    fingerprint: chain.fingerprint,
    project,
    entry: entry.method ? `${entry.method} ${entry.path}` : `ACTION ${entry.name}`,
    location: structuredClone(entry.location),
    provider: chain.dataOperation.provider,
    resource: chain.dataOperation.resource,
    operation: chain.dataOperation.operation,
    operationLocation: structuredClone(chain.dataOperation.location),
    outcome: chain.outcome,
    identityProvider: chain.identity.provider,
    selectors: chain.objectSelectors.map((selector) => ({
      kind: selector.kind, name: selector.name, origin: selector.origin,
    })),
    callEdges: chain.callEdges.map((edge) => ({ kind: edge.kind, from: edge.from, to: edge.to })),
    authorizationEvidence: chain.authorizationEvidence.map((evidence) => ({
      kind: evidence.kind, category: evidence.category, state: evidence.state,
      field: evidence.field,
    })),
    limitations: [...chain.limitations],
    frozenLabelId,
    disposition,
    reviewBoundary: chain.outcome === 'authorization_constraint_observed'
      ? 'Supported static authorization evidence was observed; runtime enforcement, denial and exploitability remain unproved.'
      : chain.outcome === 'incomplete'
        ? 'The operation path completed, while authorization evidence remained incomplete; manual review is required.'
        : 'The operation path completed without a supported authorization constraint; this is a review lead, not a vulnerability verdict.',
  };
}

function projectArtifacts(spec, reportsRoot) {
  const directory = join(reportsRoot, `${spec.id}-p11-fa21f3e`);
  const reportBytes = readFileSync(join(directory, 'report.json'));
  const routeBytes = readFileSync(join(directory, 'route-security.json'));
  const markdownBytes = readFileSync(join(directory, 'route-security.md'));
  const document = JSON.parse(routeBytes);
  return { directory, reportBytes, routeBytes, markdownBytes, document };
}

function statusCounts(chains) {
  return countBy(chains.map((chain) => chain.status));
}

export function buildV080AccessReview(reportsRoot) {
  const evaluationBytes = readFileSync(EVALUATION_PATH);
  const evaluation = JSON.parse(evaluationBytes);
  if (sha256(evaluationBytes) !== V080_LEDGER_FILE_SHA256
    || evaluation.ledgerSha256 !== V080_LEDGER_SHA256) {
    throw new Error('v0.8.0 frozen evaluation ledger semantic or file digest changed');
  }

  const documents = new Map();
  const projects = PROJECTS.map((spec) => {
    const artifacts = projectArtifacts(spec, reportsRoot);
    if (sha256(artifacts.reportBytes) !== spec.reportSha256
      || sha256(artifacts.routeBytes) !== spec.routeReportSha256
      || sha256(artifacts.markdownBytes) !== spec.routeMarkdownSha256
      || routeSemanticDigest(artifacts.document) !== spec.routeSemanticSha256) {
      throw new Error(`${spec.id} report bytes do not match the fixed fa21f3e reproduction`);
    }
    documents.set(spec.id, artifacts.document);
    const entries = [...artifacts.document.routes, ...(artifacts.document.serverActions || [])];
    const chains = entries.flatMap((entry) => entry.accessChains || []);
    const completed = chains.filter((chain) => chain.status === 'completed');
    return {
      id: spec.id,
      repository: spec.repository,
      sourceCommit: spec.commit,
      license: spec.license,
      target: spec.target,
      toolCommit: V080_TOOL_COMMIT,
      command: `SOURCE_DATE_EPOCH=0 node {tool}/scripts/webapp-security.mjs audit ${spec.target} --out {output}/${spec.id}-p11-fa21f3e --fail-on never`,
      expectedExit: 3,
      artifacts: {
        reportJsonSha256: spec.reportSha256,
        routeJsonSha256: spec.routeReportSha256,
        routeMarkdownSha256: spec.routeMarkdownSha256,
        routeSemanticSha256: spec.routeSemanticSha256,
      },
      inventory: {
        routes: artifacts.document.routes.length,
        serverActions: artifacts.document.serverActions?.length || 0,
        accessChains: chains.length,
        byStatus: statusCounts(chains),
        duplicateCompletedChainIds: completed.length - new Set(completed.map((chain) => chain.id)).size,
      },
      performance: {
        baselineVersion: '0.7.3',
        baselineMedianSeconds: spec.baselineMedianSeconds,
        candidateMedianSeconds: spec.candidateMedianSeconds,
        ratio: Number((spec.candidateMedianSeconds / spec.baselineMedianSeconds).toFixed(2)),
        boundary: 'Three local timed runs after one warm-up on the same machine; informational, not a cross-machine benchmark.',
      },
    };
  });

  const matchedChainIds = new Set();
  const dispositions = evaluation.entries.map((label) => {
    const entry = locateEntry(documents.get(label.project), label);
    if (!entry) throw new Error(`${label.id} entry was not found in the fixed report`);
    const chains = entry.accessChains || [];
    const matched = chains.find((chain) => chainMatchesFrozenOperation(label, chain)) || null;
    if (matched) matchedChainIds.add(matched.id);
    let result;
    if (label.eligibleForV080) result = matched ? 'completed_as_expected' : 'partial_retained';
    else result = label.expectedStatus === 'not_applicable'
      ? 'not_scored_by_design' : 'excluded_boundary_retained';
    return {
      id: label.id,
      project: label.project,
      entry: label.entry,
      source: structuredClone(label.source),
      eligibleForV080: label.eligibleForV080,
      expectedStatus: label.expectedStatus,
      observedChainStatuses: statusCounts(chains),
      result,
      matchedChainId: matched?.id || null,
      matchedOutcome: matched?.outcome || null,
      matchedCallEdges: matched?.callEdges.length ?? null,
      expectedCallEdges: label.expectedEdgeCount,
      incompleteReasons: [...new Set(chains.filter((chain) => chain.status === 'partial')
        .map((chain) => chain.reason).filter(Boolean))].sort(),
      boundary: label.eligibleForV080
        ? matched
          ? 'The expected selector reached the expected supported provider/resource/operation. Completion does not prove authorization correctness.'
          : 'The frozen expectation remains partial; its label and denominator were not changed.'
        : label.exclusion?.boundary || 'This entry remains outside the frozen v0.8.0 completion score.',
    };
  });

  const completedChainReview = [];
  for (const [project, document] of documents) {
    for (const entry of [...document.routes, ...(document.serverActions || [])]) {
      for (const chain of entry.accessChains || []) {
        if (chain.status !== 'completed') continue;
        const frozen = dispositions.find((item) => item.matchedChainId === chain.id);
        completedChainReview.push(summarizeChain(project, entry, chain, frozen?.id || null));
      }
    }
  }
  completedChainReview.sort((left, right) => left.id.localeCompare(right.id));

  const aggregate = {
    projects: projects.length,
    routes: projects.reduce((sum, project) => sum + project.inventory.routes, 0),
    serverActions: projects.reduce((sum, project) => sum + project.inventory.serverActions, 0),
    frozenEntries: dispositions.length,
    eligibleEntries: dispositions.filter((item) => item.eligibleForV080).length,
    completedEligibleEntries: dispositions.filter((item) =>
      item.result === 'completed_as_expected').length,
    partialEligibleEntries: dispositions.filter((item) => item.result === 'partial_retained').length,
    completionRate: Number((matchedChainIds.size
      / dispositions.filter((item) => item.eligibleForV080).length).toFixed(4)),
    completedChains: completedChainReview.length,
    frozenMatchedCompletedChains: matchedChainIds.size,
    additionalCompletedChains: completedChainReview.length - matchedChainIds.size,
    completedWithLimitations: completedChainReview.filter((chain) => chain.limitations.length).length,
  };

  return {
    schemaVersion: 1,
    release: '0.8.0',
    reviewedOn: '2026-08-30',
    evidenceType: 'fixed_commit_bounded_access_control_review',
    methodology: {
      execution: 'Repositories were read at fixed commits. Project dependencies and applications were not executed.',
      scoring: 'Only the 14 labels frozen before implementation are scored. Additional completed chains are listed separately and do not change the denominator.',
      completionBoundary: 'Completed means one exact bounded static path reached a supported operation. It does not mean secure, vulnerable, reachable, deployed or correctly enforced.',
      metricBoundary: 'This is not a production precision, recall, exploitability or whole-repository coverage measurement.',
      reviewBoundary: 'All 63 completed chain identities were manually classified. Unsupported or ambiguous paths remain partial or outside the score.',
    },
    evaluation: {
      path: 'docs/reviews/v0.8.0-access-control-evaluation.json',
      sha256: V080_LEDGER_SHA256,
      fileSha256: V080_LEDGER_FILE_SHA256,
      denominator: 14,
      minimumByRate: 10,
      groundedPathFloor: 6,
    },
    aggregate,
    distributions: {
      byProvider: countBy(completedChainReview.map((chain) => chain.provider)),
      byProject: countBy(completedChainReview.map((chain) => chain.project)),
      bySelectorKind: countBy(completedChainReview.flatMap((chain) =>
        [...new Set(chain.selectors.map((selector) => selector.kind))])),
      byCallDepth: countBy(completedChainReview.map((chain) => chain.callEdges.length)),
      byOutcome: countBy(completedChainReview.map((chain) => chain.outcome)),
      byIdentityProvider: countBy(completedChainReview.map((chain) =>
        chain.identityProvider || 'none')),
      byDisposition: countBy(completedChainReview.map((chain) => chain.disposition)),
      byLimitation: countBy(completedChainReview.flatMap((chain) => chain.limitations)),
    },
    projects,
    dispositions,
    completedChainReview,
    promotion: {
      gate: 'passed',
      prisma: {
        status: 'stable_bounded', eligible: 8, completed: 7,
        boundary: 'Exact ordinary-project Prisma paths are supported only through proven client identity and bounded static relationships; one frozen membership path remains partial.',
      },
      drizzle: {
        status: 'stable_bounded', eligible: 6, completed: 6,
        boundary: 'Exact ordinary-project Drizzle paths retain query and post-load evidence boundaries; completion is not an authorization verdict.',
      },
      identityProviders: {
        status: 'unchanged',
        boundary: 'Auth.js and Nest Passport retain their prior stable-bounded status. Clerk, Better Auth and Supabase remain experimental.',
      },
      performance: {
        status: 'passed', maxObservedRatio: 1.41, stopRatio: 2,
        boundary: 'The failed Documenso apps/web experiment is excluded because the frozen target is apps/docs.',
      },
    },
    residualLimits: [
      'v080-eval-26 ACTION getMembershipRole remains partial with argument_mapping_ambiguous and call_target_unresolved.',
      'Four completed operation paths retain supporting limitations; those limitations do not establish authorization identity, denial or safety.',
      'Fifty completed chains were outside the frozen labels. They are review leads and are not added to the 13/14 score.',
      'Dynamic dispatch, unsupported wrappers, deeper-than-four paths, raw SQL, unsupported ORMs and external policy remain outside stable completion.',
    ],
  };
}

export function validateV080AccessReview(review) {
  const errors = [];
  const completedIds = new Set((review?.completedChainReview || []).map((chain) => chain.id));
  if (review?.evaluation?.sha256 !== V080_LEDGER_SHA256) errors.push('frozen ledger digest mismatch');
  if (review?.aggregate?.frozenEntries !== 32) errors.push('frozen label count mismatch');
  if (review?.aggregate?.eligibleEntries !== 14) errors.push('eligible denominator mismatch');
  if (review?.aggregate?.completedEligibleEntries !== 13
    || review?.aggregate?.partialEligibleEntries !== 1) errors.push('13/14 outcome mismatch');
  if (review?.aggregate?.completionRate !== 0.9286) errors.push('completion rate mismatch');
  if (review?.aggregate?.completedChains !== 63
    || review?.aggregate?.additionalCompletedChains !== 50) errors.push('completed-chain count mismatch');
  if (review?.aggregate?.completedWithLimitations !== 4) errors.push('limited completion count mismatch');
  if (completedIds.size !== 63) errors.push('completed chain IDs are not unique');
  if ([...EXPECTED_COMPLETED_CHAIN_IDS].some((id) => !completedIds.has(id))
    || [...completedIds].some((id) => !EXPECTED_COMPLETED_CHAIN_IDS.has(id))) {
    errors.push('manually reviewed completed-chain identity changed');
  }
  for (const [id, limitations] of EXPECTED_LIMITED_COMPLETED) {
    const record = review.completedChainReview.find((chain) => chain.id === id);
    if (JSON.stringify(record?.limitations) !== JSON.stringify(limitations)) {
      errors.push(`${id} limitation boundary changed`);
    }
  }
  if (review?.dispositions?.length !== 32
    || new Set(review.dispositions.map((item) => item.id)).size !== 32) {
    errors.push('every frozen label must have one disposition');
  }
  const miss = review?.dispositions?.find((item) => item.id === 'v080-eval-26');
  if (miss?.result !== 'partial_retained'
    || JSON.stringify(miss.incompleteReasons) !== JSON.stringify([
      'argument_mapping_ambiguous', 'call_target_unresolved',
    ])) errors.push('frozen miss boundary changed');
  if (review?.promotion?.prisma?.completed !== 7 || review?.promotion?.drizzle?.completed !== 6) {
    errors.push('provider promotion evidence mismatch');
  }
  if (Math.max(...(review?.projects || []).map((project) => project.performance.ratio)) > 2) {
    errors.push('performance stop ratio exceeded');
  }
  if ((review?.projects || []).some((project) =>
    !/^[0-9a-f]{40}$/.test(project.sourceCommit)
      || project.toolCommit !== V080_TOOL_COMMIT
      || project.inventory.duplicateCompletedChainIds !== 0)) {
    errors.push('project provenance or chain identity mismatch');
  }
  return errors;
}

function reviewMarkdown(review) {
  const lines = [
    '# v0.8.0 bounded access-control review', '',
    '> Fixed-commit ordinary-source review. Completed is a bounded static path status, not a security verdict or production accuracy claim.', '',
    '## Result', '',
    `- Frozen eligible paths: ${review.aggregate.eligibleEntries}`,
    `- Completed frozen paths: ${review.aggregate.completedEligibleEntries}`,
    `- Retained partial paths: ${review.aggregate.partialEligibleEntries}`,
    `- Completion: ${(review.aggregate.completionRate * 100).toFixed(2)}% (gate: ${review.evaluation.minimumByRate}/${review.evaluation.denominator})`,
    `- Completed operation paths reviewed: ${review.aggregate.completedChains}`,
    `- Additional completed review paths outside the score: ${review.aggregate.additionalCompletedChains}`,
    `- Completed paths with supporting limitations: ${review.aggregate.completedWithLimitations}`, '',
    '## Provider decision', '',
    `- Drizzle: ${review.promotion.drizzle.completed}/${review.promotion.drizzle.eligible}, \`${review.promotion.drizzle.status}\`.`,
    `- Prisma: ${review.promotion.prisma.completed}/${review.promotion.prisma.eligible}, \`${review.promotion.prisma.status}\`.`,
    `- Performance: maximum ${review.promotion.performance.maxObservedRatio}x against a ${review.promotion.performance.stopRatio}x stop threshold.`, '',
    '## Frozen dispositions', '',
    '| ID | Project | Entry | Expected | Observed | Result | Matched chain |',
    '|---|---|---|---|---|---|---|',
    ...review.dispositions.map((item) => `| ${item.id} | ${item.project} | \`${item.entry.replaceAll('|', '\\|')}\` | \`${item.expectedStatus}\` | ${Object.entries(item.observedChainStatuses).map(([status, count]) => `${status}=${count}`).join(', ') || 'no chain'} | \`${item.result}\` | ${item.matchedChainId ? `\`${item.matchedChainId}\`` : '-'} |`),
    '', '## Completed-chain review', '',
    '| Chain | Project | Entry | Provider operation | Outcome | Depth | Disposition | Limitations |',
    '|---|---|---|---|---|---:|---|---|',
    ...review.completedChainReview.map((chain) => `| \`${chain.id}\` | ${chain.project} | \`${chain.entry.replaceAll('|', '\\|')}\` | \`${chain.provider}.${chain.resource}.${chain.operation}\` | \`${chain.outcome}\` | ${chain.callEdges.length} | \`${chain.disposition}\` | ${chain.limitations.length ? chain.limitations.map((item) => `\`${item}\``).join(', ') : '-'} |`),
    '', '## Boundaries', '',
    ...review.residualLimits.map((limit) => `- ${limit}`), '',
    'The four source repositories were read at fixed commits. Their dependencies and applications were not executed.',
  ];
  return `${lines.join('\n')}\n`;
}

function provenanceFor(reviewBytes, reviewMarkdownBytes, review) {
  return {
    schemaVersion: 1,
    release: '0.8.0',
    evidenceType: 'bounded_access_control_review_provenance',
    source: {
      toolCommit: V080_TOOL_COMMIT,
      evaluationLedgerSha256: V080_LEDGER_SHA256,
      evaluationLedgerFileSha256: V080_LEDGER_FILE_SHA256,
      targets: Object.fromEntries(review.projects.map((project) =>
        [project.id, project.sourceCommit])),
    },
    artifacts: {
      'docs/reviews/v0.8.0-access-control-review.json': { sha256: sha256(reviewBytes) },
      'docs/reviews/v0.8.0-access-control-review.md': { sha256: sha256(reviewMarkdownBytes) },
      routeReports: Object.fromEntries(review.projects.map((project) => [project.id, project.artifacts])),
      completedChainReviewSha256: sha256(JSON.stringify(review.completedChainReview)),
      frozenDispositionSha256: sha256(JSON.stringify(review.dispositions)),
    },
    reproduction: {
      reportCommand: 'SOURCE_DATE_EPOCH=0 node {tool}/scripts/webapp-security.mjs audit {target} --out {output} --fail-on never',
      generationCommand: 'node scripts/generate-v080-access-review.mjs --reports {fixed-report-root}',
      checkCommand: 'node scripts/generate-v080-access-review.mjs --check',
      rawRetention: 'Raw report directories are private temporary evaluation inputs and are not distributed in the repository or npm package.',
      semanticBoundary: 'Route semantic digests omit generatedAt, ephemeral subject identity, baseline and mode. Raw hashes bind the exact fa21f3e reproduction bytes.',
    },
  };
}

function provenanceMarkdown(provenance) {
  return `# v0.8.0 access-control review provenance\n\n`
    + `- Tool commit: \`${provenance.source.toolCommit}\`\n`
    + `- Frozen evaluation SHA-256: \`${provenance.source.evaluationLedgerSha256}\`\n`
    + `- Frozen evaluation file SHA-256: \`${provenance.source.evaluationLedgerFileSha256}\`\n`
    + `- Review JSON SHA-256: \`${provenance.artifacts['docs/reviews/v0.8.0-access-control-review.json'].sha256}\`\n`
    + `- Review Markdown SHA-256: \`${provenance.artifacts['docs/reviews/v0.8.0-access-control-review.md'].sha256}\`\n`
    + `- Completed-chain review SHA-256: \`${provenance.artifacts.completedChainReviewSha256}\`\n`
    + `- Frozen-disposition SHA-256: \`${provenance.artifacts.frozenDispositionSha256}\`\n\n`
    + `Raw report directories are temporary private inputs. The committed review contains bounded metadata and digests, not source snippets or runtime values.\n`;
}

export function runV080RealWorldRegression() {
  const files = [
    { path: 'apps/web/action.ts', text: `
import { prisma } from '@formbricks/database';
export async function getWorkspace(workspaceId) {
  return prisma.workspace.findUnique({ where: { id: workspaceId } });
}
` },
    { path: 'packages/database/src/index.ts', text: "export * from './client';" },
    { path: 'packages/database/src/client.ts', text: `
import { PrismaClient } from './prisma';
const prismaClientSingleton = () => new PrismaClient();
const globalForPrisma = globalThis;
export const prisma = globalForPrisma.prisma ?? prismaClientSingleton();
` },
    { path: 'packages/database/src/prisma.ts', text: `
import { PrismaClient as GeneratedPrismaClient } from '../generated/prisma/client';
import type { PrismaClient as GeneratedPrismaClientType } from '../generated/prisma/client';
export const PrismaClient = GeneratedPrismaClient;
export type PrismaClient = GeneratedPrismaClientType;
` },
  ];
  const options = {
    packageManifests: [{ path: 'packages/database/package.json', manifest: {
      name: '@formbricks/database', exports: { '.': {
        types: './dist/index.d.ts', import: './dist/index.js', require: './dist/index.cjs',
      } },
    } }],
    configFiles: [{ path: 'packages/database/vite.config.ts', text: `
import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';
export default defineConfig(async () => ({ build: { rollupOptions: {
  input: { index: resolve(__dirname, 'src/index.ts') },
  output: [{ entryFileNames: '[name].js' }, { entryFileNames: '[name].cjs' }],
} } }));
` }],
    providerFiles: [{ path: 'packages/database/schema/main.prisma', text: `
generator client {
  provider = "prisma-client"
  output = "../generated/prisma"
}
` }],
  };
  const graph = buildJsTsModuleGraph(files, options);
  const module = graph.modules.get('apps/web/action.ts');
  let handler = null;
  walkJsTsAst(module.ast, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name === 'getWorkspace') handler = node;
  });
  const result = analyzeDataOperations(graph, module, handler, {
    objectAliases: new Set(['workspaceId']), principalAliases: new Set(),
  });
  return {
    schemaVersion: 1,
    release: '0.8.0',
    id: 'formbricks-vite-prisma-facade',
    source: {
      repository: 'formbricks/formbricks',
      commit: 'b66c1dd978af618a0e402bd3343b456bed68594c',
      paths: [
        'packages/database/package.json', 'packages/database/vite.config.ts',
        'packages/database/schema/main.prisma', 'packages/database/src/index.ts',
        'packages/database/src/client.ts', 'packages/database/src/prisma.ts',
      ],
    },
    observedFailure: 'A workspace export targeting unbuilt dist files and a Prisma 7 generated-client facade left every frozen ordinary Prisma path unresolved.',
    protectedContract: 'One exact Vite Rollup input may map a built export to source, and one exact Prisma generator/output/facade/constructor chain may establish client identity.',
    boundary: 'The minimized fixture preserves structural relationships, not full project source. Names alone, type-only imports, ambiguous build inputs and missing generator evidence remain insufficient.',
    result: {
      operations: result.operations.map((operation) => ({
        provider: operation.provider,
        resource: operation.resource,
        operation: operation.operation,
        objectConstraint: operation.objectConstraint,
      })),
      limitations: result.limitations || [],
      passed: result.operations.length === 1 && result.operations[0].provider === 'prisma'
        && result.operations[0].resource === 'workspace'
        && result.operations[0].operation === 'find-unique'
        && result.operations[0].objectConstraint === 'observed',
    },
    regressionTest: 'test/v080-access-control-real-world-regression.test.mjs',
  };
}

function regressionMarkdown(regression) {
  return `# v0.8.0 real-world access-control regression\n\n`
    + `- Case: \`${regression.id}\`\n`
    + `- Source: ${regression.source.repository}@\`${regression.source.commit}\`\n`
    + `- Result: \`${regression.result.passed ? 'passed' : 'failed'}\`\n\n`
    + `## Observed failure\n\n${regression.observedFailure}\n\n`
    + `## Protected contract\n\n${regression.protectedContract}\n\n`
    + `## Boundary\n\n${regression.boundary}\n`;
}

function readPersistedReview() {
  return JSON.parse(readFileSync(REVIEW_JSON));
}

function outputsFor(review) {
  const reviewJson = `${JSON.stringify(review, null, 2)}\n`;
  const reviewMd = reviewMarkdown(review);
  const provenance = provenanceFor(reviewJson, reviewMd, review);
  const regression = runV080RealWorldRegression();
  return [
    [REVIEW_JSON, reviewJson],
    [REVIEW_MD, reviewMd],
    [PROVENANCE_JSON, `${JSON.stringify(provenance, null, 2)}\n`],
    [PROVENANCE_MD, provenanceMarkdown(provenance)],
    [REGRESSION_JSON, `${JSON.stringify(regression, null, 2)}\n`],
    [REGRESSION_MD, regressionMarkdown(regression)],
  ];
}

export function main(argv = process.argv.slice(2)) {
  const check = argv.includes('--check');
  const reportsIndex = argv.indexOf('--reports');
  if (argv.some((arg, index) => !['--check', '--reports'].includes(arg)
    && index !== reportsIndex + 1) || (reportsIndex !== -1 && !argv[reportsIndex + 1])) {
    throw new Error('usage: node scripts/generate-v080-access-review.mjs [--check | --reports <root>]');
  }
  const review = reportsIndex === -1 ? readPersistedReview()
    : buildV080AccessReview(argv[reportsIndex + 1]);
  const errors = validateV080AccessReview(review);
  if (errors.length) throw new Error(`v0.8.0 access review invalid:\n- ${errors.join('\n- ')}`);
  const outputs = outputsFor(review);
  if (check) {
    const stale = outputs.filter(([path, content]) =>
      !existsSync(path) || readFileSync(path, 'utf8') !== content);
    if (stale.length) throw new Error(`v0.8.0 access review stale: ${stale.map(([path]) => basename(path)).join(', ')}`);
    console.log('v0.8.0 access review current: 13/14 frozen paths, 63 completed chains, 50 additional review paths');
    return;
  }
  if (reportsIndex === -1) throw new Error('--reports <root> is required to regenerate review evidence');
  mkdirSync(join(ROOT, 'docs/reviews'), { recursive: true });
  mkdirSync(join(ROOT, 'docs/regressions'), { recursive: true });
  for (const [path, content] of outputs) writeFileSync(path, content);
  console.log(outputs.map(([path]) => path).join('\n'));
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
