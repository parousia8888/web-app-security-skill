#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const check = process.argv.includes('--check');
if (process.argv.slice(2).some((argument) => argument !== '--check')) {
  console.error('usage: node scripts/generate-v070-access-review.mjs [--check]');
  process.exit(2);
}

const observations = [
  ['nestjs-boilerplate', 'POST /auth/email/login', 'src/auth/auth.controller.ts:39',
    'expected_public', 'No route-scoped control observed; appropriate for a login entry but still owner-classified.'],
  ['nestjs-boilerplate', 'POST /auth/email/register', 'src/auth/auth.controller.ts:51',
    'expected_public', 'No route-scoped control observed; appropriate for registration.'],
  ['nestjs-boilerplate', 'POST /auth/logout', 'src/auth/auth.controller.ts:125',
    'supported_control', 'Route-scoped Passport authentication was observed; no authorization claim was made.'],
  ['nestjs-boilerplate', 'GET /auth/me', 'src/auth/auth.controller.ts:90',
    'supported_control', 'Route-scoped Passport authentication was observed.'],
  ['nestjs-boilerplate', 'DELETE /auth/me', 'src/auth/auth.controller.ts:154',
    'supported_control', 'State-changing route has route-scoped authentication evidence.'],
  ['nestjs-boilerplate', 'GET /files/:path', 'src/files/infrastructure/uploader/local/files.controller.ts:58',
    'review_lead', 'No route-scoped control was observed; path policy and intended public access require review.'],
  ['nestjs-boilerplate', 'DELETE /users/:id', 'src/users/users.controller.ts:129',
    'correct_bounded_stop', 'Inherited authentication and an authorization candidate were separated; the chain stopped before a second local call.'],
  ['nestjs-boilerplate', 'GET /users/:id', 'src/users/users.controller.ts:92',
    'correct_bounded_stop', 'The route was object-addressed and the one-hop chain stopped explicitly at the service boundary.'],

  ['vercel-chatbot', 'POST /api/chat', 'app/(chat)/api/chat/route.ts:70',
    'known_miss', 'Local Auth.js use is visible in source, but route control remains unclassified and body-selected IDs are outside this release.'],
  ['vercel-chatbot', 'DELETE /api/chat', 'app/(chat)/api/chat/route.ts:447',
    'known_miss', 'Local Auth.js use is visible, but query-selected IDs do not enter the v0.7.0 chain selector.'],
  ['vercel-chatbot', 'GET /api/document', 'app/(chat)/api/document/route.ts:19',
    'known_miss', 'The handler performs an owner comparison, but query-selected document IDs are outside the route-parameter selector.'],
  ['vercel-chatbot', 'POST /api/document', 'app/(chat)/api/document/route.ts:51',
    'known_miss', 'The handler performs ownership checks; no chain is emitted because the ID comes from query state.'],
  ['vercel-chatbot', 'DELETE /api/document', 'app/(chat)/api/document/route.ts:110',
    'known_miss', 'The handler performs ownership checks; no chain is emitted because the ID comes from query state.'],
  ['vercel-chatbot', 'GET /api/vote', 'app/(chat)/api/vote/route.ts:12',
    'known_miss', 'Auth.js and an explicit owner comparison are visible, but the query-selected chat ID is not modeled.'],
  ['vercel-chatbot', 'PATCH /api/vote', 'app/(chat)/api/vote/route.ts:44',
    'known_miss', 'Auth.js and an explicit owner comparison are visible, but the body-selected chat ID is not modeled.'],
  ['vercel-chatbot', 'ACTION updateChatVisibility', 'app/(chat)/actions.ts:64',
    'supported_identity', 'Exact local Auth.js identity evidence is observed; no object chain is emitted for the unsupported argument shape.'],

  ['formbricks', 'GET /legacy-organization-settings/[workspaceId]/[[...path]]',
    'apps/web/app/(redirects)/legacy-organization-settings/[workspaceId]/[[...path]]/route.ts:8',
    'correct_bounded_stop', 'The alias-resolved local call is visible, but the exported wrapper cannot be reduced to one supported operation.'],
  ['formbricks', 'POST /api/internal/feedback-datasets/[datasetId]/purge',
    'apps/web/app/api/internal/feedback-datasets/[datasetId]/purge/route.ts:15',
    'known_miss', 'The route is inventoried, but wrapper-based controls and deeper service calls remain outside the bounded chain.'],
  ['formbricks', 'DELETE /api/v1/management/action-classes/[actionClassId]',
    'apps/web/app/api/v1/management/action-classes/[actionClassId]/route.ts:146',
    'known_miss', 'The object route is inventoried; re-exported wrappers prevent a complete handler chain.'],
  ['formbricks', 'GET /api/v1/management/responses/[responseId]',
    'apps/web/app/api/v1/management/responses/[responseId]/route.ts:48',
    'known_miss', 'The object route is inventoried; handler-wrapper resolution is incomplete.'],
  ['formbricks', 'GET /api/v1/management/surveys/[surveyId]',
    'apps/web/app/api/v1/management/surveys/[surveyId]/route.ts:52',
    'known_miss', 'The object route is inventoried; handler-wrapper resolution is incomplete.'],
  ['formbricks', 'DELETE /api/v1/webhooks/[webhookId]',
    'apps/web/app/api/v1/webhooks/[webhookId]/route.ts:36',
    'known_miss', 'The object route is inventoried; no supported one-hop data operation was established.'],
  ['formbricks', 'POST /api/v2/client/[workspaceId]/responses',
    'apps/web/app/api/v2/client/[workspaceId]/responses/route.ts:201',
    'review_lead', 'No route-scoped control was observed; public client semantics require owner classification.'],
  ['formbricks', 'POST /api/v3/surveys/[surveyId]/archive',
    'apps/web/app/api/v3/surveys/[surveyId]/archive/route.ts:10',
    'known_miss', 'The state-changing object route is inventoried; wrapper and deeper-call evidence remain incomplete.'],
  ['formbricks', 'ACTION getMembershipByUserIdOrganizationIdAction',
    'apps/web/lib/membership/hooks/actions.ts:8',
    'correct_bounded_stop', 'Alias resolution exposes two local-call candidates; both stop without inventing a completed data chain.'],
  ['formbricks', 'ACTION getMembershipRole', 'apps/web/lib/membership/hooks/actions.ts:20',
    'correct_bounded_stop', 'One exact local call is followed, then analysis stops before the next local call.'],
  ['formbricks', 'ACTION logSignOutAction', 'apps/web/modules/auth/actions/sign-out.ts:12',
    'correct_bounded_stop', 'The first local call is resolved and the second edge is left incomplete.'],
  ['formbricks', 'ACTION checkRoleManagementPermission',
    'apps/web/modules/ee/role-management/actions.ts:26',
    'correct_bounded_stop', 'Alias resolution adds bounded call evidence without upgrading it to authorization proof.'],

  ['documenso', 'GET /llms-full.txt', 'apps/docs/src/app/llms-full.txt/route.ts:5',
    'expected_public', 'Public documentation route; no route-scoped authentication is expected.'],
  ['documenso', 'GET /llms.txt', 'apps/docs/src/app/llms.txt/route.ts:5',
    'expected_public', 'Public documentation route; no route-scoped authentication is expected.'],
  ['documenso', 'GET /llms.mdx/docs/[[...slug]]', 'apps/docs/src/app/llms.mdx/docs/[[...slug]]/route.ts:7',
    'expected_public', 'Public documentation route; the dynamic slug is not treated as an authorization object ID.'],
  ['documenso', 'GET /og/docs/[...slug]', 'apps/docs/src/app/og/docs/[...slug]/route.tsx:27',
    'expected_public', 'Public image route; no route-scoped authentication is expected.'],
].map(([project, entry, source, assessment, note]) => ({ project, entry, source, assessment, note }));

const projects = [
  ['nestjs-boilerplate', 'brocoders/nestjs-boilerplate', '9620f159eefe38f47747d02ab162852367c5472c',
    'MIT', 24, 0, 'completed', 3, 0],
  ['vercel-chatbot', 'vercel/chatbot', 'c2f8235e1f3ea903ad8b7f61447c4f74164b5c58',
    'Apache-2.0', 15, 7, 'partial', 0, 0],
  ['formbricks', 'formbricks/formbricks', 'b66c1dd978af618a0e402bd3343b456bed68594c',
    'AGPL-3.0', 130, 16, 'partial', 9, 0],
  ['documenso', 'documenso/documenso', '75330166cc00b29c14399bc2e391e4b4d8080c00',
    'AGPL-3.0', 4, 0, 'partial', 0, 0],
].map(([id, repository, commit, license, routes, serverActions, routeCoverage, partialChains,
  completedChains]) => ({ id, repository, commit, license, routes, serverActions, routeCoverage,
  partialChains, completedChains }));

const review = {
  schemaVersion: 1,
  release: '0.7.0',
  reviewedOn: '2026-08-24',
  methodology: {
    kind: 'fixed-commit ordinary-source review',
    networkBehavior: 'Repositories were cloned at fixed commits; project dependencies and applications were not executed.',
    scoreBoundary: 'This review is not a production precision, recall, reachability or exploitability measurement.',
    reviewCap: 'Four projects and 32 manually inspected entries; no project was added to inflate counts.',
  },
  aggregate: {
    projects: 4, routes: 173, serverActions: 23, manualEntries: observations.length,
    partialChains: 12, completedChains: 0,
  },
  aliasResolutionDelta: {
    project: 'formbricks', beforePartialChains: 3, afterPartialChains: 9,
    completedChains: 0,
    boundary: 'Static alias resolution exposed more exact local calls, but the one-hop limit and unresolved wrappers kept every ordinary-project chain incomplete.',
  },
  projects,
  observations,
  promotion: {
    identity: [
      { family: 'NestJS Passport', status: 'stable_bounded', basis: 'Existing exact package semantics plus ordinary Nest controller review.' },
      { family: 'Auth.js / NextAuth', status: 'stable_bounded', basis: 'Exact factory/export fixtures plus ordinary Vercel Chatbot source review.' },
      { family: 'Clerk', status: 'experimental', basis: 'Exact fixtures and benign neighbours only; no ordinary-project sample in this capped review.' },
      { family: 'Better Auth', status: 'experimental', basis: 'Exact fixtures and benign neighbours only; no ordinary-project sample in this capped review.' },
      { family: 'Supabase identity', status: 'experimental', basis: 'Exact fixtures only; RLS and deployed session behavior remain external.' },
    ],
    data: [
      { family: 'Prisma', status: 'stable_bounded', basis: 'Positive, benign and incomplete fixtures plus ordinary Formbricks query review; no production accuracy claim.' },
      { family: 'Drizzle', status: 'stable_bounded', basis: 'Positive and benign fixtures plus ordinary Vercel Chatbot query review; no production accuracy claim.' },
      { family: 'Supabase Query Builder', status: 'experimental', basis: 'Exact fixtures only; every result retains external_policy_required.' },
    ],
  },
  residualLimits: [
    'Ordinary-project completed chains were 0; fixture conformance is not ordinary-project effectiveness.',
    'Query-string and JSON-body object selectors are outside the v0.7.0 route-chain boundary.',
    'Next.js wrapper and re-export patterns caused 33 unresolved route/action relationships across the reviewed Next.js projects.',
    'Workspace exports that point only to unbuilt dist files are not guessed back to source files.',
    'One-hop analysis stops before a second local call even when a human can continue the chain.',
  ],
};

const regressions = {
  schemaVersion: 1,
  release: '0.7.0',
  cases: [
    {
      id: 'nestjs-global-guard-role-duplication',
      observedFailure: 'A Nest APP_GUARD RateLimitGuard was copied to every route as both authentication and authorization evidence; 72 routes with no route-scoped control were indistinguishable.',
      protectedContract: 'Application guards are listed once, auth and authz signals are separated, and no_route_scoped_control_observed remains a review state.',
      regressionTest: 'test/nest-route-extractor.test.mjs',
    },
    {
      id: 'one-hop-chain-fingerprint-collision',
      observedFailure: 'Different partial one-hop chains initially shared a fingerprint because entry identity and call edges were absent from the fingerprint input.',
      protectedContract: 'Distinct entry and call-edge evidence produces distinct access-chain fingerprints.',
      regressionTest: 'test/access-control-one-hop.test.mjs',
    },
    {
      id: 'next-monorepo-app-root-missed',
      observedFailure: 'A standard apps/web/app tree produced zero Next.js routes.',
      protectedContract: 'Root, src/app, apps/<name>/app and packages/<name>/app route roots are recognized without guessing URLs.',
      regressionTest: 'test/next-app-route-extractor.test.mjs',
    },
    {
      id: 'tsconfig-alias-local-call-missed',
      observedFailure: 'Exact @/* imports stopped local identity and one-hop resolution; Formbricks exposed only 3 partial chains before bounded alias resolution.',
      protectedContract: 'Nearest static tsconfig/jsconfig paths and existing workspace exports resolve exactly; ambiguous, missing and escaping targets fail closed.',
      regressionTest: 'test/js-ts-module-graph.test.mjs',
    },
  ],
};

function validate() {
  const errors = [];
  if (review.aggregate.manualEntries < 30 || review.aggregate.manualEntries > 50) errors.push('manual review count must stay within 30-50');
  if (review.aggregate.projects !== projects.length) errors.push('project aggregate mismatch');
  if (projects.some((project) => !/^[0-9a-f]{40}$/.test(project.commit))) errors.push('every project commit must be immutable');
  if (review.aggregate.completedChains !== 0) errors.push('ordinary completed-chain count must remain honest');
  if (!review.methodology.scoreBoundary.includes('not a production')) errors.push('score boundary is missing');
  if (regressions.cases.length !== 4) errors.push('regression case count mismatch');
  return errors;
}

function markdownReview() {
  const lines = [
    '# v0.7.0 access-control ordinary-source review', '',
    '> Fixed-commit ordinary-source review. This is not a production precision, recall, reachability or exploitability measurement.', '',
    '## Scope', '',
    `- Projects: ${review.aggregate.projects}`,
    `- Routes inventoried: ${review.aggregate.routes}`,
    `- Server Actions inventoried: ${review.aggregate.serverActions}`,
    `- Manually inspected entries: ${review.aggregate.manualEntries}`,
    `- Access chains: ${review.aggregate.partialChains} partial, ${review.aggregate.completedChains} completed`,
    '- Project dependencies and applications were not executed.', '',
    '## Project results', '',
    '| Project | Fixed commit | Routes | Actions | Coverage | Partial chains | Completed chains |',
    '|---|---|---:|---:|---|---:|---:|',
    ...projects.map((project) => `| ${project.repository} | \`${project.commit}\` | ${project.routes} | ${project.serverActions} | ${project.routeCoverage} | ${project.partialChains} | ${project.completedChains} |`),
    '', '## Alias-resolution delta', '',
    `Formbricks changed from ${review.aliasResolutionDelta.beforePartialChains} to ${review.aliasResolutionDelta.afterPartialChains} partial chains and remained at 0 completed chains. ${review.aliasResolutionDelta.boundary}`, '',
    '## Manual observations', '',
    '| Project | Entry | Source | Assessment | Observation |',
    '|---|---|---|---|---|',
    ...observations.map((item) => `| ${item.project} | \`${item.entry}\` | \`${item.source}\` | ${item.assessment} | ${item.note} |`),
    '', '## Promotion decisions', '',
    '### Identity', '',
    ...review.promotion.identity.map((item) => `- **${item.family} - ${item.status}:** ${item.basis}`),
    '', '### Data operations', '',
    ...review.promotion.data.map((item) => `- **${item.family} - ${item.status}:** ${item.basis}`),
    '', '## Residual limits', '', ...review.residualLimits.map((item) => `- ${item}`), '',
  ];
  return `${lines.join('\n')}\n`;
}

function markdownRegressions() {
  return `${[
    '# v0.7.0 access-control real-world regressions', '',
    'These cases preserve reproduced failure classes. They do not claim production vulnerability accuracy.', '',
    ...regressions.cases.flatMap((item) => [
      `## ${item.id}`, '',
      `- Observed failure: ${item.observedFailure}`,
      `- Protected contract: ${item.protectedContract}`,
      `- Regression test: \`${item.regressionTest}\``, '',
    ]),
  ].join('\n')}\n`;
}

const errors = validate();
if (errors.length) {
  console.error(`v0.7.0 access review invalid:\n${errors.map((error) => `- ${error}`).join('\n')}`);
  process.exit(1);
}

const outputs = [
  [join(ROOT, 'docs/reviews/v0.7.0-access-control-review.json'), `${JSON.stringify(review, null, 2)}\n`],
  [join(ROOT, 'docs/reviews/v0.7.0-access-control-review.md'), markdownReview()],
  [join(ROOT, 'docs/regressions/v0.7.0-access-control-real-world-regressions.json'), `${JSON.stringify(regressions, null, 2)}\n`],
  [join(ROOT, 'docs/regressions/v0.7.0-access-control-real-world-regressions.md'), markdownRegressions()],
];

if (check) {
  const stale = outputs.filter(([path, content]) => !existsSync(path) || readFileSync(path, 'utf8') !== content);
  if (stale.length) {
    console.error('v0.7.0 access review is stale; run node scripts/generate-v070-access-review.mjs');
    process.exit(1);
  }
  console.log('v0.7.0 access review current: 4 projects, 32 entries, 12 partial and 0 completed ordinary chains');
} else {
  mkdirSync(join(ROOT, 'docs/reviews'), { recursive: true });
  mkdirSync(join(ROOT, 'docs/regressions'), { recursive: true });
  for (const [path, content] of outputs) writeFileSync(path, content);
  console.log(outputs.map(([path]) => path).join('\n'));
}
