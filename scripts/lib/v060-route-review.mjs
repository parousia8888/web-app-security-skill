const METHOD = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'ALL']);
const CONTROL_CLASSES = new Set([
  'expected-public-no-route-control',
  'opaque-capability-token',
  'supported-authentication-observed',
  'supported-authentication-and-custom-authorization',
  'custom-control-requires-review',
  'not-reviewed-because-missed',
]);
const PRIORITY_ASSESSMENTS = new Set([
  'expected-benign-review', 'useful-review-lead', 'appropriate-later',
  'not-assigned-because-missed',
]);

function observed(routeId, authentication, authorization, priority) {
  return { status: 'detected', routeId, authentication, authorization, priority };
}

function missed() {
  return {
    status: 'missed', routeId: null, authentication: null, authorization: null, priority: null,
  };
}

function item(method, path, sourcePath, line, observation, controlClass, priorityAssessment, note) {
  return {
    expected: { method, path }, source: { path: sourcePath, line }, observed: observation,
    controlClass, priorityAssessment, note,
  };
}

const PROJECTS = [
  {
    id: 'uptime-kuma',
    project: 'Uptime Kuma',
    repository: 'louislam/uptime-kuma',
    commit: '6b5ea0155793e666666745fb8d6fef1e829543a2',
    license: { spdx: 'MIT', path: 'LICENSE' },
    framework: 'express',
    analyzerRun: {
      records: 23,
      coverage: 'partial',
      incompleteReasons: ['express_router_mount_unresolved'],
      sampledOutRecords: 7,
    },
    annotations: [
      item('GET', '/api/entry-page', 'server/routers/api-router.js', 28,
        observed('route.e81ca223087c6a8e0c198679', 'not_observed', 'not_observed', 'review_later'),
        'expected-public-no-route-control', 'appropriate-later',
        'Public entry-page metadata; no route-level login control is expected from this source path.'),
      item('ALL', '/api/push/:pushToken', 'server/routers/api-router.js', 47,
        observed('route.e81c7f7be6c6443194c17528', 'not_observed', 'not_observed', 'review_next'),
        'opaque-capability-token', 'useful-review-lead',
        'The token in the path is the capability boundary. Static route controls do not prove token entropy, disclosure resistance or monitor ownership.'),
      item('GET', '/api/badge/:id/status', 'server/routers/api-router.js', 148,
        observed('route.df319e8dd5783ee0fea664b2', 'candidate_observed', 'candidate_observed', 'review_next'),
        'custom-control-requires-review', 'expected-benign-review',
        'The route checks whether the monitor is public; cache/CORS helpers are not authentication controls.'),
      item('GET', '/api/badge/:id/uptime/:duration?', 'server/routers/api-router.js', 221,
        observed('route.bdfa937316105f5d17c83ecb', 'candidate_observed', 'candidate_observed', 'review_next'),
        'custom-control-requires-review', 'expected-benign-review',
        'Public-monitor filtering is performed in route logic; the custom middleware signal itself does not prove authorization.'),
      item('GET', '/api/badge/:id/ping/:duration?', 'server/routers/api-router.js', 285,
        observed('route.23fa5975b4fc1f53c9739bee', 'candidate_observed', 'candidate_observed', 'review_next'),
        'custom-control-requires-review', 'expected-benign-review',
        'The identifier deserves review, but this endpoint intentionally exposes only public-monitor badge data.'),
      item('GET', '/api/badge/:id/avg-response/:duration?', 'server/routers/api-router.js', 351,
        observed('route.e3fab6e3e92759e19b0f32e2', 'candidate_observed', 'candidate_observed', 'review_next'),
        'custom-control-requires-review', 'expected-benign-review',
        'The review priority is conservative; public-monitor filtering is visible in the handler.'),
      item('GET', '/api/badge/:id/cert-exp', 'server/routers/api-router.js', 424,
        observed('route.ae0f6d9ff8a462a404eb53a8', 'candidate_observed', 'candidate_observed', 'review_next'),
        'custom-control-requires-review', 'expected-benign-review',
        'The public-monitor check is relevant; cache and response helpers remain only candidates.'),
      item('GET', '/api/badge/:id/response', 'server/routers/api-router.js', 507,
        observed('route.8f87eee3a66a07bc390a22aa', 'candidate_observed', 'candidate_observed', 'review_next'),
        'custom-control-requires-review', 'expected-benign-review',
        'The object-shaped path is correctly prioritized, while public-monitor logic makes this an expected benign review.'),
      item('GET', '/status/:slug', 'server/routers/status-page-router.js', 16,
        observed('route.bfc12c8fc7e327ba70f7d403', 'candidate_observed', 'candidate_observed', 'review_later'),
        'expected-public-no-route-control', 'appropriate-later',
        'Status pages are public by product design; cache middleware is not a login control.'),
      item('GET', '/status/:slug/rss', 'server/routers/status-page-router.js', 22,
        observed('route.b36c795c668e09872f7c980b', 'candidate_observed', 'candidate_observed', 'review_later'),
        'expected-public-no-route-control', 'appropriate-later',
        'The public RSS endpoint is expected to be reachable without login.'),
      item('GET', '/status-page', 'server/routers/status-page-router.js', 33,
        observed('route.0f49526261281d52fbd3acd4', 'candidate_observed', 'candidate_observed', 'review_later'),
        'expected-public-no-route-control', 'appropriate-later',
        'The default public status page is correctly left for later review.'),
      item('GET', '/api/status-page/:slug', 'server/routers/status-page-router.js', 39,
        observed('route.b607c2d3de56d79758cf8a5d', 'candidate_observed', 'candidate_observed', 'review_later'),
        'expected-public-no-route-control', 'appropriate-later',
        'The slug selects a published status page rather than a private user object.'),
      item('GET', '/api/status-page/heartbeat/:slug', 'server/routers/status-page-router.js', 64,
        observed('route.e43e58c05513c823fd093d95', 'candidate_observed', 'candidate_observed', 'review_later'),
        'expected-public-no-route-control', 'appropriate-later',
        'The handler filters monitor groups to public records; route-level auth is intentionally absent.'),
      item('GET', '/api/status-page/:slug/manifest.json', 'server/routers/status-page-router.js', 113,
        observed('route.3d865fa340c0c17804ae9a7e', 'candidate_observed', 'candidate_observed', 'review_later'),
        'expected-public-no-route-control', 'appropriate-later',
        'A Web app manifest for a published status page is expected public output.'),
      item('GET', '/api/status-page/:slug/incident-history', 'server/routers/status-page-router.js', 145,
        observed('route.e8229670510a21e830d8bc39', 'candidate_observed', 'candidate_observed', 'review_later'),
        'expected-public-no-route-control', 'appropriate-later',
        'The handler requests public incident history for the selected status page.'),
      item('GET', '/api/status-page/:slug/badge', 'server/routers/status-page-router.js', 170,
        observed('route.bb5e3eaef96ca45ba3eae65d', 'candidate_observed', 'candidate_observed', 'review_later'),
        'expected-public-no-route-control', 'appropriate-later',
        'The badge aggregates monitors explicitly filtered to public groups.'),
      item('GET', '/', 'server/server.js', 264, missed(), 'not-reviewed-because-missed',
        'not-assigned-because-missed', 'A direct app alias created outside the supported factory pattern hid this registration.'),
      item('GET', '/robots.txt', 'server/server.js', 342, missed(), 'not-reviewed-because-missed',
        'not-assigned-because-missed', 'The same unresolved app alias hid this ordinary public route.'),
      item('GET', '/metrics', 'server/server.js', 355, missed(), 'not-reviewed-because-missed',
        'not-assigned-because-missed', 'The missed route has an apiAuth middleware; missing it also loses a useful authentication signal.'),
      item('GET', '/.well-known/change-password', 'server/server.js', 367, missed(),
        'not-reviewed-because-missed', 'not-assigned-because-missed',
        'The same alias boundary hides this redirect route.'),
    ],
    promotion: {
      decision: 'stable-bounded',
      boundary: 'Stable for direct Express app/router factory registrations and statically resolved mounts. Aliased app objects and unresolved mount relationships remain explicit partial coverage.',
    },
  },
  {
    id: 'nestjs-boilerplate',
    project: 'NestJS Boilerplate',
    repository: 'brocoders/nestjs-boilerplate',
    commit: '9620f159eefe38f47747d02ab162852367c5472c',
    license: { spdx: 'MIT', path: 'LICENSE' },
    framework: 'nestjs',
    analyzerRun: { records: 24, coverage: 'completed', incompleteReasons: [], sampledOutRecords: 4 },
    annotations: [
      item('POST', '/auth/apple/login', 'src/auth-apple/auth-apple.controller.ts', 26,
        observed('route.4bc323af293d8ca6effb1747', 'not_observed', 'not_observed', 'review_next'),
        'expected-public-no-route-control', 'expected-benign-review', 'A login initiation endpoint is intentionally public.'),
      item('POST', '/auth/facebook/login', 'src/auth-facebook/auth-facebook.controller.ts', 26,
        observed('route.73388104c63a2302df951e50', 'not_observed', 'not_observed', 'review_next'),
        'expected-public-no-route-control', 'expected-benign-review', 'A login initiation endpoint is intentionally public.'),
      item('POST', '/auth/google/login', 'src/auth-google/auth-google.controller.ts', 26,
        observed('route.4df7364c6dd49b21f60427ad', 'not_observed', 'not_observed', 'review_next'),
        'expected-public-no-route-control', 'expected-benign-review', 'A login initiation endpoint is intentionally public.'),
      item('POST', '/auth/email/login', 'src/auth/auth.controller.ts', 39,
        observed('route.d52c1aec80a4fe49e2d79c3c', 'not_observed', 'not_observed', 'review_next'),
        'expected-public-no-route-control', 'expected-benign-review', 'Login must be reachable before authentication; abuse controls remain a separate review.'),
      item('POST', '/auth/email/register', 'src/auth/auth.controller.ts', 51,
        observed('route.79269f8c0808134990080037', 'not_observed', 'not_observed', 'review_next'),
        'expected-public-no-route-control', 'expected-benign-review', 'Registration is intentionally public; rate limits and account policy are outside route-control mapping.'),
      item('POST', '/auth/email/confirm', 'src/auth/auth.controller.ts', 57,
        observed('route.1098f25f7efc04d70ad4ebcc', 'not_observed', 'not_observed', 'review_next'),
        'expected-public-no-route-control', 'expected-benign-review', 'Confirmation uses a token rather than an existing login session.'),
      item('POST', '/auth/email/confirm/new', 'src/auth/auth.controller.ts', 65,
        observed('route.67ac84ad62ae2e7bf72e958f', 'not_observed', 'not_observed', 'review_next'),
        'expected-public-no-route-control', 'expected-benign-review', 'Resending confirmation is a public auth workflow; abuse controls require contextual review.'),
      item('POST', '/auth/forgot/password', 'src/auth/auth.controller.ts', 73,
        observed('route.670085ff003edc89e8036f63', 'not_observed', 'not_observed', 'review_next'),
        'expected-public-no-route-control', 'expected-benign-review', 'Password recovery is intentionally pre-authentication.'),
      item('POST', '/auth/reset/password', 'src/auth/auth.controller.ts', 81,
        observed('route.c78889dc121b443bb1bb5b87', 'not_observed', 'not_observed', 'review_next'),
        'expected-public-no-route-control', 'expected-benign-review', 'The reset hash is the workflow credential; its validation is not visible as a route guard.'),
      item('GET', '/auth/me', 'src/auth/auth.controller.ts', 90,
        observed('route.a9bcdd7865a8134990080037', 'local_observed', 'not_observed', 'review_later'),
        'supported-authentication-observed', 'appropriate-later', 'Passport authentication is correctly recognized; the endpoint addresses the current subject.'),
      item('POST', '/auth/refresh', 'src/auth/auth.controller.ts', 106,
        observed('route.6a7e179540be1752cc8bc16c', 'local_observed', 'not_observed', 'review_next'),
        'supported-authentication-observed', 'expected-benign-review', 'Authentication is visible; refresh-token rotation and replay handling are outside this mapper.'),
      item('POST', '/auth/logout', 'src/auth/auth.controller.ts', 125,
        observed('route.76359c7dc816f428af487ee9', 'local_observed', 'not_observed', 'review_next'),
        'supported-authentication-observed', 'expected-benign-review', 'The route is session-bound; no separate object authorization is expected.'),
      item('PATCH', '/auth/me', 'src/auth/auth.controller.ts', 137,
        observed('route.76494a5acf9399130e027892', 'local_observed', 'not_observed', 'review_next'),
        'supported-authentication-observed', 'expected-benign-review', 'The operation updates the authenticated subject rather than a path-selected user.'),
      item('DELETE', '/auth/me', 'src/auth/auth.controller.ts', 154,
        observed('route.99938fb6962c5379b8f42f02', 'local_observed', 'not_observed', 'review_next'),
        'supported-authentication-observed', 'expected-benign-review', 'Account deletion remains high-impact, but the source binds it to the authenticated subject.'),
      item('POST', '/files/upload', 'src/files/infrastructure/uploader/local/files.controller.ts', 33,
        observed('route.556ed6443d4823c7cd23a039', 'local_observed', 'not_observed', 'review_next'),
        'supported-authentication-observed', 'useful-review-lead', 'Authentication is visible; upload authorization, type and storage policy need contextual review.'),
      item('POST', '/users', 'src/users/users.controller.ts', 50,
        observed('route.b027fc7a206e142889758e55', 'inherited_observed', 'candidate_observed', 'review_next'),
        'supported-authentication-and-custom-authorization', 'useful-review-lead', 'Passport and a custom RolesGuard are both visible; the custom role policy remains unresolved.'),
      item('GET', '/users', 'src/users/users.controller.ts', 62,
        observed('route.d748d5ec1fca798ba661dfe2', 'inherited_observed', 'candidate_observed', 'review_later'),
        'supported-authentication-and-custom-authorization', 'useful-review-lead', 'The collection route inherits Passport and RolesGuard; runtime role behavior is not proved.'),
      item('GET', '/users/:id', 'src/users/users.controller.ts', 92,
        observed('route.1d2e14af2458c7a35a0b0d43', 'inherited_observed', 'candidate_observed', 'review_next'),
        'supported-authentication-and-custom-authorization', 'useful-review-lead', 'The object-shaped path and unresolved custom role guard are correctly prioritized.'),
      item('PATCH', '/users/:id', 'src/users/users.controller.ts', 109,
        observed('route.909a92e4af6c9fc4303df26d', 'inherited_observed', 'candidate_observed', 'review_next'),
        'supported-authentication-and-custom-authorization', 'useful-review-lead', 'Authentication and a custom guard are visible; service-layer object checks remain unproved.'),
      item('DELETE', '/users/:id', 'src/users/users.controller.ts', 129,
        observed('route.ea7140c1b36144b83dd42751', 'inherited_observed', 'candidate_observed', 'review_next'),
        'supported-authentication-and-custom-authorization', 'useful-review-lead', 'The destructive object route is correctly surfaced for early authorization review.'),
    ],
    promotion: {
      decision: 'stable-bounded',
      boundary: 'Stable for static NestJS controller and method decorators, including static controller option paths, arrays and supported Passport/custom guard signals. Dynamic decorator paths remain path unknown.',
    },
  },
  {
    id: 'vercel-chatbot',
    project: 'Vercel AI Chatbot',
    repository: 'vercel/chatbot',
    commit: 'c2f8235e1f3ea903ad8b7f61447c4f74164b5c58',
    license: { spdx: 'Apache-2.0', path: 'LICENSE' },
    framework: 'next-app',
    analyzerRun: {
      records: 15,
      coverage: 'partial',
      incompleteReasons: ['next_route_handler_export_unresolved'],
      sampledOutRecords: 0,
    },
    annotations: [
      item('GET', '/api/auth/guest', 'app/(auth)/api/auth/guest/route.ts', 6,
        observed('route.ec9f3983fd7553a06d146cb6', 'not_observed', 'not_observed', 'review_later'),
        'expected-public-no-route-control', 'appropriate-later', 'The route creates a guest identity and is intentionally reachable before login.'),
      item('GET', '/api/chat/[id]/stream', 'app/(chat)/api/chat/[id]/stream/route.ts', 1,
        observed('route.988768f478a9d1865120e110', 'not_observed', 'not_observed', 'review_next'),
        'custom-control-requires-review', 'useful-review-lead', 'The object-shaped stream route delegates its checks; no supported local control is visible.'),
      item('POST', '/api/chat', 'app/(chat)/api/chat/route.ts', 70,
        observed('route.e058be486acfa2d8cdbd5002', 'candidate_observed', 'candidate_observed', 'review_next'),
        'custom-control-requires-review', 'useful-review-lead', 'The custom auth helper is visible but requires project-specific validation.'),
      item('DELETE', '/api/chat', 'app/(chat)/api/chat/route.ts', 447,
        observed('route.5e73483ae9f934b84d9ea320', 'candidate_observed', 'candidate_observed', 'review_next'),
        'custom-control-requires-review', 'useful-review-lead', 'Custom session and ownership logic is visible inside the handler but not proved by the mapper.'),
      item('GET', '/api/document', 'app/(chat)/api/document/route.ts', 19,
        observed('route.defda6e45d9a4d52788f28cc', 'candidate_observed', 'candidate_observed', 'review_later'),
        'custom-control-requires-review', 'useful-review-lead', 'The route uses custom session and document-access checks; their correctness remains contextual.'),
      item('POST', '/api/document', 'app/(chat)/api/document/route.ts', 51,
        observed('route.673a72be393b40e1a75b47ec', 'candidate_observed', 'candidate_observed', 'review_next'),
        'custom-control-requires-review', 'useful-review-lead', 'The state-changing document route is correctly prioritized while custom checks remain unresolved.'),
      item('DELETE', '/api/document', 'app/(chat)/api/document/route.ts', 110,
        observed('route.4bb07620138ba070b8fed028', 'candidate_observed', 'candidate_observed', 'review_next'),
        'custom-control-requires-review', 'useful-review-lead', 'Deletion uses custom session and ownership logic that requires project review.'),
      item('POST', '/api/files/upload', 'app/(chat)/api/files/upload/route.ts', 18,
        observed('route.047ab4b983d19b0a916002d9', 'candidate_observed', 'candidate_observed', 'review_next'),
        'custom-control-requires-review', 'useful-review-lead', 'The custom auth helper is visible; upload policy and storage controls remain outside route mapping.'),
      item('GET', '/api/history', 'app/(chat)/api/history/route.ts', 6,
        observed('route.63cc4835909350c0d45317b1', 'candidate_observed', 'candidate_observed', 'review_later'),
        'custom-control-requires-review', 'useful-review-lead', 'Custom session evidence is visible and should be reviewed with data-layer filtering.'),
      item('DELETE', '/api/history', 'app/(chat)/api/history/route.ts', 39,
        observed('route.ae7e00ce0d7f8fdf8b82c90b', 'candidate_observed', 'candidate_observed', 'review_next'),
        'custom-control-requires-review', 'useful-review-lead', 'The destructive route is correctly prioritized; custom authorization remains unresolved.'),
      item('GET', '/api/messages', 'app/(chat)/api/messages/route.ts', 5,
        observed('route.1343f800aabf9aa9a1fbfc5d', 'candidate_observed', 'candidate_observed', 'review_later'),
        'custom-control-requires-review', 'useful-review-lead', 'Message retrieval uses a custom auth helper and delegated data filtering.'),
      item('GET', '/api/models', 'app/(chat)/api/models/route.ts', 3,
        observed('route.4f9bb03f9bba04ab6570947e', 'not_observed', 'not_observed', 'review_later'),
        'expected-public-no-route-control', 'appropriate-later', 'The model catalog is intentionally public in this source version.'),
      item('GET', '/api/suggestions', 'app/(chat)/api/suggestions/route.ts', 5,
        observed('route.56ba6326b3a6d8aef7d7f0c4', 'candidate_observed', 'candidate_observed', 'review_later'),
        'custom-control-requires-review', 'useful-review-lead', 'Custom session and document access checks require project-context review.'),
      item('GET', '/api/vote', 'app/(chat)/api/vote/route.ts', 12,
        observed('route.d1356cc79683f94134bfe4e0', 'candidate_observed', 'candidate_observed', 'review_later'),
        'custom-control-requires-review', 'useful-review-lead', 'The custom auth helper is visible; query-level ownership must be reviewed separately.'),
      item('PATCH', '/api/vote', 'app/(chat)/api/vote/route.ts', 44,
        observed('route.eb87fe78924fcf6c80b86213', 'candidate_observed', 'candidate_observed', 'review_next'),
        'custom-control-requires-review', 'useful-review-lead', 'The write route is correctly prioritized, with custom authorization still unresolved.'),
      item('GET', '/api/auth/[...nextauth]', 'app/(auth)/api/auth/[...nextauth]/route.ts', 1,
        missed(), 'not-reviewed-because-missed', 'not-assigned-because-missed',
        'A handler re-export through a project alias remains explicit incomplete coverage.'),
      item('POST', '/api/auth/[...nextauth]', 'app/(auth)/api/auth/[...nextauth]/route.ts', 1,
        missed(), 'not-reviewed-because-missed', 'not-assigned-because-missed',
        'The same unresolved re-export hides the POST handler and its controls.'),
    ],
    promotion: {
      decision: 'stable-bounded',
      boundary: 'Stable for direct named Next.js App Router handler exports in route files. Handler re-exports, computed exports and unresolved project aliases remain explicit partial coverage.',
    },
  },
];

const REJECTED = [{
  project: 'Linkwarden', repository: 'linkwarden/linkwarden',
  commit: '62f1b81ff7f66001b0f5f613202f87771f3186ee',
  reason: 'The fixed revision produced no eligible Next.js App Router route records, so it was rejected as framework evidence rather than counted as a zero-result success.',
}];

function sourceUrl(project, source) {
  return `https://github.com/${project.repository}/blob/${project.commit}/${source.path}#L${source.line}`;
}

export function buildV060RouteReview() {
  const projects = PROJECTS.map((project) => ({
    ...project,
    annotations: project.annotations.map((annotation, index) => ({
      id: `${project.id}-route-${String(index + 1).padStart(2, '0')}`,
      ...annotation,
      source: { ...annotation.source, url: sourceUrl(project, annotation.source) },
    })),
    experimentalBolaReview: {
      matches: 0,
      classifications: { actionable_review_lead: 0, expected_benign_review: 0, incorrect_match: 0, unresolved: 0 },
      decision: 'experimental',
      reason: 'No direct Prisma match occurred in this bounded ordinary-project sample. Planted fixtures alone are insufficient for stable promotion.',
    },
  }));
  const annotations = projects.flatMap((project) => project.annotations);
  return {
    schemaVersion: 1,
    release: 'v0.6.0',
    evidenceType: 'bounded_ordinary_project_route_review',
    reviewedAt: '2026-08-24T00:00:00.000Z',
    method: {
      sourceOnly: true,
      fixedCommits: true,
      hostedInstancesProbed: false,
      projectDependenciesExecuted: false,
      projectDeploymentsStarted: false,
      precisionRecallPublished: false,
      routeCountTreatedAsVulnerabilityCount: false,
      manualAnnotationCap: 60,
    },
    rejectedCandidates: REJECTED,
    projects,
    aggregate: {
      projects: projects.length,
      reviewedRoutes: annotations.length,
      detectedRoutes: annotations.filter((entry) => entry.observed.status === 'detected').length,
      missedRoutes: annotations.filter((entry) => entry.observed.status === 'missed').length,
      extraRecords: annotations.filter((entry) => entry.observed.status === 'extra').length,
      experimentalBolaMatches: projects.reduce((sum, project) => sum + project.experimentalBolaReview.matches, 0),
    },
    promotionDecisions: {
      express: projects.find((project) => project.framework === 'express').promotion,
      nestjs: projects.find((project) => project.framework === 'nestjs').promotion,
      'next-app': projects.find((project) => project.framework === 'next-app').promotion,
      'experimental-prisma-bola': {
        decision: 'experimental',
        boundary: 'Direct same-handler Prisma route-identifier review only; no ordinary-project matches were available to justify stable promotion.',
      },
    },
    limitations: [
      'This purposive 57-route review is not a representative sample and does not measure production precision or recall.',
      'Static control evidence does not prove deployed reachability, middleware execution, role semantics, object ownership, row-level security or exploitability.',
      'Only selected records were manually annotated where a project emitted more than 20 routes; misses remain visible and were not added to a denominator for an accuracy score.',
    ],
  };
}

export function validateV060RouteReview(review) {
  const errors = [];
  const fail = (condition, message) => { if (!condition) errors.push(message); };
  fail(review?.schemaVersion === 1, 'schemaVersion must be 1');
  fail(review?.release === 'v0.6.0', 'release must be v0.6.0');
  fail(review?.method?.sourceOnly === true && review?.method?.hostedInstancesProbed === false
    && review?.method?.projectDependenciesExecuted === false
    && review?.method?.projectDeploymentsStarted === false, 'source-only method boundary changed');
  fail(review?.method?.precisionRecallPublished === false
    && review?.method?.routeCountTreatedAsVulnerabilityCount === false,
  'accuracy-claim boundary changed');
  fail(review?.projects?.length === 3, 'review must contain three projects');
  const all = review?.projects?.flatMap((project) => project.annotations || []) || [];
  fail(all.length === 57 && all.length <= review?.method?.manualAnnotationCap,
    'review must contain 57 routes within the 60-route cap');
  fail(review?.aggregate?.detectedRoutes === 51 && review?.aggregate?.missedRoutes === 6
    && review?.aggregate?.extraRecords === 0, 'aggregate extraction outcomes changed');
  const ids = new Set();
  for (const project of review?.projects || []) {
    fail(/^[a-f0-9]{40}$/.test(project.commit || ''), `${project.id} commit is not immutable`);
    fail(['MIT', 'Apache-2.0'].includes(project.license?.spdx), `${project.id} license is not accepted`);
    fail(project.annotations?.length <= 20, `${project.id} exceeds the 20-route project cap`);
    fail(['completed', 'partial'].includes(project.analyzerRun?.coverage), `${project.id} coverage is invalid`);
    fail(project.experimentalBolaReview?.matches === 0
      && project.experimentalBolaReview?.decision === 'experimental', `${project.id} Prisma review changed`);
    for (const annotation of project.annotations || []) {
      fail(!ids.has(annotation.id), `duplicate annotation ${annotation.id}`);
      ids.add(annotation.id);
      fail(METHOD.has(annotation.expected?.method), `${annotation.id} has invalid method`);
      fail(annotation.expected?.path?.startsWith('/'), `${annotation.id} has invalid path`);
      fail(Number.isInteger(annotation.source?.line) && annotation.source.line > 0,
        `${annotation.id} has invalid source line`);
      const expectedUrl = sourceUrl(project, annotation.source);
      fail(annotation.source?.url === expectedUrl, `${annotation.id} source is not fixed-commit linked`);
      fail(['detected', 'missed'].includes(annotation.observed?.status),
        `${annotation.id} has invalid observation status`);
      if (annotation.observed?.status === 'detected') {
        fail(/^route\.[a-f0-9]{24}$/.test(annotation.observed.routeId || ''),
          `${annotation.id} detected route ID is invalid`);
        fail(annotation.observed.priority !== null, `${annotation.id} detected route lacks priority`);
      } else {
        fail(annotation.observed.routeId === null && annotation.priorityAssessment === 'not-assigned-because-missed',
          `${annotation.id} miss is not explicit`);
      }
      fail(CONTROL_CLASSES.has(annotation.controlClass), `${annotation.id} has invalid control class`);
      fail(PRIORITY_ASSESSMENTS.has(annotation.priorityAssessment),
        `${annotation.id} has invalid priority assessment`);
      fail(Boolean(annotation.note), `${annotation.id} lacks a review note`);
    }
  }
  for (const framework of ['express', 'nestjs', 'next-app']) {
    fail(review?.promotionDecisions?.[framework]?.decision === 'stable-bounded',
      `${framework} promotion is not recorded separately`);
  }
  fail(review?.promotionDecisions?.['experimental-prisma-bola']?.decision === 'experimental',
    'experimental Prisma decision changed');
  fail(review?.rejectedCandidates?.some((item) => item.project === 'Linkwarden'),
    'rejected zero-route candidate is missing');
  return [...new Set(errors)];
}

export function renderV060RouteReview(review) {
  const lines = [
    '# v0.6.0 bounded ordinary-project route review', '',
    'This is a source-only, purposive review of 57 routes at three immutable public commits. It is',
    '**not a production precision/recall benchmark**, and the route count is not a vulnerability count.', '',
    'No hosted instance was contacted, no project dependency was executed and no project was started.', '',
    '## Aggregate', '',
    `- Reviewed: ${review.aggregate.reviewedRoutes} routes (${review.aggregate.detectedRoutes} detected, ${review.aggregate.missedRoutes} explicit misses, ${review.aggregate.extraRecords} extras).`,
    `- Experimental direct-Prisma matches: ${review.aggregate.experimentalBolaMatches}. The rule remains experimental.`,
    '- Manual cap: 20 routes per project, 60 total.', '',
    '## Promotion decisions', '',
    '| Framework/rule | Decision | Boundary |', '|---|---|---|',
    ...Object.entries(review.promotionDecisions).map(([name, value]) =>
      `| ${name} | \`${value.decision}\` | ${value.boundary} |`), '',
  ];
  for (const project of review.projects) {
    lines.push(`## ${project.project}`, '',
      `- Source: [${project.repository}@${project.commit.slice(0, 12)}](https://github.com/${project.repository}/tree/${project.commit})`,
      `- License: ${project.license.spdx}`, `- Framework: ${project.framework}`,
      `- Analyzer run: ${project.analyzerRun.records} records; coverage \`${project.analyzerRun.coverage}\`${project.analyzerRun.incompleteReasons.length ? ` (${project.analyzerRun.incompleteReasons.join(', ')})` : ''}.`,
      `- Annotation: ${project.annotations.length} routes; ${project.analyzerRun.sampledOutRecords} analyzer records deliberately outside this capped sample.`, '',
      '| # | Expected route | Observation | Control evidence | Priority review | Source |',
      '|---:|---|---|---|---|---|');
    for (const entry of project.annotations) {
      const observation = entry.observed.status === 'detected'
        ? `detected \`${entry.observed.routeId}\`; authn \`${entry.observed.authentication}\`; authz \`${entry.observed.authorization}\`; \`${entry.observed.priority}\``
        : '**missed**; no priority assigned';
      lines.push(`| ${entry.id.split('-').at(-1)} | \`${entry.expected.method} ${entry.expected.path}\` | ${observation} | \`${entry.controlClass}\` | \`${entry.priorityAssessment}\`: ${entry.note} | [${entry.source.path}:${entry.source.line}](${entry.source.url}) |`);
    }
    lines.push('');
  }
  lines.push('## Rejected candidate', '',
    ...review.rejectedCandidates.map((item) =>
      `- ${item.project} at \`${item.commit}\`: ${item.reason}`), '',
    '## Interpretation limits', '', ...review.limitations.map((item) => `- ${item}`), '');
  return `${lines.join('\n')}\n`;
}

const ROUTE_REGRESSIONS = [
  {
    id: 'nestjs-static-controller-options-path',
    sourceProject: 'nestjs-boilerplate',
    observedFailure: 'A static @Controller({ path, version }) prefix was treated as dynamic and method routes were emitted at incorrect root paths.',
    minimizedGuard: 'test/nest-route-extractor.test.mjs',
    protectedContract: 'Static NestJS controller option paths and path arrays contribute their declared prefix.',
    remainingBoundary: 'Computed option values remain dynamic and must not be guessed.',
  },
  {
    id: 'nestjs-dynamic-controller-prefix-not-guessed',
    sourceProject: 'nestjs-boilerplate',
    observedFailure: 'A dynamic controller prefix could be dropped while the method-only suffix was emitted as an apparently exact route.',
    minimizedGuard: 'test/nest-route-extractor.test.mjs',
    protectedContract: 'An unresolved NestJS controller prefix produces path null instead of a guessed method-only path.',
    remainingBoundary: 'The analyzer does not evaluate arbitrary TypeScript expressions to recover dynamic decorator values.',
  },
  {
    id: 'route-unrelated-import-failure-isolation',
    sourceProject: 'uptime-kuma',
    observedFailure: 'An unrelated unresolved local import polluted the framework route coverage status.',
    minimizedGuard: 'test/express-route-extractor.test.mjs',
    protectedContract: 'Only route-relevant structural resolution failures can make Express route coverage incomplete.',
    remainingBoundary: 'A mount, router or handler relationship that is relevant and unresolved must still produce partial coverage.',
  },
  {
    id: 'next-route-reexport-remains-incomplete',
    sourceProject: 'vercel-chatbot',
    observedFailure: 'A route-handler re-export through a project alias could disappear without route-specific incomplete evidence.',
    minimizedGuard: 'test/next-app-route-extractor.test.mjs',
    protectedContract: 'Unresolved Next.js route-handler re-exports produce next_route_handler_export_unresolved and partial coverage.',
    remainingBoundary: 'Cross-module handler re-export resolution is not stable coverage in v0.6.0.',
  },
  {
    id: 'route-coverage-reason-budget',
    sourceProject: 'uptime-kuma',
    observedFailure: 'Framework reason counts could exceed the affected-input count exposed by report-v3 coverage.',
    minimizedGuard: 'test/route-security-integration.test.mjs',
    protectedContract: 'Route coverage reason counts reconcile to affected input files instead of internal relationship-event volume.',
    remainingBoundary: 'A reason count is an affected-input count, not a number of missing routes.',
  },
  {
    id: 'express-all-state-change-priority',
    sourceProject: 'uptime-kuma',
    observedFailure: 'Express router.all was treated as read-only even though the handler accepts state-changing HTTP methods.',
    minimizedGuard: 'test/express-route-extractor.test.mjs',
    protectedContract: 'ALL is conservatively state-changing and receives state-change review reasons when controls are unresolved.',
    remainingBoundary: 'Static analysis does not know which HTTP methods a handler may reject internally.',
  },
];

export function buildV060RouteRegressions() {
  return {
    schemaVersion: 1,
    release: 'v0.6.0',
    evidenceType: 'ordinary_project_route_regression_corpus',
    limitation: 'These minimized guards protect six named correctness failures found during a purposive three-project review. They are not a representative accuracy benchmark.',
    summary: { cases: ROUTE_REGRESSIONS.length, resolvedRegressions: ROUTE_REGRESSIONS.length },
    cases: ROUTE_REGRESSIONS.map((item) => ({ ...item, classification: 'resolved_regression' })),
  };
}

export function validateV060RouteRegressions(corpus) {
  const errors = [];
  if (corpus?.schemaVersion !== 1 || corpus?.release !== 'v0.6.0') errors.push('route regression identity is invalid');
  if (corpus?.summary?.cases !== 6 || corpus?.summary?.resolvedRegressions !== 6) {
    errors.push('route regression corpus must contain six resolved failures');
  }
  const ids = new Set();
  for (const item of corpus?.cases || []) {
    if (ids.has(item.id)) errors.push(`duplicate route regression ${item.id}`);
    ids.add(item.id);
    if (item.classification !== 'resolved_regression' || !item.sourceProject || !item.observedFailure
        || !/^test\/.+\.test\.mjs$/.test(item.minimizedGuard || '') || !item.protectedContract
        || !item.remainingBoundary) errors.push(`${item.id} route regression evidence is incomplete`);
  }
  return [...new Set(errors)];
}

export function renderV060RouteRegressions(corpus) {
  const lines = [
    '# v0.6.0 ordinary-project route regressions', '', corpus.limitation, '',
    '| Regression | Origin | Failure | Protected contract | Remaining boundary | Guard |',
    '|---|---|---|---|---|---|',
    ...corpus.cases.map((item) => `| \`${item.id}\` | ${item.sourceProject} | ${item.observedFailure} | ${item.protectedContract} | ${item.remainingBoundary} | [${item.minimizedGuard}](../../${item.minimizedGuard}) |`),
    '',
  ];
  return `${lines.join('\n')}\n`;
}
