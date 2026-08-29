#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildV070AccessReview, V070_TOOL_COMMIT } from './generate-v070-access-review.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
export const FROZEN_V080_EVALUATION_SHA256 = 'b57a3e7e281e3d08ed88205004be3d6dc5c2e39549aa7c8953a1e48d23014ee6';

function selector(kind, field, expressionClass) {
  return { kind, field, expressionClass };
}

function data(provider, resource, operation, path) {
  return { provider, resource, operation, path };
}

function authorization(state, kind = 'none', category = 'none', limitation = null) {
  return { state, kind, category, limitation };
}

function disposition(project, entry, options) {
  return {
    project,
    entry,
    sampleKind: 'ordinary',
    selectorOrigin: null,
    expectedCallablePath: [],
    expectedEdgeCount: null,
    expectedDataOperation: null,
    expectedAuthorizationEvidence: authorization('not_applicable'),
    eligibleForV080: false,
    eligibilityReason: 'no_supported_object_selector',
    exclusion: { code: 'no_supported_object_selector', boundary: 'No supported client-selected object identifier enters this entry.' },
    expectedStatus: 'not_applicable',
    expectedPrimaryReason: null,
    missFamily: 'none',
    reviewerNote: 'Retained as a labeled negative; it is outside the access-path completion denominator.',
    ...options,
  };
}

const dispositions = [
  disposition('nestjs-boilerplate', 'POST /auth/email/login', { sampleKind: 'expected_public_negative' }),
  disposition('nestjs-boilerplate', 'POST /auth/email/register', { sampleKind: 'expected_public_negative' }),
  disposition('nestjs-boilerplate', 'POST /auth/logout', {
    eligibilityReason: 'principal_scoped_without_object_selector',
    exclusion: { code: 'principal_scoped_without_object_selector', boundary: 'Authentication evidence exists, but no client-selected object identifier is present.' },
  }),
  disposition('nestjs-boilerplate', 'GET /auth/me', {
    eligibilityReason: 'principal_scoped_without_object_selector',
    exclusion: { code: 'principal_scoped_without_object_selector', boundary: 'The route addresses the current principal rather than a client-selected object.' },
  }),
  disposition('nestjs-boilerplate', 'DELETE /auth/me', {
    eligibilityReason: 'principal_scoped_without_object_selector',
    exclusion: { code: 'principal_scoped_without_object_selector', boundary: 'The route addresses the current principal rather than a client-selected object.' },
  }),
  disposition('nestjs-boilerplate', 'GET /files/:path', {
    sampleKind: 'ordinary_review_negative',
    eligibilityReason: 'path_is_not_object_identifier',
    exclusion: { code: 'path_is_not_object_identifier', boundary: 'The dynamic field is named path; the v0.8.0 selector contract does not reclassify generic paths as protected object IDs.' },
  }),
  disposition('nestjs-boilerplate', 'DELETE /users/:id', {
    selectorOrigin: selector('nest_param', 'id', "@Param('id')"),
    expectedCallablePath: [
      'src/users/users.controller.ts#UsersController.remove',
      'src/users/users.service.ts#UsersService.remove',
      'src/users/infrastructure/persistence/user.repository.ts#UserRepository.remove',
    ],
    expectedEdgeCount: 2,
    expectedAuthorizationEvidence: authorization('incomplete', 'none', 'principal', 'data_client_unresolved'),
    eligibilityReason: 'unsupported_data_provider',
    exclusion: { code: 'unsupported_data_provider', boundary: 'The repository dispatches to TypeORM or Mongoose; neither provider is included in v0.8.0.' },
    expectedStatus: 'partial',
    expectedPrimaryReason: 'data_client_unresolved',
    missFamily: 'depth_propagation',
    reviewerNote: 'Useful multi-hop stop evidence, but it cannot become a completed Prisma/Drizzle path in this release.',
  }),
  disposition('nestjs-boilerplate', 'GET /users/:id', {
    selectorOrigin: selector('nest_param', 'id', "@Param('id')"),
    expectedCallablePath: [
      'src/users/users.controller.ts#UsersController.findOne',
      'src/users/users.service.ts#UsersService.findById',
      'src/users/infrastructure/persistence/user.repository.ts#UserRepository.findById',
    ],
    expectedEdgeCount: 2,
    expectedAuthorizationEvidence: authorization('incomplete', 'none', 'principal', 'data_client_unresolved'),
    eligibilityReason: 'unsupported_data_provider',
    exclusion: { code: 'unsupported_data_provider', boundary: 'The repository dispatches to TypeORM or Mongoose; neither provider is included in v0.8.0.' },
    expectedStatus: 'partial',
    expectedPrimaryReason: 'data_client_unresolved',
    missFamily: 'depth_propagation',
    reviewerNote: 'The controller/service/repository path is in scope for stopping evidence, while the terminal provider is not.',
  }),

  disposition('vercel-chatbot', 'POST /api/chat', {
    selectorOrigin: selector('request_json_candidate', 'id', 'schema_parse_of_awaited_request_json'),
    expectedCallablePath: ['app/(chat)/api/chat/route.ts#POST'],
    expectedEdgeCount: 0,
    expectedAuthorizationEvidence: authorization('incomplete', 'post_load_comparison', 'principal', 'selector_source_unresolved'),
    eligibilityReason: 'selector_transform_outside_contract',
    exclusion: { code: 'selector_transform_outside_contract', boundary: 'The ID is recovered through a Zod parse result; v0.8.0 supports direct JSON property access and destructuring, not arbitrary validator return semantics.' },
    expectedStatus: 'partial',
    expectedPrimaryReason: 'selector_source_unresolved',
    missFamily: 'selector_origin',
    reviewerNote: 'A minimized direct request.json body case belongs in P3 tests; this ordinary Zod-mediated case must remain partial.',
  }),
  disposition('vercel-chatbot', 'DELETE /api/chat', {
    selectorOrigin: selector('url_search_param', 'id', 'new_URL_request_url_searchParams_get'),
    expectedCallablePath: [
      'app/(chat)/api/chat/route.ts#DELETE',
      'lib/db/queries.ts#getChatById',
    ],
    expectedEdgeCount: 1,
    expectedDataOperation: data('drizzle', 'chat', 'select', 'lib/db/queries.ts:218'),
    expectedAuthorizationEvidence: authorization('observed', 'post_load_comparison', 'principal'),
    eligibleForV080: true,
    eligibilityReason: 'supported_query_selector_direct_return_and_comparison',
    exclusion: null,
    expectedStatus: 'completed',
    missFamily: 'selector_origin',
    reviewerNote: 'The query-selected ID reaches Drizzle and the returned chat userId is compared with Auth.js session.user.id.',
  }),
  disposition('vercel-chatbot', 'GET /api/document', {
    selectorOrigin: selector('url_search_param', 'id', 'new_URL_request_url_searchParams_get'),
    expectedCallablePath: [
      'app/(chat)/api/document/route.ts#GET',
      'lib/db/queries.ts#getDocumentsById',
    ],
    expectedEdgeCount: 1,
    expectedDataOperation: data('drizzle', 'document', 'select', 'lib/db/queries.ts:379'),
    expectedAuthorizationEvidence: authorization('observed', 'post_load_comparison', 'principal'),
    eligibleForV080: true,
    eligibilityReason: 'supported_direct_single_element_array_return_and_comparison',
    exclusion: null,
    expectedStatus: 'completed',
    missFamily: 'selector_origin',
    reviewerNote: 'D1 approves only direct const [document] = documents identity from one exact supported operation; transformed, indexed or ambiguous arrays remain partial.',
  }),
  disposition('vercel-chatbot', 'POST /api/document', {
    selectorOrigin: selector('url_search_param', 'id', 'new_URL_request_url_searchParams_get'),
    expectedCallablePath: [
      'app/(chat)/api/document/route.ts#POST',
      'lib/db/queries.ts#getDocumentsById',
    ],
    expectedEdgeCount: 1,
    expectedDataOperation: data('drizzle', 'document', 'select', 'lib/db/queries.ts:379'),
    expectedAuthorizationEvidence: authorization('observed', 'post_load_comparison', 'principal'),
    eligibleForV080: true,
    eligibilityReason: 'supported_direct_single_element_array_return_and_comparison',
    exclusion: null,
    expectedStatus: 'completed',
    missFamily: 'selector_origin',
    reviewerNote: 'The direct first-element binding grounds the pre-load owner comparison; create/update branches remain outside this labeled path.',
  }),
  disposition('vercel-chatbot', 'DELETE /api/document', {
    selectorOrigin: selector('url_search_param', 'id', 'new_URL_request_url_searchParams_get'),
    expectedCallablePath: [
      'app/(chat)/api/document/route.ts#DELETE',
      'lib/db/queries.ts#getDocumentsById',
    ],
    expectedEdgeCount: 1,
    expectedDataOperation: data('drizzle', 'document', 'select', 'lib/db/queries.ts:379'),
    expectedAuthorizationEvidence: authorization('observed', 'post_load_comparison', 'principal'),
    eligibleForV080: true,
    eligibilityReason: 'supported_direct_single_element_array_return_and_comparison',
    exclusion: null,
    expectedStatus: 'completed',
    missFamily: 'selector_origin',
    reviewerNote: 'The direct first-element binding grounds the owner comparison before the later delete.',
  }),
  disposition('vercel-chatbot', 'GET /api/vote', {
    selectorOrigin: selector('url_search_param', 'chatId', 'new_URL_request_url_searchParams_get'),
    expectedCallablePath: [
      'app/(chat)/api/vote/route.ts#GET',
      'lib/db/queries.ts#getChatById',
    ],
    expectedEdgeCount: 1,
    expectedDataOperation: data('drizzle', 'chat', 'select', 'lib/db/queries.ts:218'),
    expectedAuthorizationEvidence: authorization('observed', 'post_load_comparison', 'principal'),
    eligibleForV080: true,
    eligibilityReason: 'supported_query_selector_direct_return_and_comparison',
    exclusion: null,
    expectedStatus: 'completed',
    missFamily: 'selector_origin',
    reviewerNote: 'The chatId alias reaches getChatById and the returned chat owner is compared with the Auth.js principal.',
  }),
  disposition('vercel-chatbot', 'PATCH /api/vote', {
    selectorOrigin: selector('request_json_candidate', 'chatId', 'schema_parse_of_awaited_request_json'),
    expectedCallablePath: ['app/(chat)/api/vote/route.ts#PATCH'],
    expectedEdgeCount: 0,
    expectedAuthorizationEvidence: authorization('incomplete', 'post_load_comparison', 'principal', 'selector_source_unresolved'),
    eligibilityReason: 'selector_transform_outside_contract',
    exclusion: { code: 'selector_transform_outside_contract', boundary: 'The IDs are recovered through a Zod parse result rather than a direct request.json property/destructuring relationship.' },
    expectedStatus: 'partial',
    expectedPrimaryReason: 'selector_source_unresolved',
    missFamily: 'selector_origin',
    reviewerNote: 'Do not treat a validator result as the raw request object without an explicit supported mapping.',
  }),
  disposition('vercel-chatbot', 'ACTION updateChatVisibility', {
    selectorOrigin: selector('server_action_parameter', 'chatId', 'object_pattern_parameter'),
    expectedCallablePath: [
      'app/(chat)/actions.ts#updateChatVisibility',
      'lib/db/queries.ts#getChatById',
    ],
    expectedEdgeCount: 1,
    expectedDataOperation: data('drizzle', 'chat', 'select', 'lib/db/queries.ts:218'),
    expectedAuthorizationEvidence: authorization('observed', 'post_load_comparison', 'principal'),
    eligibleForV080: true,
    eligibilityReason: 'supported_action_selector_direct_return_and_comparison',
    exclusion: null,
    expectedStatus: 'completed',
    missFamily: 'selector_origin',
    reviewerNote: 'The action parameter and Auth.js principal meet in an exact returned-resource comparison.',
  }),

  disposition('formbricks', 'GET /legacy-organization-settings/[workspaceId]/[[...path]]', {
    selectorOrigin: selector('next_route_param', 'workspaceId', 'awaited_context_params'),
    expectedCallablePath: [
      'apps/web/app/(redirects)/legacy-organization-settings/[workspaceId]/[[...path]]/route.ts#GET',
      'apps/web/lib/workspace/service.ts#getWorkspace',
    ],
    expectedEdgeCount: 1,
    expectedDataOperation: data('prisma', 'workspace', 'findUnique', 'apps/web/lib/workspace/service.ts:118'),
    expectedAuthorizationEvidence: authorization('incomplete', 'post_load_comparison', 'principal', 'constraint_expression_unresolved'),
    eligibleForV080: true,
    eligibilityReason: 'supported_exact_react_cache_callback_prisma_operation',
    exclusion: null,
    expectedStatus: 'completed',
    missFamily: 'callable_wrapper_reexport',
    reviewerNote: 'D1 permits only a direct React cache(callback) binding with one local callback; later membership evidence remains separately bounded.',
  }),
  disposition('formbricks', 'POST /api/internal/feedback-datasets/[datasetId]/purge', {
    selectorOrigin: selector('next_wrapper_parsed_param_candidate', 'datasetId', 'withV3ApiWrapper_parsedInput_params'),
    expectedCallablePath: [
      'apps/web/app/api/internal/feedback-datasets/[datasetId]/purge/route.ts#POST.handler',
      'apps/web/app/api/internal/feedback-datasets/lib/operations.ts#purgeV3FeedbackDataset',
      'apps/web/app/api/internal/feedback-datasets/lib/access.ts#requireFeedbackDatasetMutationAccess',
      'apps/web/modules/ee/feedback-directory/lib/feedback-directory.ts#getOrganizationIdFromDirectoryId',
    ],
    expectedEdgeCount: 3,
    expectedDataOperation: data('prisma', 'feedbackDirectory', 'findUnique', 'apps/web/modules/ee/feedback-directory/lib/feedback-directory.ts:624'),
    expectedAuthorizationEvidence: authorization('incomplete', 'query_predicate', 'principal', 'selector_source_unresolved'),
    eligibilityReason: 'wrapper_parsed_selector_not_in_contract',
    exclusion: { code: 'wrapper_parsed_selector_not_in_contract', boundary: 'The handler receives parsedInput.params from a wrapper/Zod pipeline; the current selector contract does not equate that value with Next context.params.' },
    expectedStatus: 'partial',
    expectedPrimaryReason: 'selector_source_unresolved',
    missFamily: 'callable_wrapper_reexport',
    reviewerNote: 'The deeper Prisma lookup is grounded, while the route-to-parsedInput selector relationship is not.',
  }),
  disposition('formbricks', 'DELETE /api/v1/management/action-classes/[actionClassId]', {
    selectorOrigin: selector('next_route_param', 'actionClassId', 'wrapper_props_awaited_params'),
    expectedCallablePath: [
      'apps/web/app/api/v1/management/action-classes/[actionClassId]/route.ts#DELETE.handler',
      'apps/web/app/api/v1/management/action-classes/[actionClassId]/route.ts#fetchAndAuthorizeActionClass',
      'apps/web/lib/actionClass/service.ts#getActionClass',
    ],
    expectedEdgeCount: 2,
    expectedDataOperation: data('prisma', 'actionClass', 'findUnique', 'apps/web/lib/actionClass/service.ts:73'),
    expectedAuthorizationEvidence: authorization('incomplete', 'post_load_comparison', 'tenant', 'constraint_expression_unresolved'),
    eligibleForV080: true,
    eligibilityReason: 'supported_exact_react_cache_callback_prisma_operation',
    exclusion: null,
    expectedStatus: 'completed',
    missFamily: 'callable_wrapper_reexport',
    reviewerNote: 'The local V1 handler and direct React cache callback are exact; hasPermission remains an unresolved authorization candidate.',
  }),
  disposition('formbricks', 'GET /api/v1/management/responses/[responseId]', {
    selectorOrigin: selector('next_route_param', 'responseId', 'wrapper_props_awaited_params'),
    expectedCallablePath: [
      'apps/web/app/api/v1/management/responses/[responseId]/route.ts#GET.handler',
      'apps/web/app/api/v1/management/responses/[responseId]/route.ts#fetchAndAuthorizeResponse',
      'apps/web/lib/response/service.ts#getResponse',
    ],
    expectedEdgeCount: 2,
    expectedDataOperation: data('prisma', 'response', 'findUnique', 'apps/web/lib/response/service.ts:204'),
    expectedAuthorizationEvidence: authorization('incomplete', 'post_load_comparison', 'tenant', 'constraint_expression_unresolved'),
    eligibleForV080: true,
    eligibilityReason: 'supported_exact_react_cache_callback_prisma_operation',
    exclusion: null,
    expectedStatus: 'completed',
    missFamily: 'callable_wrapper_reexport',
    reviewerNote: 'The wrapper handler, helper and direct React cache callback are exact; hasPermission remains outside name-only inference.',
  }),
  disposition('formbricks', 'GET /api/v1/management/surveys/[surveyId]', {
    selectorOrigin: selector('next_route_param', 'surveyId', 'wrapper_props_awaited_params'),
    expectedCallablePath: [
      'apps/web/app/api/v1/management/surveys/[surveyId]/route.ts#GET.handler',
      'apps/web/app/api/v1/management/surveys/[surveyId]/route.ts#fetchAndAuthorizeSurvey',
      'apps/web/lib/survey/service.ts#getSurvey',
    ],
    expectedEdgeCount: 2,
    expectedDataOperation: data('prisma', 'survey', 'findUnique', 'apps/web/lib/survey/service.ts:174'),
    expectedAuthorizationEvidence: authorization('incomplete', 'post_load_comparison', 'tenant', 'constraint_expression_unresolved'),
    eligibleForV080: true,
    eligibilityReason: 'supported_exact_react_cache_callback_prisma_operation',
    exclusion: null,
    expectedStatus: 'completed',
    missFamily: 'callable_wrapper_reexport',
    reviewerNote: 'The V1 wrapper and direct React cache callback are exact; hasPermission remains an unresolved authorization candidate.',
  }),
  disposition('formbricks', 'DELETE /api/v1/webhooks/[webhookId]', {
    selectorOrigin: selector('next_route_param', 'webhookId', 'wrapper_props_awaited_params'),
    expectedCallablePath: [
      'apps/web/app/api/v1/webhooks/[webhookId]/route.ts#DELETE.handler',
      'apps/web/app/api/v1/webhooks/[webhookId]/lib/webhook.ts#getWebhook',
    ],
    expectedEdgeCount: 1,
    expectedDataOperation: data('prisma', 'webhook', 'findUnique', 'apps/web/app/api/v1/webhooks/[webhookId]/lib/webhook.ts:37'),
    expectedAuthorizationEvidence: authorization('incomplete', 'none', 'tenant', 'constraint_expression_unresolved'),
    eligibleForV080: true,
    eligibilityReason: 'supported_wrapper_handler_direct_prisma_operation',
    exclusion: null,
    expectedStatus: 'completed',
    missFamily: 'callable_wrapper_reexport',
    reviewerNote: 'The object path to Prisma is exact. The custom hasPermission call remains a separate unresolved authorization candidate.',
  }),
  disposition('formbricks', 'POST /api/v2/client/[workspaceId]/responses', {
    sampleKind: 'expected_public_negative',
    selectorOrigin: selector('next_route_param', 'workspaceId', 'awaited_context_params'),
    expectedCallablePath: [
      'apps/web/app/api/v2/client/[workspaceId]/responses/route.ts#POST',
      'apps/web/lib/utils/resolve-client-id.ts#resolveClientApiIds',
    ],
    expectedEdgeCount: 1,
    expectedDataOperation: data('prisma', 'workspace', 'findFirst', 'apps/web/lib/utils/resolve-client-id.ts:17'),
    expectedAuthorizationEvidence: authorization('not_applicable'),
    eligibilityReason: 'expected_public_ingestion_outside_completion_denominator',
    exclusion: { code: 'expected_public_ingestion_outside_completion_denominator', boundary: 'The exact cache callback may be inspected, but this intentionally public ingestion path remains a labeled negative outside the ordinary completion denominator.' },
    expectedStatus: 'not_applicable',
    expectedPrimaryReason: null,
    missFamily: 'none',
    reviewerNote: 'Retained to prevent route-control logic from converting an expected public client endpoint into an authentication finding.',
  }),
  disposition('formbricks', 'POST /api/v3/surveys/[surveyId]/archive', {
    selectorOrigin: selector('next_wrapper_parsed_param_candidate', 'surveyId', 'withV3ApiWrapper_parsedInput_params'),
    expectedCallablePath: [
      'apps/web/app/api/v3/surveys/[surveyId]/archive/route.ts#POST.handler',
      'apps/web/app/api/v3/surveys/lib/operations.ts#archiveV3Survey',
      'apps/web/app/api/v3/surveys/lib/operations.ts#runV3SurveyLifecycleMutation',
      'apps/web/app/api/v3/surveys/authorization.ts#getAuthorizedV3Survey',
    ],
    expectedEdgeCount: 3,
    expectedDataOperation: data('prisma', 'survey', 'findUnique', 'apps/web/lib/survey/service.ts:174'),
    expectedAuthorizationEvidence: authorization('incomplete', 'post_load_comparison', 'tenant', 'wrapper_handler_unresolved'),
    eligibilityReason: 'wrapper_selector_callback_and_external_cache_outside_contract',
    exclusion: { code: 'wrapper_selector_callback_and_external_cache_outside_contract', boundary: 'The route combines wrapper-produced parsedInput, a callback-based lifecycle helper and a React cache-wrapped query.' },
    expectedStatus: 'partial',
    expectedPrimaryReason: 'wrapper_handler_unresolved',
    missFamily: 'callable_wrapper_reexport',
    reviewerNote: 'Multiple independently named boundaries remain visible; none may be erased to claim completion.',
  }),
  disposition('formbricks', 'ACTION getMembershipByUserIdOrganizationIdAction', {
    selectorOrigin: selector('server_action_parameter', 'workspaceId,userId', 'direct_parameters'),
    expectedCallablePath: [
      'apps/web/lib/membership/hooks/actions.ts#getMembershipByUserIdOrganizationIdAction',
      'apps/web/lib/organization/service.ts#getOrganizationByWorkspaceId',
      'apps/web/lib/membership/hooks/actions.ts#getMembershipRole',
    ],
    expectedEdgeCount: 2,
    expectedDataOperation: data('prisma', 'organization', 'findFirst', 'apps/web/lib/organization/service.ts:123'),
    expectedAuthorizationEvidence: authorization('incomplete', 'query_predicate', 'tenant', 'constraint_expression_unresolved'),
    eligibleForV080: true,
    eligibilityReason: 'supported_exact_react_cache_callback_prisma_operation',
    exclusion: null,
    expectedStatus: 'completed',
    missFamily: 'depth_propagation',
    reviewerNote: 'The direct cache callback is analyzable. Both arguments remain client-selected facts; userId is not promoted to a current-principal fact by its name.',
  }),
  disposition('formbricks', 'ACTION getMembershipRole', {
    selectorOrigin: selector('server_action_parameter', 'userId,organizationId', 'direct_parameters'),
    expectedCallablePath: [
      'apps/web/lib/membership/hooks/actions.ts#getMembershipRole',
      'apps/web/lib/membership/service.ts#getMembershipByUserIdOrganizationId',
      'apps/web/lib/membership/service.ts#getMembershipByUserIdOrganizationIdCached',
      'apps/web/lib/membership/service.ts#getMembershipByUserIdOrganizationIdUncached',
    ],
    expectedEdgeCount: 3,
    expectedDataOperation: data('prisma', 'membership', 'findUnique', 'apps/web/lib/membership/service.ts:25'),
    expectedAuthorizationEvidence: authorization('observed', 'query_predicate', 'tenant'),
    eligibleForV080: true,
    eligibilityReason: 'supported_exact_cache_and_proven_omitted_transaction_client',
    exclusion: null,
    expectedStatus: 'completed',
    missFamily: 'depth_propagation',
    reviewerNote: 'The cache callback calls the uncached function without tx, so tx is exactly undefined and tx ?? prisma resolves to prisma. The compound tenant predicate is visible, but caller-supplied userId is not an authenticated principal.',
  }),
  disposition('formbricks', 'ACTION logSignOutAction', {
    selectorOrigin: selector('server_action_parameter_candidate', 'userId', 'direct_parameter'),
    expectedCallablePath: [
      'apps/web/modules/auth/actions/sign-out.ts#logSignOutAction',
      'apps/web/modules/auth/lib/utils.ts#logSignOut',
    ],
    expectedEdgeCount: 1,
    eligibilityReason: 'no_supported_object_operation',
    exclusion: { code: 'no_supported_object_operation', boundary: 'The action emits an audit/auth event and does not reach a supported object data operation.' },
    expectedStatus: 'not_applicable',
    expectedPrimaryReason: null,
    missFamily: 'depth_propagation',
    reviewerNote: 'A parameter named userId is not sufficient to create an object-authorization path without a supported object operation.',
  }),
  disposition('formbricks', 'ACTION checkRoleManagementPermission', {
    selectorOrigin: selector('server_action_parameter', 'organizationId', 'direct_parameter'),
    expectedCallablePath: [
      'apps/web/modules/ee/role-management/actions.ts#checkRoleManagementPermission',
      'apps/web/lib/organization/service.ts#getOrganization',
      'apps/web/modules/ee/license-check/lib/utils.ts#getAccessControlPermission',
    ],
    expectedEdgeCount: 2,
    expectedDataOperation: data('prisma', 'organization', 'findUnique', 'apps/web/lib/organization/service.ts:150'),
    expectedAuthorizationEvidence: authorization('incomplete', 'none', 'tenant', 'constraint_expression_unresolved'),
    eligibleForV080: true,
    eligibilityReason: 'supported_exact_react_cache_callback_prisma_operation',
    exclusion: null,
    expectedStatus: 'completed',
    missFamily: 'depth_propagation',
    reviewerNote: 'The direct React cache callback is analyzable. The function name is not an authorization conclusion and no current-principal fact is present.',
  }),

  disposition('documenso', 'GET /llms-full.txt', { sampleKind: 'expected_public_negative' }),
  disposition('documenso', 'GET /llms.txt', { sampleKind: 'expected_public_negative' }),
  disposition('documenso', 'GET /llms.mdx/docs/[[...slug]]', {
    sampleKind: 'expected_public_negative',
    eligibilityReason: 'slug_is_not_object_identifier',
    exclusion: { code: 'slug_is_not_object_identifier', boundary: 'The dynamic documentation slug is intentionally outside the ID selector naming contract.' },
  }),
  disposition('documenso', 'GET /og/docs/[...slug]', {
    sampleKind: 'expected_public_negative',
    eligibilityReason: 'slug_is_not_object_identifier',
    exclusion: { code: 'slug_is_not_object_identifier', boundary: 'The dynamic image slug is intentionally outside the ID selector naming contract.' },
  }),
];

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function countBy(values) {
  return Object.fromEntries([...new Set(values)].sort().map((value) => [
    value, values.filter((candidate) => candidate === value).length,
  ]));
}

function sourceRecord(project, source) {
  const match = /^(.*):(\d+)$/.exec(source);
  if (!match) throw new Error(`invalid historical source ${source}`);
  const [, path, line] = match;
  return {
    path,
    line: Number(line),
    url: `https://github.com/${project.repository}/blob/${project.commit}/${path}#L${line}`,
  };
}

function withoutDigest(value, key) {
  const copy = structuredClone(value);
  delete copy[key];
  return copy;
}

export function buildV080AccessEvaluation() {
  const historical = buildV070AccessReview();
  const projectById = new Map(historical.projects.map((project) => [project.id, project]));
  const historicalByKey = new Map(historical.observations.map((item) => [`${item.project}\u0000${item.entry}`, item]));
  const entries = dispositions.map((label, index) => {
    const historicalObservation = historicalByKey.get(`${label.project}\u0000${label.entry}`);
    const project = projectById.get(label.project);
    if (!historicalObservation || !project) throw new Error(`unmatched disposition ${label.project} ${label.entry}`);
    const record = {
      id: `v080-eval-${String(index + 1).padStart(2, '0')}`,
      project: label.project,
      repository: project.repository,
      commit: project.commit,
      entry: label.entry,
      source: sourceRecord(project, historicalObservation.source),
      historical: {
        assessment: historicalObservation.assessment,
        note: historicalObservation.note,
      },
      sampleKind: label.sampleKind,
      selectorOrigin: label.selectorOrigin,
      expectedCallablePath: label.expectedCallablePath,
      expectedEdgeCount: label.expectedEdgeCount,
      expectedDataOperation: label.expectedDataOperation,
      expectedAuthorizationEvidence: label.expectedAuthorizationEvidence,
      eligibleForV080: label.eligibleForV080,
      eligibilityReason: label.eligibilityReason,
      exclusion: label.exclusion,
      expectedStatus: label.expectedStatus,
      expectedPrimaryReason: label.expectedPrimaryReason,
      missFamily: label.missFamily,
      reviewerNote: label.reviewerNote,
    };
    record.recordSha256 = sha256(JSON.stringify(record));
    return record;
  });
  const eligible = entries.filter((entry) => entry.eligibleForV080);
  const minimumByRate = Math.ceil(eligible.length * 0.7);
  const effectiveMinimum = Math.max(minimumByRate, 6);
  const core = {
    schemaVersion: 1,
    release: '0.8.0',
    state: 'owner_approved',
    frozenOn: '2026-08-29',
    ownerDecision: {
      gate: 'D1',
      approvedOn: '2026-08-29',
      selection: ['exact_react_cache_callback_and_proven_omitted_tx', 'direct_single_element_array_return_mapping'],
      statement: 'The owner approved options 1 and 3 after the initial four-path freeze. All historical entries affected solely by either approved semantic boundary were reclassified consistently before production analyzer implementation.',
      boundaries: [
        'React cache is transparent only when the imported React cache binding and its single callback are exact; arbitrary higher-order wrappers remain unresolved.',
        'tx ?? prisma resolves to prisma only when exact argument mapping proves the optional tx parameter was omitted on the analyzed path.',
        'Array return identity is preserved only for a direct single-element destructuring binding from one exact supported operation; indexing, rest, transforms and ambiguous arrays remain unresolved.',
        'Caller-supplied userId remains an object candidate and never becomes a current-principal fact by name.',
      ],
    },
    historicalSource: {
      path: 'docs/reviews/v0.7.0-access-control-review.json',
      toolCommit: V070_TOOL_COMMIT,
      projects: historical.aggregate.projects,
      observations: historical.aggregate.manualEntries,
      observationsSha256: sha256(JSON.stringify(historical.observations)),
    },
    criteria: {
      eligible: 'A fixed-commit ordinary entry has an exact v0.8.0 selector, a uniquely resolved local path within four edges and a supported Prisma or Drizzle object operation. D1 additionally permits exact React cache callbacks, a proven omitted optional tx resolving tx ?? prisma, and direct single-element array return bindings.',
      excluded: 'The historical entry remains visible but does not enter the completion denominator when it is a labeled expected-public negative, lacks an object selector/operation or requires an explicit non-goal such as TypeORM, Mongoose, arbitrary validator semantics, arbitrary higher-order wrapper semantics, an unproved dynamic data client or transformed/ambiguous array identity.',
      evidenceBoundary: 'Eligibility predicts structural analyzability, not security, vulnerability, runtime reachability, deployed enforcement or production accuracy.',
    },
    projects: historical.projects.map(({ id, repository, commit, license, target }) => ({ id, repository, commit, license, target })),
    optionalFifthProject: {
      selected: false,
      reason: 'D1 selected two bounded semantic extensions over a fifth project. The existing fixed projects now provide a feasible denominator without adding an easy corpus solely to satisfy the floor.',
    },
    aggregate: {
      totalEntries: entries.length,
      eligibleEntries: eligible.length,
      excludedEntries: entries.length - eligible.length,
      byExpectedStatus: countBy(entries.map((entry) => entry.expectedStatus)),
      bySelectorOrigin: countBy(entries.map((entry) => entry.selectorOrigin?.kind ?? 'none')),
      byDataProvider: countBy(entries.map((entry) => entry.expectedDataOperation?.provider ?? 'none')),
      byAuthorizationKind: countBy(entries.map((entry) => entry.expectedAuthorizationEvidence.kind)),
      byMissFamily: countBy(entries.map((entry) => entry.missFamily)),
      dominantMissFamilies: ['selector_origin', 'callable_wrapper_reexport', 'depth_propagation']
        .map((family) => ({ family, count: entries.filter((entry) => entry.missFamily === family).length })),
    },
    targetCalculation: {
      completionRate: 0.7,
      denominator: eligible.length,
      minimumByRate,
      groundedPathFloor: 6,
      effectiveMinimum,
      feasibleWithCurrentBoundary: eligible.length >= effectiveMinimum,
      pathShortfall: Math.max(0, effectiveMinimum - eligible.length),
      completedProjectFloor: 2,
      representedEligibleProjects: [...new Set(eligible.map((entry) => entry.project))].sort(),
      requiredProviders: ['drizzle', 'prisma'],
      representedEligibleProviders: [...new Set(eligible.map((entry) => entry.expectedDataOperation.provider))].sort(),
      queryConstraintCases: eligible.filter((entry) => entry.expectedAuthorizationEvidence.kind === 'query_predicate').length,
      postLoadComparisonCases: eligible.filter((entry) => entry.expectedAuthorizationEvidence.kind === 'post_load_comparison').length,
      queryConstraintShortfall: eligible.some((entry) => entry.expectedAuthorizationEvidence.kind === 'query_predicate') ? 0 : 1,
    },
    decisionOutcome: {
      code: 'd1_scope_approved_and_refrozen',
      statement: `D1 approved options 1 and 3. The refrozen contract has ${eligible.length} eligible real paths, an effective completion minimum of ${effectiveMinimum} and at least one eligible query-constraint case. P2 may proceed.`,
      prohibitedResolution: 'Do not lower the frozen denominator or six-path floor, relabel client input as a principal, erase excluded entries, generalize the approved wrappers beyond their exact shapes or count fixtures as real paths.',
    },
    claims: [
      'This ledger freezes manual expectations before v0.8.0 production analyzer implementation.',
      'It is not a production precision, recall, reachability or exploitability measurement.',
      'Historical v0.7.0 assessments are copied verbatim and remain historical.',
    ],
    entries,
  };
  return { ...core, ledgerSha256: sha256(JSON.stringify(core)) };
}

export function validateV080AccessEvaluation(evaluation, { enforceFrozenDigest = true } = {}) {
  const errors = [];
  const historical = buildV070AccessReview();
  const historicalKeys = historical.observations.map((entry) => `${entry.project}\u0000${entry.entry}`).sort();
  const keys = evaluation.entries.map((entry) => `${entry.project}\u0000${entry.entry}`).sort();
  if (JSON.stringify(keys) !== JSON.stringify(historicalKeys)) errors.push('historical observation set changed');
  if (new Set(keys).size !== keys.length) errors.push('duplicate evaluation entry');
  if (evaluation.entries.length !== 32) errors.push('evaluation must retain 32 historical entries');
  for (const entry of evaluation.entries) {
    const historicalEntry = historical.observations.find((candidate) => candidate.project === entry.project && candidate.entry === entry.entry);
    if (!historicalEntry || entry.historical.assessment !== historicalEntry.assessment || entry.historical.note !== historicalEntry.note) {
      errors.push(`${entry.id} rewrote historical assessment`);
    }
    if (entry.recordSha256 !== sha256(JSON.stringify(withoutDigest(entry, 'recordSha256')))) errors.push(`${entry.id} record digest mismatch`);
    if (entry.eligibleForV080 && (entry.expectedStatus !== 'completed' || entry.exclusion !== null)) errors.push(`${entry.id} eligible disposition is inconsistent`);
    if (!entry.eligibleForV080 && !entry.exclusion) errors.push(`${entry.id} excluded disposition lacks boundary`);
    if (entry.expectedCallablePath.length > 5 || entry.expectedEdgeCount !== null && entry.expectedEdgeCount > 4) errors.push(`${entry.id} exceeds path bound`);
    if (entry.expectedDataOperation && !['prisma', 'drizzle'].includes(entry.expectedDataOperation.provider)) errors.push(`${entry.id} uses unsupported provider`);
    if (!['completed', 'partial', 'not_applicable'].includes(entry.expectedStatus)) errors.push(`${entry.id} has invalid expected status`);
  }
  const eligible = evaluation.entries.filter((entry) => entry.eligibleForV080);
  if (evaluation.aggregate.totalEntries !== evaluation.entries.length
    || evaluation.aggregate.eligibleEntries !== eligible.length
    || evaluation.aggregate.excludedEntries !== evaluation.entries.length - eligible.length) errors.push('aggregate totals changed');
  const expectedMisses = { selector_origin: 8, callable_wrapper_reexport: 7, depth_propagation: 6 };
  for (const [family, count] of Object.entries(expectedMisses)) {
    if (evaluation.entries.filter((entry) => entry.missFamily === family).length !== count) errors.push(`${family} miss count changed`);
  }
  const computedDigest = sha256(JSON.stringify(withoutDigest(evaluation, 'ledgerSha256')));
  if (evaluation.ledgerSha256 !== computedDigest) errors.push('ledger digest mismatch');
  if (enforceFrozenDigest && evaluation.ledgerSha256 !== FROZEN_V080_EVALUATION_SHA256) errors.push('frozen evaluation digest changed');
  if (evaluation.targetCalculation.denominator !== eligible.length
    || evaluation.targetCalculation.effectiveMinimum !== Math.max(Math.ceil(eligible.length * 0.7), 6)) errors.push('target calculation changed');
  return errors;
}

function renderMarkdown(evaluation) {
  const lines = [
    '# v0.8.0 access-control evaluation ledger', '',
    '> Fixed-commit structural evaluation prepared before production analyzer implementation. This is not a production precision, recall, reachability or exploitability measurement.', '',
    '## Decision status', '',
    `- State: \`${evaluation.state}\``,
    `- Ledger SHA-256: \`${evaluation.ledgerSha256}\``,
    `- Historical observations retained: ${evaluation.aggregate.totalEntries}/32`,
    `- Approved eligible denominator: ${evaluation.targetCalculation.denominator}`,
    `- 70% calculation: ceil(${evaluation.targetCalculation.denominator} x 0.70) = ${evaluation.targetCalculation.minimumByRate}`,
    `- Six-path floor: ${evaluation.targetCalculation.groundedPathFloor}`,
    `- Effective required completed paths: ${evaluation.targetCalculation.effectiveMinimum}`,
    `- Current structural shortfall: ${evaluation.targetCalculation.pathShortfall} path(s)`,
    `- Query-constraint shortfall: ${evaluation.targetCalculation.queryConstraintShortfall} case(s)`, '',
    evaluation.decisionOutcome.statement, '',
    `Prohibited shortcut: ${evaluation.decisionOutcome.prohibitedResolution}`, '',
    '## Approved D1 boundaries', '',
    ...evaluation.ownerDecision.boundaries.map((boundary) => `- ${boundary}`), '',
    '## Eligibility rule', '',
    `- Included: ${evaluation.criteria.eligible}`,
    `- Excluded: ${evaluation.criteria.excluded}`,
    `- Boundary: ${evaluation.criteria.evidenceBoundary}`, '',
    '## Miss taxonomy', '',
    '| Historical miss family | Entries |', '|---|---:|',
    ...evaluation.aggregate.dominantMissFamilies.map((item) => `| \`${item.family}\` | ${item.count} |`), '',
    '## Optional fifth project', '',
    `- Selected: ${evaluation.optionalFifthProject.selected ? 'yes' : 'no'}`,
    `- Reason: ${evaluation.optionalFifthProject.reason}`, '',
    '## Entry ledger', '',
    '| ID | Project | Entry | Historical | Selector | Path edges | Provider/op | Auth evidence | Eligible | Expected | Exclusion / note |',
    '|---|---|---|---|---|---:|---|---|---|---|---|',
    ...evaluation.entries.map((entry) => {
      const selectorLabel = entry.selectorOrigin ? `${entry.selectorOrigin.kind}:${entry.selectorOrigin.field}` : 'none';
      const operation = entry.expectedDataOperation ? `${entry.expectedDataOperation.provider}:${entry.expectedDataOperation.operation}` : 'none';
      const auth = `${entry.expectedAuthorizationEvidence.state}:${entry.expectedAuthorizationEvidence.kind}`;
      const note = entry.exclusion ? `${entry.exclusion.code}: ${entry.exclusion.boundary}` : entry.reviewerNote;
      return `| ${entry.id} | ${entry.project} | [\`${entry.entry}\`](${entry.source.url}) | \`${entry.historical.assessment}\` | \`${selectorLabel}\` | ${entry.expectedEdgeCount ?? '-'} | \`${operation}\` | \`${auth}\` | ${entry.eligibleForV080 ? 'yes' : 'no'} | \`${entry.expectedStatus}\` | ${note} |`;
    }), '',
    '## Claims boundary', '',
    ...evaluation.claims.map((claim) => `- ${claim}`), '',
  ];
  return `${lines.join('\n')}\n`;
}

function main() {
  const args = process.argv.slice(2);
  const check = args.includes('--check');
  if (args.some((argument) => argument !== '--check')) {
    console.error('usage: node scripts/generate-v080-access-evaluation.mjs [--check]');
    process.exit(2);
  }
  const evaluation = buildV080AccessEvaluation();
  const errors = validateV080AccessEvaluation(evaluation, { enforceFrozenDigest: check });
  if (errors.length) {
    console.error(`v0.8.0 access evaluation invalid:\n${errors.map((error) => `- ${error}`).join('\n')}`);
    process.exit(1);
  }
  const outputs = [
    [join(ROOT, 'docs/reviews/v0.8.0-access-control-evaluation.json'), `${JSON.stringify(evaluation, null, 2)}\n`],
    [join(ROOT, 'docs/reviews/v0.8.0-access-control-evaluation.md'), renderMarkdown(evaluation)],
  ];
  if (check) {
    const stale = outputs.filter(([path, content]) => !existsSync(path) || readFileSync(path, 'utf8') !== content);
    if (stale.length) {
      console.error('v0.8.0 access evaluation is stale; run node scripts/generate-v080-access-evaluation.mjs');
      process.exit(1);
    }
    console.log(`v0.8.0 evaluation frozen: ${evaluation.aggregate.totalEntries} entries, denominator ${evaluation.targetCalculation.denominator}, shortfall ${evaluation.targetCalculation.pathShortfall}`);
  } else {
    mkdirSync(join(ROOT, 'docs/reviews'), { recursive: true });
    for (const [path, content] of outputs) writeFileSync(path, content);
    console.log(`${evaluation.ledgerSha256}\n${outputs.map(([path]) => path).join('\n')}`);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main();
