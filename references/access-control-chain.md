# Access-control chain review

Use this reference after a built-in audit produces `route-security.json` and
`route-security.md`. It explains how to turn static access-control evidence into a bounded human
review. It does not authorize live testing and does not prove a BOLA/IDOR vulnerability.

## Read the artifact in this order

1. Read framework/action inventory coverage and `accessPathCoverage` separately. A completed route
   inventory does not erase a partial access path, and a completed access path does not repair an
   incomplete route inventory. Any partial reason limits the affected downstream conclusion.
2. Read application controls once. A Nest `APP_GUARD` or unresolved application middleware is an
   application fact; do not repeat it as proof that every route authenticates or authorizes.
3. Review state-changing or object-addressed routes with
   `no_route_scoped_control_observed`. Classify expected-public login, registration, recovery and
   webhook routes before proposing a change.
4. Review completed chains with `authorization_constraint_not_observed`, then partial chains.
   Prioritize caller-selected identifiers that reach a supported data operation without a visible
   principal or tenant query constraint or post-load comparison.
5. Check Server Actions in their separate inventory. They are callable application surfaces but do
   not have an invented HTTP method or URL.

## Keep four questions separate

| Question | Evidence field | Plain meaning |
|---|---|---|
| What application-wide control exists? | `applicationControls` | A control was registered for the application; its effective route coverage is not proven. |
| Who is the caller? | `authentication` and identity evidence | A supported session or identity source was observed in the bounded path. |
| May the caller invoke the operation? | `authorization` and route-scoped controls | A supported route/controller policy was observed; custom controls may remain unclassified. |
| May the caller access this record? | `accessChains` | A caller-selected object reached a supported operation, with or without a visible principal/tenant constraint. |

Do not use a rate-limit, logging or generic Nest guard as authentication or authorization merely
because it implements a framework control interface. Do not copy an unclassified signal into both
authentication and authorization.

## Interpret access-chain outcomes

- `authorization_constraint_observed`: a supported Prisma or Drizzle path contains a visible
  identity-derived principal/tenant query predicate or an exact post-load comparison. The artifact
  states which kind and category were observed. Runtime reachability, control-flow dominance,
  denial behavior, policy correctness and complete coverage are still not proven.
- `external_policy_required`: source evidence alone cannot settle the decision. Supabase always
  retains this state because Postgres RLS and deployed policy behavior are external.
- `authorization_constraint_not_observed`: the completed bounded path did not show a supported
  principal or tenant query predicate or post-load comparison. This is a review lead, not proof
  that no check exists elsewhere or that the operation is exploitable.
- `no_supported_object_operation`: no supported object operation completed the bounded chain.
- `incomplete`: parsing, module resolution, argument or return mapping, dynamic behavior, a budget
  or the four-edge limit stopped the analysis. Never turn this into a clean result.

The analyzer starts from exact route parameters, URL-query values, direct JSON-body fields or
Server Action parameters and follows object, principal and tenant facts through at most four exact
project-local call edges. It can resolve one unambiguous source target through relative imports,
nearest static `tsconfig.json`/`jsconfig.json` path mappings, exact workspace source exports and the
narrowly proved Vite/Prisma source relationships documented by the v0.8.0 review. Ambiguous calls,
destructuring or transforms outside the supported mapper, dynamic dispatch, cycles, escaping,
unbuilt-only targets and exhausted budgets fail closed as partial evidence.

`status: completed` means one supported selector-to-operation path finished inside this model. It
does not mean the route is authenticated, authorization is correct, the operation is reachable in
production, or a vulnerability exists. Supporting `limitations` remain material even on a
completed chain.

Route-security v3 is an explicit compatibility boundary. A v1 or v2 route baseline compared with
v3 is `not_comparable / route_schema_changed`; it cannot produce `unchanged`, `fixed` or `removed`.
Create a new v3 baseline before relying on route-regression comparison.

## Standards mapping boundary

The review is relevant to OWASP API Security Top 10 API1:2023 (Broken Object Level Authorization)
and API5:2023 (Broken Function Level Authorization), plus CWE-639 (Authorization Bypass Through
User-Controlled Key), CWE-862 (Missing Authorization) and CWE-863 (Incorrect Authorization). These
labels help route a review; they do not declare OWASP compliance, CWE-complete detection, a confirmed
weakness or coverage of every route, policy engine, ORM or runtime authorization path.

## Verify before changing access control

For a meaningful review lead, establish the intended policy first. Ask which roles may use the
operation, whether records may be shared, and whether support/admin/service flows intentionally
cross ownership boundaries. Then use only owner-controlled test data:

1. unauthenticated request or action invocation;
2. owner account accessing its own record;
3. second owner-controlled account attempting the first account's record;
4. lower-role account attempting a higher-role operation;
5. normal sharing, admin, support and background-job flows that the proposed change could break.

State the evidence precisely: for example, "the route-selected project ID reaches
`prisma.project.update` through two exact local call edges, and no supported principal/tenant query
constraint or post-load comparison was observed in that bounded path." Do not shorten this to
"confirmed IDOR" without an authorized runtime reproduction and the product policy needed to
interpret it.

## Proposal boundary

Prefer enforcing ownership or tenant scope in the data operation or a shared policy layer rather
than scattering handler-level comparisons. Before applying a change, record:

- the intended access rule and exceptions;
- the smallest affected source boundary;
- possible loss of legitimate sharing, delegation, support or admin behavior;
- data/index/query-plan effects when adding a constraint;
- security and normal-behavior retests;
- an observable rollback condition and rollback action.

Require explicit owner approval before changing authentication or authorization behavior. Follow
`references/explanation-repair-workflow.md` for repair-state and retest handling.
