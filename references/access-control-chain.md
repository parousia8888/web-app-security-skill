# Access-control chain review

Use this reference after a built-in audit produces `route-security.json` and
`route-security.md`. It explains how to turn static access-control evidence into a bounded human
review. It does not authorize live testing and does not prove a BOLA/IDOR vulnerability.

## Read the artifact in this order

1. Read framework and action coverage. Any partial or incomplete reason limits every downstream
   conclusion for the affected file or relationship.
2. Read application controls once. A Nest `APP_GUARD` or unresolved application middleware is an
   application fact; do not repeat it as proof that every route authenticates or authorizes.
3. Review state-changing or object-addressed routes with
   `no_route_scoped_control_observed`. Classify expected-public login, registration, recovery and
   webhook routes before proposing a change.
4. Review partial access chains, especially when a caller-selected identifier reaches a supported
   data operation and no principal or tenant constraint was observed in the bounded path.
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

- `principal_constraint_observed`: a supported operation visibly includes an identity-derived
  principal or tenant constraint. Runtime reachability, policy correctness and complete coverage
  are still not proven.
- `external_policy_required`: source evidence alone cannot settle the decision. Supabase always
  retains this state because Postgres RLS and deployed policy behavior are external.
- `principal_constraint_not_observed`: the bounded path did not show a supported constraint. This
  is a review lead, not proof that no check exists elsewhere.
- `no_supported_object_operation`: no supported object operation completed the bounded chain.
- `incomplete`: parsing, module resolution, argument mapping, dynamic behavior or the one-hop limit
  stopped the analysis. Never turn this into a clean result.

The analyzer follows at most one exact project-local call. It maps only direct arguments to direct
identifier parameters and stops before a second local edge. It can resolve one unambiguous source
target through relative imports, nearest static `tsconfig.json`/`jsconfig.json` path mappings or an
exact workspace package export. Missing, ambiguous, escaping and unbuilt-only targets fail closed.

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
`prisma.project.update` through one resolved local call, and no identity-derived constraint was
observed in that operation." Do not shorten this to "confirmed IDOR" without an authorized runtime
reproduction and the product policy needed to interpret it.

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
