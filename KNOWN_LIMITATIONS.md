# Known limitations

This file records current product limits and recurring review cases. A clean report means that no
configured rule produced a retained finding within the recorded scope. It does not establish that a
Web application is secure.

## Built-in detection

| Limitation | What users may observe | Current behavior | Required follow-up |
|---|---|---|---|
| Pattern analysis, not whole-program data flow | A dangerous API match can be safe because its input is constant or already sanitized; a vulnerability can be missed when its source and sink are connected indirectly. | Most source matches remain `suspected`; evidence text states that reachability and untrusted input flow were not proved. | Review the call path, trust boundary, sanitization and deployed configuration. Use a pinned external SAST adapter when deeper language coverage is needed. |
| Narrow built-in language depth | JavaScript/TypeScript and Python Web patterns receive the deepest built-in checks. Java, Go, Ruby, PHP, Rust and other code may receive only manifest/configuration checks. | Unsupported source is not counted as scanned language coverage. The report limitations name the checks that did not run. | Select supported external adapters or perform agent-guided review using the phase references. |
| Bounded hand-written tokenizers and analysis budgets | Valid but unusual JS/TS, TSX or Python syntax may not be understood. Binary/NUL content, unsupported encodings, unusually dense token streams or repeated nested scans can stop analysis. | Per-file token and operation budgets plus a whole-run operation budget are recorded in traversal metadata. Parse failures or `source_token_limit`, `source_operation_limit` and `source_global_operation_limit` make the affected coverage partial or unavailable and produce `source-evidence-incomplete / unknown`; they are never treated as a pass. | Confirm that the file is intended source, normalize its encoding, exclude generated output through the documented source layout, or reduce the pathological construct before rerunning. Report a minimized valid-syntax reproducer when ordinary source still fails. |
| Explicit exclusions versus failed evidence | User-selected scope exclusions and known generated/vendor directories can be absent from analysis, while a parser, encoding, size or budget failure can stop an otherwise eligible file. | Coverage records discovered, eligible, scanned, excluded and failed work separately. An explicit policy exclusion does not automatically make the run partial; analyzer-generated ambiguity or failed eligible evidence does. Neither class is counted as scanned. | Review exclusion reasons and counts before relying on a clean result. Remove an accidental production-source exclusion; fix or separately inspect files whose analysis failed. |
| Bounded pnpm workspace parsing | The parser supports the `packages:` list, `!` exclusions and the documented `*`/`**` package patterns. It is not a general YAML evaluator and does not execute tags, aliases or custom types. | Unreadable or uninterpretable workspace metadata becomes `pnpm_workspace_parse_error` and partial coverage. It cannot produce a confirmed missing-lockfile conclusion. | Validate `pnpm-workspace.yaml` with pnpm and simplify or report unsupported valid syntax. |
| File-read scope has strict roots | A custom source root that is missing, unreadable, a symlink, outside the project or otherwise invalid stops before report creation. This fail-closed path does not currently emit a report-level `unknown` artifact. | Built-in, route, diff and selected adapter reads share one compiled scope; mandatory engine exclusions remain active. Governing manifests/lockfiles may still be read when they control an admitted nested root. | Correct the versioned `security-scope.yml` boundary and rerun. Do not describe an aborted run as clean or checked. |
| Restricted Gitleaks history is unavailable | Exact path-bounded historical object reads have not been demonstrated under the file-read contract. | A restricted history request returns `unknown / history_scope_not_supported` instead of scanning all history and post-filtering findings. Full-scope history and restricted working-tree snapshots are separate modes. | Use working-tree mode for the narrow scope, widen the authorized scope explicitly, or perform a separately governed history review. |
| Suppression is policy, not validation | An exact reviewed match can be kept out of a configured gate, but static evidence cannot prove that the accepted condition is safe or remains unreachable. | Every renderer retains the finding, evidence state and suppression metadata. Drift, expiry, malformed policy, unmatched entries, unknown evidence and evidence-integrity findings remain active or unavailable. | Review suppressions on expiry and code change. Remove the entry after the condition is fixed; use runtime evidence when safety depends on reachability or data flow. |
| Conditional Node exports can remain ambiguous | Multiple supported conditions may resolve one specifier to different existing source files. Runtime condition selection is outside the bounded static model. | All branches are inspected, but a unique target is retained only when their source identity agrees. Divergence remains partial instead of choosing a convenient branch. | Inspect the runtime/build conditions and named candidate files manually. Do not interpret a partial path as absent. |
| File-local evidence states | A literal such as `rejectUnauthorized: false` is a strong file-local observation, while production reachability is still unknown. | Pattern matches remain `suspected`. Only the supported missing-lockfile absence and the exact Git-index fact that a sensitive `.env` filename is tracked can produce `confirmed`; neither proves a live vulnerability. | Read `evidenceBoundary` before prioritizing. Do not translate `suspected` or a narrow confirmed fact into “confirmed exploitable vulnerability.” |
| Equivalent-condition retest matching | A unique rule/snippet can disappear from one path and appear at another because of a rename, a move, or an unrelated delete-plus-add. Static evidence cannot prove object identity. | The condition remains non-fixed and preserves its prior fingerprint; ambiguous duplicates are not paired. | Review the old and new paths before describing causality or author intent. |

## Route-security review

The current route and access-control inventory parses supported JavaScript and TypeScript with a pinned bundled
`@babel/parser`, but framework semantics remain deliberately narrow. The parser understanding a
file does not mean every framework registration or authorization relationship in that file is
understood.

| Limitation | What users may observe | Current behavior | Required follow-up |
|---|---|---|---|
| Express factory, mount and registration boundary | Routes registered through an aliased app object, a computed mount, a dynamic wrapper or an unresolved router relationship can be absent. | Stable syntax includes variable-bound ESM/CommonJS `express()` and `Router()`, direct `require('express').Router()`, inline route calls, exact static router mounts and exact `app.use('/prefix', require('./local-router'))`. When an imported local registration function is invoked with a recognized Express receiver and structurally contains route/middleware registration, the unsupported relationship becomes `express_registration_function_unresolved`, partial coverage and `js-route-security-evidence-incomplete / unknown`; it cannot return a clean route result. | Read the route coverage reasons and manually inspect the named registration function. Do not treat the inventory as exhaustive when Express coverage is partial. |
| NestJS decorator and application-control boundary | Computed controller or method paths, custom decorator composition and runtime global guards may not resolve. An `APP_GUARD` can exist without applying the expected policy to every route. | Static controller/method decorators, static controller option paths and supported Passport/custom guard syntax are stable. Application guards are listed once and are never copied into every route as authentication/authorization proof. | Review dynamic decorators, global module configuration, exemptions and runtime guard behavior in project context. |
| Next.js App Router and Server Action export boundary | Wrapper/re-export patterns can hide route handlers or actions; an action has no static HTTP URL to report. Middleware/proxy matchers can also be dynamic or broader/narrower than a route tree. | Direct named route exports and direct static async Server Actions with supported `"use server"` placement are represented separately. Middleware/proxy participation is application context only and never copied into route authentication or authorization evidence. Unsupported exports or matchers produce partial coverage; the tool never invents an action URL or route enforcement relationship. | Inspect named unresolved files/exports, middleware/proxy matcher behavior and the framework invocation path; record missing surfaces manually. |
| Control signal is not control proof | Passport, a custom auth helper, middleware or a guard can be visible while its runtime behavior, order and policy remain unknown. | Authentication, route authorization and unclassified route controls are separate. An unclassified control remains review context and does not turn a bare route into classified coverage. `no_route_scoped_control_observed` is a review state, not a vulnerability. Application controls stay application-scoped. | Verify runtime middleware order, identity binding, role semantics, intentional public routes and data-layer owner/tenant constraints. |
| Priority is not severity | Public login, registration, recovery, status and badge routes can be ranked early because they change state or contain an identifier. | `review_first`/`review_next`/`review_later` order human work; it does not assert a vulnerability or CVSS severity. `router.all` is conservatively treated as potentially state-changing. | Close expected-public routes with project evidence and review abuse controls separately. |
| Bounded identity providers | Custom wrappers, renamed response shapes and runtime provider configuration can hide or change identity semantics. | Auth.js and existing Nest Passport evidence are stable bounded. Clerk, Better Auth and Supabase identity are experimental. Same-name local helpers are not accepted as provider evidence. | Trace the real session/caller binding and verify unauthenticated, owner and lower-role behavior. |
| Bounded interprocedural data-operation chain | Dynamic dispatch, computed exports, callbacks, collection indexing, arbitrary destructuring/transforms, unresolved return mappings, cycles and a fifth local call can stop the chain. Workspace exports that point only to unbuilt `dist` files are not guessed back to source. | Exact route/query/body/Server Action selectors and object/principal/tenant facts can cross at most four exact project-local call edges. Relative imports, static tsconfig/jsconfig paths, exact workspace source exports and narrowly proved Vite/Prisma source relationships resolve only when one target exists; ambiguity, escapes and unsupported relationships become partial/incomplete evidence. | Continue the named call path manually. Do not treat no completed chain as a clean result, or a completed chain as proof of correct authorization. |
| Provider and policy boundary | A visible Prisma/Drizzle/Supabase operation does not prove runtime reachability or correct ownership policy. Database RLS is external to source-query evidence. | Prisma and Drizzle operations are stable bounded. Supabase Query Builder is experimental and always retains `external_policy_required`, even when a source constraint is visible. | Review deployed database policy and test with two owner-controlled accounts before making a BOLA/IDOR conclusion. |
| Authorization-evidence semantics | A query predicate may be necessary but insufficient, and a post-load comparison may be logged or may not dominate a denial branch. Static analysis cannot prove deployed control flow or product policy. | v3 distinguishes `query_predicate`, `post_load_comparison`, `authorization_constraint_not_observed` and `incomplete`. A supported exact comparison is evidence that the expression exists, not that denial is enforced on every path. | Inspect the decision branch and test unauthenticated, owner, non-owner, lower-role and intended sharing/admin flows with owner-controlled data. |
| Route baseline compatibility | v3 adds ordered call edges, typed authorization evidence and independent access-path coverage, so v1/v2 fingerprints and regression meanings are not equivalent. | v1/v2-to-v3 comparison is always `not_comparable / route_schema_changed`; it cannot emit `unchanged`, `fixed` or `removed`. | Establish a new v3 baseline before interpreting `--fail-on-route-regression`. Keep the historical artifact for provenance only. |

`accessChains` in `route-security.json` and the matching Markdown section are the only public
authorization-analysis output. Experimental Clerk, Better Auth and Supabase support adds bounded
records to that same surface; no separate experimental finding stream is implied. Principal and
tenant field names use one shared vocabulary, but a matching name still does not prove that the
value is the authenticated caller or that the runtime query is authorized.

The [v0.7.0 four-project review](docs/reviews/v0.7.0-access-control-review.md) is historical v0.7.0
evidence: it inventories 173 HTTP
routes and 23 Server Actions and manually reviews 32 entries. It produced 12 partial chains and zero
completed ordinary-project chains. This purposive sample exposes current reach and limits; it is not
a production precision/recall measurement and does not assert current-candidate analyzer behavior.

The [v0.8.0 fixed-commit review](docs/reviews/v0.8.0-access-control-review.md) completed 13 of 14
frozen eligible paths, retained `ACTION getMembershipRole` as the sole partial miss and kept four
completed paths with supporting limitations. The author-selected denominator and manual review do
not measure production precision/recall, exploitability or framework-wide coverage.

## Evidence-output redaction

Technical evidence is recursively sanitized before JSON, Markdown, HTML, SARIF, JUnit and
additional report-bundle artifacts are written. Credential nouns are normalized across camelCase,
snake_case and kebab-case and common singular/plural forms. High-confidence GitHub, Slack, AWS,
Google, API-key and JWT formats are also removed from free text. Generic `key`/`keys` metadata stays
visible, and the two documented authorization-evidence object shapes remain readable. Finite scalar
usage counters under a narrow allowlist, such as `usage.tokens`, remain numeric; arrays, non-finite
values and credential-shaped keys do not inherit that exception.

This is bounded leak prevention, not a general secret scanner. A proprietary credential format,
an encoded or split secret, or a value stored under an unrelated generic field can remain unless a
high-confidence value pattern recognizes it. Strings are capped at 4,096 characters and arrays and
objects at 200 entries/keys; report producers must not use technical evidence as a raw data-export
channel. Review reports before external sharing and use Gitleaks or another dedicated scanner on
the intended shareable files when the consequence of disclosure is high.

## Incremental audit

`--since` and `--staged` are built-in source-audit noise filters. They do not run external adapters,
cannot be combined with baseline/retest comparison, and do not establish whole-repository safety.
`--since` excludes untracked files because Git has no diff record for them. `--staged` scans the Git
index snapshot and therefore excludes unstaged content by design.

## Deep profile

`--profile deep` expands to the built-in detector plus Checkov, Gitleaks, Opengrep and OSV-Scanner.
The CLI does not download those tools. A missing, incompatible, timed-out or failed adapter produces
`unknown` findings and exit 3 even with `--fail-on never`; this means evidence is incomplete, not
that a vulnerability gate fired. Deep mode cannot be combined with `--adapter`, `--since` or
`--staged` in v0.5.4. Checkov and OSV-Scanner can perform the network behavior documented below
when their installed binaries run.

## Rule-contract conformance interpretation

The rule-contract conformance suite uses author-maintained planted examples. Its pass/fail results
answer whether each named built-in rule recognizes its declared positive example in the expected
evidence state and stays quiet on its declared safe neighbour. They do not measure whole-project
vulnerability precision or recall, production reachability, exploitability, language coverage or
the agent-guided methodology. The [historical real-world regression corpus](docs/regressions/v0.5.4-real-world-regressions.md)
guards named minimized failures, while ordinary-project review remains a separate evidence set;
neither is a representative accuracy benchmark.

## MCP and future rule expansion

No MCP server ships in the published v0.8.1 release. npm/npx, the ordinary CLI and the Claude plugin invoke the current
runtime. The current count is 25 built-in risk rules, three evidence-integrity rules and 16 external
adapter risk rules. The documented architecture gates require a permission model and client
evidence for MCP, and positive/negative fixtures plus false-positive review for every future stable
rule.

## External adapters and runtime evidence

- Checkov, Gitleaks, Opengrep and OSV-Scanner remain explicitly selected, either individually or
  through `--profile deep`, and must be installed and version-pinned by the caller. An unavailable
  adapter produces incomplete evidence, never a pass.
- Source audit does not execute project dependencies, start the application or prove deployed
  reachability. API authorization, identity, LLM, database isolation and cloud runtime review remain
  agent-guided unless a named adapter explicitly records otherwise.
- The CLI proposes review steps and patches but does not edit the target project. Functional side
  effects still require owner approval and product-specific tests.
- Repository test evidence records every intended file and declared platform/plugin surface as
  `passed`, `failed`, `skipped` or `not_run`. A missing real adapter or Claude CLI is a visible skip
  or partial distribution result; it is not rewritten as a pass.

## Repository self-audit and release governance

The required repository self-audit is intentionally production-scoped and keeps reviewed exact
suppression dispositions visible. A green job proves only that the bounded built-in run had no
active HIGH or unavailable evidence under the checked policy. It is not independent review,
production precision evidence or a substitute for CodeQL, dependency alerts and human review.

Release publication trusts protected `main` for its verifier and signer policy, but the configured
solo-maintainer administrator bypass remains a residual governance boundary. It avoids a false
second-reviewer claim and does not protect against maintainer-account compromise. The moving `v1`
tag is convenient and explicitly passes through pending/final states; full commit pins remain the
immutable Action choice.

## Recurring expected matches

These are review classes, not blanket suppressions:

- DOM sinks can be intentional when content is constant or a reviewed sanitizer dominates the sink.
- Command-execution APIs can be safe for constant commands while still deserving review at the
  boundary where user-controlled arguments enter.
- Debug, permissive CORS or TLS options can exist only in tests or local development; the built-in
  rule does not prove which configuration reaches production.
- Security-named literals can be placeholders or test fixtures. The tool records redacted length
  bands and does not test credential validity.
- A tracked sensitive `.env` filename confirms only Git index membership. The file may contain
  placeholders, and current-index evidence does not establish history, publication or live values.
- Session-secret, cookie and CSRF-disable matches can belong to test-only or overridden settings;
  review the resolved production configuration and affected browser authentication flow.
- Missing application security headers can be supplied by a reverse proxy or CDN that source audit
  cannot see. Verify the deployed edge before closing the finding.

## Resolved regressions

The following are historical and covered by machine regressions; they are not current limitations:

| Version fixed | Regression | Guard |
|---|---|---|
| 0.5.2 | pnpm workspace packages covered by the root lockfile could be marked confirmed missing-lockfile facts. | Workspace include/exclude, deep-glob and malformed-metadata regressions. |
| 0.5.2 | v3 Markdown/HTML risk summaries rendered `[object Object]`. | Golden Markdown and HTML summary assertions. |
| 0.5.2 | Nested SSR/TSX template literals could stop analysis of the whole file. | Nested-template and executable-expression tokenizer regressions. |
| 0.5.2 | A pure path rename could appear as `fixed + new`. | Unique equivalent-condition and ambiguous-duplicate retest regressions. |
| 0.6.0 | Static NestJS controller option paths could be emitted at false root paths; a dynamic prefix could also be dropped and guessed. | Static option-path/array and dynamic-prefix-null route regressions. |
| 0.6.0 | Unrelated import gaps could pollute route coverage, while unresolved Next handler re-exports could disappear without route-specific incomplete evidence. | Route-relevance isolation and Next re-export fail-closed regressions. |
| 0.6.0 | Route reason counts could describe internal relationship events instead of affected inputs, and Express `all` could be ranked as read-only. | Coverage reason-budget and `ALL` state-change priority regressions. |
| 0.7.0 | A Nest application-level rate-limit guard could be copied onto every route as both authentication and authorization evidence, hiding routes with no route-scoped control. | Application-control-once, split auth/authz and `no_route_scoped_control_observed` regressions. |
| 0.7.0 | Access-chain fingerprints could collide, standard Next monorepo app roots could be missed, and exact tsconfig aliases could stop one-hop analysis. | Entry/call fingerprint, monorepo-root and bounded alias-resolution regressions. |
| 0.7.2 | Demo output could recursively delete an unowned directory, plural/camelCase credential keys could leak technical evidence, and two supported-looking Express shapes could return false-clean route coverage. | Ownership-marker deletion boundary, per-artifact secret sentinel, exact CommonJS route and imported registration-function fail-closed regressions. |
| 0.7.2 | Shipped JSON Schemas could drift from handwritten validators, and the v0.7.0 ordinary-review aggregate was independently hand-maintained. | Offline Ajv/manual overlap gate plus recomputed project aggregates and record/semantic digest regressions. |
| 0.7.3 | Deep member expressions and workspace patterns could abort analysis; persisted OSV lockfile paths could leave the project; supported-looking route shapes and unclassified controls could produce false-clean coverage. | Bounded expression/workspace handling, lexical and realpath containment, per-module isolation, framework-specific fail-closed route matrices and separated control roles. |
| 0.7.3 | Compound HTML sinks and Python string booleans were misclassified; project-controlled Markdown could alter report structure; journey, test and release lifecycle evidence could blur incomplete, skipped or pre-public states. | Typed literal/operator regressions, context-specific Markdown encoding, reproducible journey contracts, four-state test accounting and separate candidate/public/live release gates. |

Report new false-positive classes or minimized parser failures through
[GitHub Issues](https://github.com/parousia8888/web-app-security-skill/issues). The handling and
suppression policy is documented in [docs/false-positive-policy.md](docs/false-positive-policy.md).
