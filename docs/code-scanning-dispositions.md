# Code scanning dispositions

Owner: `@parousia8888`

Last reviewed: 2026-08-30

This ledger records the evidence behind each GitHub CodeQL alert. A successful CodeQL workflow does
not mean that the alert list is empty, and a dismissal does not mean that the matched code is safe.
Live alert state is re-read through the GitHub API before release.

| Alert | Rule | Path | Current classification | Evidence and action | Revisit condition |
|---:|---|---|---|---|---|
| 11 | `js/incomplete-sanitization` | `test/route-security-v3-renderer-baseline.test.mjs` | Test-only controlled regex construction; dismissal pending | The values are a fixed in-file phrase corpus used only to assert report ordering. No project or report value reaches `RegExp`. Retain the renderer escaping assertions. | Reopen if any phrase becomes project-controlled or the helper moves into production. |
| 10 | `js/incomplete-sanitization` | `scripts/lib/js-ts-module-graph.mjs` | Confirmed production correctness bug | Node export RHS currently replaces one wildcard although Node replaces all instances. Fix and require the alert to close on the v0.8.1 commit. | Any surviving or recurring alert blocks release. |
| 9 | `js/incomplete-sanitization` | `scripts/lib/js-ts-module-graph.mjs` | Production code with a separately proved one-wildcard invariant; disposition pending code change | TypeScript config validation rejects patterns or targets containing more than one wildcard. Refactor to a literal one-wildcard helper and retain the invalid-second-wildcard test before closing or dismissing. | Reopen if validation widens or the CodeQL alert remains unexplained. |
| 8 | `js/incomplete-sanitization` | `scripts/lib/route-security-renderer.mjs` | Fixed production alert | Current GitHub state is `fixed`; route rendering tests retain Markdown escaping and hostile input cases. | Reopen on recurrence. |
| 7 | `js/client-exposed-cookie` | `test/fixtures/js-ts-rules/vulnerable.tsx` | Deliberately vulnerable detector fixture; dismissal pending | The file is the planted positive case for the cookie rule and is excluded from repository production self-audit. | Reopen if imported by production or no longer asserted by the rule corpus. |
| 6 | `js/clear-text-cookie` | `test/fixtures/js-ts-rules/vulnerable.tsx` | Deliberately vulnerable detector fixture; dismissal pending | Same planted positive fixture; its insecure cookie options are the intended observation. | Reopen if imported by production or fixture ownership changes. |
| 5 | `js/cors-permissive-configuration` | `test/fixtures/js-ts-rules/vulnerable.tsx` | Deliberately vulnerable detector fixture; dismissal pending | The credentialed wildcard object is the intended positive CORS fixture and is excluded from production self-audit. | Reopen if imported by production or fixture ownership changes. |
| 4 | `js/bad-tag-filter` | `test/report-v3-contract.test.mjs` | Test-only hostile-output assertion; dismissal pending | The regex checks that rendered output does not contain a planted raw tag. Production HTML output is separately asserted to escape `<script>`. | Reopen if the expression moves into production sanitization. |
| 3 | `js/bad-tag-filter` | `test/report-v3-contract.test.mjs` | Test-only hostile-output assertion; dismissal pending | Same fixed assertion corpus as alert 4; it is not used to sanitize output. | Reopen if the expression moves into production sanitization. |
| 2 | `js/reflected-xss` | `test/sitemap-evidence.test.mjs` | Deliberately unsafe local HTTP fixture; dismissal pending | The loopback fixture reflects a test request into HTML so sitemap/canonical extraction can be exercised. It is not shipped in the npm package or repository production scope. | Reopen if the server becomes non-loopback, shipped or reusable production code. |
| 1 | `js/incomplete-sanitization` | `test/version-consistency.test.mjs` | Test-only repository metadata regex; dismissal pending | The value comes from the repository `VERSION` file and is used only by a CI consistency assertion. Refactoring production inputs cannot reach this expression. | Reopen if untrusted runtime input reaches the expression. |

Dismissal is executed only after this ledger is present on the candidate branch. Alerts 9 and 10
remain release blockers until their P6 code outcomes are complete.
