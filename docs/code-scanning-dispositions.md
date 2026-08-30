# Code scanning dispositions

Owner: `@parousia8888`

Last reviewed: 2026-08-30 after v0.8.1 candidate analysis

This ledger records the evidence behind each GitHub CodeQL alert. A successful CodeQL workflow does
not mean that the alert list is empty, and a dismissal does not mean that the matched code is safe.
Live alert state is re-read through the GitHub API before release.

| Alert | Rule | Path | Current classification | Evidence and action | Revisit condition |
|---:|---|---|---|---|---|
| 11 | `js/incomplete-sanitization` | `test/route-security-v3-renderer-baseline.test.mjs` | Test-only controlled regex construction; dismissed as `used in tests` | The values are a fixed in-file phrase corpus used only to assert report ordering. No project or report value reaches `RegExp`. Retain the renderer escaping assertions. | Reopen if any phrase becomes project-controlled or the helper moves into production. |
| 10 | `js/incomplete-sanitization` | `scripts/lib/js-ts-module-graph.mjs` | Fixed by v0.8.1 candidate analysis | Node export RHS now replaces every wildcard literally. GitHub marked the alert fixed on candidate analysis; it was not dismissed. | Any surviving or recurring alert blocks release. |
| 9 | `js/incomplete-sanitization` | `scripts/lib/js-ts-module-graph.mjs` | Fixed by v0.8.1 candidate analysis | TypeScript config validation retains its one-wildcard invariant and the resolver uses a literal helper. GitHub marked the alert fixed; it was not dismissed. | Reopen if validation widens or the CodeQL alert recurs. |
| 8 | `js/incomplete-sanitization` | `scripts/lib/route-security-renderer.mjs` | Fixed production alert | Current GitHub state is `fixed`; route rendering tests retain Markdown escaping and hostile input cases. | Reopen on recurrence. |
| 7 | `js/client-exposed-cookie` | `test/fixtures/js-ts-rules/vulnerable.tsx` | Deliberately vulnerable detector fixture; dismissed as `used in tests` | The file is the planted positive case for the cookie rule and is excluded from repository production self-audit. | Reopen if imported by production or no longer asserted by the rule corpus. |
| 6 | `js/clear-text-cookie` | `test/fixtures/js-ts-rules/vulnerable.tsx` | Deliberately vulnerable detector fixture; dismissed as `used in tests` | Same planted positive fixture; its insecure cookie options are the intended observation. | Reopen if imported by production or fixture ownership changes. |
| 5 | `js/cors-permissive-configuration` | `test/fixtures/js-ts-rules/vulnerable.tsx` | Deliberately vulnerable detector fixture; dismissed as `used in tests` | The credentialed wildcard object is the intended positive CORS fixture and is excluded from production self-audit. | Reopen if imported by production or fixture ownership changes. |
| 4 | `js/bad-tag-filter` | `test/report-v3-contract.test.mjs` | Test-only hostile-output assertion; dismissed as `used in tests` | The regex checks that rendered output does not contain a planted raw tag. Production HTML output is separately asserted to escape `<script>`. | Reopen if the expression moves into production sanitization. |
| 3 | `js/bad-tag-filter` | `test/report-v3-contract.test.mjs` | Test-only hostile-output assertion; dismissed as `used in tests` | Same fixed assertion corpus as alert 4; it is not used to sanitize output. | Reopen if the expression moves into production sanitization. |
| 2 | `js/reflected-xss` | `test/sitemap-evidence.test.mjs` | Deliberately unsafe local HTTP fixture; dismissed as `used in tests` | The loopback fixture reflects a test request into HTML so sitemap/canonical extraction can be exercised. It is not shipped in the npm package or repository production scope. | Reopen if the server becomes non-loopback, shipped or reusable production code. |
| 1 | `js/incomplete-sanitization` | `test/version-consistency.test.mjs` | Test-only repository metadata regex; dismissed as `used in tests` | The value comes from the repository `VERSION` file and is used only by a CI consistency assertion. Refactoring production inputs cannot reach this expression. | Reopen if untrusted runtime input reaches the expression. |

The test/fixture dismissals were executed only after this ledger reached `main`. Candidate CodeQL
analysis closed production alerts 9 and 10 as fixed; neither was manually dismissed. The live open
CodeQL count was zero at the recorded post-candidate readback. Dismissal remains a classification,
not proof that a matched pattern is generally safe.
