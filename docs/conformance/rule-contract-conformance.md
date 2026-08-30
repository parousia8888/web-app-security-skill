# v0.8.1 rule-contract conformance

> Author-maintained synthetic rule-contract conformance suite; it verifies declared planted examples. It does not measure production-vulnerability precision, recall, reachability, exploitability or security coverage.

Ruleset semantic digest: `562ca6837a5994b831e5b347263ca43eca6d152df2e69939ebda10ebc10ecf69`

## Contract results

| Group | Contracts | Positive passed | Positive failed | Negative passed | Negative failed | State mismatches |
|---|---:|---:|---:|---:|---:|---:|
| Risk detection | 25 | 25 | 0 | 25 | 0 | 0 |
| Evidence integrity | 3 | 3 | 0 | 3 | 0 | 0 |
| Combined | 28 | 28 | 0 | 28 | 0 | 0 |

A positive passes when the declared planted example emits the named rule in its expected
evidence state. A negative passes when the rule stays quiet on its declared safe neighbour.
These outcomes are rule-contract checks, not vulnerability accuracy measurements.

## Rule cases

| Rule | Kind | Expected state | Positive | Negative |
|---|---|---|---:|---:|
| `browser-html-injection-sink` | risk_detection | `suspected` | pass | pass |
| `cors-wildcard-with-credentials` | risk_detection | `suspected` | pass | pass |
| `dependency-lockfile-missing` | risk_detection | `confirmed` | pass | pass |
| `hardcoded-auth-secret` | risk_detection | `suspected` | pass | pass |
| `js-dynamic-code-execution` | risk_detection | `suspected` | pass | pass |
| `js-inline-session-secret` | risk_detection | `suspected` | pass | pass |
| `js-insecure-cookie-options` | risk_detection | `suspected` | pass | pass |
| `js-route-security-evidence-incomplete` | evidence_integrity | `unknown` | pass | pass |
| `jwt-unsafe-verification-options` | risk_detection | `suspected` | pass | pass |
| `node-child-process-shell-execution` | risk_detection | `suspected` | pass | pass |
| `node-inspector-public-bind` | risk_detection | `suspected` | pass | pass |
| `node-tls-verification-disabled` | risk_detection | `suspected` | pass | pass |
| `production-source-map-enabled` | risk_detection | `suspected` | pass | pass |
| `python-cors-wildcard-with-credentials` | risk_detection | `suspected` | pass | pass |
| `python-csrf-protection-disabled` | risk_detection | `suspected` | pass | pass |
| `python-dynamic-code-execution` | risk_detection | `suspected` | pass | pass |
| `python-framework-debug-enabled` | risk_detection | `suspected` | pass | pass |
| `python-hardcoded-framework-secret` | risk_detection | `suspected` | pass | pass |
| `python-insecure-session-cookie-settings` | risk_detection | `suspected` | pass | pass |
| `python-shell-command-execution` | risk_detection | `suspected` | pass | pass |
| `python-tls-verification-disabled` | risk_detection | `suspected` | pass | pass |
| `python-unsafe-deserialization` | risk_detection | `suspected` | pass | pass |
| `python-unsafe-yaml-load` | risk_detection | `suspected` | pass | pass |
| `react-dangerous-html-sink` | risk_detection | `suspected` | pass | pass |
| `sensitive-env-file-present` | risk_detection | `suspected` | pass | pass |
| `source-evidence-incomplete` | evidence_integrity | `unknown` | pass | pass |
| `source-stack-unsupported` | evidence_integrity | `unknown` | pass | pass |
| `tracked-sensitive-env-file` | risk_detection | `confirmed` | pass | pass |

Regenerate with `npm run conformance:rules`. CI uses the same runner with `--check` to
compare committed JSON and Markdown bytes.
