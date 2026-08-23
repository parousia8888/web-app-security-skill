# Rule taxonomy

<!-- Generated from scripts/lib/source-rule-registry.mjs and scripts/lib/crawl-rules.mjs. -->

Severity is interpreted inside the named risk domain. In particular, a HIGH
`search_discoverability` impact is not a HIGH `security_exposure`, and an
`evidence_integrity` severity describes the importance of missing evidence rather than a
confirmed product vulnerability.

Stable source inventory: 25 built-in risk rules,
2 built-in evidence-integrity rules and
16 external adapter risk rules.

## Stable source rules

| Rule | Adapter | Kind | Family | Languages | Domain | Severity / state | Standards |
|---|---|---|---|---|---|---|---|
| [`dependency-lockfile-missing`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `dependency_configuration` | `javascript`, `typescript`, `python` | `supply_chain` | `low` / `confirmed` | `NIST-SSDF-1.1-PS.3.2` |
| [`sensitive-env-file-present`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `secret_management` | `javascript`, `typescript`, `python` | `security_exposure` | `medium` / `suspected` | `CWE-798` |
| [`tracked-sensitive-env-file`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `secret_management` | `javascript`, `typescript`, `python` | `security_exposure` | `medium` / `confirmed` | `CWE-798`, `OWASP-TOP10-2025-A02` |
| [`node-inspector-public-bind`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `framework_exposure` | `javascript`, `typescript` | `security_exposure` | `high` / `suspected` | `CWE-489` |
| [`production-source-map-enabled`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `browser_output` | `javascript`, `typescript` | `security_exposure` | `medium` / `suspected` | `CWE-540` |
| [`js-dynamic-code-execution`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `injection_execution` | `javascript`, `typescript` | `security_exposure` | `high` / `suspected` | `CWE-95`, `OWASP-TOP10-2025-A05` |
| [`node-child-process-shell-execution`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `injection_execution` | `javascript`, `typescript` | `security_exposure` | `high` / `suspected` | `CWE-78`, `OWASP-TOP10-2025-A05` |
| [`react-dangerous-html-sink`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `browser_output` | `javascript`, `typescript` | `security_exposure` | `medium` / `suspected` | `CWE-79`, `OWASP-TOP10-2025-A05` |
| [`browser-html-injection-sink`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `browser_output` | `javascript`, `typescript` | `security_exposure` | `medium` / `suspected` | `CWE-79`, `OWASP-TOP10-2025-A05` |
| [`cors-wildcard-with-credentials`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `authentication_session` | `javascript`, `typescript` | `security_exposure` | `medium` / `suspected` | `CWE-942`, `OWASP-API-2023-API8` |
| [`node-tls-verification-disabled`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `transport` | `javascript`, `typescript` | `security_exposure` | `high` / `suspected` | `CWE-295`, `OWASP-TOP10-2025-A02` |
| [`jwt-unsafe-verification-options`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `authentication_session` | `javascript`, `typescript` | `security_exposure` | `high` / `suspected` | `CWE-347`, `OWASP-API-2023-API2` |
| [`hardcoded-auth-secret`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `secret_management` | `javascript`, `typescript` | `security_exposure` | `high` / `suspected` | `CWE-798`, `OWASP-TOP10-2025-A07` |
| [`js-inline-session-secret`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `secret_management` | `javascript`, `typescript` | `security_exposure` | `high` / `suspected` | `CWE-798`, `OWASP-TOP10-2025-A07` |
| [`js-insecure-cookie-options`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `authentication_session` | `javascript`, `typescript` | `security_exposure` | `medium` / `suspected` | `CWE-614`, `CWE-1004`, `OWASP-TOP10-2025-A07` |
| [`python-dynamic-code-execution`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `injection_execution` | `python` | `security_exposure` | `high` / `suspected` | `CWE-95`, `OWASP-TOP10-2025-A05` |
| [`python-shell-command-execution`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `injection_execution` | `python` | `security_exposure` | `high` / `suspected` | `CWE-78`, `OWASP-TOP10-2025-A05` |
| [`python-unsafe-deserialization`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `deserialization` | `python` | `security_exposure` | `high` / `suspected` | `CWE-502`, `OWASP-TOP10-2025-A08` |
| [`python-unsafe-yaml-load`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `deserialization` | `python` | `security_exposure` | `high` / `suspected` | `CWE-502`, `OWASP-TOP10-2025-A08` |
| [`python-tls-verification-disabled`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `transport` | `python` | `security_exposure` | `high` / `suspected` | `CWE-295`, `OWASP-TOP10-2025-A02` |
| [`python-framework-debug-enabled`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `framework_exposure` | `python` | `security_exposure` | `high` / `suspected` | `CWE-489`, `OWASP-TOP10-2025-A02` |
| [`python-hardcoded-framework-secret`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `secret_management` | `python` | `security_exposure` | `high` / `suspected` | `CWE-798`, `OWASP-TOP10-2025-A07` |
| [`python-cors-wildcard-with-credentials`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `framework_exposure` | `python` | `security_exposure` | `medium` / `suspected` | `CWE-942`, `OWASP-API-2023-API8` |
| [`python-insecure-session-cookie-settings`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `authentication_session` | `python` | `security_exposure` | `medium` / `suspected` | `CWE-614`, `CWE-1004`, `OWASP-TOP10-2025-A07` |
| [`python-csrf-protection-disabled`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `risk_detection` | `authentication_session` | `python` | `security_exposure` | `high` / `suspected` | `CWE-352`, `OWASP-TOP10-2025-A01` |
| [`source-stack-unsupported`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `evidence_integrity` | `deployment_configuration` | `javascript`, `typescript`, `python` | `evidence_integrity` | `info` / `unknown` | None |
| [`source-evidence-incomplete`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/stable-source-rules.json) | `builtin-source@1.1.0` | `evidence_integrity` | `deployment_configuration` | `javascript`, `typescript`, `python` | `evidence_integrity` | `high` / `unknown` | None |
| [`checkov-dockerfile-root-user`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `checkov@3.3.9` | `risk_detection` | `deployment_configuration` | `dockerfile` | `security_exposure` | `medium` / `suspected` | `CWE-250`, `OWASP-TOP10-2025-A02` |
| [`checkov-dockerfile-healthcheck-missing`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `checkov@3.3.9` | `risk_detection` | `deployment_configuration` | `dockerfile` | `security_exposure` | `low` / `suspected` | `OWASP-TOP10-2025-A02` |
| [`checkov-github-actions-write-all`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `checkov@3.3.9` | `risk_detection` | `deployment_configuration` | `yaml` | `supply_chain` | `high` / `suspected` | `CWE-250`, `OWASP-TOP10-2025-A03` |
| [`gitleaks-committed-secret`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `gitleaks@8.30.1` | `risk_detection` | `secret_management` | `any` | `supply_chain` | `high` / `suspected` | `CWE-798` |
| [`gitleaks-working-tree-secret`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `gitleaks@8.30.1` | `risk_detection` | `secret_management` | `any` | `supply_chain` | `high` / `suspected` | `CWE-798` |
| [`opengrep-js-request-command-flow`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `opengrep@1.27.0` | `risk_detection` | `injection_execution` | `javascript`, `typescript` | `security_exposure` | `high` / `suspected` | `CWE-78`, `OWASP-TOP10-2025-A05` |
| [`opengrep-python-request-command-flow`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `opengrep@1.27.0` | `risk_detection` | `injection_execution` | `python` | `security_exposure` | `high` / `suspected` | `CWE-78`, `OWASP-TOP10-2025-A05` |
| [`opengrep-js-request-sql-flow`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `opengrep@1.27.0` | `risk_detection` | `injection_execution` | `javascript`, `typescript` | `security_exposure` | `high` / `suspected` | `CWE-89`, `OWASP-TOP10-2025-A05` |
| [`opengrep-python-request-sql-flow`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `opengrep@1.27.0` | `risk_detection` | `injection_execution` | `python` | `security_exposure` | `high` / `suspected` | `CWE-89`, `OWASP-TOP10-2025-A05` |
| [`opengrep-js-request-ssrf-flow`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `opengrep@1.27.0` | `risk_detection` | `injection_execution` | `javascript`, `typescript` | `security_exposure` | `high` / `suspected` | `CWE-918`, `OWASP-TOP10-2025-A01` |
| [`opengrep-python-request-ssrf-flow`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `opengrep@1.27.0` | `risk_detection` | `injection_execution` | `python` | `security_exposure` | `high` / `suspected` | `CWE-918`, `OWASP-TOP10-2025-A01` |
| [`opengrep-js-request-path-flow`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `opengrep@1.27.0` | `risk_detection` | `file_path` | `javascript`, `typescript` | `security_exposure` | `high` / `suspected` | `CWE-22`, `OWASP-TOP10-2025-A01` |
| [`opengrep-python-request-path-flow`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `opengrep@1.27.0` | `risk_detection` | `file_path` | `python` | `security_exposure` | `high` / `suspected` | `CWE-22`, `OWASP-TOP10-2025-A01` |
| [`opengrep-js-request-redirect-flow`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `opengrep@1.27.0` | `risk_detection` | `authentication_session` | `javascript`, `typescript` | `security_exposure` | `medium` / `suspected` | `CWE-601`, `OWASP-TOP10-2025-A01` |
| [`opengrep-python-request-redirect-flow`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `opengrep@1.27.0` | `risk_detection` | `authentication_session` | `python` | `security_exposure` | `medium` / `suspected` | `CWE-601`, `OWASP-TOP10-2025-A01` |
| [`osv-known-vulnerability`](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/adapter-protocol.md) | `osv@2.5.0` | `risk_detection` | `dependency_configuration` | `any` | `supply_chain` | `info` / `suspected` | `CWE-1104` |

The machine-readable source contract is [`stable-source-rules.json`](stable-source-rules.json).

## Crawl rules

| Rule | Domain | Severity | Rationale |
|---|---|---|---|
| `robots-group-not-inherited` | `search_discoverability` | `medium` | Published discovery directives disagree and can produce inconsistent crawler behavior. |
| `robots-no-wildcard-group` | `search_discoverability` | `low` | The policy is ambiguous or non-portable but does not by itself block intended content. |
| `robots-duplicate-groups` | `search_discoverability` | `low` | The policy is ambiguous or non-portable but does not by itself block intended content. |
| `robots-blocks-search-crawler` | `search_discoverability` | `high` | Intended public content or its discovery path is blocked from search or AI retrieval. |
| `robots-blocks-user-fetcher` | `search_discoverability` | `medium` | A user-triggered assistant fetch is blocked. |
| `robots-no-sitemap` | `search_discoverability` | `medium` | Discovery remains possible but is slower, indirect, or unnecessarily redirected. |
| `robots-uses-dollar-anchor` | `search_discoverability` | `info` | A directive is not interpreted consistently across crawler implementations. |
| `robots-missing` | `search_discoverability` | `medium` | No explicit crawl policy is published. |
| `robots-http-error` | `reliability` | `high` | The public policy endpoint fails at the origin. |
| `robots-fetch-unknown` | `evidence_integrity` | `high` | A required input could not be obtained or interpreted; severity describes the importance of the evidence gap, not a confirmed vulnerability. |
| `llms-external-urls` | `search_discoverability` | `info` | Metadata quality affects inventory or canonicalization without proving lost availability. |
| `llms-lists-disallowed-urls` | `search_discoverability` | `medium` | Published discovery directives disagree and can produce inconsistent crawler behavior. |
| `llms-fetch-unknown` | `evidence_integrity` | `low` | An optional evidence source was unavailable. |
| `sitemap-parse-unknown` | `evidence_integrity` | `high` | A required input could not be obtained or interpreted; severity describes the importance of the evidence gap, not a confirmed vulnerability. |
| `sitemap-fetch-unknown` | `evidence_integrity` | `high` | A required input could not be obtained or interpreted; severity describes the importance of the evidence gap, not a confirmed vulnerability. |
| `sitemap-unreachable` | `search_discoverability` | `high` | Intended public content or its discovery path is blocked from search or AI retrieval. |
| `sitemap-disallowed` | `search_discoverability` | `high` | Intended public content or its discovery path is blocked from search or AI retrieval. |
| `sitemap-empty` | `search_discoverability` | `high` | Intended public content or its discovery path is blocked from search or AI retrieval. |
| `sitemap-url-fetch-unknown` | `evidence_integrity` | `medium` | A bounded content sample could not be evaluated. |
| `sitemap-url-5xx` | `reliability` | `high` | An intended public page or baseline response is unavailable. |
| `sitemap-url-404` | `search_discoverability` | `high` | A URL advertised for indexing is missing. |
| `sitemap-url-redirect` | `search_discoverability` | `medium` | Discovery remains possible but is slower, indirect, or unnecessarily redirected. |
| `sitemap-url-noindex` | `search_discoverability` | `high` | Intended public content or its discovery path is blocked from search or AI retrieval. |
| `sitemap-url-disallowed` | `search_discoverability` | `high` | Intended public content or its discovery path is blocked from search or AI retrieval. |
| `thin-initial-html` | `search_discoverability` | `medium` | Crawler-visible content differs or lacks enough initial content for dependable retrieval. |
| `missing-canonical` | `search_discoverability` | `low` | Metadata quality affects inventory or canonicalization without proving lost availability. |
| `baseline-fetch-failed` | `reliability` | `high` | An intended public page or baseline response is unavailable. |
| `matrix-baseline-unknown` | `evidence_integrity` | `high` | A required input could not be obtained or interpreted; severity describes the importance of the evidence gap, not a confirmed vulnerability. |
| `matrix-comparison-unavailable` | `evidence_integrity` | `high` | A required input could not be obtained or interpreted; severity describes the importance of the evidence gap, not a confirmed vulnerability. |
| `crawler-request-unknown` | `evidence_integrity` | `high` | A required input could not be obtained or interpreted; severity describes the importance of the evidence gap, not a confirmed vulnerability. |
| `crawler-blocked` | `search_discoverability` | `high` | Intended public content or its discovery path is blocked from search or AI retrieval. |
| `crawler-status-differs` | `search_discoverability` | `medium` | Crawler-visible content differs or lacks enough initial content for dependable retrieval. |
| `possible-cloaking` | `search_discoverability` | `medium` | Crawler-visible content differs or lacks enough initial content for dependable retrieval. |
| `public-page-noindex` | `search_discoverability` | `high` | Intended public content or its discovery path is blocked from search or AI retrieval. |
| `probe-baseline-unknown` | `evidence_integrity` | `high` | A required input could not be obtained or interpreted; severity describes the importance of the evidence gap, not a confirmed vulnerability. |
| `probe-request-unknown` | `evidence_integrity` | `high` | A required input could not be obtained or interpreted; severity describes the importance of the evidence gap, not a confirmed vulnerability. |
| `soft-404-catchall` | `reliability` | `medium` | Unknown routes return misleading success semantics. |
| `probe-soft-404` | `reliability` | `info` | An informational observation is summarized under another actionable rule. |
| `sensitive-file-exposed` | `security_exposure` | `high` | A public response matches sensitive configuration or credential material. |
| `probe-path-200` | `security_exposure` | `medium` | A private-looking path responds publicly but content sensitivity is not confirmed. |
| `probe-path-403` | `security_exposure` | `low` | The response discloses that a private-looking route exists. |
| `probe-summary` | `security_exposure` | `info` | An informational count records the bounded probe result. |
| `source-map-discovery-unknown` | `evidence_integrity` | `high` | A required input could not be obtained or interpreted; severity describes the importance of the evidence gap, not a confirmed vulnerability. |
| `source-map-check-unknown` | `evidence_integrity` | `high` | A required input could not be obtained or interpreted; severity describes the importance of the evidence gap, not a confirmed vulnerability. |
| `source-map-exposed` | `security_exposure` | `high` | Original source and comments are publicly reconstructable from a served source map. |
| `semantic-cache-buster` | `security_exposure` | `low` | Asset naming reveals internal release or feature labels. |

