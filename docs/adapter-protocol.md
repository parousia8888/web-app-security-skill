# External source and deployment adapter protocol

External adapters are optional. The built-in source audit remains the default and performs no
adapter download. `webapp-security doctor` only probes installed executables and exits `3` when a
selected prerequisite is unavailable.

## Contract

An adapter must define a stable ID, exact tested version, maturity, rule inventory, applicability,
machine-output command, timeout and network behavior. Each rule declares a revision, risk domain,
local severity and rationale. Reports record adapter and ruleset identity even when no finding is
produced.

Execution follows this sequence:

1. Verify the executable reports the exact supported version.
2. Compile the persisted source roots and excluded directory basenames into the same canonical
   file-read policy used by the built-in analyzer.
3. Determine applicability from admitted source or governing manifest/lockfile inputs.
4. Invoke the bounded machine-output command without executing project dependencies or reading a
   broader tree merely to filter results afterward.
5. Parse only documented fields and reject malformed, oversized, path-escaping or out-of-scope output.
6. Convert results to sanitized v3 findings and per-rule coverage, recording `scopeMode`.
7. Convert missing tools, unsupported exact scope, version drift, timeout, malformed output,
   inconsistent exit status and
   internal errors to `unknown`/unavailable coverage, never a clean result.

Raw stdout and stderr are not persisted. Adapter implementations must discard secret values,
credentials and unnecessary personal data before constructing a finding. Scanner matches are
`suspected` leads: Gitleaks does not establish credential validity or exposure, OSV does not
establish reachability or production impact, and Checkov does not establish effective deployment
runtime or workflow permissions.

## Supported adapters

| Adapter | Tested version | License | Invocation boundary | Persisted evidence | Network |
|---|---:|---|---|---|---|
| Checkov | `3.3.9` | Apache-2.0 | Exact admitted root `Dockerfile`/`.github/workflows/*.yml|yaml` input list; only `CKV_DOCKER_8`, `CKV_DOCKER_2` and `CKV2_GHA_1` | External rule ID, framework and sanitized relative path/line range; code blocks, resources and stderr are discarded | `--skip-download`; may query PyPI for version metadata, never uploads project source |
| Gitleaks | `8.30.1` | MIT | Full scope: Git history plus working tree. Restricted scope: private path-preserving working-tree snapshot; history is explicitly unsupported | External rule ID, sanitized path/line, optional commit and SHA-256 fingerprint digest | No |
| Opengrep | `1.27.0` | LGPL-2.1-or-later engine; project-owned MIT rules | Admitted JavaScript, TypeScript and Python copied to a private path-preserving snapshot with the bundled SHA-256-pinned local taint ruleset | External rule ID, sanitized relative path/line/column, engine kind and ruleset SHA-256; source lines and metavariables are discarded | No |
| OSV-Scanner | `2.5.0` | Apache-2.0 | Admitted or ancestor governing recorded lockfiles; call analysis disabled | Ecosystem, package/version, advisory IDs, aliases and upstream maximum severity | May query the public OSV database |

OSV matches use local severity `info`: upstream CVSS or database severity is preserved as evidence,
not converted into a Web App Security severity. Project reachability and priority require review.

Checkov is intentionally limited to three fixed upstream rules. A missing matching input is
`not_applicable`; a missing fixed rule in Checkov output, parse error, unknown rule, path outside
the enumerated inputs or rule-level suppression is `unknown`, never clean. Each suppression is
scoped to its exact rule and path rather than silencing the whole file. Compose, Terraform,
Kubernetes, nested Dockerfiles and the rest of Checkov's catalogue are not stable v0.5.0 coverage.
Checkov state is redirected to a private temporary HOME/cache/TMPDIR and deleted after each
probe/scan. Upstream exposes no reliable switch for its PyPI update check, so the product does not
claim zero network attempts; an OS-level network-denied run remains supported.

Opengrep is intentionally limited to ten same-file data-flow rules: request data reaching command,
SQL, outbound-URL, file-path or redirect sinks in JavaScript/TypeScript and Python. It is not a
general Opengrep rules catalogue and is not advertised as whole-program analysis. The bundled
`rules/opengrep-source.yml` file has SHA-256
`62e9fb0fb382e0f12443adb28ed73bebec5aa390dec7a1ca5692ea6882d138d8`; a missing or changed file
makes coverage unavailable. The caller installs the exact engine and may set
`WEBAPP_SECURITY_OPENGREP_BIN`; the runtime does not download an executable or remote rules.

Use `--adapter builtin|checkov|gitleaks|opengrep|osv|all` repeatedly and
`--adapter-timeout 1..600`. A persisted run fixes both values in its scope. Use `--fail-on never`
for evidence-only external runs. Any external adapter run that can affect an exit-code gate also
requires `--acknowledge-alert-policy`; see
[`alert-policy.md`](alert-policy.md).

`--profile deep` is the no-download shorthand for `builtin`, `checkov`, `gitleaks`, `opengrep` and
`osv` in stable order. It cannot be combined with explicit `--adapter`, `--since` or `--staged`.
Unavailable prerequisites still produce one `unknown` result per applicable adapter rule and exit
3; `webapp-security doctor . --adapter all --json` reports exact version/setup guidance.

The report records adapter `scopeMode` as `full`, `scoped_snapshot`, `governing_inputs` or
`unsupported`. An adapter that cannot prove the persisted file-read boundary returns unknown
coverage and exit 3; a broader scan followed by path filtering is not accepted. Working snapshots
are private temporary directories removed after success, failure or timeout. The root
`webapp-security.suppressions.json` file is evaluated only after findings are constructed and does
not broaden adapter input scope.

## Provenance and deferred adapters

CI obtains Checkov, Gitleaks, Opengrep and OSV-Scanner only from their upstream versioned releases
and verifies the fixed SHA-256 values in `test/install-pinned-adapters.sh`. The product does not
download these tools at runtime.

[`sast-adapter-benchmark.md`](sast-adapter-benchmark.md) records the v0.5.0 Semgrep CE versus
Opengrep comparison. Semgrep remains a documented alternative rather than a stable adapter in this
release. Neither upstream public rules repository is copied or bundled. ZAP remains outside the
source-adapter scope.

[`iac-adapter-benchmark.md`](iac-adapter-benchmark.md) records the v0.5.0 Trivy versus Checkov
decision. Trivy remains a documented alternative for broader configuration scanning; it was not
promoted because this release's fixed Dockerfile plus GitHub Actions scope would require an
additional policy bundle and maintenance boundary.
