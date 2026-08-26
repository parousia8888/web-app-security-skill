# Compatibility matrix

| Surface | Supported | CI / verification |
|---|---|---|
| Node.js | 22, 24 | Ubuntu and macOS CI |
| Bash | 3.2+ | macOS Bash 3.2 smoke and integration tests |
| Verified bootstrap | POSIX `sh`, Node.js and curl | Immutable bootstrap digest plus loopback fixture tests |
| curl | Modern curl with `--tls-max` for full TLS policy | Missing capability becomes `unknown`, never pass; HTTPS fixtures pass an explicit CA file on macOS and Linux |
| OpenSSL | Required only by the local HTTPS test fixture | CI and local integration test |
| Claude Code | Skill directory under `~/.claude/skills/` | Install, marker, upgrade, uninstall and migration tests in an isolated home |
| Codex | Skill directory under `~/.codex/skills/` | `agents/openai.yaml`, Skill validator and isolated lifecycle tests |
| Ordinary CLI | `~/.local/share/web-app-security` plus `~/.local/bin/webapp-security` | Extracted-release lifecycle under a network-denied isolated home |
| GitHub Actions | Linux runner; composite Action crawl and source modes | Local entrypoint regression plus manually dispatched real `@v1` consumer workflow |
| Checkov | Exactly 3.3.9 when selected; root Dockerfile and root GitHub Actions YAML only | Pinned Linux real-tool positive/safe fixtures plus parser/failure/redaction/suppression regressions |
| Gitleaks | Exactly 8.30.1 when selected | Pinned Linux real-tool fixture plus parser/failure/redaction regressions |
| Opengrep | Exactly 1.27.0 when selected | Pinned Linux real-tool positive/safe fixtures plus parser/failure/redaction regressions |
| OSV-Scanner | Exactly 2.5.0 when selected | Pinned Linux real-tool fixture plus parser/failure/severity regressions |
| AWS CLI | v2 recommended | Optional; missing CLI, permission failures and malformed JSON are v2 `unknown` evidence |
| Windows / WSL2 | Not supported | No maintained native-Windows or clean WSL2 verification environment |

Project discovery currently identifies Node projects from `package.json`, common JavaScript
lockfiles and supported framework dependencies; Python projects from `pyproject.toml` or
`requirements*.txt` plus common Python lockfiles; and multi-root combinations of those ecosystems.
It records deployment/config file paths without reading them. Unsupported or ambiguous stacks
remain explicit in `security-scope.yml`.

Built-in language depth is intentionally narrower than project discovery:

| Source surface | Stable v0.7.0 built-in boundary | Explicit limit |
|---|---|---|
| JavaScript / TypeScript | `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`; direct lexical constructs for dynamic execution, child-process shell use, React/browser HTML sinks, wildcard credentialed CORS, disabled TLS verification, unsafe JWT options, hardcoded auth/session secrets and recognized insecure cookie options | No whole-program data flow, alias-complete symbol resolution, runtime reachability or sanitizer proof; explicit exclusions and failed eligible evidence remain separate coverage counts |
| Python | `.py`; tokenizer-backed constructs for dynamic execution, shell subprocess use, pickle and YAML deserialization, disabled TLS verification, framework debug, hardcoded framework secrets, wildcard credentialed CORS, recognized insecure session cookies and explicit CSRF disable/exempt constructs | A tokenizer failure becomes `unknown`; no interprocedural data flow or deployment-state proof |
| Shared project configuration | Supported manifests/lockfiles, sensitive environment filenames, exact Git-index tracking of real `.env` names, public Node inspector binds and production source-map flags | A filename/config/Git fact proves only the named condition, not secret content, deployment or exploitability |
| Other languages | Discovery may record the stack. | No equal built-in or bundled Opengrep coverage is claimed; use agent-guided review or another independently governed scanner. |

Framework-aware route review has its own narrower contract:

| Framework | Stable syntax | Explicit limit |
|---|---|---|
| Express | Direct `express()`/`Router()` registrations, route chains and statically resolved router mounts | Aliased app objects, wrappers, computed mounts and unresolved route relationships become partial coverage. |
| NestJS | Static controller/method decorators, static controller option paths/arrays, exact Passport inheritance, bounded structural route controls and one exact constructor-injected local service call | Application guards are inventoried once; dynamic decorators, runtime order, exemptions, dependency-container behavior and a second service call are not proved. |
| Next.js App Router | Direct named HTTP handler exports from `route.js`/`route.ts` variants under root, `src/app`, `apps/<name>/app` and `packages/<name>/app` | Wrapper/re-export relationships and unsupported middleware/proxy matchers become partial coverage. Middleware/proxy controls are application context, not per-route enforcement. Pages Router is not supported. |
| Next.js Server Actions | Direct static async exports with a module-level or function-level `"use server"`; identity/data analysis shares the route boundary | Actions are separate named surfaces without invented HTTP routes. Re-exports, wrappers, non-static exports and runtime invocation policy can remain unresolved. |

Access-control-chain compatibility is narrower than route extraction:

| Surface | Stable bounded evidence | Experimental or explicit limit |
|---|---|---|
| Identity | Existing exact Nest Passport and Auth.js/NextAuth package/factory/export semantics | Clerk, Better Auth and Supabase identity remain experimental; custom wrappers and response transformations are unresolved. |
| Data operations | Direct Prisma and Drizzle operations, same handler or one exact local call | Supabase Query Builder remains experimental and always requires external RLS-policy review; other ORMs are not supported. |
| Local module resolution | Relative imports, one unambiguous nearest static tsconfig/jsconfig path target and one exact workspace package source export | Ambiguous, missing, escaping, dynamic and unbuilt-dist-only targets fail closed. Analysis stops before a second local call. |
| Object selectors | Supported route/path parameters and direct Server Action parameters/form fields | Query-string and JSON-body selectors, transformations and indirect aliases remain outside the v0.7.0 boundary. |

Authorization analysis is published only through each route/action `accessChains` array. Shared
principal and tenant tokens reduce vocabulary drift across stable and experimental providers; a
token match remains bounded static evidence and does not establish caller identity or policy
enforcement. Unclassified controls remain distinct from classified authentication/authorization
and from the bare-route review context.

JavaScript/TypeScript parsing uses the pinned bundled `@babel/parser` recorded in the route
artifact. The bundle is included in npm, Skill and Action payloads; audited projects do not install
or execute it as a project dependency.

The deterministic source audit currently runs 25 bounded built-in risk rules across shared project
configuration, JavaScript/TypeScript and Python, plus three evidence-integrity rules. Opt-in Gitleaks
checks Git history and the working tree; opt-in
Opengrep checks JavaScript/TypeScript and Python with ten bundled same-file local rules and performs no
network request. Checkov checks only the three fixed root Dockerfile/GitHub Actions rules documented
in the adapter protocol; it uses `--skip-download` but may query PyPI for version metadata and never
uploads project source. OSV-Scanner checks recorded lockfiles and may query the public OSV database.
None is downloaded automatically or executes project dependencies. Every source pattern and
external scanner result remains `suspected` unless a rule-specific independent confirmation
contract is satisfied. JSON, Markdown, HTML, SARIF
2.1.0 and JUnit render from one report object. Compose, Terraform, Kubernetes and other security
domains remain unavailable or agent-guided until a specific deterministic adapter ships.

`--profile deep` selects the built-in detector and all four external adapters in one command. It
does not change these coverage boundaries or install prerequisites; a missing tool is explicit
`unknown` evidence and exit 3. Diff-scoped `--since` and `--staged` runs remain built-in-only.

Node 20 or earlier may run some scripts but is not a supported release target. TLS results vary by curl TLS
backend; protocol checks are capability-tested and stop with `unknown` if they cannot be proven.

The local test runner writes `test-results/test-outcomes.json` and accounts for each intended test
file and declared surface as `passed`, `failed`, `skipped` or `not_run`. Optional real adapters and
the Claude plugin check may be skipped when their exact prerequisites are absent; the summary keeps
that state visible instead of treating the surface as verified.

The low-level lifecycle commands do not fetch remote code. `install` copies the extracted release
that executes it. The verified bootstrap downloads a pinned verifier and explicit release assets,
checks their independent SHA-256 trust anchors, manifest, checksum list, SBOM, commit and archive
paths, then invokes the same lifecycle command. Replacement and removal require a recognized install
marker or the documented legacy Skill identity; unknown paths are left untouched. Native Windows,
PowerShell launchers and WSL2 remain unsupported until a maintained verification environment exists.
