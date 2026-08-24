# Changelog

All notable changes to **Web App Security Skill** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.7.0] — 2026-08-24

### Added
- Route-security schema v2 records application controls once, route-scoped-control state,
  access-control chains and Next.js Server Actions as a separate non-HTTP surface.
- Exact bounded identity evidence covers Nest Passport and Auth.js as stable families, with Clerk,
  Better Auth and Supabase identity explicitly experimental.
- Prisma and Drizzle operations have stable bounded same-handler and one-local-call evidence;
  Supabase Query Builder remains experimental and always retains `external_policy_required`.
- One-hop local resolution supports exact same-file calls, relative imports, bounded Nest
  constructor injection, unambiguous nearest tsconfig/jsconfig paths and exact workspace source
  exports. It stops before a second local call.
- An opt-in `--fail-on-route-regression` gate reports defined route/action access-control
  degradations without overriding incomplete-evidence exit behavior.
- A fixed-commit four-project review inventories 173 routes and 23 Server Actions, manually reviews
  32 entries and records 12 partial and zero completed ordinary-project chains without publishing a
  production accuracy claim.

### Changed
- Application-wide guards are no longer copied onto every route. Authentication, authorization and
  unclassified route-control signals are separate, and `no_route_scoped_control_observed` is
  directly reviewable.
- Access-control review explanations include observed facts, proof limits, likely consequences,
  change risks and owner-controlled unauthenticated/owner/non-owner/lower-role/normal-flow checks.
- Route v1 baselines are explicitly not comparable with route-security v2.

### Fixed
- Named regressions protect Nest global-guard role duplication, access-chain fingerprint
  collisions, standard Next monorepo app roots and exact tsconfig alias resolution.

### Security boundary
- A missing route control or principal/tenant query constraint is review evidence, never automatic
  proof of BOLA/IDOR. Runtime reachability, deployed policy, RLS and paths beyond one exact local call
  remain outside the automated conclusion.

Publication status: v0.7.0 candidate only until signed tag, GitHub Release, npm provenance,
verified installer, immutable Action and signed `v1` consumers pass.

## [0.6.0] — 2026-08-24

### Added
- Built-in audits now produce private, digest-bound `route-security.json` and
  `route-security.md` companions for bounded Express, NestJS and Next.js App Router syntax.
- Route evidence separates authentication, route-level authorization and object-level
  authorization, then applies review-order labels that are explicitly not severity.
- A pinned bundled `@babel/parser` runtime supports AST extraction without installing project
  dependencies at audit time; version, license, digest and SBOM inclusion are recorded.
- Exact-compatible route baselines and full-context `--since`/`--staged` route views preserve
  inherited control evidence and fail closed when current evidence is incomplete.
- An experimental direct same-handler Prisma route-identifier review lead ships outside the stable
  risk-rule count and does not claim BOLA/IDOR proof.
- The fixed-commit 57-route ordinary-project review records 51 detected routes, six explicit misses
  and separate Express/NestJS/Next promotion decisions without publishing accuracy percentages.

### Changed
- Stable rule inventory is 25 built-in risk rules, three built-in evidence-integrity rules and 16
  external adapter risk rules, 44 total. Route records are not counted as vulnerability rules.
- Express `router.all` is conservatively treated as potentially state-changing for review order.

### Fixed
- Ordinary-project review guards static Nest controller option paths, dynamic-prefix non-guessing,
  route-relevant import failure isolation, Next handler re-export incomplete evidence and
  reconciling route coverage reason counts.

Publication status: v0.6.0 candidate only until signed tag, GitHub Release, npm provenance,
verified installer, immutable Action and signed `v1` consumers pass.

## [0.5.4] — 2026-08-23

### Added
- Five bounded built-in risk rules detect exact Git tracking of sensitive `.env` names,
  JavaScript session secrets and insecure cookie options, plus Python insecure session-cookie and
  disabled-CSRF settings. Source-pattern matches remain `suspected`; the narrow Git index fact is
  `confirmed` without reading file contents.
- Eight project-owned Opengrep rules add same-file request-to-SQL, outbound-URL, file-path and
  redirect flows for JavaScript/TypeScript and Python. The digest-pinned local ruleset now contains
  ten rules including the existing command-execution pair.
- `audit --profile deep` expands to built-in, Checkov, Gitleaks, Opengrep and OSV-Scanner. It never
  downloads a tool; unavailable prerequisites produce per-rule `unknown` evidence and doctor
  guidance.
- A deterministic historical real-world regression corpus executes four minimized v0.5.2
  correctness failures against product code and retains one numeric SVG `innerHTML` result as an
  `expected_benign_match` requiring manual input-boundary review.

### Changed
- The self-authored planted fixture suite is now named rule-contract conformance. Its generated
  summary reports literal positive/negative/state pass and failure counts instead of TP/FP/FN
  language that could be mistaken for production vulnerability accuracy. It now covers all 25
  built-in risk and two evidence-integrity rules.
- The main-branch first-trial command follows the latest npm release without a version suffix.
  Reusable CI, signed release verification and the trusted installer remain version- or
  commit-pinned.

### Security boundary
- Stable detector reach is 25 built-in risk rules, two evidence-integrity rules and 16 opt-in
  external-adapter rules: 43 total. Built-in pattern and Opengrep matches remain bounded leads;
  rule-contract and historical regression results are not precision/recall measurements.

## [0.5.3] — 2026-08-16

### Added
- The public npm package exposes both `web-app-security-skill` and `webapp-security` executables, so
  `npx web-app-security-skill@0.5.3` can run the real CLI without a persistent installation. An
  explicit package allowlist excludes tests, engineering plans and adoption working notes.
- Claude Code plugin and marketplace manifests support repository marketplace registration and
  `web-app-security-skill@web-app-security` installation while reusing the root `SKILL.md`.
- `--since <ref>` filters built-in source findings to added Git lines, and `--staged` audits an
  isolated Git index snapshot. Reports record the immutable base, snapshot kind, changed-file and
  added-line counts, plus excluded untracked files.
- A reproducible ground-truth runner publishes JSON and Markdown TP/FP/FN results for all 20 built-in
  risk-rule and two evidence-integrity planted pattern contracts; CI compares committed bytes and
  tests planted missing-positive and unexpected-negative failures.
- `KNOWN_LIMITATIONS.md` publishes detector, parser, incremental, external-adapter, recurring-match
  and benchmark interpretation boundaries.

### Changed
- npm/npx, Claude plugin and existing CLI installations invoke the same runtime and skill body.
- The roadmap now records explicit permission, demand, transport and regression gates for any future
  MCP adapter, and evidence/fixture/false-positive gates for future stable rule expansion. Neither
  MCP nor additional stable detection rules ships in this release.

### Security boundary
- Diff-scoped runs support the built-in adapter only and cannot participate in baseline/retest
  lifecycle claims. `--since` excludes untracked files; `--staged` excludes unstaged content. A clean
  diff does not establish whole-repository safety.
- The benchmark measures planted rule contracts, not production vulnerability precision, recall,
  reachability or exploitability. The stable rule count and evidence-state definitions remain
  unchanged from v0.5.2.

## [0.5.2] — 2026-08-16

### Fixed
- Risk-domain summaries in v3 Markdown and HTML reports now render state totals and severity
  breakdowns instead of JavaScript object coercions such as `[object Object]`; zero-count states are
  omitted.
- Node package manifests covered by a root `pnpm-lock.yaml` are no longer reported as confirmed
  missing-lockfile findings when `pnpm-workspace.yaml` includes them. Exclusion patterns are
  honored, and unreadable or unsupported workspace metadata fails closed as incomplete evidence.
- Nested JavaScript/TypeScript template literals, including SSR HTML and TSX brace expressions, no
  longer make the containing file partial. Executable expressions inside templates remain scanned.
- A uniquely identifiable finding moved to another path is now retested as `unchanged` with
  `condition_moved`, rather than producing a false `fixed` plus `new` pair. Ambiguous duplicate
  matches are deliberately left unmatched.

### Security boundary
- The stable 30-rule corpus, finding/report schemas, evidence-state definitions, passive network
  defaults and review-only repair behavior are unchanged from v0.5.1.

## [0.5.1] — 2026-08-14

### Fixed
- JSX child text containing comment-shaped glob notation such as `skills/*.yaml` no longer causes
  all JavaScript/TypeScript rules for that file to become partial. JSX expressions, attributes and
  nested elements remain tokenized as code.
- CPython-valid raw strings with backslash-quoted delimiters no longer produce an unbalanced
  delimiter error and partial Python coverage.
- The five-project review now distinguishes the original report byte SHA-256 from a reproducible
  semantic digest over report schema, ruleset, finding identities and states, with a machine
  comparison command for third-party reruns.
- The HTTPS hardening fixture clears an inherited `SSL_CERT_FILE` before using its local certificate
  authority, reducing host-specific trust-store interference.

### Security boundary
- The stable 30-rule corpus, finding/report schemas, evidence-state semantics, passive network
  defaults and review-only repair behavior are unchanged from v0.5.0.

## [0.5.0] — 2026-08-14

### Added
- Finding/report v3 gives every actionable source result a professional term, plain-language
  explanation, realistic consequence, evidence boundary, standards references, reviewable
  proposal, alternatives, side effects, required owner decisions, separate security/functional
  retests and rollback criteria while preserving v2 subject, scope, coverage and baseline safety.
- Eight bounded JavaScript/TypeScript and eight Python source rules expand the four shared built-in
  risk checks to 20 stable built-in risk rules plus two evidence-integrity rules. Every stable rule
  has a vulnerable fixture, safe near-neighbour, explicit confirmation boundary and planted
  missing-observation failure in the generated 30-rule corpus.
- Opt-in Opengrep 1.27.0 adapter runs two bundled digest-pinned request-to-command taint rules;
  opt-in Checkov 3.3.9 runs three fixed root Dockerfile/GitHub Actions rules. External matches remain
  suspected and unavailable/malformed evidence remains unknown.
- `repair-plan` and `repair-validate` create and validate a private review-only workflow record with
  explicit approval, application, dual-retest and rollback states. The CLI does not edit projects.
- A new network-free 30-second source demo explains one suspected command-execution lead, proposes
  shell-free argument handling, names its quoting/platform side effect, then records a compatible
  security retest and separate functional retest.
- A fixed-commit v0.5.0 built-in pass over five ordinary projects classifies all 43 findings as 11
  useful leads, 27 expected benign matches, 1 unknown and 4 confirmed missing-lockfile facts without
  publishing precision/recall or calling the finding count a vulnerability count.

### Changed
- Source reports default to the readable explanation layer while preserving explicit technical
  evidence views and sanitized JSON, Markdown, HTML, SARIF and JUnit output.
- Public source counts now come from the stable rule registry/corpus and separate built-in risk,
  evidence-integrity and external-adapter rules from crawl and agent-guided methodology.

### Fixed
- Multiple same-rule JS/TS or Python observations in one file now include line and construct in the
  fingerprint subject, preventing valid distinct findings from colliding and invalidating a report.

## [0.4.0] — 2026-08-14

### Added
- Report/finding v2 design schemas and migration contract define privacy-preserving subject identity,
  scope/ruleset compatibility, risk domains, coverage accounting, affirmative `fixed` evidence and
  explicit non-comparable migration from v1.
- The deterministic source runtime now writes v2 evidence with persisted or explicit ephemeral
  subject identity, scope/ruleset digests, rule revisions, per-rule coverage, report sidecars,
  explicit v1 migration and moved-project rebind commands.
- Regression contracts reject fixed results without a completed compatible check, silent v1
  comparison, unreconciled coverage, and capability metadata that counts demos, renderers or
  distribution as vulnerability detection.
- Private atomic evidence bundles use restrictive permissions, reject overwrite, sanitize all
  formats before commit and roll back handled write failures without leaving partial output.
- Opt-in, exact-version Gitleaks 8.30.1 and OSV-Scanner 2.5.0 adapters expose per-rule coverage and
  keep every scanner match as a `suspected` lead. Missing, incompatible, timed-out or malformed
  external tools produce explicit `unknown` evidence.
- Five fixed-commit ordinary-project journeys exercise the complete v2 built-in/Gitleaks/OSV path,
  with a release regression inventory for historical correctness failures and detector applicability.
- Deterministic local fixtures cover crawler range integrity, nested AWS permission denial and
  sitemap XML/off-origin boundaries without third-party network or cloud access.

### Changed
- Capability claims now use independent category and maturity fields. The public matrix identifies
  seven stable narrow detection families separately from evidence,
  reporting, lifecycle, distribution and agent-guided capabilities.
- The threat model now covers cross-project baseline substitution, incomplete traversal,
  parser/external-tool failure and partial report disclosure.
- Risk summaries and gates are domain-aware: security exposure and supply chain are separated from
  search discoverability, reliability and evidence integrity. A failed check cannot become a pass.
- The composite Action retains v0.3 crawl inputs and adds source mode with built-in or
  caller-provided adapters. Supported Node releases are 22 and 24 on Ubuntu and macOS.

### Fixed
- Source retest rejects cross-project, replaced-identity, malformed, digest-mismatched and internally
  forged baselines before writing output. Missing, unavailable or revision-incompatible rules become
  `unretested` or `not_comparable`; only a completed compatible check can produce `fixed`.
- Crawler range evidence now rejects missing, non-array, empty, invalid-CIDR, future and stale
  vendor data. The claimed product's own validated list is still authoritative; a sibling product
  cannot verify or convict it. `unverifiable` now exits `3`, while traffic remains subject to normal
  anonymous-client limits rather than an evidence-based block.
- AWS nested inventory permission failures now remain explicit `UNCHECKED` results instead of
  becoming fabricated IAM MFA or CloudTrail findings. Captured AWS error payloads are withheld,
  and an audit with unknown checks but no confirmed HIGH result exits `3`.
- Sitemap parsing now safely normalizes predefined/numeric entities and CDATA, rejects external
  declarations and malformed XML, and constrains sitemap indexes and sampled URLs to the audited
  origin. Unknown sitemap evidence still writes a report, queues no URLs from that document, and
  exits `3` independently of `--fail-on`.
- Gitleaks exact duplicates no longer create duplicate findings, distinct tool fingerprints no
  longer collide, and numeric fingerprint prefixes cannot be rewritten by evidence sanitization.

## [0.3.0] — 2026-08-13

### Added
- Network-free `webapp-security start <project>` discovery for Node, Python and split-stack layouts,
  with a versioned `security-scope.yml`, explicit source/local/remote modes, pending authorization,
  secret-file avoidance and an installable scope schema.
- Versioned finding/report schemas, narrow deterministic source rules, JSON/Markdown/escaped HTML/
  SARIF/JUnit renderers, stable fingerprints, `audit`, `explain`, required-baseline `retest`,
  patch-only proposals and `new`/`fixed`/`unchanged`/`regressed` comparison states.
- Unified zero-dependency CLI with Claude Code, Codex and ordinary CLI installation, atomic
  replacement and timestamped backups.
- Deterministic local before/after demo (`13 high / 6 medium` to zero) with JSON, Markdown and
  patch evidence.
- Passive-by-default composite GitHub Action with explicit authorization and stable report paths.
- Release workflow for reproducible source archive, SPDX 2.3 SBOM, SHA-256 checksums and GitHub
  build-provenance attestation; release manifest, byte-for-byte rebuild comparison, clean archive
  lifecycle test, CodeQL v4 and full-SHA third-party Action pins.
- Security policy, threat model, false-positive policy, compatibility matrix, issue forms, bounded
  good-first issues and versioned release evidence.
- Five immutable-commit source case studies: Juice Shop, NodeGoat, DVWA, Uptime Kuma and Mealie.
- Versioned install markers plus network-free `version`, `upgrade` and `uninstall` paths for Claude
  Code, Codex and the ordinary CLI; a manual real `@v1` Action consumer workflow.

### Changed
- Public identity is unified as **Web App Security Skill**: repository `web-app-security-skill`,
  Skill ID `web-app-security`, CLI `webapp-security`, and matching Action/release/SBOM names. The
  installer detects the earlier `webapp-security-hardening` path and backs it up during migration.
- Sensitive-path crawl probes and rate-limit bursts now require an explicit authorization
  acknowledgement; passive checks remain the default.
- Crawl reports support stable filenames and configurable fail thresholds for CI use.
- README now follows result, install, first-project prompt, capability boundary, deterministic
  tools, trust and case-study evidence. English and Chinese claims, demo counts and case counts are
  checked against structured or generated sources.

## [0.2.4] — 2026-08-13

### Changed
- CI: bumped `actions/checkout` and `actions/setup-node` to `@v5`. GitHub was force-running the
  `@v4` actions on Node 24 (the Node 20 action runtime is deprecated) and printing a deprecation
  notice on every run; `@v5` targets the supported runtime and clears the warning. No change to the
  test matrix (ubuntu/macOS × Node 20/22) or what runs.

## [0.2.3] — 2026-08-13

### Changed
- **verify-hardening TLS verification is now per-version and stricter.** It checks TLS 1.0, 1.1,
  and 1.2 handshakes independently (`--tlsvX --tls-max X`), so "1.0/1.1 refused, 1.2 works" is
  actually proven rather than inferred; certificate + hostname validation and connect/max timeouts
  are applied to every request.
- **Three-state outcome: pass / fail / `unknown`.** Network- or TLS-layer failures and
  unverifiable conditions (e.g. `curl` without `--tls-max`, an unreachable redirect endpoint) are
  reported as `unknown`, and the script exits non-zero unless every check passed — an `unknown`
  no longer reads as success.
- `--content-path` / `--probe-path` must start with `/`; added `--help`/usage output.

### Added
- `test/verify-hardening.test.mjs` — a **deterministic** integration test for the shell tool: it
  stands up a real local HTTPS origin (self-signed cert, `minVersion: TLSv1.2`) plus an HTTP→HTTPS
  redirect server, then asserts the passive checks pass, TLS 1.0 is reported rejected while 1.2
  succeeds, the certificate validates, `--active-rate-limit` sees the probe throttled (429) while
  content stays available, out-of-range `--n` exits `2`, and an unreachable target can never be
  reported crawler-safe. No network, no third-party host — the first roadmap v0.3 fixture, landed early.

## [0.2.2] — 2026-08-13

Third-audit fixes — result trustworthiness. Crawler identity moved to product granularity,
the TLS check made real, failure semantics and argument handling tightened, and CI turned into
an actual gate.

### Fixed
- **crawler verifier: identity is now resolved at PRODUCT granularity** (GPTBot⇄`gptbot.json`,
  OAI-SearchBot⇄`searchbot.json`, …), not vendor granularity. A single list's outage while a
  sibling OpenAI list loads no longer brands a real crawler `spoofed`; a sibling product
  containing the IP is not proof the request is GPTBot. Verified end-to-end (not just via
  `decideVerdict`) by a real-CLI integration test with a local fixture.
- **verify-hardening TLS check was inert** — it printed `%{http_version}` and, in v0.2.1, the
  non-existent `%{ssl_version}` write-out variable (which errors on curl 8.x). Replaced with an
  active policy test: `--tls-max 1.1` must be **refused**, `--tlsv1.2` must **work**.
- **verify-hardening failure semantics** — `curl 000` / DNS failure / timeout is now `ERROR/UNKNOWN`,
  never counted as "content class safe". An unreachable target no longer reads as a pass.
- **verify-hardening argument handling** — `--n` bounded to 1–100; missing values, bad scheme, and
  non-numeric `--n` all exit `2`.
- **IP parsing** — `net.isIP` gate plus explicit rejection of zone ids (`%`); junk like
  `2001:db8::1g`, `1::2::3`, `:::` no longer silently parses.
- **version metadata** — `package.json` realigned to `VERSION`/tag (was stuck at 0.2.0).

### Added
- `test/integration.test.mjs` — real-CLI, multi-source aggregation over a local HTTP fixture
  (all-ok / fetch-fail / sibling-hit / IP-present), the coverage pure-function tests couldn't give.
- `test/shell-smoke.sh` — exit-code contracts + Bash-3.2 + passive-default, run as a CI gate.
- `test/version-consistency.test.mjs` — CI fails if VERSION / package.json / CHANGELOG disagree.
- `ROADMAP.md` — public roadmap (v0.3 deterministic fixtures + ShellCheck/CodeQL/coverage; v0.4
  SARIF/CLI/Action + hardening-patch generation).

### Changed
- **Rate-limit probe is now opt-in** (`--active-rate-limit`, with a request-volume + authorization
  notice). It sends many concurrent requests and is an ACTIVE test — it no longer runs by default,
  restoring the read-only default the docs claim.
- **CI is a real gate**: dropped every `|| true`; added the shell-smoke gate and a
  ubuntu/macOS × Node 20/22 matrix.

## [0.2.1] — 2026-08-13

Second-audit fixes: three real defects found by re-auditing v0.2.0, each frozen as a regression.

### Fixed
- **`verify-crawler-ip`: a failed range-source fetch convicted a real crawler as `spoofed`.**
  The logic used "we have a source configured" where it needed "the source loaded this run", so
  pointing OpenAI's range URL at an unreachable address made a genuine GPTBot IP resolve to
  `spoofed` — which, wired to an allowlist, would wrongly block it. Now **fails open**: a source
  that fails to fetch yields `unverifiable`, and only a *successfully-loaded* source that lacks the
  IP yields `spoofed`. `decideVerdict` gained a `claimedVendorSourceLoaded` input; `verify()` tracks
  per-source load success.
- **`verify-hardening.sh`: crashed on macOS's Bash 3.2** — an empty `${HOSTHDR[@]}` under `set -u`
  is an unbound-variable error there (the README advertises macOS/Codex support). Reworked to pass
  the optional `Host` header without array expansion; concurrency loop rewritten to be 3.2-safe.
- **`verify-hardening.sh`: reported the HTTP version as if it were the TLS version, and never
  validated the certificate.** It printed `%{http_version}` (HTTP/1.1·2·3) labelled as TLS and ran
  everything under `-k`. Now reads `%{ssl_version}` (the real TLSv1.2/1.3 protocol), fails on weak
  TLS, and — for a bare public hostname — verifies the certificate chain without `-k`.

### Added
- `verify-crawler-ip` tests: the source-fetch-failure case as a named regression, plus 17
  IPv4/IPv6 CIDR-boundary assertions (`inCidr`/`parseIp` now exported) — the CIDR math had zero
  coverage before. Suite is 54 assertions.
- CI now runs on **ubuntu + macOS** (macOS ships Bash 3.2, so the empty-array/`set -u` traps are
  caught in CI) and adds shell smoke steps for the `.sh` tools.

### Changed
- `bot-verification.md` — documents fail-open semantics: a range list that can't be fetched is
  `unverifiable`, never `spoofed`; the verdict table clarifies "source loaded, IP absent" (spoof)
  vs "source failed to load" (unverifiable).

## [0.2.0] — 2026-08-13

First maintenance release. Adds a test suite, CI, and four references distilled from
running the skill end-to-end against a production app — and fixes a real defect in the
crawler verifier found during that run.

### Fixed
- **`verify-crawler-ip`: a UA claiming one vendor from another vendor's IP was reported `verified`.**
  Both verification paths only proved "this IP belongs to *some* known crawler" and never
  compared that against the vendor the UA *claimed*. So `Googlebot IP + GPTBot UA` and
  `GPTBot IP + ClaudeBot UA` both returned `verified` — meaning the script could not safely
  back a rate-limit allowlist. UA claims are now resolved into the same canonical vendor
  namespace as rDNS ownership and published-range membership, and compared strictly: a proven
  owner that **disagrees** with a non-null claim is `spoofed`, never `verified`. Decision logic
  extracted into pure, unit-tested functions (`uaVendor`, `decideVerdict`).

### Added
- **Test suite** (`test/`, run with `npm test`): `verify-crawler-ip.test.mjs` (35 assertions,
  including both reported spoof cases as regressions) and `robots.test.mjs` (17 assertions
  covering most-specific-group, longest-match, Allow tie-break, `*`/`$` wildcards, named-group
  precedence). Pure functions, no network.
- **CI** (`.github/workflows/ci.yml`): Node 22, runs `npm run lint` (syntax check every script +
  `bash -n`) and `npm test` on push/PR. `package.json` added with `test` / `lint` scripts.
- **`references/regression-gate.md`** — turning each fix into a machine-checked CI assertion,
  and the discipline of proving every assertion by planting the failure (so it is never vacuous).
  Elevated to the skill's third core principle.
- **`references/deploy-safety.md`** — shipping edge/proxy/WAF/container changes without an outage:
  validate a throwaway config before cutover (never after), the single-file bind-mount inode trap,
  regex-`location` `proxy_pass` rules, `add_header` non-inheritance, proving a limiter engages,
  and the healthcheck/volume/migration-credential dependencies that hardening breaks.
- **`scripts/verify-hardening.sh`** — read-only external check that the edge hardening actually
  engages: security-header matrix, tiered rate-limit (probe throttled, content not), TLS/redirect.
- **`scripts/lib/robots.mjs`** — robots.txt parse/evaluate extracted from `crawl-surface-audit.mjs`
  into a shared, testable module.

### Changed
- `enforcement-layers.md` — new §7b "Real client IP", the control that silently unblocks every
  IP-based defense: how `X-Forwarded-For` is client-forgeable, why `X-Real-IP`/exact-hop
  `trust proxy` is the fix, and how to prove it.
- `phase-5-database.md` §2 — least-privilege now includes runtime-role **verification** SQL
  (`rolsuper` must be false; `CREATE TABLE` and `COPY … TO PROGRAM` must be denied — the
  injection-to-RCE path) and the migration-vs-runtime credential split.
- `phase-4-code-audit.md` §4–5 — startup self-check must cover *every* security secret (weak
  config that boots silently is the trap), salts must not fall back to the signing key,
  `jwt.verify` must pin `algorithms`, CORS must fail closed, and CSP should ship Report-Only first.
- `SKILL.md` — third principle (regression gates), phase map entries X-7/X-8, `verify-hardening`
  in tooling, and a note that the verifier's `verified` verdict now requires UA↔owner agreement.

## [0.1.0] — 2026-08-13

### Added
- Initial public release: nine-phase web-app security & hardening program with the crawl
  boundary as a first-class concern (open to every AI crawler, closed to scanners).
- References for phases 0–8 plus crawl-boundary, bot-verification, enforcement-layers,
  exposure-checks, overlooked-surface, and aws-hardening.
- Scripts: `crawl-surface-audit.mjs`, `verify-crawler-ip.mjs`, `aws-exposure-audit.sh` (all read-only).
- `assets/scope-template.md`, bilingual README.
