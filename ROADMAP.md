# Roadmap

The roadmap separates shipped behavior from proposed work. An unchecked item is not available until
its acceptance test lands. Priorities are correctness and evidence integrity first, then platform
coverage and adoption.

## Shipped in v0.3.0

- Unified `webapp-security` CLI with `start`, `audit`, `explain`, required-baseline `retest`, local
  demo and lifecycle commands.
- Stable JSON finding/report schemas rendered to Markdown, escaped HTML, SARIF 2.1.0 and JUnit.
- Network-free project discovery and narrow source rules with explicit `confirmed`, `suspected`,
  `unknown` and `not_applicable` states.
- Passive-by-default crawl and edge verification with authorization gates before active probes.
- Composite GitHub Action, stable `v1` alias and immutable full-SHA example.
- Claude Code, Codex and ordinary CLI installation, legacy migration, timestamped backups, upgrade
  and guarded uninstall.
- Reproducible source archive, SPDX SBOM, release manifest, checksums, provenance attestation and
  signed release tags.
- Three fixed-commit ordinary-project journeys plus five separate source methodology studies.

See the [v0.3.0 release evidence](docs/releases/v0.3.0.md) and
[generated capability matrix](docs/capabilities.md) for exact boundaries.

## Shipped in v0.4.0

The published v0.4.0 release implements cross-project baseline isolation, honest incomplete-scan semantics,
domain-separated risk reporting, private atomic evidence output, stable Gitleaks and OSV-Scanner
adapters, and regenerated evidence from five fixed-commit ordinary Web projects. It remains an
agent-guided hardening skill with narrow deterministic automation, not a general SAST/DAST scanner.

The complete milestone sequence, tests, stop conditions and Definition of Done live in the
[v0.4.0 engineering plan](docs/V0.4.0_ENGINEERING_PLAN.md). The signed release, immutable asset
verification, verified installer, exact-version external consumer and owner-approved public `v1`
promotion are complete. Final M8 evidence is recorded in the engineering plan.

## Shipped in v0.5.0

v0.5.0 is the source-detection and understandable-remediation release:

- 20 stable built-in risk rules and 2 evidence-integrity rules, including eight bounded
  JavaScript/TypeScript and eight bounded Python rules;
- finding/report v3 with professional and plain-language explanation, consequence, evidence limit,
  proposal, alternatives, side effects, owner decisions, dual retests and rollback;
- stable bounded Opengrep 1.27.0 and Checkov 3.3.9 adapters, in addition to Gitleaks and OSV-Scanner;
- a review-only repair record and approval/retest state machine that never edits project files;
- a labelled 30-rule fixture corpus, one planted missing-observation failure per rule and a manually
  classified five-project ordinary-source review;
- a source-focused local demo that records both security and normal functional retests.

The signed release, reproducible artifacts and verified installer are published. Immutable
`v0.5.0` and signed `v1` Action references both passed external crawl and source consumers. The
guarded `v1` promotion is complete and the stable alias resolves to the v0.5.0 release source.

The complete audited baseline, milestone sequence, tests, stop conditions and publication gates
live in the [v0.5.0 engineering plan](docs/V0.5.0_ENGINEERING_PLAN.md). Built-in depth for other
languages, authenticated DAST, automatic BOLA/IDOR proof and unattended production patching are
outside this release.

## v0.5.1 compatibility patch

v0.5.1 repairs independently reproduced parser and evidence-reproduction defects without changing
the stable rule count or report schema. JSX child text and CPython-valid raw strings retain source
coverage, the five-project review exposes a path-independent semantic comparison, and the local TLS
fixture isolates inherited certificate-file state. The signed release, verified installer and
guarded signed `v1` promotion are published; the public Action consumer passed. Exact evidence is in
the [v0.5.1 patch plan](docs/V0.5.1_PATCH_PLAN.md).

## v0.5.2 correctness patch

v0.5.2 repairs four independently reproduced correctness gaps without changing the stable rule
count or evidence-state definitions: v3 state summaries render structured counts, pnpm workspace
packages inherit an applicable root lockfile, nested JS/TS templates retain file coverage, and a
unique path-only move no longer makes a condition look fixed. Ambiguous movement remains
unreconciled, and unavailable workspace or tokenizer evidence continues to fail closed. Exact
release progress and evidence are in the [v0.5.2 patch plan](docs/V0.5.2_PATCH_PLAN.md).

## v0.5.3 distribution and review-noise release

The v0.5.3 candidate adds a zero-install npm/npx path, a Claude Code plugin marketplace manifest,
public known limitations, Git-aware `--since` and `--staged` built-in audit scopes, and a
reproducible planted pattern-contract benchmark for all 20 built-in risk rules plus two evidence-
integrity rules. The benchmark is fixture evidence, not a production precision/recall claim.

MCP and a larger stable rule catalogue are intentionally outside v0.5.3. Their entry conditions,
permission boundaries and evidence requirements are recorded in the
[MCP and rule-expansion decision](docs/architecture/mcp-and-rule-expansion.md). Exact implementation
and release progress lives in the [v0.5.3 engineering plan](docs/V0.5.3_ENGINEERING_PLAN.md).

## Shipped in v0.6.0

v0.6.0 adds a companion route-security artifact to the local Skill + CLI. Bounded stable framework
support covers direct Express registrations/static mounts, static NestJS decorators/guards and
direct Next.js App Router handler exports. Authentication, route authorization and object
authorization remain separate evidence, while review priority remains separate from severity.

A pinned parser bundle removes the need to install dependencies in audited projects. Incremental
mode retains whole-project route/control context, route baselines compare exact compatible records,
and incomplete relationships fail closed. A 57-route fixed-commit review records six explicit
misses and keeps the direct-Prisma BOLA lead experimental after zero ordinary-project matches.
Implementation evidence is in the [v0.6.0 route review](docs/reviews/v0.6.0-route-review.md),
[route regressions](docs/regressions/v0.6.0-route-real-world-regressions.md) and
[engineering plan](docs/V0.6.0_ENGINEERING_PLAN.md). The signed GitHub Release, npm provenance,
verified installer, immutable Action and signed `v1` consumers are complete; exact public facts are
in the [v0.6.0 release evidence](docs/releases/v0.6.0.md).

## Implemented for v0.7.0 candidate

v0.7.0 corrects application-guard aggregation and deepens the route inventory into a bounded
access-control-chain review. Nest application controls are listed once; authentication,
authorization and unclassified route controls no longer share one signal list; and
`no_route_scoped_control_observed` creates a human-review queue without becoming a vulnerability.

Supported identity and data evidence can now connect inside one handler or through one exact local
call. Stable bounded families are Nest Passport/Auth.js and Prisma/Drizzle. Clerk, Better Auth and
Supabase remain experimental; Supabase always requires external RLS-policy evidence. Static
relative, tsconfig/jsconfig and exact workspace source relationships are accepted only when one
target resolves. Next.js Server Actions are separate named surfaces, never invented HTTP routes.

The capped [v0.7.0 access-control review](docs/reviews/v0.7.0-access-control-review.md) inventories
173 HTTP routes and 23 Server Actions at four fixed public commits and manually reviews 32 entries.
All 12 ordinary-project chains are partial and zero are completed, which remains a published limit.
Four [real-world regressions](docs/regressions/v0.7.0-access-control-real-world-regressions.md) and
the [engineering plan](docs/V0.7.0_ENGINEERING_PLAN.md) record exact scope and release progress.

## Shipped in v0.5.4

v0.5.4 expands the bounded automatic first pass with five built-in checks, eight same-file
Opengrep flow rules across JavaScript/TypeScript and Python, and `--profile deep` for explicitly
selecting the built-in detector plus four caller-installed external adapters. Missing adapter
prerequisites remain `unknown`; source and flow matches remain `suspected` until reproduced.

The release records 25 built-in risk rules, 2 evidence-integrity rules and 16 opt-in external
adapter rules: 43 stable rules total. The self-authored planted suite is a rule-contract
conformance gate, while a separate five-case corpus preserves named real-world regressions. Neither
is presented as production precision or recall. The signed GitHub Release, npm package with SLSA
provenance, verified installer, and owner-approved public `v1` promotion are complete. Exact facts
are in the [v0.5.4 release evidence](docs/releases/v0.5.4.md) and
[engineering plan](docs/V0.5.4_ENGINEERING_PLAN.md).

## Correctness backlog

Included in the published v0.4.0 release:

- [x] [#1](https://github.com/parousia8888/web-app-security-skill/issues/1): malformed, empty, stale
  and wrong-product crawler-range fixtures; invalid evidence is `unverifiable` and exit `3`.
- [x] [#2](https://github.com/parousia8888/web-app-security-skill/issues/2): fake AWS CLI
  permission-denied fixtures preserve `UNCHECKED` and never synthesize MFA/CloudTrail findings.
- [x] [#5](https://github.com/parousia8888/web-app-security-skill/issues/5): sitemap entities, CDATA,
  malformed XML, external declarations and off-origin entries are covered by local fixtures.

Still open:

- [#4](https://github.com/parousia8888/web-app-security-skill/issues/4): an informational
  `security.txt` check that never labels absence a vulnerability.
- [#6](https://github.com/parousia8888/web-app-security-skill/issues/6): ShellCheck and an
  evidence-based coverage threshold without weakening Bash 3.2 support.
- [#7](https://github.com/parousia8888/web-app-security-skill/issues/7): Gitleaks/OSV evidence-only
  adapters and the [response-policy template](docs/alert-policy.md) are implemented on `main`;
  blocking use remains pending explicit signal-owner assignments and owner acceptance.

## Platform and documentation backlog

- [#3](https://github.com/parousia8888/web-app-security-skill/issues/3): verify and document
  install, lifecycle and tutorial behavior on a clean WSL2 image.
- Add source adapters only with planted failure fixtures and stable evidence output.
- Add policy packs for common deployment controls only when their patch and rollback behavior can be
  retested without claiming broad scanner coverage.
- Reconsider a local stdio MCP adapter only after the documented demand, permission, schema,
  distribution and regression gates are satisfied.
- Promote additional detection rules only through planted positive/negative fixtures, ordinary-code
  false-positive review and explicit fail-closed evidence behavior.

Tracked, contributor-ready items and acceptance tests live in
[`docs/GOOD_FIRST_ISSUES.md`](docs/GOOD_FIRST_ISSUES.md). The GitHub issue, not this summary, owns
implementation discussion and status.
