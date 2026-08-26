# Web App Security Skill productization plan

Status: completed
Owner: parousia8888  
Started: 2026-08-13  
Completed: 2026-08-13
Canonical repository: `parousia8888/web-app-security-skill`

This document is the source of truth for the P0-P7 productization program. Update a phase record
immediately after its acceptance criteria pass. A phase is not complete because files exist; it is
complete only when its behavior is tested and the evidence below is recorded.

## Product contract

### Audience

Web product owners and builders who use AI coding agents and do not need prior offensive-security
experience. Public copy must not label or segment them as "vibe coders".

### Public identity

- Product name: **Web App Security Skill**
- Planned repository: `parousia8888/web-app-security-skill`
- Skill identifier: `web-app-security`
- CLI command: `webapp-security`
- GitHub Action: `parousia8888/web-app-security-skill@v1`

The product and repository names end in `Skill`. The CLI remains shorter because it is a command,
not a public project name.

### Core promise

> Give an AI coding agent a web project. It scopes the work, finds explainable risks, prepares the
> smallest reviewable hardening changes, retests them, and records what is fixed and what remains.

Chinese:

> 把 Web 项目交给 AI coding agent，完成范围确认、风险检查、最小加固、复测和证据交付。

### First-use path

```text
project source + optional owned deployment
  -> stack and scope discovery
  -> passive/source checks
  -> confirmed / suspected / unknown / not-applicable findings
  -> reviewable patch plan or patch
  -> retest and baseline diff
  -> evidence report and remaining risks
```

### Capability labels

Every public capability claim must use one of these labels:

1. **Automated and regression-tested**: implemented by a deterministic script or CLI path with a
   test that plants the failure.
2. **Agent-guided methodology**: the Skill tells an agent how to perform context-dependent review;
   there is no claim of a general automatic scanner.
3. **Planned**: not shipped and not shown as available.

Never collapse these labels into one undifferentiated coverage claim.

### Result states

- `confirmed`: reproduced with sufficient sanitized evidence.
- `suspected`: a lead requiring more context or reproduction.
- `unknown`: the check or evidence source was unavailable.
- `not_applicable`: outside the recorded scope or absent from the project.

An unavailable check is never a pass. Installing the Skill does not prove a project secure.

## Packaging audit baseline

The useful lesson from `reverse-skill` is product packaging, not website layout:

- Keep one memorable project/repository identity.
- Compress a complex system into a small number of user outcomes before showing internal modules.
- Separate the human entry (`README.md`) from the agent bootstrap (`README_AI.md`) and execution
  contract (`SKILL.md`).
- Turn first use into one copyable prompt or command.
- Use countable, reproducible maturity signals instead of generic claims.
- Provide visible tutorial, release, contribution, community, and evidence paths.

Do not copy these weaknesses:

- Dynamic counts that disagree across surfaces.
- Scope breadth presented without per-capability completion state.
- Stars, sponsors, or growth curves used as correctness evidence.
- Release tags without artifacts and verification material.

Current project strengths at program start:

- deterministic local before/after demo;
- Claude Code, Codex, and ordinary CLI installer;
- passive-by-default Action and explicit active-test authorization gates;
- CI, CodeQL, SPDX generation, checksums, and provenance workflow;
- threat model, false-positive policy, compatibility matrix, and five fixed-commit case studies;
- fail-closed result semantics: evidence failure becomes `unknown`, not safe.

Current project gaps at program start:

- four competing names across repository, UI, Skill ID, and CLI;
- public copy mixes deterministic automation with broad agent-guided methodology;
- no `start <project>` path that discovers a project and creates a scoped run;
- no stable finding schema, HTML/SARIF output, baseline diff, or general retest command;
- examples establish methodology but do not yet show a complete ordinary project journey;
- no published v0.3 release artifacts or stable major Action tag;
- no dedicated human tutorial / agent-bootstrap separation.

## Program rules

1. Complete phases in order unless a later task is an independent prerequisite.
2. Update the phase record in this file before starting the next phase.
3. Keep active network testing behind ownership/written-authorization gates.
4. Prefer source analysis and local fixtures for demonstrations and case studies.
5. Do not publish an unverified metric or claim a methodology is an automated scanner.
6. Keep changes reviewable; use separate commits for phase completion and external migrations.
7. Do not create the `v0.3.0` tag until the release phase verifies the final versioned tree.

## Phase ledger

| Phase | Deliverable | Status | Evidence |
|---|---|---|---|
| P0 | Product contract and honest capability boundary | completed | `ea90082` + checks below |
| P1 | Unified identity and human/agent entrypoints | completed | `c27a8ec` + migration evidence below |
| P2 | Outcome-led README and first-run packaging | completed | `cf3ae40` + checks below |
| P3 | `start <project>` project discovery and scoped run | completed | `91a6dc9` + checks below |
| P4 | Finding schema, reports, patch/retest baseline loop | completed | `6454fb1` + checks below |
| P5 | Three ordinary open-source project journeys | completed | `39eb817` + fixed-commit runs below |
| P6 | Install/upgrade/uninstall, Action v1, signed release | completed | `dcb4975` + release evidence below |
| P7 | Tutorial, contribution path, launch evidence | completed | `21a95f5` + public/live evidence below |

## P0 - Product contract and capability boundary

### Deliverables

- Record the audience, identity, promise, first-use path, result states, and non-goals.
- Publish a capability matrix that separates automated, agent-guided, and planned behavior.
- Align the Skill output contract and public description with the result states.
- Add checks that prevent capability-state drift in the main public surfaces.

### Acceptance

- A first-time reader can state the input, process, output, and limits without knowing AppSec terms.
- API, OAuth, LLM, database, and supply-chain methodology is not presented as one automatic scan.
- `npm run check` and the Skill validator pass.

### Completion record

- Status: completed 2026-08-13
- Implementation: `docs/capabilities.json` is the structured source of truth for 14 capabilities
  across automated/regression-tested, agent-guided, and planned labels. The generated
  `docs/capabilities.md` links every capability to repository evidence. README, Chinese README and
  `SKILL.md` now state the same boundary and the four result states.
- Tests: `npm run check`; `node scripts/generate-capability-matrix.mjs --check`;
  `node scripts/check-product-contract.mjs`; Skill Creator `quick_validate.py`. All passed. The
  contract check fails on missing states, invalid/duplicate capabilities, missing evidence files,
  stale generated output, or missing public-surface markers.
- Commit: `ea90082` (`feat: define product capability contract`)
- Remaining risks: the current repository and Skill identifiers still use the pre-P1 name. The
  capability matrix is English-only until the public documentation phase adds a localized view.

## P1 - Unified identity and entrypoints

### Deliverables

- Migrate public identity to **Web App Security Skill** and repository to
  `parousia8888/web-app-security-skill`.
- Use `web-app-security` as the Skill identifier while preserving documented compatibility for the
  previous `webapp-security-hardening` install path.
- Add `README_AI.md` as the agent bootstrap; keep `README.md` human-facing and `SKILL.md` procedural.
- Update package metadata, Action references, SBOM namespace, installer paths, links, and tests.

### Acceptance

- One public project name appears across GitHub, README, Skill UI, release assets, and Action docs.
- Old repository links redirect; old local installs receive a migration message or upgrade path.
- Claude Code, Codex, and CLI installs pass isolated-home tests.

### Completion record

- Status: completed 2026-08-13
- Implementation: all public and package identities now use **Web App Security Skill**, repository
  `parousia8888/web-app-security-skill`, Skill ID `web-app-security`, CLI `webapp-security`, and the
  matching Action and release artifact prefix. `README_AI.md` is the repository-mode agent entry;
  `README.md` remains the human entry and `SKILL.md` remains the execution contract. The installer
  detects both current and legacy paths, fails before a partial install, and backs up an existing
  `webapp-security-hardening` install only when the user supplies `--force`. An identity gate checks
  package, Skill, Action, README, SBOM, release workflow, and permitted legacy-name locations.
- Tests: `npm run check`; Skill Creator `quick_validate.py`; PyYAML parse of every YAML file;
  isolated-home Claude Code, Codex, CLI, legacy-conflict, and forced-migration tests. GitHub CI run
  [31627604914](https://github.com/parousia8888/web-app-security-skill/actions/runs/31627604914)
  passed on Node 20/22 and Ubuntu/macOS. CodeQL run
  [31627604893](https://github.com/parousia8888/web-app-security-skill/actions/runs/31627604893)
  passed.
- Commit / migration: `c27a8ec` (`feat: unify Web App Security Skill identity`) and `10942b7`
  (`docs: pin Action example to immutable commit`). GitHub renamed the repository in place; the new
  URL returns HTTP 200 and the previous URL returns HTTP 301 to it. `main`, tags `v0.2.0` through
  `v0.2.4`, stars, topics, and workflow history remained attached. Local `origin` now uses the new
  URL. The documented immutable Action reference is
  `c27a8ecae69271a5a2fdfb6acc314cb4ef3ea967`.
- Remaining risks: the public `v1` Action tag and a real `v0.3.0` release do not exist until P6.
  GitHub reports that the pinned CodeQL v3 Action will be deprecated in December 2026 and that
  pinned Actions declaring Node 20 are being forced onto Node 24; P6 must refresh those immutable
  pins and rerun the supply-chain checks.

## P2 - README and first-run packaging

### Deliverables

- Order README as outcome -> demo -> install -> first task -> evidence -> capability limits -> trust.
- Add one copyable first-task prompt for project owners.
- Show a readable before / proposed change / retest example using generated evidence.
- Keep advanced security vocabulary in the detailed references.

### Acceptance

- The first screen states what the Skill does, who it is for, and the next action.
- Every count shown is generated from a checked source of truth.
- English and Chinese public claims remain aligned by an automated consistency test.

### Completion record

- Status: completed 2026-08-13
- Implementation: English and Chinese README surfaces now follow result -> install -> first-project
  prompt -> capability boundary -> deterministic tools -> trust -> cases. The shared
  `docs/public-contract.json` holds both first-task prompts and the case-study inventory.
  `scripts/generate-demo-evidence.mjs` executes the owned local fixture through the real product
  path and generates `docs/demo-evidence.md` with the observed `13 high / 6 medium -> 0 high /
  0 medium` comparison and patch. `scripts/check-public-surfaces.mjs` verifies the outcome-led
  section order, navigation anchors, exact localized prompts, generated demo counts, case count,
  capability-level count, result states, and absence of stale Action placeholder copy. The first
  prompt permits source/local work only; it does not imply authorization for deployment probing.
- Tests: `npm run check`; `node scripts/generate-demo-evidence.mjs --check`;
  `node scripts/check-public-surfaces.mjs`; Skill Creator `quick_validate.py`. The product-surface
  regression also asserts that every demo run produces `summary.md`, JSON reports and patch
  evidence. All passed.
- Commit: `cf3ae40` (`docs: make first-run security outcome reproducible`)
- Remaining risks: the first-project path is still an agent prompt over repository context; it
  does not yet create a versioned scope or detect the target stack. P3 owns that CLI contract. The
  demo covers the existing crawl-boundary automation and must not be read as evidence that every
  agent-guided review is automated.

## P3 - Project start and discovery

### Deliverables

- Add `webapp-security start <project>`.
- Detect supported frameworks, package managers, lockfiles, deployment/config surfaces, and likely
  public origins without reading secrets.
- Create a versioned `security-scope.yml` and run directory before audit work.
- Separate source checks, local checks, passive remote checks, and authorized active checks.
- Make unsupported or ambiguous evidence explicit instead of guessing.

### Acceptance

- Deterministic fixtures cover at least Node/Next.js, Python/FastAPI or Django, and split frontend /
  backend layouts.
- Discovery never prints secret values and performs no network access by default.
- Invalid targets and missing authorization fail before active traffic.

### Completion record

- Status: completed 2026-08-13
- Implementation: `webapp-security start <project>` performs allowlisted, network-free discovery of
  Node, Python and split-stack layouts; records framework/package-manager evidence, manifests,
  lockfiles, deployment/config paths and normalized origin hints; and atomically creates a private
  run directory with a versioned `security-scope.yml`. The scope separates source, local, remote
  passive and remote active modes. Both remote modes remain blocked pending recorded authorization,
  even when an origin is supplied. Discovery skips symlinks and ignored/build/dependency trees,
  reads only supported manifests under a size cap, never reads `.env` contents, strips origin
  path/query/fragment data, and records unsupported/ambiguous evidence as unknown. The schema and
  generated capability matrix ship inside installed Skill payloads.
- Tests: `npm run check`; `node test/project-discovery.test.mjs`; Skill Creator
  `quick_validate.py`; PyYAML parse of repository YAML. Fixtures cover Next.js/pnpm,
  FastAPI/uv, split React/Vite + FastAPI/pip, unsupported projects, missing targets, duplicate run
  IDs, symlink escape attempts, a secret sentinel, origin credential leakage, 0600 scope files,
  0700 run directories and a preload that throws on HTTP/HTTPS/net/DNS/fetch. The installed CLI is
  separately exercised from an isolated home and produces the same blocked scope. All passed.
- Commit: `91a6dc9` (`feat: add network-free project discovery and scope`)
- Remaining risks: dependency-name discovery is evidence-based, not arbitrary code execution, so
  custom or unsupported frameworks remain `ambiguous` or `unsupported`. Manifest `homepage` and
  user origins are unverified hints only. The scope intentionally cannot grant authorization;
  ownership proof and rules of engagement still require a user/agent update before remote work.

## P4 - Finding, report, patch, and retest loop

### Deliverables

- Define a versioned finding/report JSON schema.
- Add Markdown, HTML, SARIF, and JUnit renderers where the target format fits.
- Add baseline diff states: `new`, `fixed`, `unchanged`, and `regressed`.
- Add `audit`, `explain <finding-id>`, and `retest --baseline` CLI paths.
- Generate reviewable patch evidence; default risky changes to patch-only.

### Acceptance

- The demo and project fixtures use the same schema and renderer paths.
- Schema validation, renderer snapshots, planted regressions, and exit-code contracts pass.
- A patch never becomes a confirmed fix until its retest evidence passes.

### Completion record

- Status: completed 2026-08-13
- Implementation: versioned finding/report schemas define five severities, the four product result
  states, stable SHA-256 fingerprints and `new`/`fixed`/`unchanged`/`regressed` baseline states.
  One validated report object renders JSON, Markdown, escaped standalone HTML, SARIF 2.1.0 and
  JUnit. `webapp-security audit` runs narrow source-only rules, writes a non-applying
  `proposed.patch`, and refuses to overwrite existing evidence; `explain` resolves a stable finding
  ID; `retest` requires a baseline. Only confirmed, non-fixed results trip severity gates.
  Suspected results retain that evidence state even when fixed or regressed. The local crawl demo
  now also emits the same evidence schema and renderer bundle without changing its original raw
  reports or `13 high / 6 medium -> 0 high / 0 medium` result. Schemas and runtime modules ship in
  installed Skill payloads.
- Tests: `npm run check`; `node test/evidence-loop.test.mjs`;
  `node scripts/check-evidence-contract.mjs`; Skill Creator `quick_validate.py`; JSON parse of all
  three public schemas. Regressions cover new, unchanged, fixed and regressed state transitions;
  stable fingerprints; a renderer snapshot; HTML hostile-path escaping; SARIF evidence properties;
  JUnit confirmed-vs-suspected semantics; confirmed/suspected exit thresholds; required baseline;
  report collision preservation; patch-only behavior; `explain`; no-network preload; demo schema
  reuse; private output modes; and audit execution from an isolated installed CLI. All passed.
- Commit: `6454fb1` (`feat: add structured findings and baseline retest`)
- Remaining risks: the deterministic source audit intentionally has only four narrow rule families:
  adjacent lockfile absence, environment-named files without reading contents, Node inspector bind
  hints and common production source-map settings. It is not a general SAST engine. API, OAuth,
  LLM, database and other agent-guided reviews can use the schema but still require contextual
  evidence. SARIF and JUnit are projections for integrations; they do not upgrade a suspected
  finding to confirmed.

## P5 - Ordinary open-source project journeys

### Deliverables

- Publish three fixed-commit, source-only journeys covering Node, Python, and a split-stack project.
- For each: scope, discovery, leads, false-positive closure, minimal patch or upstream repair,
  regression, retest, and unreached surfaces.
- Keep intentionally vulnerable benchmarks as ground truth, not as the only product story.

### Acceptance

- No third-party hosted instance is probed.
- Every confirmed statement links to immutable source evidence and a reproducible local path.
- Unknown and false-positive outcomes remain visible.

### Completion record

- Status: completed 2026-08-13
- Implementation: `docs/case-studies/journeys/evidence.json` is the structured source for three
  ordinary-project journeys: Linkwarden at
  `62f1b81ff7f66001b0f5f613202f87771f3186ee`, Healthchecks at
  `49653c350cddc47fc00a471bd1b08b5771a7967c`, and Open WebUI at
  `01f4282f1ffe0d6212f58d3afbeae21fffd0c4be`. The current network-denied deterministic path
  produced respectively 0, 0 and one medium `suspected` source-map result, with zero confirmed
  findings across the three projects. Each public journey records discovery, raw leads,
  false-positive closure, a narrow manual trace, repair/retest and unreached surfaces. The earlier
  five methodology studies remain separate instead of being blended into the ordinary-project
  count. Real-project feedback repaired three precision defects: declared Node workspaces inherit
  their matching ancestor lockfile, requirements files are not required to have a second adjacent
  lockfile, and known `.env` template suffixes are excluded while real environment filenames stay
  filename-only suspected results. `scripts/run-case-journey.mjs` requires a clean Git checkout at
  the exact catalog commit, canonicalizes output containment through symlinked path ancestors,
  refuses output inside the checkout, records the selected adapters' network prerequisites, and compares discovery plus
  selected finding fields against the structured evidence. The Open WebUI upstream tree was not
  edited; a minimal local representative changes `sourcemap: true` to `false` and required-baseline
  retest records the suspected lead as `fixed`.
- Tests: `npm run check`; Skill Creator `quick_validate.py`; JSON and repository YAML parse;
  `node test/case-journeys.test.mjs`; `node test/evidence-loop.test.mjs`;
  `node scripts/check-case-journeys.mjs`; `node scripts/check-public-surfaces.mjs`; and
  `git diff --check` all passed. The journey test plants workspace, requirements, environment-file
  and Open WebUI source-map regressions; asserts no secret sentinel enters evidence; and verifies
  runner rejection of dirty, wrong-commit and in-tree-output checkouts. The runner also passed
  against clean Git checkouts of all three recorded commits with `catalog: matched` and
  `network: none`.
- Commit: `39eb817` (`feat: add reproducible project security journeys`)
- Remaining risks: zero findings means only that the four narrow deterministic rule families did
  not produce a result. No dependency SCA, build execution, hosted artifact request, authenticated
  API exercise, LLM/plugin/data-layer test or third-party deployment probe ran. Linkwarden proxy
  mode, Healthchecks production environment values and Open WebUI public `.map` delivery remain
  `unknown`. Open WebUI's source-map result remains `suspected`; the fixture retest proves the
  rule's local repair loop, not an upstream or deployed fix.

## P6 - Distribution and release

### Deliverables

- Support install, upgrade, uninstall, version, and migration across Claude Code, Codex, and CLI.
- Publish the renamed composite Action and maintain `v1` plus immutable SHA documentation.
- Produce a GitHub Release with source archive, SPDX SBOM, checksums, provenance, and evidence note.
- Verify clean installation from the actual release artifact, not only the working tree.

### Acceptance

- Release/tag/version/evidence match and all public install commands run in clean temporary homes.
- Release assets verify by checksum and GitHub attestation.
- The Action succeeds and fails correctly from an external fixture repository or equivalent isolated
  consumer test.

### Completion record

- Status: completed 2026-08-13
- Implementation: `webapp-security` now supports versioned install markers, `version`, network-free
  `upgrade` from an explicitly obtained payload, `uninstall`, current/legacy migration, timestamped
  backups and refusal of unknown payloads or launchers even with `install --force`. Release builders
  derive version, commit and epoch from the selected Git ref; create a reproducible archive, SPDX
  SBOM, release manifest and sorted checksums; verify archive paths/content and metadata; build twice
  byte-for-byte; and run `install -> version -> start -> upgrade -> uninstall` from the extracted
  archive in a network-denied isolated home. Release/CI Actions use full SHAs, CodeQL is v4, the
  release trigger excludes moving major tags, and a manual consumer workflow executes the public
  `@v1` Action against an owned local fixture for both passive success and authorization rejection.
- Tests: local `npm run check`, `node test/release-artifacts.test.mjs`, release-contract checks,
  workflow YAML parsing and Skill Creator `quick_validate.py` passed. The final public-surface pin
  passed [CI 31637125096](https://github.com/parousia8888/web-app-security-skill/actions/runs/31637125096)
  on Node 20/22 and Ubuntu/macOS plus
  [CodeQL 31637125115](https://github.com/parousia8888/web-app-security-skill/actions/runs/31637125115).
  [Release run 31636806872](https://github.com/parousia8888/web-app-security-skill/actions/runs/31636806872)
  passed every build, lifecycle, attestation, publication and evidence-upload step. Downloaded public
  assets independently passed all three checksums, the archive/manifest verifier, the network-denied
  lifecycle and `gh attestation verify`. The
  [real `@v1` consumer run 31636995276](https://github.com/parousia8888/web-app-security-skill/actions/runs/31636995276)
  passed passive evidence/no-`/.env` assertions and the expected fail-closed authorization path.
- Release / Action pin: implementation `dcb4975`, signing trust anchor `d7df9fa`, public pin update
  `930b7d2`; [v0.3.0](https://github.com/parousia8888/web-app-security-skill/releases/tag/v0.3.0)
  is a signed annotated tag (`fc353ea`, peeled commit `d7df9fa6efd466c3eb13768c3b9ad259d2636e04`).
  Its public asset SHA-256 digests are archive
  `1964253e9057b802fd4ef61eeda9059c230daa8cf066b2b556fa0cbdf4d7bda2`, SBOM
  `6b2abe6e8974255f24e150db3733f3dc2366a641fdb315c9179a7a2aa51c3f19`, manifest
  `045b3ab3130b34c6eb4ee6111472dc5e936f7f84fa853c02763daafdf3599eb4` and checksum file
  `472d7552ad4e5bc54dc0982798a0b59cc5114efb8292e105502f533c64e44d46`. Signed `v1` tag object `440da72`
  peels to the same release commit; the immutable Action reference is
  `parousia8888/web-app-security-skill@d7df9fa6efd466c3eb13768c3b9ad259d2636e04`.
- Remaining risks: GitHub reports the SSH tag signature as `unknown_key` because the public key is
  not registered as an account signing key. The signature itself verifies against the repository's
  `.github/release-signers` trust anchor with fingerprint
  `SHA256:DmZYVL1dLhUmgaJnfZKpZIexgzMv5jk9+YCoBT3zRIg`; registering that same key is required only for
  GitHub's green Verified UI. `v1` is intentionally moving, so security-sensitive consumers should
  keep the immutable SHA pin. Checksums, signatures and attestations prove artifact identity and
  build origin, not that every agent-guided security conclusion is correct.

## P7 - Tutorial, contribution, and launch evidence

### Deliverables

- Publish a concise human tutorial and a separate agent bootstrap.
- Cover installation, first project, result interpretation, patch review, retest, troubleshooting,
  upgrade, uninstall, authorization, and false-positive reporting.
- Convert bounded roadmap work into labeled issues with contribution and test instructions.
- Prepare launch evidence using only reproducible counts, release links, and project journeys.

### Acceptance

- A clean-room first-time flow reaches a report in ten minutes on a supported fixture.
- Tutorial commands are tested as documentation examples.
- GitHub description, topics, homepage, README, tutorial, and release use the same promise.
- No star target is used as an engineering acceptance criterion.

### Completion record

- Status: completed 2026-08-13
- Implementation: `docs/tutorial.md` and `docs/tutorial.zh-CN.md` cover verified release/current
  checkout installation, first-project scope, the four result states, explanation, patch-only
  review, retest, authorization, troubleshooting, false-positive reporting, upgrade and uninstall.
  `README_AI.md` now gives agents the matching repository-mode lifecycle and stop conditions. The
  network-denied `scripts/run-clean-room-tutorial.mjs` installs into an isolated home and exercises
  `version -> start -> audit -> explain -> retest -> upgrade -> uninstall` on a planted before/after
  fixture. `docs/launch-evidence.md` is generated from the 14-capability contract, three journey
  records, five methodology studies, real local demo and v0.3.0 release. Stars and forks were
  removed from the evidence surface. `CONTRIBUTING.md` and `ROADMAP.md` now describe the shipped
  multi-surface product instead of listing shipped CLI/SARIF/Action work as future work.
- Contribution / public surface: GitHub labels are sourced by `docs/github-metadata.json`; bounded
  work is live as issues [#1](https://github.com/parousia8888/web-app-security-skill/issues/1)
  through [#7](https://github.com/parousia8888/web-app-security-skill/issues/7), each with a fixture,
  planted-failure requirement, acceptance tests and no-third-party-target boundary. The GitHub
  description uses the canonical promise, the homepage points to the
  [human tutorial](https://github.com/parousia8888/web-app-security-skill/blob/main/docs/tutorial.md),
  topics are sourced and checked, and the
  [v0.3.0 release](https://github.com/parousia8888/web-app-security-skill/releases/tag/v0.3.0)
  body uses the same promise. `scripts/check-p7-surfaces.mjs --live` checks description, homepage,
  topics, labels, open issue titles/labels, release tag/URL/body and local documentation together.
- Tests: `npm run check`; Skill Creator `quick_validate.py`; parse all 12 YAML files with
  `/usr/local/bin/python3` + PyYAML; `git diff --check`; focused tutorial/P7 tests; local/live P7
  surface checks. All passed. A fresh GitHub clone at
  `6b635437ea3c4aa9fe414e391f035363c1b86d83` remained clean, denied all network from the tutorial
  process, reached a four-finding report (one `confirmed`, three `suspected`) and recorded four
  `fixed`, zero unchanged/regressed results in 658 ms against a 600-second budget.
- Commits / CI: implementation `21a95f5`, public issue inventory `2f170dc`, release live-contract
  check `6b63543`. Implementation-head [CI run 31639404785](https://github.com/parousia8888/web-app-security-skill/actions/runs/31639404785)
  passed the Ubuntu/macOS x Node 20/22 matrix; [CodeQL run 31639404837](https://github.com/parousia8888/web-app-security-skill/actions/runs/31639404837)
  passed. Release tags were not moved: signed `v0.3.0` and `v1` still peel to
  `d7df9fa6efd466c3eb13768c3b9ad259d2636e04`.
- Remaining risks: native Windows is unsupported and the clean WSL2 verification remains tracked in
  #3. The deterministic source audit intentionally has a narrow rule set; agent-guided domains are
  not a general automatic scanner and the case corpus is not a precision benchmark. GitHub still
  shows the release SSH signature as `unknown_key` until the same public key is registered to the
  maintainer account, although repository trust-anchor verification succeeds. Open roadmap issues
  are planned work, not shipped capability, and adoption metrics remain outside engineering
  acceptance.

## Program completion

The program is complete only when P0-P7 are completed, the final worktree is clean, required CI and
release checks pass, public links resolve, and any unavoidable external limitation is recorded with
an exact owner action rather than silently marked done.
