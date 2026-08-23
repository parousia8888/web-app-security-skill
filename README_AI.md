# Web App Security Skill - agent bootstrap

This file is the repository-mode entry for an AI coding agent. Human-facing product and install
information lives in `README.md`; the execution contract lives in `SKILL.md`.

## Start here

1. Read `SKILL.md` and `docs/capabilities.md` completely.
2. Identify the user's project root, deployment context if supplied, and requested outcome.
3. Separate available deterministic tools from agent-guided review. Do not imply that every
   methodology phase is an automatic scan.
4. Create or update an authorization scope before any active request. Passive/source work may be
   prepared first, but do not access a third-party host without written authorization.
5. Prefer source review and local fixtures. Use the smallest non-destructive proof necessary.
6. Classify every result as `confirmed`, `suspected`, `unknown`, or `not_applicable`.
7. Present the professional term, plain-language meaning, consequence, evidence boundary, proposal,
   alternatives, side effects, owner decisions, security retest, functional retest and rollback.
8. Prepare reviewable changes, preserve existing user edits, and retest every applied fix.
9. Report evidence, limitations, remaining risks, and the exact verification that ran.

## First task prompt

```text
Use $web-app-security on this web project. Start with source and local checks, explain each risk in
plain language, prepare the smallest reviewable hardening changes, and retest applied fixes. Do not
run active checks against a deployment until I provide ownership or written authorization.
```

## Required inputs

Use what the user supplied. Ask only when a missing item changes authorization or the requested
result:

- project root or repository;
- optional owned deployment origin;
- environment (`local`, `staging`, or `production`);
- ownership or written authorization before active traffic;
- prohibited actions and availability constraints;
- whether the agent may apply patches or must produce patch-only evidence.

Never infer ownership from repository access, DNS reachability, or a user-agent string.

## Current execution surfaces

- `node scripts/webapp-security.mjs install [--target claude|codex|cli|both|all]`
- `node scripts/webapp-security.mjs version`
- `node scripts/webapp-security.mjs start <project>`
- `node scripts/webapp-security.mjs audit <project-or-run> [--profile deep]`
- `node scripts/webapp-security.mjs explain <finding-id> --report <report.json>`
- `node scripts/webapp-security.mjs repair-plan <finding-id> --report <report.json> --out <directory>`
- `node scripts/webapp-security.mjs repair-validate <repair-record.json>`
- `node scripts/webapp-security.mjs retest <project-or-run> --baseline <report.json>`
- `node scripts/webapp-security.mjs demo`
- `node scripts/webapp-security.mjs crawl ...`
- `node scripts/webapp-security.mjs verify-crawler ...`
- `node scripts/webapp-security.mjs verify-edge ...`
- `node scripts/webapp-security.mjs aws ...`
- `node scripts/webapp-security.mjs upgrade [--target ...]`
- `node scripts/webapp-security.mjs uninstall [--target ...]`

The source audit has narrow deterministic rules and stable multi-format findings; it is not a
general SAST engine. Agent-guided findings may use the same evidence contract, but do not gain
automatic confirmation. Project discovery only establishes source/local scope; it does not prove
deployment ownership or authorize remote traffic.

Every actionable source finding must retain both audiences. Keep the professional term and
standards reference, then explain the issue without assuming security vocabulary. Phrase the
consequence conditionally for `suspected` or `unknown` evidence. Never omit likely product side
effects or select an authentication, authorization, public-access, CORS/session, stored-data or
production policy on the user's behalf.

## Repository-mode first run

1. Run `webapp-security version` and record it with the result.
2. Run `webapp-security start <project> --run-id <id>` and review the generated
   `security-scope.yml` before audit work.
3. Run `webapp-security audit <run-directory> --name report --fail-on never` so findings do not
   prevent evidence creation.
4. For wider caller-installed tooling, run `webapp-security doctor <project> --adapter all`, then
   use `webapp-security audit <project> --profile deep --fail-on never`. Missing tools are `unknown`;
   the command does not install them.
5. Use `webapp-security explain <finding-id> --report <report.json>` when evidence, consequence or
   retest is unclear.
6. Review `proposed.patch`. Do not apply it automatically. It may combine diffs with manual steps
   and may cover only part of the report.
7. If patch-only was requested, stop after delivering the patch, affected files, expected risk and
   exact retest command. Do not report any item as fixed.
8. If changes were authorized and applied, run project tests, then write `retest` evidence to a new
   directory using the original JSON report as `--baseline`.
9. Report `fixed`, `unchanged`, `regressed`, remaining and unreached results separately.

## Result interpretation

- `confirmed`: reproduced with sufficient sanitized evidence. It may be described as demonstrated.
- `suspected`: a lead. Obtain runtime/context evidence or close it with an explicit reason.
- `unknown`: evidence was unavailable. State what failed and never convert it to safe.
- `not_applicable`: absent or outside the recorded scope. Preserve the scope reason.

Baseline states do not replace evidence states. `fixed` means the baseline fingerprint no longer
reproduced on retest; source-only `suspected` findings can still require runtime verification before
claiming the deployed risk is closed.

## Patch and change handling

- Default to patch-only for production, authentication, authorization, data, WAF/CDN, IAM and other
  high-blast-radius changes unless the user explicitly authorizes application.
- Inspect the worktree before editing and preserve unrelated changes.
- Keep the smallest reviewable change and identify rollback/availability effects.
- Never treat generated `proposed.patch`, a successful build or an AI explanation as fix evidence.
- Run the project's own focused tests plus the Skill retest for every applied change.

## Lifecycle

Lifecycle commands operate only on an explicitly obtained checkout or release payload and never
download code themselves. Prefer a verified release for stable use. `upgrade` recognizes current or
documented legacy installs, creates timestamped backups and refuses unknown paths. `uninstall`
removes only recognized current installs and preserves prior backups.

The complete human flow, expected outputs and troubleshooting table are in
[`docs/tutorial.md`](docs/tutorial.md) and [`docs/tutorial.zh-CN.md`](docs/tutorial.zh-CN.md).

## Stop conditions

Stop active work when authorization is missing or ambiguous, scope expands, real third-party data
is reached, production health degrades, credentials appear in output, or required evidence cannot
be obtained safely. Record the state as `unknown` or `suspected`; do not convert it to a pass.

Also stop before applying a patch when the user requested patch-only output, the worktree contains
overlapping changes that cannot be preserved, a required rollback path is absent, or the change
would materially alter production without explicit approval.
