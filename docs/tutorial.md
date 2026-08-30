# First project tutorial

This tutorial takes a clean machine from installation to a scoped source audit, patch review,
retest, upgrade and uninstall. The product promise is: **Scope, audit, harden, and retest web
projects with AI coding agents and reproducible evidence.**

The deterministic path shown here reads local source files and does not contact a deployment. In
the published v0.8.0 release it runs 25 built-in risk rules and 3 evidence-integrity rules, with
deeper JavaScript/TypeScript and Python coverage. Supported Express, NestJS and Next.js App Router
projects also receive a separate route-security review with bounded access-control chains and
separate Next.js Server Actions. It remains a bounded first pass, not a general SAST scan,
automatic BOLA proof or proof that a project is secure. Effective lexical token and operation
budgets are recorded in the report; exhaustion is incomplete evidence with exit `3`, not a pass.

The current v0.8.0 release writes route-security v3. For exact supported selectors it can
carry object, principal and tenant facts through at most four project-local call edges into bounded
Prisma/Drizzle operations, then distinguish a visible query predicate from a supported post-load
comparison. Read framework inventory coverage and `accessPathCoverage` separately. `completed`
means the bounded analysis finished, not that authorization is correct or a BOLA/IDOR vulnerability
exists. A route-security v1/v2 artifact is `not_comparable / route_schema_changed` against v3; make
a new v3 baseline before enabling the route-regression gate.

### Make the recorded source scope real

`webapp-security start` writes `auditBoundary.sourceRoots` and `excludedDirectories` into the
run's `security-scope.yml`. In the v0.8.1 candidate these values are a file-read boundary, not a
report filter. Edit the versioned scope before auditing when a monorepo needs a narrower review,
then keep the subject and scope file with the run evidence:

```yaml
auditBoundary:
  sourceRoots:
    - apps/web
    - packages/auth
  excludedDirectories:
    - generated
    - fixtures
```

Roots are unique POSIX-relative directories inside the project. Exclusions are directory
basenames, not globs or paths. `.git` and `.webapp-security` remain mandatory engine exclusions.
Missing, unreadable or symlink roots fail closed before a report is written. Governing manifests
and lockfiles can be read only when they govern an admitted nested root; source outside the roots is
not opened. The same compiled policy applies to route analysis and Git diff selection.

External adapters must honor the same read boundary. Checkov receives admitted Dockerfiles and
workflow files; OSV receives admitted or governing lockfiles; Opengrep and working-tree Gitleaks run
against private path-preserving snapshots. Gitleaks history cannot currently prove exact restricted
scope, so a restricted historical run records `unknown / history_scope_not_supported` and exits
non-zero rather than scanning broadly and hiding the extra reads. Read
[`adapter-protocol.md`](adapter-protocol.md) before selecting a deep profile for a narrow scope.

### Record an exact reviewed suppression

Use suppression only after reviewing a finding. Create `webapp-security.suppressions.json` at the
project root and copy the exact adapter ID, rule ID, repository-relative path and fingerprint from
the report. Bind the file to the persisted project subject:

```json
{
  "schemaVersion": 1,
  "subjectId": "copy-from-security-scope-subject-id",
  "entries": [
    {
      "id": "reviewed-generated-html-2026-08",
      "adapterId": "builtin-source",
      "ruleId": "js-dom-html-injection",
      "path": "apps/web/src/generated-preview.ts",
      "fingerprint": "copy-the-64-character-report-fingerprint",
      "reason": "Reviewed generated numeric chart markup; no untrusted string reaches the sink.",
      "owner": "@security-owner",
      "createdAt": "2026-08-31T00:00:00Z",
      "expiresAt": "2026-11-30T00:00:00Z"
    }
  ]
}
```

The entry does not delete or downgrade the finding. Every renderer keeps it and labels the policy
disposition. A different path, rule or fingerprint, an expired entry, malformed/symlink policy, or
an unmatched target leaves the finding active and adds a diagnostic. Unknown and
evidence-integrity results remain active. Local evidence-only built-in use may omit owner and
expiry; CI/release gates and all external-adapter suppressions require both. Commit a gate-changing
policy for review and remove it when the underlying condition is fixed. See the
[false-positive policy](false-positive-policy.md) for the governance contract.

## Prerequisites

- macOS or Linux;
- Node.js 22 or 24;
- Git;
- a project you may inspect and modify.

See the [compatibility matrix](compatibility.md) for the tested environment boundary.

## Install

### Stable release

Download every v0.8.0 asset, verify the checksums, extract the archive and install from that verified
payload:

```bash
mkdir web-app-security-release && cd web-app-security-release
gh release download v0.8.0 --repo parousia8888/web-app-security-skill
sha256sum -c SHA256SUMS
tar -xzf web-app-security-skill-0.8.0.tar.gz
node web-app-security-skill-0.8.0/scripts/webapp-security.mjs install
webapp-security version
```

On macOS, use `shasum -a 256 -c SHA256SUMS` when GNU `sha256sum` is unavailable. The release page
also publishes an SPDX SBOM, source manifest, build-provenance attestation and signed tag. See the
[v0.8.0 release](https://github.com/parousia8888/web-app-security-skill/releases/tag/v0.8.0).

### Current checkout

Use this path to evaluate the current `main` branch or contribute:

```bash
git clone https://github.com/parousia8888/web-app-security-skill.git
cd web-app-security-skill
node scripts/webapp-security.mjs install
webapp-security version
```

The default installs Claude Code, Codex and the ordinary CLI. Use `--target claude`, `codex`, `cli`
or `both` to select a subset. Installation refuses unknown existing paths; `--force` only replaces
recognized current or legacy payloads and creates timestamped backups.

## Reproduce the local tutorial

From a current checkout, run the complete tutorial against the intentionally misconfigured fixture:

```bash
tutorial_output="$(mktemp -d)"
node scripts/run-clean-room-tutorial.mjs --out "$tutorial_output"
cat "$tutorial_output/tutorial-result.json"
```

The runner creates an isolated home, installs the CLI, denies network access, creates a persisted
scope, audits the `before` fixture, explains one lead, explicitly rebinds the hardened fixture,
retests it, upgrades and uninstalls. The expected baseline is four findings: one `confirmed` and
three `suspected`. The retest must record all four as `fixed` within the ten-minute budget.

## Start your project

Change to the root of a project you own or are authorized to inspect:

```bash
cd /path/to/your-project
webapp-security start . --run-id first-review
```

Review `.webapp-security/runs/first-review/security-scope.yml`. It records a privacy-preserving
persisted subject ID, scope digest, discovered frameworks, package managers, lockfiles,
deployment/config paths, assumptions and blocked remote modes. The private identity record lives
under `.webapp-security/project.json`. Neither file grants authorization to contact a deployment.

Run the source audit into that scoped directory:

```bash
webapp-security audit .webapp-security/runs/first-review \
  --name report --fail-on never
```

The output includes `report.json`, `report.sha256`, `report.md`, `report.html`, `report.sarif`,
`report.junit.xml` and `proposed.patch`. Use JSON for automation, the sidecar for local integrity
checking, Markdown/HTML for review, SARIF/JUnit for CI, and the patch file only as a proposal.

On a supported Express, NestJS or Next.js App Router project, also open `route-security.md` before
making an authorization change. Review it in this order: framework and access-path coverage,
application controls, state-changing/object-addressed routes without route-scoped controls,
completed paths without an observed supported constraint, partial paths, then the separate Server
Action inventory. The companion JSON and Markdown have independent entries in
`route-security.sha256`.

The default policy gates HIGH confirmed and suspected security or supply-chain findings. Suspected
evidence is not promoted: exit `1` means the lead needs review before CI passes, while the report
continues to state what was not proved. Use `--fail-on never` for a non-blocking first report.
Reports summarize by domain, evidence state and severity. Keep `--fail-on` for the compatible
security/supply-chain threshold, and add a repeatable domain override only when that domain belongs
in the CI gate:

```bash
webapp-security audit .webapp-security/runs/first-review \
  --fail-on high --fail-on-domain reliability=high
```

## Interpret results

| State | Meaning | Required response |
|---|---|---|
| `confirmed` | Reproduced with sufficient sanitized evidence | Prioritize and retest the fix |
| `suspected` | A source or scanner lead lacks runtime/context evidence | Reproduce or close with evidence |
| `unknown` | The check or evidence source was unavailable | Restore evidence access; never count as pass |
| `not_applicable` | Outside the recorded scope or absent | Keep the scope reason |

Explain one finding without changing the project:

```bash
webapp-security explain <finding-id> \
  --report .webapp-security/runs/first-review/report.json
```

Do not promote a filename match, static pattern or AI suggestion to `confirmed`. For example,
enabled source maps remain `suspected` until a built artifact or owned deployment proves public
delivery.

The default explanation is deliberately readable before it is technical. For every actionable v3
finding, check these fields in order:

1. `technicalTerm` and `state`: the professional name and what the audit actually proved.
2. `plainLanguage` and `consequence`: what the code is doing and what might happen if the missing
   conditions are real.
3. `evidenceBoundary`: what the rule did not establish, such as input flow or runtime reachability.
4. `proposal`, `alternatives` and `sideEffects`: the suggested change, another viable path and what
   normal behavior could change.
5. `userDecisions`, `securityRetest`, `functionalRetest` and `rollback`: decisions the project
   owner must make and the evidence required before keeping the change.

## Review and apply a patch

Open both the report and `.webapp-security/runs/first-review/proposed.patch`. The patch may contain
machine-applicable diffs and manual review instructions. It is never applied by `audit`, may not
cover every finding, and does not prove a fix.

Before changing source:

1. Verify the evidence points to the intended component.
2. Check whether the change affects production traffic, authentication, data, SEO or crawlers.
3. Keep the smallest reviewable change and preserve the original report as the baseline.
4. Run the project's own tests after the change.

Create a private review-only repair record for one finding:

```bash
webapp-security repair-plan <finding-id> \
  --report .webapp-security/runs/first-review/report.json \
  --out .webapp-security/runs/first-review/repair-review
webapp-security repair-validate \
  .webapp-security/runs/first-review/repair-review/repair-record.json
```

The initial record remains `review_required` with approval pending and no patch applied. The CLI
does not edit it into an approved or applied state and does not edit project files. Authentication,
authorization, public routes, CORS, cookies/sessions, stored data and production infrastructure
always require an explicit owner decision. A repair reaches `retested` only after both its named
security verification and the affected normal product journey pass.

For an AI coding agent, use the canonical first-task prompt from the repository README or
[`README_AI.md`](../README_AI.md). Tell the agent whether it may apply changes or must return
patch-only evidence. High-risk and production changes require explicit approval.

## Retest

After reviewing and applying the chosen change, create a new run and write new evidence there:

```bash
webapp-security start . --run-id first-review-retest
webapp-security retest .webapp-security/runs/first-review-retest \
  --name report \
  --baseline .webapp-security/runs/first-review/report.json \
  --fail-on high
```

Inspect `summary.byBaseline` in the new JSON report. A finding is `fixed` only when subject and
scope match, the rule identity is compatible, current coverage completed and the condition is
affirmatively absent. Removed or unavailable checks become `unretested`; incompatible revisions
become `not_comparable`. Keep runtime or deployment verification requirements for source-only
`suspected` results.

For a moved or fresh clone, first review a prior scope, then explicitly bind the clone:

```bash
webapp-security rebind /path/to/moved-project \
  --scope /path/to/prior/security-scope.yml \
  --acknowledge-subject <exact-subject-id>
```

Historical v1 reports cannot become comparable. `migrate-report` preserves their byte digest and
explicit lineage in a new v2 document, while leaving the original unchanged. Establish a new v2
audit as the first comparable baseline.

## Authorization boundary

Local source work does not authorize remote testing. Before any active request, record ownership or
written authorization, exact origins/accounts, time window, prohibited actions and stop conditions.
Never use a third-party hosted instance as a tutorial target.

Passive crawl inspection still sends HTTP requests. Sensitive-path probes and active rate-limit
checks additionally require `--acknowledge-authorization`. Stop if scope expands, third-party data
appears, production health degrades or evidence would expose a secret.

## Troubleshooting

| Symptom | Resolution |
|---|---|
| `webapp-security: command not found` | Add `~/.local/bin` to `PATH`, or invoke the checkout's `node scripts/webapp-security.mjs` |
| Exit code `1` | Findings met `--fail-on`; evidence was still written |
| Exit code `2` | Usage, scope, authorization or evidence setup failed; do not treat it as a pass |
| Exit code `3` | Required evidence was unknown, partial or unavailable and no configured actionable threshold breach took precedence |
| `refusing to overwrite existing evidence` | Choose a new `--out` directory or report name; retain the baseline |
| Unsupported or ambiguous stack | Keep `unknown` and use the agent-guided methodology |
| Remote check blocked | Supply recorded authorization and acknowledgement only for an owned target |

## Report a false positive

Use the [false-positive issue form](https://github.com/parousia8888/web-app-security-skill/issues/new?template=false-positive.yml)
with the version, finding ID, minimal sanitized fixture, actual/expected state and environment. Do
not include tokens, cookies, account identifiers, private source or real client IPs. Use the private
channel in [`SECURITY.md`](../SECURITY.md) when the report itself is sensitive.

The [false-positive policy](false-positive-policy.md) requires a reproduced failing regression
before a rule changes.

## Upgrade or uninstall

Lifecycle commands never download code. Obtain and verify the newer release first, then run its
payload:

```bash
node /path/to/new-release/scripts/webapp-security.mjs upgrade
webapp-security version
webapp-security uninstall
```

Upgrade backs up recognized installations before replacement. Uninstall removes recognized current
payloads and launchers while preserving prior backups; it refuses unknown directories.
