# External adapter alert policy

Status: **owner policy accepted for this repository on 2026-08-30**. The policy below also defines
the conditions another repository must accept before Checkov, Gitleaks, Opengrep or OSV-Scanner
findings become a merge or release gate. Acceptance does not by itself enable a GitHub setting or
prove that an alert was triaged.

## This repository

| Responsibility | Accepted value |
|---|---|
| Signal owner | `@parousia8888` |
| Triage target | HIGH secret: one business day; dependency finding: three business days |
| Update owner | `@parousia8888` |
| Private escalation | The private reporting process in `SECURITY.md` |
| Gate authority | `@parousia8888` |

The single-maintainer assignment is an ownership record, not independent review. GitHub setting
availability and each live alert disposition are verified separately.

## Required assignment

Before passing `--acknowledge-alert-policy` with a blocking threshold, record all of the following in
the consuming repository:

| Responsibility | Required value |
|---|---|
| Signal owner | Named team or person who receives and closes secret/dependency alerts |
| Triage target | Confirm receipt of a HIGH secret alert within one business day; dependency findings within three business days |
| Update owner | Named team or person responsible for adapter/ruleset updates and fixture review |
| Private escalation | A non-public channel for live credentials, private source details and embargoed advisories |
| Gate authority | Named maintainer who may suppress, downgrade or temporarily disable the gate |

The owner chooses the actual assignments and may set stricter targets. Until those assignments are
accepted, run external adapters with `--fail-on never` and treat their reports as evidence only.

## Triage and suppression

1. Reproduce the finding with the recorded adapter version and sanitized evidence.
2. For a potentially live secret, revoke or rotate first; do not paste the value into an issue.
3. For a dependency advisory, establish whether the package/version is shipped and whether the
   vulnerable path is reachable. The adapter's local `info` severity is not a priority decision.
4. For a Checkov lead, establish the effective deployed user, health probe or workflow token
   permissions. Test file ownership/startup or release/publish/deploy jobs before accepting a fix.
5. Close as fixed only after the same adapter no longer reports the identity under completed
   coverage.

A suppression that affects CI/release or an external adapter must be stored in the consuming
repository and include the exact adapter, rule, path and fingerprint, rationale, approving owner
and an expiry date. Expired or drifted suppressions become active findings and must be removed,
renewed with new evidence or replaced by a fix. Broad repository-wide allowlists without exact
identity, owner and expiry are not accepted. Local built-in evidence-only runs may omit owner and
expiry, but the finding remains visible and the same entry cannot affect a gate.

Repository CodeQL dispositions are recorded in
[`code-scanning-dispositions.md`](code-scanning-dispositions.md) before a test/fixture alert is
dismissed. Production alerts are fixed on the candidate and verified by hosted analysis; they are
not relabelled as fixtures to obtain a green dashboard. The required repository self-audit uses a
separate production-only scope and exact suppressions and fails on active HIGH or unavailable
evidence. Its green result is one bounded signal, not a repository-safety claim.

## Updates and unavailable capability

The update owner reviews new tool versions and rule/database behavior against planted fixtures
before changing a pin. Missing tools, plan-limited GitHub features, timeouts or parse failures remain
`unknown`; no workflow may rewrite them as zero findings. External tools are supplied by the caller
or CI and are never downloaded by the Action.
