# Report v2 migration contract

Report v2 is the v0.4.0 evidence contract. Source `audit` and `retest`, crawl, demo, crawler identity,
edge and AWS conclusions use the same v2 finding, coverage, policy, renderer and exit semantics.
Tool-specific HTTP, DNS, TLS and AWS collection records may use a narrow observation schema, but
they are stored separately and cannot override the v2 conclusion report.

Only source `audit` and `retest` currently implement persisted subject identity and comparable
baseline semantics. Network and AWS helpers use ephemeral subject bindings unless their CLI
explicitly supports a compatible baseline; an ephemeral report is valid evidence for one run but
cannot establish `fixed` in an independent run.

## Identity model

A v2 report identifies its audit subject without publishing a local absolute path:

- `subject.id` is created once by `webapp-security start` and persisted with the project scope.
- `subject.scopeDigest` covers the normalized, security-relevant scope fields.
- `subject.binding=persisted` means the ID came from that reviewed scope.
- A direct audit without a persisted scope uses `binding=ephemeral`; it can be read and rendered, but
  cannot establish compatibility with a later independent run.
- Moving or cloning the project preserves identity only when the reviewed scope record moves with it.
  Rebinding is an explicit operation with lineage, not a path-name inference.

Absolute project paths may be used locally to execute an audit but are not part of the public
subject identity and must not appear in a v2 report's `subject` object.

## Comparable retest

A retest baseline is comparable only when all of these are true:

1. both reports are schema v2;
2. `subject.id` and `subject.scopeDigest` match;
3. the baseline bytes match the recorded `sourceDigest`;
4. the relevant adapter and rule revisions are compatible;
5. the current coverage record proves the same check completed.

Rules added after the baseline may produce `new`. A removed, disabled, unavailable or incomplete
check produces `unretested`. An incompatible rule revision produces `not_comparable`.

`fixed` has one narrow meaning: the same compatible check completed against the same subject and
scope, and the prior condition was absent. Missing fingerprints alone are never evidence of a fix.

## Version 1 reports

Version 1 remains readable for historical display and release verification. It lacks a trustworthy
subject ID, scope digest, ruleset digest, adapter coverage and rule revision, so it must never be
silently accepted as a comparable v2 baseline.

The `migrate-report` command requires the user to review and explicitly bind the v1 report to a
persisted v2 scope. It writes a new v2 document containing:

- the SHA-256 digest of the original v1 bytes;
- the current migration generator version and original v1 producer name/version as separate
  provenance fields;
- `subject.binding=migrated`;
- `migration.boundBy=explicit_user_binding` and a timestamp;
- the original v1 file unchanged;
- baseline compatibility `not_comparable` until a new v2 audit establishes the first trusted
  baseline.

Malformed v1 input is rejected. Missing identity is not inferred from `scope.projectRoot`, report
filename, current working directory, repository name or finding overlap.

## Domain policy

Every v2 report records the effective CI thresholds instead of relying on an undocumented CLI
default. The default policy is:

| Domain | Default threshold |
|---|---|
| `security_exposure` | confirmed or suspected `high` or `critical` |
| `supply_chain` | confirmed or suspected `high` or `critical` |
| `search_discoverability` | `never` |
| `reliability` | `never` |
| `evidence_integrity` | handled by incomplete-evidence exit `3`, not severity inflation |

Users may explicitly configure discoverability or reliability thresholds. Severity remains scoped
to its domain; a HIGH discoverability impact is not relabelled as a HIGH security vulnerability.
The compatible `--fail-on` option sets `security_exposure` and `supply_chain` together. Repeat
`--fail-on-domain <domain=threshold>` for explicit overrides; duplicate domains and malformed
thresholds are rejected. Every report stores the resulting five-domain policy.

New reports record `gateStates: [confirmed, suspected]` with
`actionable_threshold_before_incomplete`. Historical reports without `gateStates` retain their
confirmed-only interpretation. When a run contains both a configured actionable threshold breach
and unrelated incomplete evidence, exit `1` takes precedence and the report retains both. When
there is no actionable threshold breach but required evidence is incomplete, exit `3` applies.

## Failure behavior

- Subject/scope mismatch, tampered baseline, malformed schema or impossible migration metadata:
  exit `2`; commit no retest bundle.
- Compatible subject with a required check unavailable or incomplete: emit explicit `unretested` or
  `unknown` evidence and exit `3` when no confirmed configured threshold is crossed.
- Confirmed threshold breach: exit `1`, while retaining unrelated incomplete evidence in the report.

`migrate-report` produces lineage evidence, not a comparable baseline. Establish the first trusted
baseline with a new persisted v2 source audit. Use `rebind` only after reviewing the prior scope and
acknowledging its exact subject ID; neither command infers identity from a path, repository name or
finding overlap.

The adjacent SHA-256 sidecar detects accidental or partial report modification, and runtime
validation recomputes finding, adapter and report ruleset identities. This is not an authenticated
signature. A principal allowed to rewrite the project identity, report and sidecar can replace the
whole local evidence set; preserve high-trust baselines in access-controlled or signed storage.
