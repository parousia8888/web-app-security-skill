# Threat Model

## Assets and trust boundaries

The project protects five assets: the target application's availability, confidential evidence,
the correctness of audit verdicts, baseline identity and lineage, and crawler/search availability.
Trust boundaries exist between the user and agent, the local skill and target, prior and current
audit runs, external tool output, vendor-published crawler data, cloud APIs, CI, and release
consumers.

## In-scope threats

| Threat | Consequence | Primary controls |
|---|---|---|
| Unauthorized active testing | Legal or operational harm | Phase 0 gate; active probes opt-in |
| False `verified` crawler | Attacker gains a rate-limit exemption | Product-specific published ranges or FCrDNS |
| False `spoofed` crawler | Legitimate search/AI traffic is blocked | Fail open on unavailable evidence; exact source matching |
| Network failure reported as safe | Missing control is trusted | Explicit `unknown`; non-zero exit |
| Cross-project or partially tampered baseline accepted | Unrelated findings are reported as fixed | Persisted subject/scope identity, report sidecar, internal digest validation, ruleset compatibility, reject-before-write |
| Incomplete traversal reported clean | Unscanned source is interpreted as no findings | Coverage ledger; relevant skip/truncation becomes `unknown` and non-zero |
| Parser or external tool failure reported clean | Missing detection is trusted | Structured adapters; unavailable/malformed evidence becomes `unknown` |
| Lexical source match reported as an exploitable vulnerability | Users make risky changes based on an unproven input path | Source/scanner matches default to `suspected`; evidence boundary names missing flow/reachability proof |
| Security patch breaks normal product behavior | A warning disappears while the product regresses | Review-only proposal; side-effect field; separate security and functional retests; rollback criteria |
| Agent silently selects product policy | Authentication, CORS, public access, data or infrastructure changes without owner intent | Structured `userDecisions`; approval gate; CLI never applies project edits |
| Secret leakage in reports | Credential or user-data exposure | Sanitized evidence contract; private reporting |
| Partial or permissive report write | Sensitive or misleading evidence remains on disk | Private modes, exclusive staging, validation and atomic bundle commit |
| CI/release substitution | Consumers run modified code | Full-SHA actions, cross-channel source identity, repository-local tag policy, platform signature verification, separate GitHub-asset and npm provenance, checksums and SPDX SBOM |
| Agent overreach | Destructive or out-of-scope actions | Read-only default; minimum proof; explicit phase routing |
| Denial of service by verification | Target availability impact | Bounded concurrency; active rate test opt-in; `--n` cap |

## Non-goals

The project does not make a site secure by installing the skill, replace authenticated application
testing, prove absence of vulnerabilities, or authorize testing of third-party systems. User-agent
identity never grants access to private routes.

## Security invariants

1. Unknown evidence must never be rendered as passing.
2. A crawler claim is verified only by evidence for that exact product or by matching FCrDNS.
3. Active traffic beyond ordinary page retrieval requires an authorization anchor and explicit flag.
4. A confirmed bug fix must have a regression that fails when the bug is restored.
5. Reports must state what was not reached and keep suspected findings separate from confirmed ones.
6. A prior finding is `fixed` only when subject, scope and rule evidence are compatible and the same
   current check completed; absence from output alone is insufficient.
7. Detection coverage must not include demo, reporting, installation or distribution capabilities.
8. A source syntax/sink pattern or external scanner match cannot become `confirmed` without the
   rule-specific independent evidence required by its boundary.
9. A repair cannot be called `retested` unless both the security-specific check and affected normal
   product behavior passed; unavailable functional evidence remains `unknown`.
10. Authentication, authorization, public access, CORS/session, stored-data and production-policy
    choices remain owner decisions rather than agent defaults.

The v0.4.0 identity and v1 migration boundary are recorded in
[`report-v2-migration.md`](report-v2-migration.md). v0.5.0 source findings use the v3 explanation
contract while preserving compatible persisted v2 source baselines in memory. Crawl, crawler
identity, edge and AWS evidence remain v2 surfaces.
The local report sidecar is an integrity check, not an authenticated signature: a principal that can
rewrite the project identity, report and sidecar can replace the evidence set. Preserve important
baselines in access-controlled or signed storage when the local writer is outside the trust boundary.
