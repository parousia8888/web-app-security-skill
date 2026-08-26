# Ordinary project journeys

These five project records preserve the original v2 source journeys against ordinary open-source
web projects at exact commits. That dated `2026-08-14` evidence is historical: it is not presented
as a current-tool reproduction gate. The separate
[`evidence-v0.7.3.json`](evidence-v0.7.3.json) catalog records current source identity, exact adapter
selection, the exact target-commit boundary used for Gitleaks history, audit exit, byte digest,
stable semantic digest and manual-annotation identity. Neither catalog is a vulnerability
leaderboard or precision benchmark.

The [v0.5.0 built-in review](v0.5.0-review.md) is a separate, additive evidence set. It keeps these
same five commits but runs the broader v3 built-in JavaScript/TypeScript and Python path, then
uniquely classifies every observed finding in
[`v0.5.0-evidence.json`](v0.5.0-evidence.json). The v2 snapshot below remains unchanged for release
history and external-adapter evidence.

| Project | Stack | v2 snapshot | Manual trace |
|---|---|---|---|
| [Linkwarden](linkwarden.md) | Node/Next.js monorepo | 0 confirmed; OSV leads suspected | Direct URL-fetch path `not_applicable`; proxy path unreached |
| [Healthchecks](healthchecks.md) | Python/Django | 0 confirmed; Gitleaks doc/test leads suspected; OSV not applicable | Deployment values remain `unknown` |
| [Open WebUI](open-webui.md) | SvelteKit/Vite + FastAPI | Source-map plus OSV leads suspected | Local source-map fixture retested `fixed`; delivery unknown |
| [Uptime Kuma](uptime-kuma.md) | Express + Vue/Vite | 4 confirmed lockfile facts; external leads suspected | Operator webhook sink `not_applicable` without a boundary bypass |
| [Mealie](mealie.md) | Nuxt/Vue + FastAPI | 0 confirmed; Gitleaks test-material leads suspected | Limited URL-fetch path `not_applicable`; broader paths unknown |

The historical machine-readable [`evidence.json`](evidence.json) records immutable commits, discovery,
adapter/ruleset identity, every rule's coverage, the `2026-08-14` snapshot, deterministic sanitized
finding digests, reviewed confirmed IDs, closures, repair/retest outcome and unreached surfaces. OSV uses a mutable public
advisory database: reruns must report advisory drift rather than rewriting the historical snapshot.

Uptime Kuma and Mealie also appear in the separate five-study [source-methodology corpus](../README.md)
at the same commits. Those documents test manual source-to-boundary reasoning; the journeys here
test the v2 CLI/adapter path. This is five ordinary projects plus five studies, not ten distinct
projects.

## Reproduction boundary

Fetch the source explicitly and run the active catalog contract. Its prerequisite block is generated
from the same adapter definitions used by the runner:

<!-- journey-prerequisites:start -->
The active catalog selects `builtin, gitleaks, osv`. The runner requires only these external binaries:

| Adapter | Required version | Environment variable |
|---|---:|---|
| Gitleaks | `8.30.1` | `WEBAPP_SECURITY_GITLEAKS_BIN` |
| OSV-Scanner | `2.5.0` | `WEBAPP_SECURITY_OSV_SCANNER_BIN` |

```bash
export WEBAPP_SECURITY_GITLEAKS_BIN=/verified/path/to/gitleaks-8.30.1
export WEBAPP_SECURITY_OSV_SCANNER_BIN=/verified/path/to/osv-scanner-2.5.0
```
<!-- journey-prerequisites:end -->

Then reproduce a project from its immutable commit:

```bash
git clone https://github.com/linkwarden/linkwarden.git /tmp/linkwarden-case
git -C /tmp/linkwarden-case checkout 62f1b81ff7f66001b0f5f613202f87771f3186ee
node scripts/run-case-journey.mjs linkwarden /tmp/linkwarden-case --out /tmp/linkwarden-evidence
```

The runner refuses missing caller-provided binaries, a dirty checkout, mismatched `HEAD`, a shallow
repository, an existing output path, or output inside the checkout. It scans the fixed clean checkout
directly and bounds Gitleaks committed-history evidence to commits reachable from the journey's exact
target commit; unrelated local refs and tags are excluded. The boundary is recorded in
`journey-run.json` and the active catalog. The runner writes evidence outside the checkout and
verifies that the checkout remains unchanged. It never downloads tools, executes project
dependencies, or contacts a hosted project.
OSV-Scanner may query the public OSV service; this is the only project-journey network exception.
An audit exit `3` is recorded as incomplete evidence and is not converted to an invocation failure.
Missing or malformed report artifacts still stop the journey. Use `--refresh` only to collect a
new observation; it explicitly does not claim a catalog match.

No hosted instance was probed. Reproducing a journey does not authorize remote testing.
