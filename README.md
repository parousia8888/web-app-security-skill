<h1 align="center">Web App Security Skill</h1>
<h3 align="center">Scope, audit, harden, and retest web projects with AI coding agents and reproducible evidence.</h3>

<p align="center">
  <a href="https://github.com/parousia8888/web-app-security-skill/tags"><img src="https://img.shields.io/github/v/tag/parousia8888/web-app-security-skill?sort=semver" alt="latest tag"></a>
  <a href="https://github.com/parousia8888/web-app-security-skill/actions/workflows/ci.yml"><img src="https://github.com/parousia8888/web-app-security-skill/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/parousia8888/web-app-security-skill/actions/workflows/codeql.yml"><img src="https://github.com/parousia8888/web-app-security-skill/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://www.npmjs.com/package/web-app-security-skill"><img src="https://img.shields.io/npm/v/web-app-security-skill" alt="npm version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="MIT license"></a>
  <a href="#trust-and-release-evidence"><img src="https://img.shields.io/badge/SBOM-SPDX%202.3-5965d8" alt="SPDX 2.3 SBOM"></a>
</p>

<p align="center">
  <a href="#see-the-result">Demo</a> ·
  <a href="#whats-new-in-v071">v0.7.1</a> ·
  <a href="#install">Install</a> ·
  <a href="#run-the-first-project">First project</a> ·
  <a href="docs/tutorial.md">Tutorial</a> ·
  <a href="#github-action">GitHub Action</a> ·
  <a href="#5-ordinary-project-journeys">Project journeys</a> ·
  <a href="README.zh-CN.md">中文</a>
</p>

<p align="center">
  For web product owners and builders using AI coding agents; no offensive-security background is
  required. Run a local source-only first pass from the root of a project you may inspect.
</p>

```bash
npx --yes web-app-security-skill audit . --fail-on never
```

`--fail-on never` lets the first report finish without turning a suspected lead into a failing CI
claim. This command reads local project files, does not contact a deployment and does not edit code.
For each actionable result, the report gives you:

- the security term, a plain-language explanation and a realistic consequence;
- what the evidence proves and what still needs human or runtime confirmation;
- a reviewable change, likely product side effects, rollback conditions, and separate security and
  normal-behavior retests.

For supported JavaScript/TypeScript frameworks, the same command also writes
`route-security.json`, `route-security.md` and a SHA-256 sidecar. It inventories HTTP routes and
Next.js Server Actions separately, lists application-wide controls once, and shows what to review
next:

| Security term | Plain meaning | What the route view can say |
|---|---|---|
| Application control | What was registered for the whole app? | A global guard or middleware is listed once; this does not prove it protects every route. |
| Authentication (authn) | Who is making the request? | A supported login/session source was observed, was not observed, or could not be resolved. |
| Route-level authorization (authz) | May this identity call this operation? | A supported policy/guard was observed, or a custom route control still needs review. |
| Object-level authorization (BOLA/IDOR) | May this identity access this specific record? | A caller-selected ID can be followed into supported Prisma/Drizzle/Supabase operations in the handler or through one exact local call. A missing visible constraint is a review lead, not proof of a vulnerability. |

`review_first`, `review_next` and `review_later` are work-order labels, not severity scores. A missing
visible control is never converted into a confirmed vulnerability.

In plain language, the access-chain view can say: "this route takes a project ID, obtains the
current user through Auth.js, and sends both values into a Prisma query through one resolved local
function." It cannot prove runtime reachability, a database policy, or what happens beyond a second
local call. Supabase results always say that external RLS policy evidence is still required.

For the widest maintained local pass, select the no-download deep profile. It uses the built-in
rules and calls pinned Checkov, Gitleaks, Opengrep and OSV-Scanner binaries already installed by the
user. A missing tool becomes `unknown` evidence with setup guidance:

```bash
npx --yes web-app-security-skill audit . --profile deep --fail-on never
```

<p align="center">
  <a href="docs/demo-evidence.md"><img src="docs/assets/demo.gif" alt="Owned local source fixture: a suspected HIGH OS command injection lead is explained, changed from shell execution to argument-separated execution, then security and normal product behavior are retested"></a>
</p>

<p align="center"><a href="docs/demo-evidence.md">Read the generated reports and patch behind this demo.</a></p>

## See the result

Audit an intentionally unsafe local source file, inspect the explanation and proposed change, then
run both the security retest and the fixture's normal behavior test. Nothing reaches the network
and no project dependency is installed.

| Input | Finding | Evidence | Reviewable change | Retest |
|---|---|---|---|---|
| `src/export-report.mjs` | OS command injection lead (CWE-78), HIGH | `suspected`; input flow and reachability are not proven | replace shell parsing with `execFile` and separate arguments; quoting/platform behavior may change | security `fixed`; functional `passed` |

```bash
git clone https://github.com/parousia8888/web-app-security-skill.git
cd web-app-security-skill
npm run demo -- --out ./demo-output
```

Read the [generated before / proposed change / retest evidence](docs/demo-evidence.md), then inspect
`demo-output/demo-result.json`, `summary.md`, `before.json`, `hardening.patch`, `after.json`, and
`functional-retest.txt`. Every public demo fact is derived from `demo-result.json`; the repository
check reruns the fixture and fails if any surface disagrees.

For the complete install-to-uninstall path, follow the tested
[first project tutorial](docs/tutorial.md).

## What's new in v0.7.1

v0.7.1 is a security-boundary and execution-reliability patch for the v0.7.0 route and
access-control release. It does not add detectors or widen framework support. The signed tag,
GitHub Release, npm package, provenance and verified installer are public. The signed `v1` alias
now resolves to the immutable v0.7.1 source after both immutable and public-alias consumers passed:

- **Actionable default HIGH gate:** a `suspected` HIGH source lead now fails the default `high`
  policy without being relabelled `confirmed`. Old reports without the new policy field retain
  confirmed-only behavior.
- **Bounded source analysis:** JavaScript/TypeScript and Python scans have per-file token and
  operation limits plus a run-wide operation limit. Exhaustion is explicit `unknown` evidence and
  exit code `3`; affected route coverage becomes partial.
- **Bounded crawl networking:** every request and redirect is checked against destination, DNS,
  private-network, response-size and timeout limits. Local fixtures still require an explicit
  private-network opt-in.
- **Recursive evidence redaction:** nested credential wrappers, arrays, Bearer/Basic values and
  embedded private paths are sanitized across JSON, Markdown, HTML, SARIF, JUnit and observation
  outputs while documented authorization evidence models remain readable.
- **No dynamic robots regex:** attacker-controlled wildcard rules use a literal cached matcher,
  including adversarial repeated-wildcard input.
- **Complete installed payload:** Claude plugin metadata, bundled Opengrep rules and v0.7 review
  evidence are included, and the installed ruleset digest is checked.

The stable inventory remains 25 built-in risk rules, 3 evidence-integrity rules and 16 opt-in
external-adapter risk rules. Pattern matches remain `suspected`; policy gating never upgrades
evidence, and incomplete analysis never becomes pass. The v0.7.0
[access-control review](docs/reviews/v0.7.0-access-control-review.md),
[regressions](docs/regressions/v0.7.0-access-control-real-world-regressions.md) and
[access-control-chain reference](references/access-control-chain.md) continue to define the route
review boundary.

The existing finding explanation contract remains: every v3 source finding includes the technical
term, plain-language meaning, realistic consequence, evidence boundary, proposal, alternatives,
side effects, owner decisions, separate security/functional retests and rollback. Stable rule
inventory is now 25 built-in risk rules, 3 evidence-integrity rules and 16 opt-in external-adapter
risk rules, for 44 total. Route records are not counted as vulnerability rules.
The [v0.6.0 planted rule-contract conformance](docs/conformance/v0.6.0-rule-contract-conformance.md)
checks the 28 built-in contracts and remains explicitly separate from production accuracy.

## Install

### Zero-install CLI trial

Try the CLI without keeping an installation:

```bash
npx --yes web-app-security-skill audit . --fail-on never
```

### Claude Code plugin

Install the Claude Code plugin from this repository marketplace in one shell line:

```bash
claude plugin marketplace add parousia8888/web-app-security-skill --scope user && claude plugin install web-app-security-skill@web-app-security --scope user
```

Inside an existing Claude Code session, the equivalent commands are:

```text
/plugin marketplace add parousia8888/web-app-security-skill
/plugin install web-app-security-skill@web-app-security
```

### Verified multi-surface installation

For a signature- and checksum-verified multi-surface installation, the command below installs the
skill for Claude Code and Codex, plus the ordinary CLI under
`~/.local/bin`. Existing installs are refused unless you explicitly pass `--force`, which creates
timestamped backups before replacement. It downloads an immutable bootstrap, verifies its SHA-256
before execution, then verifies the selected release manifest, checksums, SBOM, source commit and
archive before installation.

```bash
( set -eu; p="$(mktemp "${TMPDIR:-/tmp}/web-app-security-bootstrap.XXXXXX")"; trap 'rm -f "$p"' EXIT HUP INT TERM; curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location --output "$p" 'https://raw.githubusercontent.com/parousia8888/web-app-security-skill/25a37e476720ad8ef221e38c0e2842abf928a1db/scripts/bootstrap-install.sh?immutable=25a37e476720ad8ef221e38c0e2842abf928a1db'; node -e 'const c=require("node:crypto"),f=require("node:fs"),p=process.argv[1],e=process.argv[2],a=c.createHash("sha256").update(f.readFileSync(p)).digest("hex");if(a!==e){console.error(`bootstrap SHA-256 mismatch: ${a}`);process.exit(1)}' "$p" 'ce37908a73bd9ffd004ec3c0a4d36dc88e3baa6187bd17df816a454a940bfe63'; sh "$p" )
```

Select a surface when needed:

```bash
sh bootstrap-install.sh --target claude
sh bootstrap-install.sh --target codex
sh bootstrap-install.sh --target cli
sh bootstrap-install.sh --target both   # Claude Code + Codex
```

The shortened examples assume you already downloaded and verified `bootstrap-install.sh` using the
command above. Explicit-version, offline/manual, attestation and trust-anchor details are in
[verified installation](docs/verified-installation.md). Supported environments and current limits
are recorded in the [compatibility matrix](docs/compatibility.md).

Check, upgrade, or remove an installation:

```bash
webapp-security version
# Run the verified bootstrap with --mode upgrade for a recognized installation.
sh bootstrap-install.sh --mode upgrade
webapp-security uninstall
```

`upgrade` replaces only installations carrying a recognized Web App Security Skill marker (or the
documented legacy Skill identity), and keeps timestamped backups. `uninstall` removes recognized
current installs but preserves those backups. Unknown directories and launchers are refused even
with `install --force`.

## Run the first project

Open the target repository in Claude Code or Codex and send this prompt:

```bash
webapp-security start .
```

This creates a private project identity plus `.webapp-security/runs/<run-id>/security-scope.yml`,
records detected framework, package manager, lockfile and deployment/config paths, and performs no
network access. Review the scope, then send:

```text
Use $web-app-security on this repository. Start with source and local checks only. Record scope and assumptions. Classify every result as confirmed, suspected, unknown, or not_applicable. Prepare the smallest reviewable hardening patch, do not apply risky or production changes without approval, retest every applied fix, and finish with fixed, remaining, and unreached risks.
```

The deterministic source path can then run as:

```bash
webapp-security audit .webapp-security/runs/<run-id> --fail-on high
webapp-security explain <finding-id> --report .webapp-security/runs/<run-id>/report.json
webapp-security repair-plan <finding-id> \
  --report .webapp-security/runs/<run-id>/report.json --out ./repair-review
webapp-security start . --run-id <retest-run-id>
webapp-security retest .webapp-security/runs/<retest-run-id> \
  --baseline .webapp-security/runs/<run-id>/report.json

# Review-noise filters for the built-in adapter only
webapp-security audit . --since HEAD~1 --fail-on never
webapp-security audit . --staged --fail-on never
```

`--since` excludes untracked files. `--staged` reads the Git index, not unstaged working-tree
content. Neither mode can be combined with external adapters or baseline/retest comparison.

The default is the bundled, network-free source adapter. Optional external adapters are explicit:

```bash
webapp-security doctor . --adapter all --json
webapp-security audit . --profile deep --fail-on never
```

Tested versions are Checkov `3.3.9`, Gitleaks `8.30.1`, Opengrep `1.27.0` and OSV-Scanner `2.5.0`.
The CLI and Action do not download them. Checkov runs only three fixed root Dockerfile/GitHub
Actions rules with `--skip-download`; it may query PyPI for version metadata but does not upload
project source. Opengrep uses only the bundled, digest-pinned ten-rule local ruleset and makes no
network request; OSV-Scanner may query the public OSV database. Project dependencies are not
executed. Compose, Terraform, Kubernetes and the rest of Checkov are not stable coverage. A
blocking external-adapter run additionally requires `--acknowledge-alert-policy` after the consuming repository accepts the responsibilities in
[`docs/alert-policy.md`](docs/alert-policy.md). See the
[`adapter protocol`](docs/adapter-protocol.md) for failure, redaction and version semantics.

Each source audit writes v3 JSON, Markdown, HTML, SARIF, JUnit, a SHA-256 sidecar and
`proposed.patch`. Every source finding keeps the professional term and adds plain-language meaning,
consequence, evidence limits, a reviewable proposal, side effects, separate security and functional
retests, rollback criteria and user decisions. A direct project audit is allowed for one-off review
but has ephemeral identity and cannot be a retest baseline. `fixed` requires the same persisted
subject and scope, a compatible rule, completed current coverage and affirmative absence of the
condition. The patch is never applied by this command. None of these commands grants permission to
probe a deployment.

Reports summarize by risk domain, then evidence state, then severity. The default CI policy gates
HIGH `confirmed` and `suspected` findings in `security_exposure` and `supply_chain`. A suspected
lead remains suspected in every artifact; the gate means it needs review before CI can pass, not
that exploitability was proved. Use `--fail-on never` for a non-blocking first report. Existing
`--fail-on` behavior continues to set those two domains; opt into another domain explicitly, for example:

```bash
webapp-security crawl --site https://example.com --out ./security-report \
  --fail-on high --fail-on-domain search_discoverability=high
```

Multiple `--fail-on-domain <domain=threshold>` options may be combined. Effective thresholds are
recorded in the report. The [generated rule taxonomy](docs/rule-taxonomy.md) separates source rule
kind, family, language, domain, severity, default evidence state and standards. Exact stable source
counts and complete explanation metadata come from the machine-readable
[`stable-source-rules.json`](docs/stable-source-rules.json): 25 built-in risk rules, 3 built-in
evidence-integrity rules and 16 external adapter risk rules on `main`, for 44 stable source and
deployment-policy rules. Ten JavaScript/TypeScript and ten Python built-in rules are bounded lexical
leads for execution, unsafe browser or framework configuration, transport, authentication/session
settings and deserialization; five shared checks cover repository and project configuration. Their
exact detection and false-positive boundaries are recorded in the
[JS/TS](docs/js-ts-rule-decisions.md) and [Python](docs/python-rule-decisions.md) decisions. Pattern
matches do not prove input flow or runtime reachability and remain `suspected` until independently
reproduced; only a narrow rule-specific observable fact can be `confirmed`. Per-file token and
operation budgets plus a whole-run operation budget bound the built-in lexical analysis. A limit
produces `source-evidence-incomplete / unknown`, partial or unavailable coverage, and recorded
effective limits; it is never reported as a clean scan.

## Capability boundary

Capabilities use two independent dimensions so support tooling is not counted as vulnerability
coverage:

- **Category:** Detection; Evidence and reporting; Lifecycle and distribution; or Agent-guided
  methodology.
- **Maturity:** `stable`, `experimental`, `agent_guided`, or `planned`.

The current stable Detection families are the narrow built-in source audit, opt-in Checkov,
Gitleaks, Opengrep and OSV-Scanner adapters, crawl-boundary audit, crawler identity verification, edge
verification, and the read-only AWS inventory helper. Project discovery,
the demo, report renderers, retest infrastructure, installer, and GitHub Action are tested product
capabilities, but are not additional detector families. API authorization, business logic,
LLM/OAuth, data-layer and broader AWS
reviews remain Agent-guided methodology until a named adapter earns regression evidence.

The [generated capability matrix](docs/capabilities.md) links every category and maturity statement
to evidence. Results
are `confirmed`, `suspected`, `unknown`, or `not_applicable`; a check that could not run is never a
pass. Installing the Skill does not prove a project secure.

Current detector and workflow constraints are listed in [`KNOWN_LIMITATIONS.md`](KNOWN_LIMITATIONS.md).
The [MCP and stable-rule expansion decision](docs/architecture/mcp-and-rule-expansion.md) is a future
gate, not shipped behavior.

## Deterministic tools

Ask Claude Code or Codex to use `web-app-security`, or run the same deterministic tools
directly:

```bash
# Network-free project discovery and versioned scope
webapp-security start .

# Source-only audit, explain and required-baseline retest
webapp-security audit .webapp-security/runs/<run-id> --fail-on high
webapp-security audit . --since HEAD~1 --fail-on never
webapp-security audit . --staged --fail-on never
webapp-security doctor . --adapter all
webapp-security audit . --profile deep --fail-on never
webapp-security explain <finding-id> --report <report.json>
webapp-security start . --run-id <retest-run-id>
webapp-security retest .webapp-security/runs/<retest-run-id> \
  --baseline <report.json> --fail-on high

# Historical v1 reports stay non-comparable; moved/cloned projects require explicit binding
webapp-security migrate-report <v1-report.json> --scope <security-scope.yml> \
  --acknowledge-subject <subject-id> --out <new-directory>
webapp-security rebind <moved-project> --scope <security-scope.yml> \
  --acknowledge-subject <subject-id>

# Passive crawl-boundary and crawler accessibility audit
webapp-security crawl --site https://example.com --out ./security-report

# Localhost/RFC1918 targets are blocked unless the authorized operator opts in
webapp-security crawl --site http://127.0.0.1:3000 --out ./security-report \
  --allow-private-network

# Active sensitive-path probes require both ownership/written authorization and an explicit gate
webapp-security crawl --site https://example.com --out ./security-report \
  --active-probe --acknowledge-authorization

# Crawler identity: exact product ranges or FCrDNS, never a user-agent string alone
webapp-security verify-crawler --ip 66.249.66.1 --ua Googlebot --ranges

# Passive headers, redirect, certificate and TLS policy verification
webapp-security verify-edge --site https://example.com

# Read-only AWS posture inventory
webapp-security aws --profile default --region us-east-1 --out ./security-report
```

Active rate-limit verification also requires `--acknowledge-authorization`. Network or evidence
failure is `unknown` and exits non-zero; it is never rendered as safe.
The crawl client stays on the initial origin, validates and pins DNS on every redirect hop, blocks
local/private/link-local/reserved destinations by default, and enforces request plus compressed and
decoded response-byte budgets. `--allow-private-network` permits only an explicitly selected
localhost/private origin; link-local metadata and reserved ranges remain blocked.

Source conclusions use finding/report v3, including the before/after source reports inside the new
demo. Crawl, crawler identity, edge and AWS remain on v2; the demo's small `demo-result.json` fact
schema is separate from either report schema. Both report versions preserve the same coverage,
evidence-state, policy and exit-code semantics. Report
bundles and their tool-specific observations are sanitized in memory, staged as private files in the
target directory, and committed together without overwriting prior evidence. A renderer or handled
write failure is rolled back without leaving a partial new bundle. Historical v1 reports remain
readable only for display, release verification and explicit non-comparable migration; they are
never accepted as a comparable baseline. Compatible persisted v2 source baselines remain readable
and are upgraded in memory for v3 comparison without rewriting their bytes.

## GitHub Action

The composite Action keeps the v0.3 crawl inputs and outputs. Crawl mode is passive by default and
requires deployment authorization acknowledgement:

```yaml
- name: Audit public crawl boundary
  uses: parousia8888/web-app-security-skill@2b746b168d767c9b2225a273474e561650b2b6f8
  with:
    site: https://example.com
    acknowledge-authorization: true
    active-probe: false
    fail-on: high
```

For repeatable CI, use the immutable v0.7.1 commit above. The signed stable major-version alias now
resolves to that source; its post-promotion public consumer
[`32753263317`](https://github.com/parousia8888/web-app-security-skill/actions/runs/32753263317)
passed:

```yaml
uses: parousia8888/web-app-security-skill@v1
```

Source mode defaults to the bundled adapter. The immutable v0.7.1 Action runs the v3 source
contract, 25 built-in risk rules, 3 evidence-integrity rules, bounded Express/NestJS/Next.js route
and Server Action inventory, and bounded access-control-chain review. External binaries must be
installed and pinned by the caller; the Action never downloads them:

```yaml
- name: Audit source
  uses: parousia8888/web-app-security-skill@2b746b168d767c9b2225a273474e561650b2b6f8
  with:
    mode: source
    project: .
    adapters: builtin
    fail-on: high
```

The moving `v1` tag was promoted with a guarded lease only after the versioned source, installation
and immutable Action gates passed. Review release notes before accepting a future update; use the
full commit above when the workflow must not move.

## Trust and release evidence

- CI runs Ubuntu/macOS x Node 22/24, deterministic HTTP/HTTPS fixtures and Bash 3.2 smoke tests.
- Third-party Actions in release and CodeQL workflows are pinned to full commit SHAs.
- Tagged releases require matching `VERSION`, changelog and a versioned evidence note. The tag is
  signed and the release records its source commit.
- Release assets contain a reproducible source archive, SPDX 2.3 SBOM, `SHA256SUMS` and GitHub
  build-provenance attestation. CI builds the archive twice, compares every byte, then runs the
  lifecycle from the extracted archive in an isolated home with network access denied.
- [`SECURITY.md`](SECURITY.md), [threat model](docs/threat-model.md),
  [false-positive policy](docs/false-positive-policy.md) and
  [compatibility matrix](docs/compatibility.md) make the trust boundary reviewable.

Verify downloaded release assets:

```bash
sha256sum -c SHA256SUMS
gh attestation verify web-app-security-skill-*.tar.gz \
  --repo parousia8888/web-app-security-skill
git -c gpg.ssh.allowedSignersFile=.github/release-signers verify-tag v0.6.0
```

## 5 ordinary project journeys

The original v0.4.0 journeys preserve the complete v2 built-in/Gitleaks/OSV evidence. The separate
[v0.5.0 built-in review](docs/case-studies/journeys/v0.5.0-review.md) reruns the same fixed commits
through the broader v3 JavaScript/TypeScript and Python rules and manually classifies every finding.
No hosted instance or project dependency was executed in either pass.

| Project | Evidence outcome | Manual outcome |
|---|---|---|
| [Linkwarden](docs/case-studies/journeys/linkwarden.md) | v3: 6 suspected | 6 expected benign matches after JSDOM, DOMPurify and constant-content review |
| [Healthchecks](docs/case-studies/journeys/healthchecks.md) | v3: 5 suspected | 4 useful response-encoding leads; 1 expected benign opt-in shell match |
| [Open WebUI](docs/case-studies/journeys/open-webui.md) | v3: 6 suspected; 1 unknown | 3 useful leads; 3 expected benign; tokenizer failure stays unknown |
| [Uptime Kuma](docs/case-studies/journeys/uptime-kuma.md) | v3: 4 confirmed facts; 21 suspected | 4 useful leads; 17 expected benign; confirmed items are lockfile hygiene, not four app vulnerabilities |
| [Mealie](docs/case-studies/journeys/mealie.md) | v3: 0 findings | No configured pattern matched; this does not establish security |

Read the [structured v0.5.0 classification](docs/case-studies/journeys/v0.5.0-evidence.json) and the
[historical journey method](docs/case-studies/journeys/README.md).
Confirmed source facts, scanner leads and false-positive outcomes are kept visible; this is not a
precision score. Uptime Kuma and Mealie overlap with the methodology corpus below at the same
commits, so these are two evidence views rather than ten distinct projects.

The **5 earlier source methodology studies** remain as a separate corpus: three intentionally
vulnerable benchmarks and two production projects.

| Project | Evidence outcome |
|---|---|
| [OWASP Juice Shop](docs/case-studies/juice-shop.md) | Confirmed intentional SQL injection plus upstream prepared-statement repair |
| [OWASP NodeGoat](docs/case-studies/nodegoat.md) | Confirmed intentional server-side `eval`, IDOR and open redirect |
| [DVWA](docs/case-studies/dvwa.md) | Confirmed low/impossible SQLi, XSS and command-injection control pairs |
| [Uptime Kuma](docs/case-studies/uptime-kuma.md) | SSRF-shaped outbound sinks closed as product behavior; no vulnerability counted |
| [Mealie](docs/case-studies/mealie.md) | URL-fetch lead traced to auth and private-IP guard; no vulnerability counted |

Read the [method and corpus limits](docs/case-studies/README.md). These are evidence for the
methodology, not a fabricated precision score for a CLI that is not yet a general SAST engine.

## Program map

| Phase | Focus | Active? |
|---|---|---|
| 0 | Scope, ownership and authorization anchor | gate |
| 1 | Frontend exposure | no |
| 2 | API: IDOR/BOLA, auth, limits, races, SSRF | yes |
| 3 | LLM abuse and OAuth/OIDC | yes |
| 4 | Server-side source audit | source access |
| 5 | Database and tenant isolation | yes |
| 6 | Supply chain, SBOM, SCA and SRI | partial |
| 7 | Blue-team detection | no |
| 8 | Report, patch evidence and retest | no |

Cross-cutting references cover crawl boundaries, verified crawler identity, source-map/dotfile
exposure, enforcement placement, AWS hardening, overlooked surfaces, regression gates and safe
deployment. Start from [`SKILL.md`](SKILL.md).

## Contributing

The [roadmap](ROADMAP.md) separates correctness work from adoption work. New contributors can start
from [bounded good-first issues](docs/GOOD_FIRST_ISSUES.md), the issue forms, and
[`CONTRIBUTING.md`](CONTRIBUTING.md). False-positive reports need a sanitized minimal fixture and
expected classification; sensitive details go through private vulnerability reporting.

The [generated launch evidence](docs/launch-evidence.md) collects only reproducible capability,
demo, project-journey, methodology-study and release facts. The
[publication kit](docs/adoption/launch-brief.md) provides evidence-linked drafts and a reusable
public/private case-study workflow without claiming that external publication has occurred.

MIT licensed.
