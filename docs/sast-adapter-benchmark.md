# v0.5.0 SAST adapter benchmark

Reviewed: 2026-08-14

This record explains the bounded v0.5.0 selection between Semgrep CE and Opengrep. It is an
adapter-maintainability comparison on one Apple Silicon host and four tiny fixtures, not a general
engine-quality or performance ranking.

## Fixed candidates and legal boundary

| Candidate | Tested release | Executable distribution | Executable license | Public rules repository |
|---|---|---|---|---|
| Semgrep CE | `1.173.0`, released 2026-08-13 | PyPI macOS arm64 wheel, 49,472,798 bytes, SHA-256 `c62eb7c13257c3cc58106b8f6afab152f9f99bfe36fdfebd6f09809fa1c50966` | LGPL-2.1-or-later | Separate Semgrep Rules License v1.0 |
| Opengrep | `1.27.0`, released 2026-08-12 | Signed GitHub macOS arm64 executable, 47,248,688 bytes, SHA-256 `9f2c016ac74b9821b73fa3bea86a2d0b9ccb9aabe7b5bd9d6e3ff3b3b05cbd07` | LGPL-2.1-or-later | LGPL-2.1 plus Commons Clause |

Executable and rules licenses are separate. This project does not copy, modify, download at runtime
or redistribute either public rules repository. The current adapter uses only the ten project-owned
MIT-licensed rules in `rules/opengrep-source.yml`, whose v0.5.4 SHA-256 is
`62e9fb0fb382e0f12443adb28ed73bebec5aa390dec7a1ca5692ea6882d138d8`.

Immutable source references used in the review:

- Semgrep `v1.173.0`: tag object `8469b044604f827b13917d864a616a491b41eca6`, commit
  `abce3b5391706850837d4339f84bfaa3ec08604b`;
- Opengrep `v1.27.0`: tag/commit `3bd8e95fea8992e15ea2451286dd1cb145e57add`;
- both executable repositories exposed the same LGPL license file digest at review time;
- upstream rule licences were checked separately and are not inputs to the shipped ruleset.

## Method

The original v0.5.0 engine comparison ran the same local YAML with two same-file taint rules:

1. JavaScript/TypeScript request query data reaching command execution;
2. Python Flask request data reaching `subprocess` with `shell=True`.

Each language had one vulnerable fixture and one safe near-neighbour using a fixed executable and
argument array. Commands used local config, JSON output, one job, bounded per-rule time and target
size, disabled version checks, no automatic config and no project build. Semgrep metrics and traces
were explicitly disabled. A macOS sandbox denied network access for the offline observations.

## Observations

| Variable | Semgrep CE `1.173.0` | Opengrep `1.27.0` |
|---|---|---|
| Version pin | Exact version probe succeeded | Exact version probe succeeded |
| Install form | Python tool with 66 packages | One checksum- and signature-published executable; first run expands a local cache |
| Observed installed size | 257,392 KiB tool tree | 46,144 KiB download plus 250,744 KiB first-run cache |
| First measured run | 1.12 s | 0.97 s |
| Immediate repeat | 1.01 s | 0.91 s |
| Fixture result | 2 intended findings; 0 safe-neighbour findings | 2 intended findings; 0 safe-neighbour findings |
| Normalized result identity | Same stable digest on two runs | Same stable digest on two runs |
| Raw JSON stability | Timing fields changed | Byte-identical in the two ordinary runs |
| Local evidence | Unauthenticated output replaced source lines and fingerprints with `requires login` | Local JSON included source/data-flow detail; adapter can discard it before persistence |
| Offline local-config run | Completed with network denied after allowing normal local system access | Completed with network denied and an isolated writable cache |
| Rule ID | Stable with `--no-rewrite-rule-ids` | Stable with `--no-rewrite-rule-ids` |

Times and sizes are environment observations, not promises. Both engines supplied useful local
same-file taint analysis and both require substantially more installed space than their downloaded
artifact alone suggests.

## Decision

Opengrep `1.27.0` is the one stable v0.5.0 SAST adapter. The deciding factors are its direct signed
multi-platform release artifacts, simple caller-controlled binary pin, stable local JSON and usable
local structural output without an account. Semgrep CE remains compatible with the project-owned
rules in the bounded fixture but is not integrated in v0.5.0 because its packaging and local
evidence behavior add maintenance cost without improving these two proven rules.

The selection does not claim Opengrep is universally more accurate than Semgrep. It also does not
adopt the Opengrep public rules catalogue. Every match remains `suspected`, same-file only, and
requires route/reachability review plus a security and functional retest.

## v0.5.4 bounded ruleset expansion

v0.5.4 keeps the same Opengrep engine/version and adds eight project-owned rules. JavaScript/
TypeScript and Python now each cover request data reaching SQL query text, outbound request URLs,
filesystem paths and browser redirect targets, alongside the original command-execution rule.
The current stable inventory is ten rules total.

This expansion is a rule-contract change, not a new engine ranking or a production accuracy
benchmark. Each language still uses one planted vulnerable fixture and one neighboring safe fixture;
the pinned real-adapter CI cell requires all ten positives and no planted safe match. The rules do
not perform interfile analysis, prove framework routing, establish runtime reachability or test
exploitability.

## Adapter gates

The promoted adapter verifies the exact binary version and bundled ruleset digest before scanning,
performs no runtime download, does not execute project dependencies, fixes rule IDs, limits jobs,
time and target bytes, and rejects malformed JSON, scanner errors, inconsistent exits, oversized
output and scope-escaping paths. Missing or failed evidence produces `unknown` coverage.

Persisted evidence excludes raw stdout/stderr, source lines, metavariable contents and data-flow
traces. It retains only local/external rule identity, sanitized relative location, engine kind and
ruleset SHA-256. One Ubuntu/Node 22 CI cell downloads the upstream binary from the fixed release and
verifies its SHA-256 before exercising the positive and safe fixtures.

Opengrep's default terminal setup writes a DEBUG log to `~/.opengrep/semgrep.log`; that log can
contain scan paths and source/data-flow detail even when JSON output is sanitized. The adapter sets
the upstream-supported `SEMGREP_LOG_FILE`, `SEMGREP_SETTINGS_FILE` and
`OPENGREP_VERSION_CACHE_PATH` variables to a mode-`0700` temporary state directory for both the
version probe and scan, then removes it on every exit path. It does not redirect the engine's
content-only expansion cache, so repeated invocation does not pay the approximately 245 MiB
extraction cost. A regression makes the fake engine write a source sentinel through the same log
variable and proves the user's existing `~/.opengrep/semgrep.log` remains unchanged.
