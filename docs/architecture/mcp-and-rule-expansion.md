# MCP and detection-rule expansion decision

Status: accepted for v0.5.3; gates applied to the v0.5.4 rule expansion

## Context

Web App Security Skill currently exposes one deterministic runtime through the ordinary CLI, npm
and `npx`; Claude Code can also discover the same root `SKILL.md` through its plugin marketplace.
The stable source boundary is 25 built-in risk rules, two evidence-integrity rules and 16 opt-in
external-adapter rules. The built-in rules are deliberately narrow and do not claim whole-program
data flow or production reachability.

Two possible expansions were considered for v0.5.3:

1. add an MCP server so more agent clients can invoke named tools without shell commands;
2. add more built-in detection patterns to increase automatic rule count.

Both introduce contracts that are harder to remove than to add. MCP creates another long-running
process, permission boundary, install path and tool schema. A new rule creates a permanent false-
positive, evidence-state and compatibility obligation.

## Decision for v0.5.3

v0.5.3 does not ship an MCP server and does not expand the stable detection-rule count.

- CLI, npm/npx and the Claude plugin remain the execution and distribution boundaries.
- MCP is deferred until a concrete cross-client workflow cannot be served safely by the CLI.
- Rule work prioritizes accuracy, parser coverage and stable evidence over catalogue size.
- Any future transport must call the same runtime; it cannot copy rule logic or create a second
  report contract.

This is a deferral with explicit entry gates, not a claim that MCP or additional rules have no
value.

## v0.5.4 application

v0.5.4 keeps MCP deferred and promotes five bounded built-in rules plus eight project-owned
Opengrep rules after applying the detection-rule gates below. Each promoted rule has registry
metadata, positive and neighboring negative fixtures, an explicit evidence boundary, dual retests,
rollback language and focused parser/adapter regression coverage. The built-in additions are exact
Git/configuration or recognized file-local constructs; the request-flow additions use the existing
pinned same-file Opengrep adapter.

The `--profile deep` CLI option is orchestration over the same runtime and adapters. It does not add
a transport, daemon or automatic dependency install, and it does not count as another detector.

## MCP entry gates

An MCP implementation can enter a release plan only when all of these are documented:

1. **Demand:** named client workflows from at least two non-Claude integrations show why direct CLI
   execution or parsing report v3 is insufficient.
2. **Tool contract:** a versioned schema defines inputs, outputs, cancellation, progress, maximum
   output size and the mapping from process exit states `0/1/2/3` to tool results.
3. **Permission model:** project roots are explicitly allowlisted; path traversal and symlink escape
   are rejected; active network probes retain their authorization acknowledgement; secret values
   cannot enter tool logs or protocol errors.
4. **Transport boundary:** the first implementation is local stdio. Remote HTTP, multi-user tenancy,
   credential storage and unattended production access require separate threat models.
5. **Runtime reuse:** MCP delegates to the same audit, evidence and renderer modules as the CLI. No
   detector, evidence state or redaction behavior is reimplemented.
6. **Distribution and trust:** install, upgrade, signature, SBOM and version pinning work for the MCP
   package without weakening the existing release chain.
7. **Regression evidence:** fixtures cover malformed messages, cancellation, concurrent requests,
   output limits, unavailable adapters, authorization refusal and cleanup after process failure.

Until these gates are met, MCP stays outside the advertised capability matrix.

## Detection-rule entry gates

A proposed stable rule must include all of the following in one reviewable change:

1. a concrete Web-product threat and a user action that can reduce it;
2. a rule family, domain, default severity, default evidence state, revision and standards mapping;
3. an `evidenceBoundary` that states what the match proves and what it cannot prove;
4. at least one planted positive and one neighbouring negative fixture, included in the reproducible
   rule-contract conformance suite;
5. parser or adapter failure behavior that becomes explicit incomplete coverage rather than pass;
6. plain-language consequence, proposal, alternatives, side effects, security retest, functional
   retest, rollback and owner-decision text;
7. a focused false-positive review on ordinary code and an entry in known limitations when a
   recurring benign class remains;
8. deterministic output, redaction and bounded runtime under the existing traversal limits.

Rules needing cross-file input flow should normally use a pinned parser/SAST adapter. Extending the
hand-written lexical analysers is acceptable only for bounded file-local facts with adversarial
syntax fixtures. Stable rule count is an inventory value, not a quality metric.

## Promotion sequence

Future rules move through these states:

1. decision record and fixture contract;
2. `experimental` implementation, excluded from default gating;
3. ordinary-project false-positive review and benchmark evidence;
4. stable registry entry with a compatible rule revision and public limitation text.

Future MCP work follows the same sequence: threat model, local prototype, client integration
evidence, then stable distribution. No planned or experimental item is described as shipped.

## Rejected shortcuts

- A remote MCP endpoint with repository upload was rejected because it adds data custody and tenant
  isolation obligations unrelated to current local-first behavior.
- Wrapping shell strings as a generic MCP `run` tool was rejected because it exposes broader command
  execution than the current named CLI commands.
- Adding simple string patterns to raise the rule count was rejected because the resulting alert
  volume would weaken the product's evidence and explanation contract.
- Making external scanners implicit dependencies was rejected for this release because zero-download
  default execution and explicit version ownership are current supply-chain boundaries.
