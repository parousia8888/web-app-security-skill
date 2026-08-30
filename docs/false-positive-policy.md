# False-positive policy

## Result states

- `confirmed`: reproduced through the real execution path with sufficient, sanitized evidence.
- `suspected`: a source pattern or scanner hit that still requires runtime or ownership context.
- `unknown`: the check could not run or its evidence source was unavailable.
- `not applicable`: the component or control is outside the recorded scope.

Only `confirmed` findings may be counted as demonstrated vulnerabilities. Case studies and release
notes must not promote `suspected` findings to confirmed for presentation value.

## Reporting a false positive

Open the false-positive issue form with the tool version, sanitized command, affected finding ID,
minimal fixture, actual output, expected output, and environment. For private target details, use
the channel in `SECURITY.md`.

Maintainers reproduce the report, classify whether the error is a rule problem, missing context,
transport failure, or documentation ambiguity, then add a failing regression before changing the
rule. A suppression is accepted only when its scope is narrower than the finding it suppresses.

`webapp-security.suppressions.json` records a policy disposition; it does not change a finding from
`suspected` to `confirmed`, hide it from reports or prove that it is safe. v0.8.1 accepts only an
exact adapter/rule/path/fingerprint match bound to the project subject. Fingerprint, path or rule
drift leaves the finding active. Unknown and evidence-integrity findings cannot be suppressed.
Owner and expiry are mandatory whenever the entry affects a CI/release gate or an external adapter.

For stable source rules, promotion requires a vulnerable fixture, a meaningful safe near-neighbour,
an explicit evidence boundary and a planted missing-observation failure. A normal source pattern
that requires context can remain a useful `suspected` lead without being labelled a confirmed
vulnerability. Ordinary-project review therefore keeps four separate manual classes:
`useful_lead`, `expected_benign_match`, `unknown` and `confirmed`.

## Metrics

Releases report confirmed regressions, known unknown states, and case-study false positives. The
project does not publish a single precision percentage until the corpus and ground truth are large
enough to make that number meaningful.

The five-project v0.5.0 review is a bounded noise review, not a benchmark denominator. Its 43
findings were manually classified as 11 useful leads, 27 expected benign matches, 1 unknown and 4
confirmed missing-lockfile facts. Those counts must not be converted into precision/recall or a
claim that the zero-finding project is secure.
