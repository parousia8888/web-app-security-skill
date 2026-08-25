# Security Policy

## Supported versions

Security fixes are applied to the latest release. Older tags remain available for reproducibility
but are not maintained. Pin a full commit SHA or a signed release artifact for high-assurance use.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/parousia8888/web-app-security-skill/security/advisories/new).
Do not open a public issue for a vulnerability that could expose a user's target, credentials,
report contents, or a bypass in a security decision.

Include the affected version or commit, the smallest non-destructive reproduction, expected and
actual results, and whether the issue can create a false `verified`, false `safe`, or false
`spoofed` decision. Remove tokens, cookies, account identifiers, and real client IPs.

## Response targets

- Acknowledge a complete report within 5 business days.
- Triage security-decision errors before documentation-only issues.
- Freeze confirmed bugs as deterministic regressions before release.
- Publish a sanitized advisory and credit the reporter unless anonymity is requested.

## Release verification

Tagged releases include an SPDX SBOM, `SHA256SUMS`, and a GitHub artifact attestation. Verify with:

```bash
sha256sum -c SHA256SUMS
gh attestation verify web-app-security-skill-*.tar.gz \
  --repo parousia8888/web-app-security-skill
```

The attestation proves which GitHub workflow produced an artifact. It does not prove that every
security conclusion made by the scripts is correct; the test and release evidence address that
separate question.

The local `.github/release-signers` check is a repository-consistency check, GitHub's verified tag
status is a platform signal, and npm OIDC provenance covers the npm package. Read
[`docs/release-trust-boundaries.md`](docs/release-trust-boundaries.md) before treating one channel's
result as evidence for another channel.
