# Release trust boundaries

Release verification uses several related signals. Each signal answers a different question and no
single signal proves detector correctness or that an audited application is secure.

## Source identity invariant

For a published version, these identities must resolve to the same immutable source commit:

```text
release tag source commit = release manifest source commit = npm gitHead = immutable Action commit
```

The GitHub Release is created from that version tag. `main` may contain later verifier, bootstrap or
public-state commits, so `main` HEAD is not required to equal the release source commit. The moving
`v1` Action tag is checked separately and consumers that require immutability use the full source
commit.

## What each signal proves

| Signal | What it establishes | Boundary |
|---|---|---|
| `.github/release-signers` plus `git verify-tag` | The tag signature matches the repository-local signer policy in the checked-out tree. | The policy file and key live in the same repository. This is a repository-consistency check; it does not independently prove GitHub account ownership. |
| GitHub tag `verification.verified` | GitHub accepted the signature for the exact tag object under its platform verification rules. | Check this separately in GitHub UI/API. It does not validate npm bytes or detector conclusions. |
| GitHub build-provenance attestation | The named GitHub Actions workflow produced the attested release asset. | It covers the listed release asset, not the npm package unless that package is separately attested. |
| npm OIDC/SLSA provenance | npm trusted publishing binds the package version to its publishing workflow and source context. | It covers the npm package. It is separate from the GitHub release-asset attestation and tag-signature check. |
| SHA-256, manifest and SBOM checks | Downloaded bytes and declared asset relationships match the recorded values. | A checksum is an integrity value; its authenticity depends on how the trusted value was obtained. |

## Published-release verification

For published `v0.8.0`, verify the local tag policy and compare immutable identities:

```bash
git fetch --tags --force
git -c gpg.ssh.allowedSignersFile=.github/release-signers verify-tag v0.8.0
git rev-parse 'v0.8.0^{}'
npm view web-app-security-skill@0.8.0 gitHead
```

Inspect the exact tag object's GitHub verification separately:

```bash
tag_object="$(git rev-parse v0.8.0)"
gh api "repos/parousia8888/web-app-security-skill/git/tags/$tag_object" \
  --jq '.verification | {verified,reason,verified_at}'
```

The versioned release evidence records the GitHub Release source, npm provenance URL, immutable
Action commit and post-publication checks. A result from one channel must not be described as proof
for another channel.
