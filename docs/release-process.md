# Release process

This maintainer procedure separates an immutable source candidate, public package state and the
later movable `v1` alias. A local or tagged candidate cannot claim that GitHub Release assets, npm
provenance or public consumers already exist.

## 1. Freeze the candidate

1. Update `VERSION`, `package.json`, plugin manifests, changelog and the versioned release-evidence
   draft together. Regenerate every checked artifact.
2. Run the bounded candidate gates once after the tree stabilizes: `npm run check`,
   `npm pack --dry-run --json`, Skill validation and `git diff --check`.
3. Push the source commit and require CI and CodeQL to pass on that exact commit.
4. Create an SSH-signed annotated `vX.Y.Z` tag and verify it with
   `.github/release-signers` before pushing the tag.

## 2. Publish immutable channels

1. Let `.github/workflows/release.yml` build the archive twice, compare bytes and publish the
   archive, SPDX SBOM, release manifest and `SHA256SUMS` with GitHub provenance.
2. Verify downloaded asset digests and provenance. Do not use the pre-public candidate check as
   evidence that these remote objects exist.
3. Dispatch `.github/workflows/npm-publish.yml` for the exact signed tag. npm publishing uses OIDC
   trusted publishing; record `gitHead`, shasum, integrity and npm provenance.
4. Compare npm package files with the signed source archive. A missing or skipped public check is
   not a pass.

## 3. Update installer trust anchors

Record the observed immutable release digests in `scripts/install-verified.mjs`, then update the
bootstrap pin and English/Chinese installation examples. Verify a clean install from the immutable
bootstrap commit. SHA-256 verification is mandatory; GitHub attestation is optional by default and
becomes mandatory only with `--attestation required`.

## 4. Promote and verify `v1`

1. Pin the immutable Action consumer to the release source and verify that pin through the ordinary
   repository gates. The combined public consumer workflow is not dispatched yet because it also
   creates the version-named live-verification record.
2. Move the SSH-signed annotated `v1` tag only with a guarded lease against the exact prior tag
   object. Consumers needing immutability must use the full release commit rather than `v1`.
3. Dispatch `.github/workflows/action-v1-consumer.yml` once after promotion. It verifies both the
   immutable source and the promoted `v1`; its post-public job verifies Release assets,
   tag signature, GitHub and npm provenance, verified installation, immutable and `v1` Action
   consumers, and moving-alias state.
4. Publish exactly one version-named live-verification record as both a workflow artifact and a
   GitHub Release asset. A rerun may replace that named record but may not create untracked assets.

## 5. Close the release record

Update `docs/release-state.json` and the versioned release-evidence document only from observed
public values and workflow URLs. Run the candidate-state checker locally and the public-state
checker against the published repository. The release is complete only when every intended check
is recorded as passed, failed, skipped or not run and all required checks passed.
