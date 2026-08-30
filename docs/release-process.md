# Release process

This maintainer procedure separates an immutable source candidate, public package state and the
later movable `v1` alias. A local or tagged candidate cannot claim that GitHub Release assets, npm
provenance or public consumers already exist.

## 1. Freeze the candidate

1. Update `VERSION`, `package.json`, plugin manifests, changelog and the versioned release-evidence
   draft together. Regenerate every checked artifact.
2. Run the bounded candidate gates once after the tree stabilizes: `npm run check`,
   `npm pack --dry-run --json`, Skill validation and `git diff --check`.
3. Push the source commit and require repository self-audit, all four CI matrix jobs and CodeQL to
   pass on that exact commit.
4. Create an SSH-signed annotated `vX.Y.Z` tag and verify it with
   `.github/release-signers` before pushing the tag. A tag push does not publish a release.

## 2. Publish immutable channels

1. From `main`, manually dispatch `.github/workflows/release.yml` with the exact plain version and
   signed tag. Its read-only job sources the verifier and signer policy from `main`, verifies the
   tag, source commit and hosted checks before `npm ci`, and builds the archive twice. Its separate
   `release`-environment job publishes the archive, SPDX SBOM, release manifest and `SHA256SUMS`
   with GitHub provenance. The final job downloads the public assets and verifies them read-only.
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

1. Pin the immutable Action consumer to the release source and dispatch the `immutable-only` phase.
   Do not move `v1` unless that full-SHA consumer passes.
2. Record a pending promotion in `docs/release-state.json` with the public release version/source
   and the exact prior annotated `v1` tag object:

   ```bash
   prior_v1="$(git rev-parse 'refs/tags/v1^{tag}')"
   node scripts/action-promotion-state.mjs begin --state docs/release-state.json \
     --version "$version" --expected-source "$release_commit" \
     --prior-tag-object "$prior_v1"
   ```

   Commit and push this pending state. Generic CI is branch-scoped and checks the tracked state; it
   does not treat a moving tag as an ordinary branch build.
3. Create and locally verify the new SSH-signed annotated `v1`, then update only the recorded prior
   remote tag object:

   ```bash
   git tag -s -f v1 "$release_commit" -m "Web App Security Skill v1 -> v$version"
   git -c gpg.ssh.allowedSignersFile=.github/release-signers verify-tag v1
   git push --force-with-lease="refs/tags/v1:$prior_v1" origin refs/tags/v1:refs/tags/v1
   ```

   Consumers needing immutability must use the full release commit rather than `v1`.
4. Dispatch `.github/workflows/action-v1-consumer.yml` with phase `promotion`. It verifies the
   immutable source, promoted `v1`, Release assets, tag signatures, GitHub/npm provenance and the
   required-attestation installer while the tracked state remains pending. Retain its numeric run
   ID; its artifact binds both consumer results to the expected source.
5. Finalize the tracked state only for that same source, commit it and push it:

   ```bash
   node scripts/action-promotion-state.mjs finalize --state docs/release-state.json \
     --source-commit "$release_commit"
   ```

6. Dispatch the same workflow with phase `final` and the successful promotion run ID. It downloads
   that exact prior artifact, requires finalized public state, and publishes one version-named
   live-verification record as both a workflow artifact and GitHub Release asset. A rerun may reuse
   the same named record only when its digest is identical.

## 5. Close the release record

Update `docs/release-state.json` and the versioned release-evidence document only from observed
public values and workflow URLs. Run the candidate-state checker locally and the public-state
checker against the published repository. The release is complete only when every intended check
is recorded as passed, failed, skipped or not run and all required checks passed.
