# Verified installation

The recommended README command has three independently reviewable stages. It does not execute bytes
merely because they came from the same TLS origin as a checksum file.

1. The README fixes `bootstrap-install.sh` to commit
   `5de57e8a974247a2f519ac93cea580923aaaff6a` and verifies SHA-256
   `2226efeed8127d2cd33fb05cbb0a3197952f8686d8ea9cf497bba1c6d33e6ef9` before `sh` runs it.
2. The bootstrap fixes `install-verified.mjs` to commit
   `ab80e144171b0e3ff350514c5d342e07737604fc` and verifies SHA-256
   `74d166797fb3630dd3764fad4feee9f8dacee23acc9f1a22ef22bc039a54c44a` before Node runs it.
3. The verifier selects one explicit version from its built-in trust map. It requires fixed SHA-256
   values for the archive, release manifest, SPDX SBOM and `SHA256SUMS`, then cross-checks repository,
   product, tag, source commit, version, asset sets, archive root and paths before invoking the
   existing atomic lifecycle installer.

`--attestation auto` additionally runs `gh attestation verify` when GitHub CLI is installed and
authenticated. Its output explicitly says when this extra check did not run. Use
`--attestation required` when absence of authenticated attestation verification must stop the
installation. SHA-256 and manifest verification always run and cannot be disabled.

## Explicit version and target

After downloading and verifying the bootstrap using the README command, retain it at a known path:

```bash
sh ./bootstrap-install.sh --version 0.7.3 --target codex
sh ./bootstrap-install.sh --version 0.7.3 --target claude
sh ./bootstrap-install.sh --version 0.7.3 --target cli
```

The verifier rejects a version absent from its built-in trust map. It never resolves `latest`, a
moving branch or a moving major tag.

## Offline or fully manual path

Download these files on a connected machine and transfer them without renaming:

```text
SHA256SUMS
web-app-security-skill-0.7.3.release.json
web-app-security-skill-0.7.3.spdx.json
web-app-security-skill-0.7.3.tar.gz
```

Also download `scripts/install-verified.mjs` from commit
`ab80e144171b0e3ff350514c5d342e07737604fc` and verify its SHA-256 against the value above. On the
offline machine, run:

```bash
node ./install-verified.mjs --version 0.7.3 --from-dir ./release-assets --attestation skip
```

The offline path performs no HTTP request. `--attestation skip` records that the optional GitHub
attestation check was intentionally skipped; it does not skip asset, manifest, SBOM or archive
verification.

## Upgrade, force and uninstall

```bash
sh ./bootstrap-install.sh --version 0.7.3 --mode upgrade
sh ./bootstrap-install.sh --version 0.7.3 --force
webapp-security uninstall
```

`upgrade` requires a recognized existing installation. `--force` is valid only for installation and
backs up recognized paths before replacement. Unknown directories or launchers are refused before
any selected surface is changed, preventing a partial install.

## What the verification proves

The chain proves that the bytes match the repository's documented trust anchors and release
identity. When attestation verification runs, it also proves the GitHub Actions provenance claim.
It does not prove that every security conclusion or implementation choice is correct. Review the
source commit, signed tag, release evidence and threat model for that judgment.
