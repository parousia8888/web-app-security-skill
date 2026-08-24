# Verified installation

The recommended README command has three independently reviewable stages. It does not execute bytes
merely because they came from the same TLS origin as a checksum file.

1. The README fixes `bootstrap-install.sh` to commit
   `cb36196fb438fb0ad0e5b5a6a27043bf48ffb018` and verifies SHA-256
   `544d0ded89ed98467c275c838f033148d944668b0b56842d849ff8ae4abc63d2` before `sh` runs it.
2. The bootstrap fixes `install-verified.mjs` to commit
   `7f84917f5014b4f0f2eb532b7007394ad3123615` and verifies SHA-256
   `38d40a706fc4e0c377657d5b49a4a8980811a2518104ac95c762278b87d7b804` before Node runs it.
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
sh ./bootstrap-install.sh --version 0.7.1 --target codex
sh ./bootstrap-install.sh --version 0.7.1 --target claude
sh ./bootstrap-install.sh --version 0.7.1 --target cli
```

The verifier rejects a version absent from its built-in trust map. It never resolves `latest`, a
moving branch or a moving major tag.

## Offline or fully manual path

Download these files on a connected machine and transfer them without renaming:

```text
SHA256SUMS
web-app-security-skill-0.7.1.release.json
web-app-security-skill-0.7.1.spdx.json
web-app-security-skill-0.7.1.tar.gz
```

Also download `scripts/install-verified.mjs` from commit
`7f84917f5014b4f0f2eb532b7007394ad3123615` and verify its SHA-256 against the value above. On the
offline machine, run:

```bash
node ./install-verified.mjs --version 0.7.1 --from-dir ./release-assets --attestation skip
```

The offline path performs no HTTP request. `--attestation skip` records that the optional GitHub
attestation check was intentionally skipped; it does not skip asset, manifest, SBOM or archive
verification.

## Upgrade, force and uninstall

```bash
sh ./bootstrap-install.sh --version 0.7.1 --mode upgrade
sh ./bootstrap-install.sh --version 0.7.1 --force
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
