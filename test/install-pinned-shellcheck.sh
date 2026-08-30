#!/usr/bin/env bash
set -euo pipefail

: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_PATH:?GITHUB_PATH is required}"

version="0.11.0"
case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    platform="linux.x86_64"
    expected_sha256="8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198"
    ;;
  Darwin:arm64)
    platform="darwin.aarch64"
    expected_sha256="56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79"
    ;;
  Darwin:x86_64)
    platform="darwin.x86_64"
    expected_sha256="3c89db4edcab7cf1c27bff178882e0f6f27f7afdf54e859fa041fca10febe4c6"
    ;;
  *)
    echo "no pinned ShellCheck asset for $(uname -s):$(uname -m)" >&2
    exit 2
    ;;
esac
archive_name="shellcheck-v${version}.${platform}.tar.xz"
archive="$RUNNER_TEMP/$archive_name"
install_root="$RUNNER_TEMP/webapp-security-shellcheck"
url="https://github.com/koalaman/shellcheck/releases/download/v${version}/$archive_name"

curl --fail --silent --show-error --location \
  --proto '=https' --proto-redir '=https' --tlsv1.2 "$url" --output "$archive"
printf '%s  %s\n' "$expected_sha256" "$archive" | sha256sum --check --strict -
mkdir -p "$install_root"
tar -xJf "$archive" -C "$install_root"
binary_dir="$install_root/shellcheck-v${version}"
test -x "$binary_dir/shellcheck"
"$binary_dir/shellcheck" --version | grep -Fx "version: $version"
printf '%s\n' "$binary_dir" >> "$GITHUB_PATH"
