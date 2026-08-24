#!/bin/sh
set -eu

installer_commit='7f84917f5014b4f0f2eb532b7007394ad3123615'
installer_sha256='38d40a706fc4e0c377657d5b49a4a8980811a2518104ac95c762278b87d7b804'
installer_url="https://raw.githubusercontent.com/parousia8888/web-app-security-skill/${installer_commit}/scripts/install-verified.mjs?immutable=${installer_commit}"

if test -n "${WEB_APP_SECURITY_INSTALLER_URL:-}" || test -n "${WEB_APP_SECURITY_INSTALLER_SHA256:-}"; then
  if test -z "${WEB_APP_SECURITY_INSTALLER_URL:-}" || test -z "${WEB_APP_SECURITY_INSTALLER_SHA256:-}"; then
    echo 'error: installer URL and SHA-256 overrides must be provided together' >&2
    exit 2
  fi
  installer_url=$WEB_APP_SECURITY_INSTALLER_URL
  installer_sha256=$WEB_APP_SECURITY_INSTALLER_SHA256
fi

case "$installer_sha256" in
  *[!0-9a-f]*|'')
    echo 'error: installer SHA-256 must be 64 lowercase hexadecimal characters' >&2
    exit 2
    ;;
esac
if test "${#installer_sha256}" -ne 64; then
  echo 'error: installer SHA-256 must be 64 lowercase hexadecimal characters' >&2
  exit 2
fi

case "$installer_url" in
  https://*) curl_security_args='--proto =https --proto-redir =https --tlsv1.2' ;;
  http://127.0.0.1:*|http://localhost:*|http://\[::1\]:*)
    if test "${WEB_APP_SECURITY_ALLOW_TEST_HTTP:-}" != '1'; then
      echo 'error: loopback HTTP requires WEB_APP_SECURITY_ALLOW_TEST_HTTP=1' >&2
      exit 2
    fi
    curl_security_args=''
    ;;
  *)
    echo 'error: installer URL must use HTTPS (loopback HTTP is test-only)' >&2
    exit 2
    ;;
esac

if ! command -v node >/dev/null 2>&1; then
  echo 'error: Node.js 22 or 24 is required' >&2
  exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
  echo 'error: curl is required to download the pinned verifier' >&2
  exit 2
fi

bootstrap_temp=$(mktemp -d "${TMPDIR:-/tmp}/web-app-security-bootstrap.XXXXXX")
cleanup() {
  rm -rf "$bootstrap_temp"
}
trap cleanup EXIT HUP INT TERM
installer_path="$bootstrap_temp/install-verified.mjs"

# shellcheck disable=SC2086 # the fixed curl flags intentionally expand to separate arguments.
curl $curl_security_args --location --fail --silent --show-error \
  --output "$installer_path" "$installer_url"

actual_sha256=$(node -e '
  const { createHash } = require("node:crypto");
  const { readFileSync } = require("node:fs");
  process.stdout.write(createHash("sha256").update(readFileSync(process.argv[1])).digest("hex"));
' "$installer_path")
if test "$actual_sha256" != "$installer_sha256"; then
  echo "error: pinned verifier SHA-256 mismatch: expected $installer_sha256, got $actual_sha256" >&2
  exit 2
fi

node "$installer_path" "$@"
