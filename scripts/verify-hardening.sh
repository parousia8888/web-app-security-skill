#!/usr/bin/env bash
# verify-hardening.sh — verify externally observable edge hardening.
#
# Passive mode sends one request per transport/header check. Rate-limit verification is
# active and must be enabled explicitly with --active-rate-limit after Phase 0 authorization.
# Portable to macOS Bash 3.2.
set -uo pipefail

usage() {
  sed -n '2,16p' "$0"
  cat <<'EOF'
# Usage:
#   scripts/verify-hardening.sh --site https://example.com
#   scripts/verify-hardening.sh --site https://example.com --active-rate-limit --acknowledge-authorization --n 30
#   scripts/verify-hardening.sh --site https://1.2.3.4 --host example.com
#
# Options:
#   --site URL             Required http(s) origin
#   --host HOST            Override Host header for an origin/IP check
#   --cacert FILE          Explicit CA certificate bundle for curl verification
#   --http-site URL        HTTP origin used for redirect check (default: SITE with http scheme)
#   --content-path PATH    Public content path (default /)
#   --probe-path PATH      Probe path for active limiting (default /.env)
#   --active-rate-limit    Send the bounded concurrent rate-limit checks
#   --acknowledge-authorization
#                          Confirm ownership or written authorization for the active test
#   --n COUNT              Requests per class, 1..100 (default 30)
#   --out DIR              Write the v2 report bundle and observations
#   --report-name NAME     Report basename (default edge-report)
#   --fail-on LEVEL        critical, high, medium, low, or never (default high)
EOF
}

SITE="" HTTP_SITE="" HOST="" CACERT="" CONTENT="/" PROBE="/.env" N=30 ACTIVE_RATE_LIMIT=0 ACKNOWLEDGED=0
OUT_DIR="" REPORT_NAME="edge-report" FAIL_ON="high"
CURL_BIN="${WEBAPP_SECURITY_CURL_BIN:-curl}"
while [ $# -gt 0 ]; do
  case "$1" in
    --site|--http-site|--host|--cacert|--content-path|--probe-path|--n|--out|--report-name|--fail-on)
      [ $# -ge 2 ] || { echo "error: $1 requires a value" >&2; exit 2; }
      case "$1" in
        --site) SITE="$2";;
        --http-site) HTTP_SITE="$2";;
        --host) HOST="$2";;
        --cacert) CACERT="$2";;
        --content-path) CONTENT="$2";;
        --probe-path) PROBE="$2";;
        --n) N="$2";;
        --out) OUT_DIR="$2";;
        --report-name) REPORT_NAME="$2";;
        --fail-on) FAIL_ON="$2";;
      esac
      shift 2;;
    --active-rate-limit) ACTIVE_RATE_LIMIT=1; shift;;
    --acknowledge-authorization) ACKNOWLEDGED=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

[ -n "$SITE" ] || { echo "error: --site <url> required" >&2; exit 2; }
case "$SITE" in http://*|https://*) ;; *) echo "error: --site must start with http:// or https://" >&2; exit 2;; esac
if [ -n "$HTTP_SITE" ]; then
  case "$HTTP_SITE" in http://*) ;; *) echo "error: --http-site must start with http://" >&2; exit 2;; esac
fi
case "$N" in ''|*[!0-9]*) echo "error: --n must be an integer from 1 to 100" >&2; exit 2;; esac
[ "$N" -ge 1 ] && [ "$N" -le 100 ] || { echo "error: --n must be an integer from 1 to 100" >&2; exit 2; }
case "$CONTENT" in /*) ;; *) echo "error: --content-path must start with /" >&2; exit 2;; esac
case "$PROBE" in /*) ;; *) echo "error: --probe-path must start with /" >&2; exit 2;; esac
[ "$ACTIVE_RATE_LIMIT" -ne 1 ] || [ "$ACKNOWLEDGED" -eq 1 ] || {
  echo "error: --active-rate-limit requires --acknowledge-authorization" >&2
  exit 2
}
case "$FAIL_ON" in critical|high|medium|low|never) ;; *) echo "error: --fail-on is invalid" >&2; exit 2;; esac
case "$REPORT_NAME" in ''|*[!A-Za-z0-9._-]*) echo "error: --report-name contains unsupported characters" >&2; exit 2;; esac
[ -z "$CACERT" ] || [ -r "$CACERT" ] || { echo "error: --cacert must be a readable file" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OBS_FILE="$(mktemp "${TMPDIR:-/tmp}/webapp-security-edge.XXXXXX")" || exit 2
trap 'rm -f "$OBS_FILE"' EXIT
record() {
  rule="$1" state="$2" message="$3"
  encoded="$(printf '%s' "$message" | base64 | tr -d '\n')"
  printf '%s\t%s\t%s\n' "$rule" "$state" "$encoded" >> "$OBS_FILE"
}
emit() {
  node "$SCRIPT_DIR/edge-hardening-report.mjs" \
    --observations "$OBS_FILE" --site "$SITE" --report-name "$REPORT_NAME" --fail-on "$FAIL_ON" \
    --active "$([ "$ACTIVE_RATE_LIMIT" -eq 1 ] && printf true || printf false)" \
    ${OUT_DIR:+--out "$OUT_DIR"}
}
record_all_unknown() {
  message="$1"
  for rule in edge-curl-capability edge-hsts edge-nosniff edge-frame-protection edge-referrer-policy \
    edge-content-security-policy edge-rate-probe-throttling edge-rate-content-availability \
    edge-http-redirect edge-tls-max-capability edge-tls12-available edge-tls11-rejected \
    edge-tls10-rejected edge-certificate-validation; do
    record "$rule" unknown "$message"
  done
}

if ! command -v "$CURL_BIN" >/dev/null 2>&1; then
  record_all_unknown "curl is unavailable; no edge conclusion is possible"
  emit
  exit $?
fi
record edge-curl-capability passed "curl is available"

hcurl() {
  if [ -n "$HOST" ] && [ -n "$CACERT" ]; then
    "$CURL_BIN" --cacert "$CACERT" -H "Host: $HOST" "$@"
  elif [ -n "$HOST" ]; then
    "$CURL_BIN" -H "Host: $HOST" "$@"
  elif [ -n "$CACERT" ]; then
    "$CURL_BIN" --cacert "$CACERT" "$@"
  else
    "$CURL_BIN" "$@"
  fi
}

pass=0; warn=0; unknown=0
ok()      { echo "  [ok] $2"; record "$1" passed "$2"; pass=$((pass+1)); }
bad()     { echo "  [fail] $2"; record "$1" failed "$2"; warn=$((warn+1)); }
unknown() { echo "  [unknown] $2"; record "$1" unknown "$2"; unknown=$((unknown+1)); }
n_a()     { echo "  [note] $2"; record "$1" not_applicable "$2"; }
note()    { echo "  [note] $1"; }

echo "== verify-hardening =="

echo "[headers]"
H=""
if ! H="$(hcurl -skS --connect-timeout 5 --max-time 15 -I "$SITE$CONTENT")"; then
  H_AVAILABLE=0
else
  H_AVAILABLE=1
fi
need_re() {
  if [ "$H_AVAILABLE" -eq 0 ]; then unknown "$1" "header request failed; $3 evidence is unavailable"
  elif printf '%s' "$H" | grep -iqE "$2"; then ok "$1" "$3 present"; else
    bad "$1" "$3 missing"
  fi
}
need_re edge-hsts "^strict-transport-security:" "Strict-Transport-Security"
printf '%s' "$H" | grep -iE "^strict-transport-security:" | grep -iq "includesubdomains" \
  && note "HSTS includeSubDomains present" || note "HSTS lacks includeSubDomains (consider adding)"
need_re edge-nosniff "^x-content-type-options:[[:space:]]*nosniff" "X-Content-Type-Options: nosniff"
need_re edge-frame-protection "^x-frame-options:|content-security-policy(-report-only)?:.*frame-ancestors" "X-Frame-Options / frame-ancestors"
need_re edge-referrer-policy "^referrer-policy:" "Referrer-Policy"
need_re edge-content-security-policy "^content-security-policy(-report-only)?:" "Content-Security-Policy"

echo "[rate-limit]"
if [ "$ACTIVE_RATE_LIMIT" -ne 1 ]; then
  note "skipped; pass --active-rate-limit only after scope/authorization is recorded"
  n_a edge-rate-probe-throttling "active rate-limit check disabled"
  n_a edge-rate-content-availability "active rate-limit check disabled"
else
  echo "  concurrency=$N"
  burst() {
    local url="$1" ua="${2:-}" i=0
    while [ "$i" -lt "$N" ]; do
      if [ -n "$ua" ]; then
        hcurl -skS --connect-timeout 5 --max-time 15 -o /dev/null -A "$ua" -w '%{http_code}\n' "$url" 2>/dev/null &
      else
        hcurl -skS --connect-timeout 5 --max-time 15 -o /dev/null -w '%{http_code}\n' "$url" 2>/dev/null &
      fi
      i=$((i+1))
    done
    wait
  }
  PB="$(burst "$SITE$PROBE" 'probe-scanner' | sort | uniq -c | tr '\n' ' ')"
  CT="$(burst "$SITE$CONTENT" | sort | uniq -c | tr '\n' ' ')"
  note "probe responses: $PB"
  note "content responses: $CT"
  if printf '%s %s' "$PB" "$CT" | grep -qE '(^|[^0-9])000([^0-9]|$)'; then
    unknown edge-rate-probe-throttling "rate-limit request evidence is unavailable (HTTP 000)"
    unknown edge-rate-content-availability "content availability evidence is unavailable (HTTP 000)"
  else
    if printf '%s' "$PB" | grep -qE '(^|[^0-9])(429|503)([^0-9]|$)'; then
      ok edge-rate-probe-throttling "probe class is being throttled"
    else
      bad edge-rate-probe-throttling "probe class never returned 429/503; limiter absent or below threshold"
    fi
    if printf '%s' "$CT" | grep -qE '(^|[^0-9])(429|503)([^0-9]|$)'; then
      bad edge-rate-content-availability "content class got 429/503; normal users and crawlers can be blocked"
    else
      ok edge-rate-content-availability "content class remained available"
    fi
  fi
fi

echo "[transport]"
case "$SITE" in
  https://*)
    [ -n "$HTTP_SITE" ] || HTTP_SITE="$(printf '%s' "$SITE" | sed 's,^https:,http:,')"
    RC="$(hcurl -skS --connect-timeout 5 --max-time 15 -o /dev/null -w '%{http_code} %{redirect_url}' "$HTTP_SITE$CONTENT" 2>/dev/null || true)"
    REDIRECT_STATUS="${RC%% *}"
    case "$RC" in
      30[12378]\ https://*) ok edge-http-redirect "HTTP redirects to HTTPS (status $REDIRECT_STATUS)";;
      000*|'') unknown edge-http-redirect "HTTP redirect endpoint was unreachable";;
      *) bad edge-http-redirect "HTTP did not redirect to HTTPS (status $REDIRECT_STATUS)";;
    esac

    if "$CURL_BIN" --help all 2>/dev/null | grep -q -- '--tls-max'; then
      record edge-tls-max-capability passed "curl supports --tls-max"
      if hcurl -skS --connect-timeout 5 --max-time 15 --tlsv1.2 --tls-max 1.2 -o /dev/null "$SITE$CONTENT" 2>/dev/null; then
        ok edge-tls12-available "TLS 1.2 handshake succeeds"
      else
        bad edge-tls12-available "TLS 1.2 handshake failed"
      fi
      if hcurl -skS --connect-timeout 5 --max-time 15 --tlsv1.1 --tls-max 1.1 -o /dev/null "$SITE$CONTENT" 2>/dev/null; then
        bad edge-tls11-rejected "TLS 1.1 handshake succeeds; disable TLS 1.1"
      else
        ok edge-tls11-rejected "TLS 1.1 handshake rejected"
      fi
      if hcurl -skS --connect-timeout 5 --max-time 15 --tlsv1.0 --tls-max 1.0 -o /dev/null "$SITE$CONTENT" 2>/dev/null; then
        bad edge-tls10-rejected "TLS 1.0 handshake succeeds; disable TLS 1.0"
      else
        ok edge-tls10-rejected "TLS 1.0 handshake rejected"
      fi
    else
      unknown edge-tls-max-capability "curl lacks --tls-max; TLS versions were not verified"
      unknown edge-tls12-available "TLS 1.2 availability was not verified"
      unknown edge-tls11-rejected "TLS 1.1 rejection was not verified"
      unknown edge-tls10-rejected "TLS 1.0 rejection was not verified"
    fi

    if [ -z "$HOST" ]; then
      if hcurl -sS --connect-timeout 5 --max-time 15 -o /dev/null "$SITE$CONTENT"; then
        ok edge-certificate-validation "TLS certificate chain and hostname validate"
      else
        bad edge-certificate-validation "TLS certificate chain or hostname validation failed"
      fi
    else
      unknown edge-certificate-validation "certificate validation skipped for --host origin/IP mode"
    fi
    ;;
  *)
    note "site is not https://; TLS checks skipped"
    n_a edge-http-redirect "site is not HTTPS"
    n_a edge-tls-max-capability "site is not HTTPS"
    n_a edge-tls12-available "site is not HTTPS"
    n_a edge-tls11-rejected "site is not HTTPS"
    n_a edge-tls10-rejected "site is not HTTPS"
    n_a edge-certificate-validation "site is not HTTPS"
    ;;
esac

echo "== $pass passed · $warn failed · $unknown unknown =="
emit
exit $?
