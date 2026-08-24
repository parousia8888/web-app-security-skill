#!/usr/bin/env bash
set -euo pipefail

INPUT_MODE="${INPUT_MODE:-crawl}"
INPUT_SITE="${INPUT_SITE:-}"
INPUT_ACKNOWLEDGE_AUTHORIZATION="${INPUT_ACKNOWLEDGE_AUTHORIZATION:-false}"
INPUT_PROJECT="${INPUT_PROJECT:-.}"
INPUT_ADAPTERS="${INPUT_ADAPTERS:-builtin}"
INPUT_ADAPTER_TIMEOUT="${INPUT_ADAPTER_TIMEOUT:-120}"
INPUT_ACKNOWLEDGE_ALERT_POLICY="${INPUT_ACKNOWLEDGE_ALERT_POLICY:-false}"
INPUT_OUTPUT_DIR="${INPUT_OUTPUT_DIR:-webapp-security-report}"
INPUT_FAIL_ON="${INPUT_FAIL_ON:-high}"
INPUT_FAIL_ON_DOMAIN="${INPUT_FAIL_ON_DOMAIN:-}"
INPUT_ACTIVE_PROBE="${INPUT_ACTIVE_PROBE:-false}"
INPUT_ALLOW_PRIVATE_NETWORK="${INPUT_ALLOW_PRIVATE_NETWORK:-false}"

ACTION_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
summary_file="$(mktemp "${RUNNER_TEMP:-/tmp}/webapp-security-summary.XXXXXX")"
trap 'rm -f "$summary_file"' EXIT
if [ "$INPUT_ALLOW_PRIVATE_NETWORK" != "true" ] && [ "$INPUT_ALLOW_PRIVATE_NETWORK" != "false" ]; then
  echo "allow-private-network must be true or false" >&2
  exit 2
fi
set +e
if [ "$INPUT_MODE" = "crawl" ]; then
  if [ -z "$INPUT_SITE" ]; then
    echo "site is required in crawl mode" >&2
    exit 2
  fi
  if [ "$INPUT_ACKNOWLEDGE_AUTHORIZATION" != "true" ]; then
    echo "acknowledge-authorization must be true in crawl mode" >&2
    exit 2
  fi
  args=(--site "$INPUT_SITE" --out "$INPUT_OUTPUT_DIR" --report-name report --fail-on "$INPUT_FAIL_ON")
  if [ -n "$INPUT_FAIL_ON_DOMAIN" ]; then args+=(--fail-on-domain "$INPUT_FAIL_ON_DOMAIN"); fi
  if [ "$INPUT_ALLOW_PRIVATE_NETWORK" = "true" ]; then args+=(--allow-private-network); fi
  if [ "$INPUT_ACTIVE_PROBE" = "true" ]; then
    args+=(--active-probe --acknowledge-authorization)
  elif [ "$INPUT_ACTIVE_PROBE" != "false" ]; then
    echo "active-probe must be true or false" >&2
    exit 2
  fi
  node "$ACTION_ROOT/scripts/crawl-surface-audit.mjs" "${args[@]}" > "$summary_file"
elif [ "$INPUT_MODE" = "source" ]; then
  if [ "$INPUT_ALLOW_PRIVATE_NETWORK" != "false" ]; then
    echo "allow-private-network is only valid in crawl mode" >&2
    exit 2
  fi
  if [ "$INPUT_ACTIVE_PROBE" != "false" ]; then
    echo "active-probe is only valid in crawl mode" >&2
    exit 2
  fi
  args=("$INPUT_PROJECT" --out "$INPUT_OUTPUT_DIR" --name report --fail-on "$INPUT_FAIL_ON" --adapter-timeout "$INPUT_ADAPTER_TIMEOUT")
  IFS=',' read -r -a adapter_values <<< "$INPUT_ADAPTERS"
  for adapter in "${adapter_values[@]}"; do args+=(--adapter "$adapter"); done
  if [ -n "$INPUT_FAIL_ON_DOMAIN" ]; then args+=(--fail-on-domain "$INPUT_FAIL_ON_DOMAIN"); fi
  if [ "$INPUT_ACKNOWLEDGE_ALERT_POLICY" = "true" ]; then
    args+=(--acknowledge-alert-policy)
  elif [ "$INPUT_ACKNOWLEDGE_ALERT_POLICY" != "false" ]; then
    echo "acknowledge-alert-policy must be true or false" >&2
    exit 2
  fi
  node "$ACTION_ROOT/scripts/project-audit.mjs" audit "${args[@]}" > "$summary_file"
else
  echo "mode must be crawl or source" >&2
  exit 2
fi
status=$?
set -e
cat "$summary_file"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  if [ "$INPUT_MODE" = "source" ] && [ -s "$INPUT_OUTPUT_DIR/report.md" ]; then
    cat "$INPUT_OUTPUT_DIR/report.md" >> "$GITHUB_STEP_SUMMARY"
  else
    cat "$summary_file" >> "$GITHUB_STEP_SUMMARY"
  fi
fi
exit "$status"
