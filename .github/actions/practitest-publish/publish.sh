#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${MANUAL_API_TOKEN:-}" || -z "${MANUAL_BUILD_NUMBER:-}" ]]; then
  echo "::error::Practitest requires PRACTITEST_PAT and the tested Pentaho Server version."
  exit 1
fi
[[ -n "${MANUAL_BUILD_PLUGIN:-}" ]] || unset MANUAL_BUILD_PLUGIN
[[ -n "${PT_USERNAME:-}" ]] || unset PT_USERNAME
# The uploader groups by browser when PLAYWRIGHT_PROJECT is unset.
unset PLAYWRIGHT_PROJECT

# Absolute paths let a packaged uploader (e.g. under node_modules) find the caller's config and results.
absolute() { [[ "$1" == /* ]] && printf '%s' "$1" || printf '%s/%s' "$PWD" "$1"; }
PT_ENV_FILE="$(absolute "${ENV_FILE:-.env}")"
if [[ ! -f "$PT_ENV_FILE" ]]; then
  echo "::error::Practitest env file not found: $PT_ENV_FILE"
  exit 1
fi
export PT_ENV_FILE
if [[ -n "${RESULTS_DIR:-}" ]]; then
  PT_RESULTS_DIR="$(absolute "$RESULTS_DIR")"
  export PT_RESULTS_DIR
fi

if [[ "${VERBOSE:-false}" == true ]]; then
  printf 'Practitest version: %s\nUploader: %s\nEnv file: %s\nResults: %s\n' \
    "$MANUAL_BUILD_NUMBER" "$PWD" "$PT_ENV_FILE" "${PT_RESULTS_DIR:-uploader default}"
fi
npm run "${SCRIPT:-upload}"
node "$(dirname "${BASH_SOURCE[0]}")/link.cjs"
