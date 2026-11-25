#!/usr/bin/env bash
# Shared runner for Playwright report generator scripts.
#
# Arguments:
# - $1: generator script name (e.g., generate-expected-md.cjs).
# - $2..: extra arguments passed through to the generator script.
#
# Behavior:
# - Resolves scripts relative to this file's own directory, so it works
#   regardless of how GITHUB_ACTION_PATH is reported (host vs container mount).
# - Fails fast when the script is missing, listing the action directory.
# - Runs the generator with node, forwarding extra arguments.

set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <generator-script-name> [generator-args...]" >&2
  echo "Example: $0 generate-expected-md.cjs \"*/playwright-report/output/*\"" >&2
  exit 2
fi

SCRIPT_NAME="$1"
shift

ACTION_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_PATH="${ACTION_DIR}/${SCRIPT_NAME}"

if [ ! -f "$SCRIPT_PATH" ]; then
  echo "Expected script not found: $SCRIPT_PATH"
  ls -lab "${ACTION_DIR}"
  exit 1
fi

node "$SCRIPT_PATH" "$@"
