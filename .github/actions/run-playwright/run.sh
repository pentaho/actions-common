#!/usr/bin/env bash
set -euo pipefail

: "${TEST_SCRIPT:?TEST_SCRIPT is required}"
# YAML literal blocks put arguments on separate lines; read only consumes the first line.
test_args="${TEST_ARGS:-}"
test_args="${test_args//$'\r'/ }"
test_args="${test_args//$'\n'/ }"
read -r -a args <<< "$test_args"
if [[ "${VERBOSE:-false}" == true ]]; then
  printf 'Test directory: %s\nBASE_URL: %s\nPLAYWRIGHT_PROJECT: %s\nnpm script: %s\n' \
    "$PWD" "${BASE_URL:-}" "${PLAYWRIGHT_PROJECT:-}" "$TEST_SCRIPT"
fi

if (( ${#args[@]} > 0 )); then
  npm run "$TEST_SCRIPT" -- "${args[@]}"
else
  npm run "$TEST_SCRIPT"
fi
