#!/usr/bin/env bash
set -euo pipefail

if [[ "${VERBOSE:-false}" == true ]]; then
  node --version
  npm --version
  echo "Installing dependencies in $PWD"
fi
npm install

read -r -a browsers <<< "${PLAYWRIGHT_BROWSERS:-}"
if (( ${#browsers[@]} > 0 )); then
  npx playwright install --with-deps "${browsers[@]}"
fi
