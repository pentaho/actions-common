#!/usr/bin/env bash
set -euo pipefail

: "${LOG_DIRECTORY:?LOG_DIRECTORY is required}"
mkdir -p "$LOG_DIRECTORY"
collect() {
  local container="$1" name="$2" file="$LOG_DIRECTORY/$2.log"
  if [[ -z "$container" ]]; then
    echo "::warning::No container ID available for $name; cannot collect logs."
    return
  fi
  if ! docker logs "$container" > "$file" 2>&1; then
    echo "::warning::Unable to collect $name logs; see $file for the Docker error."
  fi
  if [[ "${VERBOSE:-false}" == true ]]; then
    echo "::group::$name logs"
    cat "$file"
    echo "::endgroup::"
  fi
}
collect "${PAS_CONTAINER:-}" pentaho-server-console
collect "${POSTGRES_CONTAINER:-}" postgres
