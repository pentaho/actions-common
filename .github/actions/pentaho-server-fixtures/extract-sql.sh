#!/usr/bin/env bash
# ******************************************************************************
#
# Pentaho
#
# Copyright (C) 2026 by Pentaho Canada Inc. : http://www.pentaho.com
#
# Use of this software is governed by the Business Source License included
# in the LICENSE.TXT file.
#
# Change Date: 2030-06-15
# ******************************************************************************
#
# Copies the Pentaho repository PostgreSQL scripts shipped in the Pentaho Server image,
# so the database always matches the server version under test.
set -euo pipefail

: "${SERVER_IMAGE:?SERVER_IMAGE is required}"
: "${SQL_OUTPUT_DIR:?SQL_OUTPUT_DIR is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"
server_home="${PLUGIN_PATH:-/home/devuser/pentaho/pentaho-server/pentaho-solutions/system/}"
server_home="${server_home%/}"
server_home="${server_home%/pentaho-solutions/system}"
SERVER_SQL_PATH="${SERVER_SQL_PATH:-$server_home/data/postgresql}"
REGISTRY_USERNAME="${REGISTRY_USERNAME:-}"
REGISTRY_PASSWORD="${REGISTRY_PASSWORD:-}"

if ! command -v docker >/dev/null 2>&1 || ! docker version >/dev/null 2>&1; then
  echo "::error::Docker is not available in this job; it is needed to read the SQL scripts from $SERVER_IMAGE."
  exit 1
fi

registry="${SERVER_IMAGE%%/*}"
container_id=""
extract_dir="$(mktemp -d)"
export DOCKER_CONFIG="$extract_dir/docker"
mkdir -p "$DOCKER_CONFIG" "$extract_dir/sql"
cleanup() {
  if [[ -n "$container_id" ]] && ! docker rm --force "$container_id" >/dev/null; then
    echo "::warning::Unable to remove temporary SQL extraction container $container_id."
  fi
  rm -rf "$extract_dir"
}
trap cleanup EXIT

# Only log in when the image names a registry host (e.g. artifactory.example.com/...).
if [[ "$SERVER_IMAGE" == */* && -n "$REGISTRY_USERNAME" && -n "$REGISTRY_PASSWORD" &&
      ( "$registry" == *.* || "$registry" == *:* || "$registry" == localhost ) ]]; then
  printf '%s' "$REGISTRY_PASSWORD" | docker login "$registry" --username "$REGISTRY_USERNAME" --password-stdin >/dev/null
fi

# Reduces an image reference to its repository so Docker Hub aliases compare equal.
normalize_repository() {
  local ref="${1%%@*}" last
  last="${ref##*/}"
  [[ "$last" == *:* ]] && ref="${ref%:*}"
  ref="${ref#docker.io/}"
  ref="${ref#index.docker.io/}"
  ref="${ref#library/}"
  printf '%s' "$ref"
}

digest_pattern='^[^[:space:]@]+@sha256:[[:xdigit:]]{64}$'
docker pull --quiet "$SERVER_IMAGE"
resolved_image=""
if [[ "$SERVER_IMAGE" == *@* ]]; then
  [[ "$SERVER_IMAGE" =~ $digest_pattern ]] && resolved_image="$SERVER_IMAGE"
elif repo_digests="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$SERVER_IMAGE")"; then
  # An image pulled through several repositories lists one digest per repository; keep the requested one
  # so the service pulls from the same registry the credentials belong to.
  wanted="$(normalize_repository "$SERVER_IMAGE")"
  while IFS= read -r digest; do
    if [[ "$digest" =~ $digest_pattern && "$(normalize_repository "$digest")" == "$wanted" ]]; then
      resolved_image="$digest"
      break
    fi
  done <<< "$repo_digests"
fi
if [[ -z "$resolved_image" ]]; then
  echo "::error::Unable to resolve an immutable registry digest for $SERVER_IMAGE."
  exit 1
fi
container_id="$(docker create "$resolved_image")"

if ! docker cp "$container_id:${SERVER_SQL_PATH%/}/." "$extract_dir/sql" >/dev/null; then
  echo "::error::Folder '$SERVER_SQL_PATH' not found in $resolved_image."
  exit 1
fi

mkdir -p "$SQL_OUTPUT_DIR"
rm -f "${SQL_OUTPUT_DIR%/}/"*.sql
# Every staged *.sql file runs as a Postgres init script on a fresh database, so only the
# fresh-install scripts are copied; upgrade, migrate and drop scripts fail without existing objects.
required_scripts=(create_jcr_postgresql.sql create_quartz_postgresql.sql create_repository_postgresql.sql)
optional_scripts=(pentaho_logging_postgresql.sql pentaho_mart_postgresql.sql)

missing=()
for script in "${required_scripts[@]}"; do
  if [[ -s "$extract_dir/sql/$script" ]]; then
    cp "$extract_dir/sql/$script" "$SQL_OUTPUT_DIR"
  else
    missing+=("$script")
  fi
done
for script in "${optional_scripts[@]}"; do
  if [[ -s "$extract_dir/sql/$script" ]]; then
    cp "$extract_dir/sql/$script" "$SQL_OUTPUT_DIR"
  fi
done
if (( ${#missing[@]} > 0 )); then
  echo "::error::$resolved_image is missing ${missing[*]} in $SERVER_SQL_PATH."
  exit 1
fi

echo "Copied $(find "$SQL_OUTPUT_DIR" -maxdepth 1 -name '*.sql' | wc -l | tr -d ' ') Postgres init scripts from $resolved_image:$SERVER_SQL_PATH"
if [[ "${VERBOSE:-false}" == true ]]; then
  ls -1 "$SQL_OUTPUT_DIR"
fi
printf 'server_image=%s\n' "$resolved_image" >> "$GITHUB_OUTPUT"
