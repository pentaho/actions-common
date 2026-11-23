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
# Volume layout (relative to VOLUME_DIR / HOST_VOLUME_PATH):
#   postgres/                    Pentaho repository SQL scripts (Postgres init scripts)
#   logs/                        Pentaho Server Tomcat logs and collected service logs
#   pentaho-solutions/system/<p> Plugins mounted into the Pentaho Server
set -euo pipefail

: "${VOLUME_DIR:?VOLUME_DIR is required}"
: "${HOST_VOLUME_PATH:?HOST_VOLUME_PATH is required}"
: "${SQL_SOURCE_DIR:?SQL_SOURCE_DIR is required}"
PLUGIN_PATH="${PLUGIN_PATH:-/home/devuser/pentaho/pentaho-server/pentaho-solutions/system/}"
server_home="${PLUGIN_PATH%/}"
server_home="${server_home%/pentaho-solutions/system}"
LOGS_PATH="${LOGS_PATH:-$server_home/tomcat/logs}"
REQUIRED_PLUGINS="${REQUIRED_PLUGINS:-}"

host_root="${HOST_VOLUME_PATH%/}"
system_dir="${VOLUME_DIR%/}/pentaho-solutions/system"

for mount_path in "$host_root" "$PLUGIN_PATH" "$LOGS_PATH"; do
  if [[ "$mount_path" != /* || "$mount_path" == *[[:space:],:\"]* || "$mount_path" == *"'"* ]]; then
    echo "::error::Unsupported Docker bind mount path: $mount_path"
    exit 1
  fi
done

mkdir -p "${VOLUME_DIR%/}/postgres" "${VOLUME_DIR%/}/logs" "$system_dir"

rm -f "${VOLUME_DIR%/}/postgres/"*.sql
cp "$SQL_SOURCE_DIR"/*.sql "${VOLUME_DIR%/}/postgres/"
if [[ "${VERBOSE:-false}" == true ]]; then
  echo "Staged Postgres init scripts:"
  ls -1 "${VOLUME_DIR%/}/postgres"
fi

# The Pentaho Server runs as a non-root user and writes into the mounted folders.
chmod -R a+rwX "${VOLUME_DIR%/}/logs" "$system_dir"

required_plugins="${REQUIRED_PLUGINS//,/ }"
required_plugins="${required_plugins//$'\r'/ }"
required_plugins="${required_plugins//$'\n'/ }"
read -r -a required <<< "$required_plugins"
missing=()
for plugin in ${required[@]+"${required[@]}"}; do
  if [[ ! -s "$system_dir/$plugin/plugin.xml" ]]; then
    missing+=("$plugin")
  fi
done
if (( ${#missing[@]} > 0 )); then
  echo "::error::Required plugin(s) missing a plugin.xml in $system_dir: ${missing[*]}"
  exit 1
fi

plugins=()
while IFS= read -r plugin; do
  [[ -n "$plugin" ]] && plugins+=("$plugin")
done < <(find "$system_dir" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | LC_ALL=C sort)

if (( ${#plugins[@]} == 0 )); then
  echo "::warning::No plugins staged in $system_dir; the Pentaho Server will run with its bundled plugins only."
fi

mounts="--mount type=bind,source=${host_root}/logs,target=${LOGS_PATH%/}"
for plugin in ${plugins[@]+"${plugins[@]}"}; do
  if [[ ! "$plugin" =~ ^[A-Za-z0-9_-][A-Za-z0-9._-]*$ || ! -s "$system_dir/$plugin/plugin.xml" ]]; then
    echo "::error::Invalid plugin folder or missing plugin.xml: $system_dir/$plugin"
    exit 1
  fi
  mounts+=" --mount type=bind,source=${host_root}/pentaho-solutions/system/${plugin},target=${PLUGIN_PATH%/}/${plugin}"
done

plugins_csv="$(IFS=,; echo "${plugins[*]-}")"

echo "Staged plugins: ${plugins_csv:-bundled plugins only}"
if [[ "${VERBOSE:-false}" == true ]]; then
  echo "Pentaho Server mounts: $mounts"
fi
{
  echo "plugins=$plugins_csv"
  echo "mounts=$mounts"
} >> "${GITHUB_OUTPUT:-/dev/stdout}"
