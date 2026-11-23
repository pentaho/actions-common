#!/usr/bin/env bash
set -euo pipefail

: "${MAVEN_SETTINGS_FILE:?MAVEN_SETTINGS_FILE is required}"
: "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is required}"

args=(-B -ntp -s "$MAVEN_SETTINGS_FILE" clean install)
if [[ "${RUN_UNIT_TESTS:-false}" == true ]]; then
  args+=(-DskipTests=false -Daudit -Dmaven.test.failure.ignore=false)
else
  args+=(-DskipTests)
fi
args+=("-DbiserverHome=$GITHUB_WORKSPACE/pentaho-build")
if [[ -n "${MVN_DIRECTIVES:-}" ]]; then
  arguments_file="$(mktemp)"
  trap 'rm -f "$arguments_file"' EXIT
  python3 -c 'import shlex, sys; sys.stdout.buffer.write(b"".join(arg.encode() + b"\0" for arg in shlex.split(sys.argv[1])))' \
    "$MVN_DIRECTIVES" > "$arguments_file"
  while IFS= read -r -d '' argument; do
    args+=("$argument")
  done < "$arguments_file"
fi

if [[ "${VERBOSE:-false}" == true ]]; then
  mvn --version
  echo "Plugin install directory: $GITHUB_WORKSPACE/pentaho-build"
fi
mvn "${args[@]}"

if [[ "${VERBOSE:-false}" == true ]]; then
  system_dir="$GITHUB_WORKSPACE/pentaho-build/pentaho-solutions/system"
  # Staging may be left to post_build_command, so a missing folder is not an error here.
  if [[ -d "$system_dir" ]]; then
    find "$system_dir" -mindepth 2 -maxdepth 2 -name plugin.xml -print
  else
    echo "No plugins staged by Maven in $system_dir"
  fi
fi
