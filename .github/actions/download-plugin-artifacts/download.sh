#!/usr/bin/env bash
set -euo pipefail

: "${ARTIFACTS:?ARTIFACTS is required}"
: "${ARTIFACT_DIR:?ARTIFACT_DIR is required}"
: "${ARTIFACTORY_URL:?ARTIFACTORY_URL is required}"
: "${ACCESS_TOKEN:?ACCESS_TOKEN is required}"
REPOSITORY="${REPOSITORY:-pntprv-maven-dev}"

if [[ -z "${VERSION:-}" || "$VERSION" == null ]]; then
  echo "::error::No version given and the latest build version could not be resolved"
  exit 1
fi

artifacts="${ARTIFACTS//,/ }"
artifacts="${artifacts//$'\r'/ }"
artifacts="${artifacts//$'\n'/ }"
read -r -a paths <<< "$artifacts"
if (( ${#paths[@]} == 0 )); then
  echo "::error::No artifacts given"
  exit 1
fi

mkdir -p "$ARTIFACT_DIR"
zip="$(mktemp)"
trap 'rm -f "$zip"' EXIT
echo "Downloading ${#paths[@]} artifact(s) version $VERSION from $REPOSITORY"

for path in "${paths[@]}"; do
  path="${path#/}"
  path="${path%/}"
  artifact_id="${path##*/}"
  url="${ARTIFACTORY_URL%/}/$REPOSITORY/$path/$VERSION/$artifact_id-$VERSION.zip"
  echo "Downloading $artifact_id"
  curl -LgfsS -H "Authorization: Bearer $ACCESS_TOKEN" -o "$zip" "$url"
  unzip -qo "$zip" -d "$ARTIFACT_DIR"
done

if [[ "${VERBOSE:-false}" == true ]]; then
  find "$ARTIFACT_DIR" -mindepth 1 -maxdepth 1 -type d -print | sort
fi

echo "version=$VERSION" >> "$GITHUB_OUTPUT"
