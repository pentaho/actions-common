#!/usr/bin/env bash
set -eo pipefail

icons_file="$RUNNER_TEMP/icons.properties"
if [[ ! -e "$icons_file" ]]; then
  printf 'sonar_scan=x\nbuild=x\nunit_test=x\nintegration_test=x\ngeneric_test=x\n' > "$icons_file"
  if [[ "$GITHUB_EVENT_NAME" != pull_request ]]; then
    printf 'create_tag=x\ndeploy=x\n' >> "$icons_file"
  fi
fi

build_icon=white_check_mark
[[ "$BUILD_OUTCOME" == success ]] || build_icon=boom
sed -i "s/build=x/build=${build_icon}/g" "$icons_file"

if [[ "$RUN_UNIT_TESTS" == true ]]; then
  test_icon=white_check_mark
  if [[ "$BUILD_OUTCOME" != success || "$REPORT_OUTCOME" != success ||
        "$REPORT_CONCLUSION" == failure ]]; then
    test_icon=boom
  fi
  sed -i "s/unit_test=x/unit_test=${test_icon}/g" "$icons_file"
  if [[ -n "$REPORT_URL" ]]; then
    printf 'url=%s\n' "$REPORT_URL" > "$RUNNER_TEMP/unit_test_links.txt"
  fi
fi
