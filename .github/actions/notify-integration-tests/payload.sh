#!/usr/bin/env bash
set -euo pipefail

case " $SETUP_RESULT $TESTS_RESULT " in
  *" failure "*) status=failure ;;
  *" cancelled "*) status=cancelled ;;
  *" skipped "*) status=skipped ;;
  *) status=success ;;
esac
payload="$(jq -cn \
  --arg status "$status" \
  --arg channel "$SLACK_CHANNEL" \
  --arg event "Event: <$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID|$EVENT_NAME>" \
  --arg branch "Branch: $BRANCH" \
  --arg version "Version: ${SERVER_VERSION:-unknown}" \
  --arg server "Server: $SERVER_BUILD_NAME ($SERVER_CONTEXT), Project: $PLAYWRIGHT_PROJECT" \
  --arg summary "${TESTS_SUMMARY:-Tests: no results found}" \
  --arg practitest "${PRACTITEST_URL:-}" \
  --arg jobs "Setup: $SETUP_RESULT, Integration tests: $TESTS_RESULT" \
  --arg actor "$GITHUB_ACTOR" \
  '{
    status: $status, channel: $channel,
    attachments: [{
      title: "Pentaho Plugin Integration Tests",
      fields: ([
        {value: $event, short: true},
        {value: ("Status: " + $status), short: true},
        {value: $branch, short: true},
        {value: $version, short: true},
        {value: $server, short: true},
        {value: $summary, short: false}
      ] + (if $practitest == "" then [] else [{value: ("Practitest: <" + $practitest + "|Test Sets & Runs>"), short: false}] end)
        + [{value: $jobs, short: false}]),
      footer: ("by " + $actor),
      footer_icon: ("https://github.com/" + $actor + ".png?size=20")
    }]
  }')"
printf 'json=%s\n' "$payload" >> "$GITHUB_OUTPUT"
if [[ "${VERBOSE:-false}" == true ]]; then
  printf 'Notification status: %s\n%s\n' "$status" "${TESTS_SUMMARY:-Tests: no results found}"
fi
