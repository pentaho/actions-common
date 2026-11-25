#!/usr/bin/env bash
set -euo pipefail

case "$FORMAT" in
  pull_request)
    case " $RESULTS " in
      *" failure "*) status=failure; icon="❌" ;;
      *" cancelled "*) status=cancelled; icon="⚠️" ;;
      *) status=success; icon="✅" ;;
    esac
    title="$WORKFLOW_NAME #${PR_NUMBER:-}"
    payload="$(jq -cn \
      --arg status "$status" \
      --arg icon "$icon" \
      --arg channel "$SLACK_CHANNEL" \
      --arg title "$title" \
      --arg event "Event: <$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID|$EVENT_NAME>" \
      --arg branch "Branch: $BRANCH" \
      --arg pr "PR: <${PR_URL:-}|#${PR_NUMBER:-}>" \
      --arg version "Version: ${SERVER_VERSION:-unknown}" \
      --arg summary "${TESTS_SUMMARY:-Tests: no results found}" \
      --arg jobs "${JOBS_SUMMARY:-}" \
      --arg actor "$GITHUB_ACTOR" \
      '{
        status: $status, channel: $channel,
        attachments: [{
          title: $title,
          fields: [
            {value: $event, short: true},
            {value: ("Status: " + $status + " " + $icon), short: true},
            {value: $branch, short: true},
            {value: $pr, short: true},
            {value: $version, short: true},
            {value: $summary, short: false},
            {value: $jobs, short: false}
          ],
          footer: ("by " + $actor),
          footer_icon: ("https://github.com/" + $actor + ".png?size=20")
        }]
      }')"
    ;;
  integration_tests)
    case " $SETUP_RESULT $TESTS_RESULT " in
      *" failure "*) status=failure; icon="❌" ;;
      *" cancelled "*) status=cancelled; icon="⚠️" ;;
      *" skipped "*) status=skipped; icon="⚠️" ;;
      *) status=success; icon="✅" ;;
    esac
    title="${NOTIFICATION_TITLE:-Pentaho Plugin Integration Tests}"
    status_text="Status: $status"
    if [[ "${STATUS_ICONS:-false}" == true ]]; then
      status_text+=" $icon"
    fi
    version_text="Version: ${SERVER_VERSION:-unknown}"
    if [[ -n "${PLUGIN_VERSION:-}" ]]; then
      version_text+=" | Plugin version: $PLUGIN_VERSION"
    fi
    payload="$(jq -cn \
      --arg status "$status" \
      --arg status_text "$status_text" \
      --arg title "$title" \
      --arg channel "$SLACK_CHANNEL" \
      --arg event "Event: <$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID|$EVENT_NAME>" \
      --arg branch "Branch: $BRANCH" \
      --arg version "$version_text" \
      --arg server "Server: $SERVER_BUILD_NAME ($SERVER_CONTEXT), Project: $PLAYWRIGHT_PROJECT" \
      --arg summary "${TESTS_SUMMARY:-Tests: no results found}" \
      --arg practitest "${PRACTITEST_URL:-}" \
      --arg jobs "Setup: $SETUP_RESULT, Integration tests: $TESTS_RESULT" \
      --arg actor "$GITHUB_ACTOR" \
      '{
        status: $status, channel: $channel,
        attachments: [{
          title: $title,
          fields: ([
            {value: $event, short: true},
            {value: $status_text, short: true},
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
    ;;
  *)
    echo "::error::Unsupported notification format: $FORMAT"
    exit 1
    ;;
esac

{
  printf 'title=%s\n' "$title"
  printf 'json=%s\n' "$payload"
} >> "$GITHUB_OUTPUT"

if [[ "${VERBOSE:-false}" == true ]]; then
  printf 'Notification status: %s\n' "$status"
fi
