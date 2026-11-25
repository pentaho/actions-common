#!/usr/bin/env bash
# Shared analyzer for Playwright failure lists.
#
# Required environment variables:
# - ANALYSIS_INPUT_PATH: CSV path injected into instruction template.
# - ANALYSIS_LABEL: section label used in prompt (e.g., Flaky, Unexpected).
# - ANALYSIS_MODEL: Copilot model id.
# - ANALYSIS_EFFORT: Copilot reasoning effort.
# - ANALYSIS_OUTPUT_PATH: markdown file path used to persist analysis content.
# - COPILOT_GITHUB_TOKEN: auth token for copilot CLI; the only credential passed to it.
#
# Behavior:
# - Copies ANALYSIS_INPUT_PATH and the artifacts it references into an empty sandbox
#   (stage-analysis-input.cjs); the CLI runs there, never in the job workspace.
# - Renders instruction.md (resolved relative to this file's own directory).
# - Runs copilot CLI under `env -i` with only PATH, a throwaway HOME/COPILOT_HOME, proxy
#   settings and COPILOT_GITHUB_TOKEN, so job credentials and Docker variables are not inherited.
# - Exposes only the read-only view/glob/grep tools; shell, write, URL and memory are denied.
# - Writes non-empty analysis output to ANALYSIS_OUTPUT_PATH.

set -euo pipefail

: "${ANALYSIS_INPUT_PATH:?ANALYSIS_INPUT_PATH is required}"
: "${ANALYSIS_OUTPUT_PATH:?ANALYSIS_OUTPUT_PATH is required}"
: "${ANALYSIS_MODEL:?ANALYSIS_MODEL is required}"
: "${ANALYSIS_EFFORT:?ANALYSIS_EFFORT is required}"
: "${COPILOT_GITHUB_TOKEN:?COPILOT_GITHUB_TOKEN is required}"

ACTION_DIR="$(cd "$(dirname "$0")" && pwd)"
PROMPT_FILE="${ACTION_DIR}/instruction.md"
NODE_BIN="$(command -v node)"
COPILOT_BIN="$(command -v copilot)"

SANDBOX="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/copilot-analysis.XXXXXX")"
trap 'rm -rf "$SANDBOX"' EXIT
mkdir -p "$SANDBOX/workspace" "$SANDBOX/home/.copilot"

"$NODE_BIN" "${ACTION_DIR}/stage-analysis-input.cjs" "$ANALYSIS_INPUT_PATH" "$SANDBOX/workspace"

FAILURE_ANALYSIS_PROMPT="$("$NODE_BIN" -e '
const fs = require("node:fs");
const template = fs.readFileSync(process.argv[1], "utf8");
const rendered = template
  .split("{{INPUT_PATH}}").join(process.env.ANALYSIS_INPUT_PATH ?? "")
  .split("{{ANALYSIS_LABEL}}").join(process.env.ANALYSIS_LABEL ?? "");

process.stdout.write(rendered);
' "$PROMPT_FILE")"

# Only network settings needed to reach the Copilot API are forwarded from the job environment.
isolated_env=(
  "PATH=$(dirname "$NODE_BIN"):$(dirname "$COPILOT_BIN"):/usr/bin:/bin"
  "HOME=$SANDBOX/home"
  "COPILOT_HOME=$SANDBOX/home/.copilot"
  "LANG=C.UTF-8"
  "COPILOT_GITHUB_TOKEN=$COPILOT_GITHUB_TOKEN"
)
for name in HTTPS_PROXY https_proxy HTTP_PROXY http_proxy NO_PROXY no_proxy NODE_EXTRA_CA_CERTS SSL_CERT_FILE; do
  if value="$(printenv "$name")" && [ -n "$value" ]; then
    isolated_env+=("$name=$value")
  fi
done

FAILURE_ANALYSIS_JSONL="$(cd "$SANDBOX/workspace" && env -i "${isolated_env[@]}" "$COPILOT_BIN" \
  --model "${ANALYSIS_MODEL}" \
  --effort "${ANALYSIS_EFFORT}" \
  -p "$FAILURE_ANALYSIS_PROMPT" \
  --output-format json \
  --stream off \
  --silent \
  --available-tools='view,glob,grep' \
  --allow-tool='read' \
  --deny-tool='shell,write,url,memory' \
  --disable-builtin-mcps \
  --no-custom-instructions \
  --disallow-temp-dir \
  --no-auto-update \
  --no-ask-user)"

# Extract only assistant final content from JSONL events.
FAILURE_ANALYSIS_CONTENT="$(printf '%s\n' "$FAILURE_ANALYSIS_JSONL" | "$NODE_BIN" -e '
const fs = require("node:fs");
const lines = fs.readFileSync(0, "utf8").split(/\r?\n/).filter(Boolean);
let content = "";

for (const line of lines) {
  let entry;
  try {
    entry = JSON.parse(line);
  } catch {
    continue;
  }

  if (entry?.type === "assistant.message" && typeof entry?.data?.content === "string") {
    content = entry.data.content;
    continue;
  }

  if (typeof entry?.content === "string" && Array.isArray(entry?.toolRequests)) {
    content = entry.content;
  }
}

process.stdout.write(content);
')"

if [ -n "$FAILURE_ANALYSIS_CONTENT" ]; then
  printf '%s\n' "$FAILURE_ANALYSIS_CONTENT" > "$ANALYSIS_OUTPUT_PATH"
fi
