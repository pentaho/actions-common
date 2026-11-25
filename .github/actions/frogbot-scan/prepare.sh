#!/usr/bin/env bash
set -eo pipefail

: "${MAVEN_MODE:?MAVEN_MODE is required}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT is required}"

case "$MAVEN_MODE" in
  directives)
    args=()
    if [[ -n "$MAVEN_DIRECTIVES" ]]; then
      arguments_file="$(mktemp)"
      trap 'rm -f "$arguments_file"' EXIT
      python3 -c 'import shlex, sys; sys.stdout.buffer.write(b"".join(arg.encode() + b"\0" for arg in shlex.split(sys.argv[1])))' \
        "$MAVEN_DIRECTIVES" > "$arguments_file"
      while IFS= read -r -d '' argument; do
        args+=("$argument")
      done < "$arguments_file"
    fi
    modules=""
    reactor_file=""
    for ((i = 0; i < ${#args[@]}; i++)); do
      case "${args[i]}" in
        -pl|--projects) value="${args[i + 1]:-}"; i=$((i + 1)) ;;
        --projects=*) value="${args[i]#--projects=}" ;;
        # Project selections resolve against the selected reactor, so keep its POM (last one wins, as in Maven).
        -f|--file) reactor_file="${args[i + 1]:-}"; i=$((i + 1)); continue ;;
        --file=*) reactor_file="${args[i]#--file=}"; continue ;;
        -ff|-fae|-fn) continue ;;
        -f?*) reactor_file="${args[i]#-f}"; continue ;;
        *) continue ;;
      esac
      [[ -n "$value" ]] && modules+="${modules:+,}$value"
    done
    # Maven splits MAVEN_ARGS on blanks without honoring quotes, so such values cannot be forwarded safely.
    if [[ "$reactor_file$modules" =~ [[:blank:]] ]]; then
      echo "::warning::FrogBot Maven selections contain spaces or tabs and cannot be forwarded; FrogBot will scan without a module filter."
      reactor_file=""
      modules=""
    fi
    project_list_option="${reactor_file:+-f $reactor_file}"
    if [[ -n "$modules" ]]; then
      project_list_option+="${project_list_option:+ }-pl $modules"
    fi
    ;;
  validate)
    declare -a valid_modules=()
    IFS=',' read -ra modules_array <<< "$MAVEN_MODULES"

    for module in "${modules_array[@]}"; do
      module="${module// /}"
      [[ -z "$module" ]] && continue

      if ! response_code=$(curl -sS -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $JF_GIT_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${REPOSITORY}/contents/${module}?ref=${BASE_REF}"); then
        echo "::warning::Unable to validate Maven modules; FrogBot will run without a module filter."
        exit 1
      fi

      module_exists=false
      [[ "$response_code" == "200" ]] && module_exists=true
      echo "INFO: Module '${module}' existence in ${REPOSITORY}@${BASE_REF}: ${module_exists} (HTTP ${response_code})"
      [[ "$module_exists" == "true" ]] && valid_modules+=("$module")
    done

    project_list_option=""
    echo "INFO: Frogbot inclusions: ${MAVEN_MODULES}"
    echo "INFO: Valid modules for Frogbot scan: ${valid_modules[*]}"
    if [[ ${#valid_modules[@]} -eq ${#modules_array[@]} ]] && [[ ${#modules_array[@]} -gt 0 ]]; then
      joined=$(IFS=','; echo "${valid_modules[*]}")
      project_list_option="-pl ${joined}"
    else
      echo "WARN: Not all specified modules are valid in the target branch. Skipping module filtering for Frogbot scan."
    fi
    ;;
  *)
    echo "::error::Unsupported FrogBot Maven selection mode: $MAVEN_MODE" >&2
    exit 1
    ;;
esac

if [[ "$project_list_option" == *$'\n'* || "$project_list_option" == *$'\r'* ]]; then
  echo "::error::FrogBot Maven project selections must not contain line breaks" >&2
  exit 1
fi

printf 'maven_args=%s\n' "$project_list_option" >> "$GITHUB_OUTPUT"
