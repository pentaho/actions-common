echo "Running PDI plugin integration tests"

# $1 = the path to the json scenario file
# $2 = comma-separated string listing changed modules

# make sure the test scenario input is valid json
if ! jq -e . >/dev/null 2>&1 <<< cat "$1"; then
  echo "Failed to successfully parse the plugin test scenarios JSON."
  echo "Exiting."
  exit 1
fi

# get the list of plugin code modules that have opted in to plugin integration testing
readarray -t eligible_modules <<< "$(jq -r keys[] "$1")"

for eligible_module in "${eligible_modules[@]}"; do

  case "$2" in
    *$eligible_module* )
      echo -e "\nPlugin module ${eligible_module} has changed; running integration tests for it"

      # ["'" "'"] is required because eligible_module names could contain hyphens
      has_non_default_plugin_test_scenarios="$(jq '.["'"$eligible_module"'"] | has("scenarios")' "$1")"

      # Notes about some of these properties:
      # -Drelease and -Dpentaho-ee-dsc.version are needed for building the obfuscated jar
      # -Dmaven.test.redirectTestOutputToFile=false ensures test output is displayed in the github action web UI
      # -Duse-existing-docker-network attaches all test containers to the same docker custom network that the github actions runner container uses
      base_cmd=(mvn verify -Dpdi-plugin-test -Drelease -Dpentaho-ee-dsc.version="${BASE_VERSION}" \
        -Dmaven.test.redirectTestOutputToFile=false -B -amd -pl "$eligible_module" \
        -Duse-existing-docker-network=$(docker network ls --filter name=github_network* -q))

      if [ "$has_non_default_plugin_test_scenarios" = false ]; then
        echo -e "\nRunning default test command: ${base_cmd[0]}"
        "${base_cmd[@]}"
      else
        number_of_scenarios="$(jq '.["'"$eligible_module"'"].scenarios | length' "$1")"
        echo "Plugin ${eligible_module} has ${number_of_scenarios} unique test scenarios"

        for ((i = 0; i < number_of_scenarios; i++)); do
          unset cmd
          cmd=("${base_cmd[@]}")
          number_of_params_in_scenario="$(jq '.["'"$eligible_module"'"].scenarios['"${i}"'] | length' "$1")"
          for ((j = 0; j < number_of_params_in_scenario; j++)); do
            cmd+=("$(jq -r '.["'"$eligible_module"'"].scenarios['"${i}"']['"${j}"']' "$1")")
            cmd+=(-Dsurefire.reportNameSuffix=scenario"${i}")
          done
          echo -e "\nRunning test command:" "${cmd[@]}"
          "${cmd[@]}"
        done
      fi
      ;;
  esac
done
