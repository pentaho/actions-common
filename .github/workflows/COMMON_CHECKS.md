# GitHub Actions Reusable Workflows

> **See also:** [AUXILIAR.md](AUXILIAR.md) for documentation on auxiliary workflows: `check.yml`, `update-version.yml`, `publish-npm.yml`, and `bootstrap-image.yml`.

---

## What Are Reusable Workflows?

[Reusable workflows](https://docs.github.com/en/actions/sharing-automations/reusing-workflows) are GitHub Actions workflows that can be called from other workflows, much like a function call in programming. Instead of duplicating the same CI/CD logic across multiple repositories, a reusable workflow is defined once (using `on: workflow_call`) and referenced by any number of caller workflows via `uses:`.

Key characteristics:
- **Defined with `on: workflow_call`** — marks the workflow as callable by others.
- **Accept `inputs` and `secrets`** — callers can pass parameters to customize behavior.
- **Can produce `outputs`** — results can be consumed by downstream jobs in the caller workflow.
- **Called with `uses:`** — referenced as `{owner}/{repo}/.github/workflows/{file}.yml@{ref}`.
- **`secrets: inherit`** — allows the caller to forward all its secrets to the reusable workflow automatically.

📖 For full details, see the [official GitHub documentation on reusing workflows](https://docs.github.com/en/actions/sharing-automations/reusing-workflows).

---

## 1. `pr.yml` — Pull Request Workflow

Runs on every pull request. Performs code quality checks, builds, tests, security scans, and sends notifications.

### Jobs

| Job                     | Condition                      | Purpose                                              |
|-------------------------|--------------------------------|------------------------------------------------------|
| `check-commit-messages` | `check_commit_messages == true` | Validates commits follow Conventional Commits spec  |
| `common-job`            | always                         | Build, test, Sonar scan, Frogbot security scan       |

### Required Project Files

#### `sonar-project.properties` (root of the repository)

For the **SonarQube scan** step to execute correctly, a `sonar-project.properties` file must exist at the root of the calling repository. This file is the standard SonarQube configuration descriptor — it tells the `sonar-scanner` CLI how to analyse the project: which sources and tests to include, which languages to scan, encoding settings, and any additional analysis parameters. Without it, the scanner will either fail to start or produce an incomplete analysis.

Minimal example:
```properties
sonar.projectName=my-project
sonar.sources=src/main
sonar.tests=src/test
sonar.java.binaries=**/target/classes
sonar.java.test.binaries=**/target/test-classes
```

📖 See the [SonarQube documentation](https://docs.sonarsource.com/sonarqube/latest/project-administration/analysis-parameters/) for the full list of supported parameters.

### Inputs

| Input                          | Type    | Required | Default                        | Description & Usage                                                                                                                                                               |
|-------------------------------|---------|----------|--------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `slack_channels`               | string  | No       | —                              | Passed as `Slack_Channel` env var to the **Report notifications** step to determine where build result messages are sent.                                                         |
| `sonar_project_key`            | string  | No       | repo name                      | Used in the **SonarQube scan** step as `-Dsonar.projectKey`. Defaults to the repository name if not provided.                                                                     |
| `additional_mvn_directives`    | string  | No       | `""`                           | Appended verbatim to the `mvn clean verify` command in the **Build & Run tests** step. Also inspected for `-DrunITs` to decide whether to include integration tests in reporting. |
| `ms_teams_webhook_secret_name` | string  | No       | `""`                           | Used as a dynamic secret key (`secrets[inputs.ms_teams_webhook_secret_name]`) in the **Report notifications** step to resolve the MS Teams webhook URL at runtime.                |
| `container_image`              | string  | No       | `vars.PDIA_AC_CONTAINER_IMAGE` | Sets the Docker image used for the job container. Falls back to the org-level variable if not specified.                                                                          |
| `resolve_repo`                 | string  | No       | `pnt-mvn`                      | Interpolated into `RESOLVE_REPO_MIRROR` env var (`{artifactory_base_url}/{resolve_repo}`), which Maven uses as its mirror for dependency resolution via `settings.xml`.           |
| `check_commit_messages`        | boolean | No       | `false`                        | Gates the `check-commit-messages` job. When `true`, triggers `check.yml` to validate every commit message on the PR against the Conventional Commits regex.                       |
| `modules_to_build`             | string  | No       | auto-detected                  | Passed as `-pl` to the `mvn` command. When empty, the `change-detection-builder` action determines which modules changed. Also used to scope the Frogbot security scan.           |

### Usage Example

```yaml
# .github/workflows/pr.yml (in your project repo)
name: Pull Request
on:
  pull_request:
    branches: [main, master]

jobs:
  pr:
    uses: pentaho/actions-common/.github/workflows/pr.yml@stable
    secrets: inherit
    with:
      slack_channels: "#my-team-alerts"
      sonar_project_key: "my-project"
      check_commit_messages: true
      additional_mvn_directives: "-DrunITs"
      modules_to_build: "module-a,module-b"
```

---

## 2. `merge.yml` — Merge Workflow

Runs after a PR is merged. Has two independent jobs: a **Snapshot** build (deploys `-SNAPSHOT` artifacts) and optionally a **Release Candidate** build (versioned, tagged, and promoted to Artifactory).

### Jobs

| Job                 | Condition                          | Purpose                                                              |
|---------------------|------------------------------------|----------------------------------------------------------------------|
| `snapshot`          | `run_snapshot == true` (default)   | Build & deploy SNAPSHOT artifacts, Sonar scan                        |
| `release-candidate` | `run_release_candidate == true`    | Version bump, build, deploy RC artifacts, tag Git release            |

### Required Project Files

#### `sonar-project.properties` (root of the repository)

For the **SonarQube scan** step to execute correctly, a `sonar-project.properties` file must exist at the root of the calling repository. This file is the standard SonarQube configuration descriptor used by the `sonar-scanner` CLI to determine how to analyse the project: which sources and tests to include, which languages to scan, encoding settings, and any additional analysis parameters. Without it, the scanner will either fail to start or produce an incomplete analysis.

Minimal example:
```properties
sonar.projectName=my-project
sonar.sources=src/main
sonar.tests=src/test
sonar.java.binaries=**/target/classes
sonar.java.test.binaries=**/target/test-classes
```

📖 See the [SonarQube documentation](https://docs.sonarsource.com/sonarqube/latest/project-administration/analysis-parameters/) for the full list of supported parameters.

#### `.github/release-versions.properties`

For the **Version set** step in the `release-candidate` job to work correctly (when `run_versioning: true`), a `release-versions.properties` file must exist inside the `.github` folder of the calling repository. This file acts as a version manifest: it holds placeholder tokens (such as `BASE_VERSION` and `BUILD_NBR`) that the workflow replaces at build time using `sed` substitutions and then feeds into `version-merger.jar`. The merger propagates the resolved values across all `pom.xml` files and other version-tracked resources in the project.

Example:
```properties
coding-standards.version=BASE_VERSION
some-dependency.version=BASE_VERSION-BUILD_NBR
```

At runtime, `BASE_VERSION` is replaced with the effective base dependency version and `BUILD_NBR` with the GitHub run number. Additional custom tokens can be injected via the `replacements` input.

### Inputs

| Input                                  | Type    | Required | Default                        | Description & Usage                                                                                                                                                                                    |
|---------------------------------------|---------|----------|--------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `base_version`                         | string  | **Yes**  | —                              | Stored as `BASE_VERSION` env var. Used in the **Version set** step to replace the `BASE_VERSION` placeholder in `release-versions.properties`, ensuring dependencies resolve against a known baseline. |
| `modules_to_build`                     | string  | No       | auto-detected                  | Passed as `-pl` to all `mvn` commands in both jobs. When empty, `change-detection-builder` determines changed modules automatically.                                                                   |
| `version`                              | string  | No       | from `pom.xml`                 | Stored as `VERSION` env var. If provided, overrides the version read from `mvn help:evaluate`. Used as the base for computing the final RC version string.                                             |
| `base_build_name`                      | string  | No       | `pdia-master`                  | Passed to the **Get latest base version** action when `base_version` is empty, to look up the most recent version of the baseline build in Artifactory.                                                |
| `slack_channels`                       | string  | No       | —                              | Passed as `Slack_Channel` to the **Report notifications** step in both jobs.                                                                                                                           |
| `sonar_project_key`                    | string  | No       | repo name                      | Used as `-Dsonar.projectKey` in the **SonarQube scan** steps of both jobs. Defaults to the repository name.                                                                                            |
| `additional_snapshot_mvn_directives`   | string  | No       | `""`                           | Appended to the `mvn clean deploy` command in the **snapshot** job. Also checked for `-DrunITs` to include integration test reporting.                                                                 |
| `additional_mvn_directives`            | string  | No       | `""`                           | Appended to the `mvn clean deploy` command in the **release-candidate** job. Also checked for `-DrunITs` to enable integration test reporting.                                                         |
| `run_snapshot`                         | boolean | No       | `true`                         | Controls whether the `snapshot` job runs at all via its `if:` condition. Also gates the SonarQube scan in the RC job (runs only when snapshot is skipped).                                             |
| `run_release_candidate`                | boolean | No       | `false`                        | Controls whether the `release-candidate` job runs at all via its `if:` condition.                                                                                                                      |
| `run_versioning`                       | boolean | No       | `true`                         | Gates the **Version set** step. When `true`, runs `version-merger.jar` to update all version properties and POM files before the build.                                                                |
| `add_github_run_number`                | boolean | No       | `true`                         | When `true` and `run_versioning` is enabled, appends `${{ github.run_number }}` to the version string (e.g. `1.0.0` → `1.0.0-42`).                                                                   |
| `use_semver_release_candidate`         | boolean | No       | `false`                        | When `true`, fetches existing tags and auto-increments an `-rc.N` suffix (e.g. `1.0.0-rc.1`, `1.0.0-rc.2`) instead of using the run number.                                                           |
| `container_image`                      | string  | No       | `vars.PDIA_AC_CONTAINER_IMAGE` | Sets the Docker image for both job containers. Falls back to the org-level variable if not specified.                                                                                                   |
| `resolve_repo`                         | string  | No       | `pnt-mvn`                      | Interpolated into `RESOLVE_REPO_MIRROR` env var, which Maven uses as its dependency resolution mirror via `settings.xml`.                                                                              |
| `ms_teams_webhook_secret_name`         | string  | No       | `""`                           | Resolved dynamically as `secrets[inputs.ms_teams_webhook_secret_name]` in the **Report notifications** step of both jobs.                                                                              |
| `replacements`                         | string  | No       | `""`                           | Newline-separated `KEY=VALUE` pairs parsed in the **Version set** step and applied as `sed` substitutions on `release-versions.properties` before running `version-merger.jar`.                       |
| `blackduck_project_key`                | string  | No       | `Pentaho`                      | Reserved for BlackDuck scan integration (declared but not yet wired into a step in the current workflow version).                                                                                       |
| `blackduck_server_url`                 | string  | No       | Orion URL                      | Reserved for BlackDuck scan integration (declared but not yet wired into a step in the current workflow version).                                                                                       |
| `blackduck_additional_args`            | string  | No       | `""`                           | Reserved for BlackDuck scan integration (declared but not yet wired into a step in the current workflow version).                                                                                       |

### Outputs

| Output            | Description                              |
|-------------------|------------------------------------------|
| `current-version` | The version built by the RC job          |

### Usage Examples

**Snapshot only (typical merge to main):**

```yaml
# .github/workflows/merge.yml (in your project repo)
name: Merge
on:
  push:
    branches: [main]

jobs:
  merge:
    uses: pentaho/actions-common/.github/workflows/merge.yml@stable
    secrets: inherit
    with:
      base_version: "[11.1.0.0-1,11.1.0.0-999]" #Maven version ranges are accepted, so this looks up the latest
      slack_channels: "#my-team-alerts"
```

**Snapshot + Release Candidate with semver:**

```yaml
jobs:
  merge:
    uses: pentaho/actions-common/.github/workflows/merge.yml@stable
    secrets: inherit
    with:
      base_version: "10.2.0.0"
      run_snapshot: true
      run_release_candidate: true
      use_semver_release_candidate: true
      slack_channels: "#releases"
      replacements: |
        PLATFORM_VERSION=10.2.0.0
        HADOOP_VERSION=3.3.1
```

**Consuming the output version:**

```yaml
jobs:
  merge:
    uses: pentaho/actions-common/.github/workflows/merge.yml@stable
    secrets: inherit
    with:
      base_version: "10.2.0.0"
      run_release_candidate: true

  downstream:
    needs: merge
    runs-on: ubuntu-latest
    steps:
      - run: echo "Built version ${{ needs.merge.outputs.current-version }}"
```

---

## 3. `release.yml` — Release / Promotion Workflow

Promotes a previously built RC artifact from the dev Artifactory repository to the release repository (`pntpub-maven-release` for public repos, `pntprv-maven-release` for private repos). Optionally bumps the `pom.xml` version afterwards.

### Jobs

| Job               | Condition                  | Purpose                                          |
|-------------------|----------------------------|--------------------------------------------------|
| `pentaho-release` | always                     | Promote artifacts in Artifactory via JFrog CLI   |
| `update-version`  | `update_version == true`   | Bump `pom.xml` version post-release              |

### Inputs

| Input              | Type    | Required | Default                        | Description & Usage                                                                                                                                                                          |
|-------------------|---------|----------|--------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `release_version`  | string  | **Yes**  | —                              | Stored as `BUILD_NUMBER` env var. Passed directly to `jf rt build-promote` to identify which Artifactory build to promote. Must match an existing artifact version (e.g. `10.0.0.0-245`).  |
| `dry_run`          | boolean | No       | `true`                         | Forwarded as `--dry-run=${{ inputs.dry_run }}` to the `jf rt build-promote` command. When `true`, the promotion is simulated with no actual repository changes. Also passed to `update-version.yml` if triggered. |
| `container_image`  | string  | No       | `vars.PDIA_AC_CONTAINER_IMAGE` | Sets the Docker image for the job container. Falls back to the org-level variable if not specified.                                                                                          |
| `update_version`   | boolean | No       | `false`                        | Gates the `update-version` job via its `if:` condition. When `true`, calls `update-version.yml` after a successful promotion to bump the patch version in `pom.xml` and `package.json`.     |

### Usage Examples

**Dry-run promotion (preview):**

```yaml
# .github/workflows/release.yml (in your project repo)
name: Release
on:
  workflow_dispatch:
    inputs:
      release_version:
        description: "Version to release"
        required: true

jobs:
  release:
    uses: pentaho/actions-common/.github/workflows/release.yml@stable
    secrets: inherit
    with:
      release_version: ${{ inputs.release_version }}
      dry_run: true
```

**Real promotion + version bump:**

```yaml
jobs:
  release:
    uses: pentaho/actions-common/.github/workflows/release.yml@stable
    secrets: inherit
    with:
      release_version: "10.2.0.0-245"
      dry_run: false
      update_version: true
```

