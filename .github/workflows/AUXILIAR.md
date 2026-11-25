---
type: reference
title: Auxiliary GitHub Actions Workflows
description: Contracts and usage of the reusable Pentaho supporting workflows and their shared actions.
---

# Auxiliar GitHub Actions Workflows

> **See also:** [COMMON_CHECKS.md](COMMON_CHECKS.md) for the main CI workflows: `pr.yml`, `merge.yml`, and `release.yml`.

---

## 1. `check.yml` — Commit Message Checker

Validates that all commit messages on a pull request follow the [Conventional Commits](https://www.conventionalcommits.org/) specification. Called internally by `pr.yml` when `check_commit_messages` is enabled, but can also be used standalone.

### Jobs

| Job                     | Condition | Purpose                                               |
|-------------------------|-----------|-------------------------------------------------------|
| `check-commit-message`  | always    | Checks each commit message against a regex pattern    |

### Accepted Commit Types

`feat`, `fix`, `perf`, `revert`, `docs`, `style`, `chore`, `refactor`, `test`, `build`, `ci`, `improvement`

**Format:** `<type>(<optional-scope>): <description>`
**Example:** `feat(auth): add OAuth2 support`

### Inputs

This workflow takes no inputs. It inherits `secrets` from the caller.

### Usage Example

```yaml
# .github/workflows/pr.yml (in your project repo)
name: Pull Request
on:
  pull_request:
    branches: [main]

jobs:
  check-commits:
    uses: pentaho/actions-common/.github/workflows/check.yml@stable
    secrets: inherit
    permissions:
      statuses: write
      checks: write
      contents: write
      pull-requests: write
      actions: write
```

---

## 2. `update-version.yml` — Version Bump Workflow

Automatically increments the patch segment of the project version (e.g. `1.2.3-SNAPSHOT` → `1.2.4-SNAPSHOT`) in both Maven (`pom.xml`) and NPM (`package.json`) files, then commits and pushes the change. Typically called as a follow-up job after `release.yml`.

### Jobs

| Job            | Condition | Purpose                                                              |
|----------------|-----------|----------------------------------------------------------------------|
| `bump-version` | always    | Reads current version, increments patch, updates files, and commits  |

### Inputs

| Input             | Type    | Required | Default                        | Description                              |
|------------------|---------|----------|--------------------------------|------------------------------------------|
| `container_image` | string  | No       | `vars.PDIA_AC_CONTAINER_IMAGE` | Docker image override                    |
| `dry_run`         | boolean | No       | `true`                         | Preview-only; no git commit/push occurs  |

### Behavior

- Reads the version from `mvn help:evaluate`.
- Strips `-SNAPSHOT`, increments the last numeric segment, re-appends `-SNAPSHOT` if it was present.
- Updates all `pom.xml` files via `mvn versions:set`.
- If NPM is detected, runs `npm run version:set` and `npm run version:print`.
- Commits all changed `pom.xml`, `package.json`, `package-lock.json`, and `lerna.json` files.

### Usage Examples

**Standalone dry-run (preview):**

```yaml
# .github/workflows/update-version.yml (in your project repo)
name: Bump Version
on:
  workflow_dispatch:

jobs:
  bump:
    uses: pentaho/actions-common/.github/workflows/update-version.yml@stable
    secrets: inherit
    with:
      dry_run: true
```

**After a release (real commit):**

```yaml
jobs:
  bump:
    uses: pentaho/actions-common/.github/workflows/update-version.yml@stable
    secrets: inherit
    with:
      dry_run: false
```

> **Note:** `release.yml` calls this workflow automatically when `update_version: true` is set.

---

## 3. `publish-npm.yml` — Publish NPM Modules Workflow *(Legacy)*

> **⚠️ Legacy workflow, kept for backward compatibility only.** New and existing NPM projects should migrate to [`pr-npm.yml`](#4-pr-npmyml--npm-pull-request-workflow), [`merge-npm.yml`](#5-merge-npmyml--npm-merge-workflow), and [`release-npm.yml`](#6-release-npmyml--npm-release-workflow) instead. `publish-npm.yml` is not actively developed further and may be removed in a future major version.

Builds and publishes NPM packages to Artifactory. Supports both dev and release registries, and can be run as a dry-run to validate without publishing.

### Jobs

| Job                   | Condition | Purpose                                          |
|-----------------------|-----------|--------------------------------------------------|
| `publish-npm-modules` | always    | Install dependencies, build, and publish to NPM  |

### Inputs

| Input             | Type    | Required | Default                        | Description                                                                              |
|------------------|---------|----------|--------------------------------|------------------------------------------------------------------------------------------|
| `container_image` | string  | No       | `vars.PDIA_AC_CONTAINER_IMAGE` | Docker image override                                                                    |
| `release_version` | string  | No       | `""`                           | Version to set for the NPM modules; if empty, uses the version defined in `package.json` |
| `dry_run`         | boolean | No       | `true`                         | Skip the actual `npm publish` step                                                       |
| `release`         | boolean | No       | `false`                        | Publish to release registry (`pntprv-npm-release`) instead of dev (`pntprv-npm-dev`)    |

### Registry Resolution

| `release` value | Target Registry          |
|-----------------|--------------------------|
| `false`         | `pntprv-npm-dev`         |
| `true`          | `pntprv-npm-release`     |

### Usage Examples

**Dry-run dev publish (preview):**

```yaml
# .github/workflows/publish-npm.yml (in your project repo)
name: Publish NPM
on:
  workflow_dispatch:

jobs:
  publish:
    uses: pentaho/actions-common/.github/workflows/publish-npm.yml@stable
    secrets: inherit
    with:
      dry_run: true
```

**Real release publish with explicit version:**

```yaml
jobs:
  publish:
    uses: pentaho/actions-common/.github/workflows/publish-npm.yml@stable
    secrets: inherit
    with:
      release_version: "10.2.0.0"
      release: true
      dry_run: false
```

---

## 4. `pr-npm.yml` — NPM Pull Request Workflow

Runs the standard PR checks for NPM-based projects: commit message validation, build, tests, Sonar code quality scan, and Frogbot security scan.

> **Note:** the `build` and `test` npm scripts are **required** in the consumer's `package.json` (not run with `--if-present`). If either script is missing, the job fails — a project without a real build/test step would defeat the purpose of this workflow.

### Jobs

| Job                      | Condition | Purpose                                                              |
|--------------------------|-----------|-----------------------------------------------------------------------|
| `check-commit-messages`  | always    | Validates commit messages via `check.yml`                            |
| `pr`                     | always    | Install dependencies, build, test, Sonar scan, Frogbot scan, notify  |

### Inputs

| Input                          | Type   | Required | Default                        | Description                               |
|--------------------------------|--------|----------|---------------------------------|--------------------------------------------|
| `container_image`               | string | No       | `vars.PDIA_AC_CONTAINER_IMAGE` | Docker image override                     |
| `slack_channels`                | string | No       |                                 | Slack channel(s) to send notifications to |
| `sonar_project_key`             | string | No       | repo name                      | Sonar's project identifier key            |
| `ms_teams_webhook_secret_name`  | string | No       | `""`                            | The MS Teams webhook secret name          |

### Usage Example

```yaml
# .github/workflows/pr.yml (in your project repo)
name: Pull Request
on:
  pull_request:
    branches: [main]

jobs:
  pr:
    uses: pentaho/actions-common/.github/workflows/pr-npm.yml@stable
    secrets: inherit
    with:
      slack_channels: "#my-channel"
```

---

## 5. `merge-npm.yml` — NPM Merge Workflow

Runs on merge for NPM-based projects: builds, runs a Sonarqube scan, and publishes packages to the dev Artifactory registry (`pntprv-npm-dev`).

> **Note:** the `build` and `artifactory-publish` npm scripts are **required** in the consumer's `package.json` (not run with `--if-present`). If either script is missing, the job fails — a project without a real build/publish step would defeat the purpose of this workflow. The publish script is intentionally **not** named `publish`: that name collides with npm's reserved `publish` lifecycle hook, so a consumer script like `"publish": "npm publish"` would re-trigger itself and loop indefinitely when invoked.

### Jobs

| Job     | Condition | Purpose                                                                    |
|---------|-----------|------------------------------------------------------------------------------|
| `merge` | always    | Install dependencies, build, Sonarqube scan, publish to dev registry, notify |

### Inputs

| Input                          | Type   | Required | Default                        | Description                                |
|--------------------------------|--------|----------|---------------------------------|---------------------------------------------|
| `container_image`               | string | No       | `vars.PDIA_AC_CONTAINER_IMAGE` | Docker image override                      |
| `slack_channels`                | string | No       |                                 | Slack channel(s) to send notifications to  |
| `sonar_project_key`             | string | No       | repo name                      | Sonar's project identifier key             |
| `ms_teams_webhook_secret_name`  | string | No       | `""`                            | The MS Teams webhook secret name           |

### Usage Example

```yaml
# .github/workflows/merge.yml (in your project repo)
name: Merge
on:
  push:
    branches: [main]

jobs:
  merge:
    uses: pentaho/actions-common/.github/workflows/merge-npm.yml@stable
    secrets: inherit
    with:
      slack_channels: "#my-channel"
```

---

## 6. `release-npm.yml` — NPM Release Workflow

Promotes an NPM package release by publishing to the release Artifactory registry (`pntprv-npm-release`). Supports a dry-run mode to validate without publishing.

> **Note:** the `build`, `artifactory-publish`, and `dry-run-artifactory-publish` npm scripts are **required** in the consumer's `package.json` (not run with `--if-present`). If a required script is missing, the job fails — a project without a real build/publish step would defeat the purpose of this workflow. The publish scripts are intentionally **not** named `publish`: that name collides with npm's reserved `publish` lifecycle hook, so a consumer script like `"publish": "npm publish"` would re-trigger itself and loop indefinitely when invoked.

### Jobs

| Job       | Condition | Purpose                                                          |
|-----------|-----------|---------------------------------------------------------------------|
| `release` | always    | Install dependencies, build, publish to release registry, notify  |

### Inputs

| Input                          | Type    | Required | Default                        | Description                                |
|--------------------------------|---------|----------|---------------------------------|---------------------------------------------|
| `container_image`               | string  | No       | `vars.PDIA_AC_CONTAINER_IMAGE` | Docker image override                      |
| `slack_channels`                | string  | No       |                                 | Slack channel(s) to send notifications to  |
| `ms_teams_webhook_secret_name`  | string  | No       | `""`                            | The MS Teams webhook secret name           |
| `dry_run`                       | boolean | No       | `true`                          | Runs `dry-run-artifactory-publish` instead of `artifactory-publish` |

### Usage Examples

**Dry-run (preview):**

```yaml
# .github/workflows/release.yml (in your project repo)
name: Release
on:
  workflow_dispatch:

jobs:
  release:
    uses: pentaho/actions-common/.github/workflows/release-npm.yml@stable
    secrets: inherit
    with:
      dry_run: true
```

**Real release publish:**

```yaml
jobs:
  release:
    uses: pentaho/actions-common/.github/workflows/release-npm.yml@stable
    secrets: inherit
    with:
      dry_run: false
```

---

## 7. `pdi-plugin-compatibility-test.yml` — PDI Plugin Compatibility Test

Runs compatibility automation tests for PDI plugin repos

### Jobs

| Job                   | Condition | Purpose                                          |
|-----------------------|-----------|--------------------------------------------------|
| `common-job`          | always    | Runs the automation tests                        |

### Inputs

| Input                      | Type    | Required | Default                        | Description                                                                              |
|----------------------------|---------|----------|--------------------------------|------------------------------------------------------------------------------------------|
| `plugin-directory-name`    | string  | No       | `"."`                          | The name of the subdirectory containing the plugin to test (defaults to `.`, the repo's root dir) |
| `pdi-version`              | string  | Yes      |                                | The version of PDI that you want to test the plugin against. Valid values are tag values for the pdi-client Docker image, maintained in the qa-automation repo. For example, '11.0' or '10.2'. |
| `plugin-version`           | string  | Yes      |                                | The version of the plugin that you want to test. Valid values are build numbers, such as '10.2.0.0-222' or '11.0.0.0-SNAPSHOT'. |

### Usage Examples

**Single-module repo (plugin at root):**

```yaml
# .github/workflows/compatibility-test.yml (in your project repo)
name: Compatibility Test
on:
  workflow_dispatch:

jobs:
  compatibility-test:
    uses: pentaho/actions-common/.github/workflows/pdi-plugin-compatibility-test.yml@stable
    secrets: inherit
    with:
      pdi-version: "11.1"
      plugin-version: "11.1.0.0-SNAPSHOT"
```

**Multi-module repo (plugin in a subdirectory -- like pdi-plugins-ee):**

```yaml
jobs:
  compatibility-test:
    uses: pentaho/actions-common/.github/workflows/pdi-plugin-compatibility-test.yml@stable
    secrets: inherit
    with:
      plugin-directory-name: "my-plugin-module"
      pdi-version: "10.2"
      plugin-version: "10.2.0.0-222"
```

---

## 8. `bootstrap-image.yml` — Build & Push Container Image

Builds a Docker container image (used as the CI runner image for other workflows) and pushes it to Artifactory. Triggered automatically on pushes to `master` that modify files under `.github/bootstrap-image/`, or manually via `workflow_dispatch`. Builds in a matrix for **JDK 17** and **JDK 21**.

### Trigger

| Event               | Condition                                              |
|---------------------|--------------------------------------------------------|
| `push` to `master`  | Only when `.github/bootstrap-image/**` files change   |
| `workflow_dispatch` | Manual trigger, no conditions                          |

### Jobs

| Job               | Purpose                                                             |
|-------------------|---------------------------------------------------------------------|
| `bootstrap-image` | Builds and pushes the image for each JDK version in the matrix     |

### Matrix

| Variable | Values     |
|----------|------------|
| `jdk`    | `17`, `21` |

### Image Naming

Images are tagged using the pattern:

```
<owner>/<repo>:jdk<JDK_VERSION>-<YYYYMMDD>.<run_number>
```

**Example:** `pentaho/actions-common:jdk17-20260422.5`

### Inputs

This workflow takes **no inputs**. All configuration is derived from repository variables and secrets.

### Required Variables & Secrets

| Name                     | Type    | Description                          |
|--------------------------|---------|--------------------------------------|
| `vars.ARTIFACTORY_HOST`  | var     | Artifactory hostname                 |
| `secrets.PENTAHO_CICD_ONE_USER` | secret | Artifactory username          |
| `secrets.PENTAHO_CICD_ONE_KEY`  | secret | Artifactory API key/password  |

### Usage

This workflow is **not intended to be called** with `workflow_call`. It runs automatically or via manual dispatch within the `actions-common` repository itself. No consumer configuration is needed.

To trigger a manual image rebuild:

1. Go to **Actions** → **Build and Push Container Image**
2. Click **Run workflow** on the desired branch

---

## 9. `integration-tests-npm.yml` — npm Playwright Integration Tests

Runs a project's Playwright integration tests, using npm only, against a Pentaho Server with a Postgres repository. Both run as job services. The plugins under test are mounted into the server from a shared runner volume. Gating (labels, paths, schedules) is left to the caller.

The build/artifact, service-backed tests, per-browser counts, platform version, CTRF report, Practitest upload, Slack notification and teardown follow the Scheduler workflows. Unlike Scheduler, SQL comes from the **tested Pentaho Server image**, never from the caller's `.github/postgresql` folder. Scheduler-specific POM paths, legacy ZIP assembly commands and frontend checks remain the caller's responsibility.

Both shared workflows use `workflow_call`. Add `pull_request` and `workflow_dispatch` to the **project caller**, as in the example below, so manual runs build and test the selected project branch rather than this actions repository.

### Jobs

| Job       | Condition                                              | Purpose |
|-----------|--------------------------------------------------------|---------|
| `setup`   | always                                                 | Empties the run's volume, downloads `pentaho-plugins` when `use_pr_build` is true, copies SQL from the server image, verifies plugins and generates Docker bind mounts. |
| `tests`   | `setup` succeeded                                      | Waits for healthy Postgres and Pentaho Server services, runs `npm install`, installs browsers, optionally applies custom locale overrides and runs the test script. Summarizes results, publishes the CTRF report and optional Practitest results, and uploads results/logs. |
| `notify`  | always, when `slack_channels` is set                     | Sends setup/test status, platform version, per-browser counts and optional Practitest link to Slack, including setup failures. |
| `cleanup` | always, when setup ran                                 | When `tests` failed, uploads `/volume/logs` as `<artifact_prefix>-startup-server-logs` (covers service start failures, which skip every test step), then empties the shared volume. |

### Volume Layout

The path `/home/runner/caches/pentaho/<owner>/<repo>/<run_id>` is derived by the workflow and mounted as `/volume` in the setup, test and cleanup containers. There is no caller-supplied path or separate path-validation step.

| Folder                         | Content |
|--------------------------------|---------|
| `pentaho-solutions/system/<p>` | Plugins downloaded from `pentaho-plugins`, mounted at `/home/devuser/pentaho/pentaho-server/pentaho-solutions/system/<p>`. `use_pr_build: false` uses the image's bundled plugins. |
| `postgres/`                    | Pentaho repository SQL scripts, mounted read-only as the Postgres init scripts (copied from the server image, see below) |
| `logs/`                        | Tomcat logs (mounted into the server) and the `pba` / `postgres` service console logs |

Jobs require `/home/runner/caches` storage shared across the selected `[k8s, orl-lab]` runners. The derived host path expression is repeated in container and service volume declarations because GitHub Actions does not make the `env` context available there; `VOLUME_PATH` is used where `env` is supported, including the fixture action input. Bind mounts are passed through service `options`, as in Scheduler, rather than an expression-generated `volumes` array. Every staged plugin folder must have a nonempty `plugin.xml`.

The path is stable across run attempts. Cleanup always empties it after the services stop; use **Re-run all jobs** to recreate the fixtures and download the build artifact, not **Re-run failed jobs**. Run matrix invocations sequentially (`max-parallel: 1`), since one workflow run shares a volume; use a distinct `artifact_prefix` per matrix combination. Also give each combination a distinct `ctrf_artifact_name` that stays the same across runs (for example, `ctrf-scheduler-sample-chrome`); unlike `artifact_prefix`, it must not contain run IDs or attempt numbers.

### Postgres Init Scripts

The `setup` job reads the scripts from the Pentaho Server image, so the repository schema always matches the server under test:

- The folder is `/home/devuser/pentaho/pentaho-server/data/postgresql`. The workflow uses the standard Pentaho Server layout; custom paths remain available only to direct users of the fixture action.
- Only the fresh-install scripts are staged: the required `create_jcr_postgresql.sql`, `create_quartz_postgresql.sql` and `create_repository_postgresql.sql`, plus `pentaho_logging_postgresql.sql` and `pentaho_mart_postgresql.sql` when present. Upgrade, migrate and drop scripts (`alter_script_*`, `migrate_*`, `pentaho_mart_drop_*`) are skipped because they need existing objects and would fail the Postgres init.
- The job fails if the folder is missing or lacks any of the required `create_*` scripts.
- The `setup` job container needs the Docker CLI and daemon socket. When both `PENTAHO_CICD_ONE_USER` and `PENTAHO_CICD_ONE_KEY` are set, it logs in only if the image reference specifies a registry host followed by `/` (for example, `registry.example.com/image` or `localhost:5000/image`). Unqualified images such as `pentaho-server:11` are pulled without a login. The job resolves the pulled image's immutable `repository@sha256:...` registry digest for the requested repository (Docker Hub `docker.io/`, `index.docker.io/` and `library/` aliases are treated as equal; digests recorded for other repositories or mirrors are ignored), or keeps an explicitly supplied `@sha256:` reference unchanged, and copies the folder out of a created (never started) container using that digest. The fixture action's `server_image` output passes the same digest to the test service. Setup fails if no registry digest can be resolved.

### Environment Passed to the Tests

| Variable             | Value |
|----------------------|-------|
| `BASE_URL`           | `<server_url>/<server_context>/` |
| `WEBAPP_NAME`        | `<server_context>` |
| `PLAYWRIGHT_PROJECT` | `<playwright_project>` |
| `CI`                 | `true` |

### Inputs

| Input                          | Type    | Required | Default | Description |
|--------------------------------|---------|----------|---------|-------------|
| `use_pr_build`                 | boolean | No       | `false` | Download this run's fixed `pentaho-plugins` artifact; otherwise test bundled plugins |
| `required_plugins`             | string  | No       | `""`    | Comma-, space-, tab-, or newline-separated plugin folders that must contain a nonempty `plugin.xml` |
| `server_image`                 | string  | No       | `<ARTIFACTORY_HOST>/docker/pentaho-app-shell/<server_build_name>/<server_context>` | Pentaho Server image; also the source of the Postgres init scripts |
| `server_build_name`            | string  | No       | `pdia-master` | Pentaho Server image build name |
| `server_context`               | string  | No       | `pentaho` | Pentaho Server image context / web application name; Analyzer/Scheduler explicitly use `sample` |
| `server_url`                   | string  | No       | `http://pba:8080` | Test server URL without the application context; service health checks still use the provisioned container |
| `working_directory`            | string  | No       | `.`     | Folder with the `package.json` that runs the tests |
| `test_script`                  | string  | No       | `test`  | npm script that runs the tests |
| `test_args`                    | string  | No       | `""`    | Whitespace- or newline-separated arguments appended after `--` (no shell expansion or embedded quoting) |
| `playwright_project`           | string  | No       | `all` | Exported as `PLAYWRIGHT_PROJECT`; caller's npm script/config must honor it, as Scheduler does |
| `playwright_browsers`          | string  | No       | `chromium firefox webkit chrome msedge` | Bundled Playwright browsers plus Chrome/Edge, matching Scheduler; empty skips installation |
| `playwright_install_timeout_minutes` | number | No | `10` | Separate timeout for npm dependency and browser installation |
| `apply_custom_locales`         | boolean | No       | `false` | After installation, copy the `@pentaho/common-automation-resources` locale overrides into the running server's plugin `locales` folders; `working_directory` must depend on that package |
| `timeout_minutes`              | number  | No       | `60`    | Test job timeout, including the server startup |
| `artifact_prefix`              | string  | No       | `<repo>-it-<run_id>-<run_attempt>` | Prefix of the `-results`, `-server-logs` and (on test failure) `-startup-server-logs` artifacts |
| `container_image`              | string  | No       | `vars.PDIA_AC_CONTAINER_IMAGE` | Docker image override |
| `slack_channels`               | string  | No       |         | Destination accepted by `hv-actions/slack-action`; empty skips Slack |
| `slack_title`                  | string  | No       | `""`    | Override the integration-test notification title; default is `Pentaho Plugin Integration Tests` |
| `slack_status_icons`           | boolean | No       | `false` | Add success/failure/cancelled/skipped status icons to integration-test Slack messages |
| `ms_teams_webhook_secret_name` | string  | No       | `""`    | The MS Teams webhook secret name |
| `practitest_working_directory` | string  | No       | `""`    | Set to enable publishing; folder whose `package.json` defines `practitest_script` (a local uploader or a suite depending on a packaged one). Empty skips Practitest |
| `practitest_script`            | string  | No       | `upload` | npm script in `practitest_working_directory` that uploads the results |
| `practitest_env_file`          | string  | No       | `.env`  | Practitest settings file (`PT_PROJECT_ID`, filters, attributes), relative to `practitest_working_directory`; passed as absolute `PT_ENV_FILE` |
| `practitest_results_dir`       | string  | No       | `""`    | Playwright results folder (`playwright-report`), relative to `practitest_working_directory`; passed as absolute `PT_RESULTS_DIR`. Empty keeps the uploader default |
| `server_version_file`          | string  | No       | `src/resources/.auth/server-version.json` | JSON file containing `{"version":"11.0.0.4.338"}`, relative to `working_directory` |
| `report_title`                 | string  | No       | `Publish Test Report` | Title of the CTRF GitHub report |
| `ctrf_report_path`             | string  | No       | `""`    | Repository-relative report glob; defaults to `ctrf-report.json` files under `working_directory` |
| `ctrf_artifact_name`           | string  | No       | `ctrf-report` | Stable processed CTRF artifact name for history lookup and upload; distinct per matrix combination, unchanged across runs |
| `report_template_path`         | string  | No       | `""`    | Repository-relative Handlebars template; empty uses the bundled custom report |
| `report_guide_path`            | string  | No       | `""`    | Optional repository-relative failure inspection guide, linked on the PR's source repository/ref |
| `summary_format`              | string  | No       | `compact` | `compact` uses one line; `multiline` uses capitalized browser names on separate lines |
| `verbose`                      | boolean | No       | `false` | Print tool versions, staged SQL/plugin details, parsed report paths and service console logs |

### Outputs

| Output          | Description |
|-----------------|-------------|
| `tests_summary` | Human-readable test counts |
| `tests_total`   | Total tests |
| `tests_passed`  | Passed tests (Playwright flaky tests count as passed) |
| `tests_failed`  | Failed tests |
| `tests_skipped` | Skipped tests |
| `server_version` | Version saved by global setup, normalized from `11.0.0.4.338` to `11.0.0.4-338` |
| `practitest_url` | Test Sets & Runs link when Practitest publishing succeeds |

Counts come from each test's status in `ctrf-report.json`, not the raw CTRF summary: expected failures count as passed, pending as skipped, and tests whose suite starts with the `setup` project are excluded. CTRF `suite` may be a `project > file > title` string or an array starting with the project. Counts are grouped by the test's explicit `browser` field, falling back to the suite's project name, then `Tests`.

When no valid CTRF report is found, the summary falls back to Playwright JSON reporter files under `playwright-report` folders. It counts nested test entries, excludes `projectName: setup`, and reports aggregate counts: `expected` and `flaky` count as passed, `skipped` as skipped, and other statuses as failed.

CTRF reports feed `ctrf-io/github-test-reporter` with `custom-report: true` and the restored [custom template](../actions/playwright-test-summary/custom-report.hbs). It includes raw counts (explicitly labeled as including expected failures), duration, tool/application/build/PR/commit metadata, trends, and separate unexpected-failure, flaky, skipped, pending and other test lists. The commit line (non-PR runs) uses the event's first pushed commit when present; scheduled and manual runs have no event commits, so it links the tested `github.sha` instead. A custom report glob affects publishing, not the independent count aggregation. Publishing is skipped when the glob matches no report files; an unreadable template fails explicitly. The glob is checked with Node's `fs.globSync`, which uses the same minimatch semantics as the reporter's `glob` package (braces such as `playwright-report/{chrome,firefox}/ctrf-report.json`, extglobs, `**`, and wildcards that skip dot folders), so the check and the reporter select the same files. Template paths are resolved inside the action's container, not through the host-only `github.action_path` expression. Test images must provide Node 22 or later for aggregation and report-glob checking; the shared build image also requires Python 3 for Maven argument parsing.

Historical comparisons are enabled with `fetch-previous-results: true`. The reporter uploads its processed CTRF report with `upload-artifact: true` and uses the same `ctrf_artifact_name` for history lookup and upload. History comes from matching earlier runs of the caller workflow (same branch or pull request), not from the HTML-report artifact. Trend arrows appear for nonzero changes when a usable baseline exists; the first run, expired history, or a new artifact name has no historical comparison. Callers must grant `actions: read` as well as `contents: read`; the reusable workflow grants these permissions and the action supplies `GITHUB_TOKEN` to the reporter. Direct `playwright-test-summary` consumers use its `artifact_name` input and need the same permissions.

The `<artifact_prefix>-results` artifact contains `playwright-report/` folders under `working_directory`, including hidden files but excluding `node_modules`, and is retained for 5 days. The upload warns if no matching files exist. Suites should write every Playwright output under `playwright-report/` (HTML report, `outputDir` traces and error context, JSON and CTRF reports), as Scheduler and Analyzer do, so the artifact keeps them; files written elsewhere, such as Playwright's default `outputDir`, are not uploaded. The reporter also retains its processed CTRF report separately under `ctrf_artifact_name` using the repository's default artifact retention.

The job summary always includes local HTML-report and trace-viewing commands. Trace viewing requires a trace retained under `playwright-report/` or one included in the HTML report. `report_guide_path` adds a verified document link when configured; the removed Scheduler helper linked to a document that was not present in that repository. `summary_format: multiline` preserves Scheduler's capitalized, per-browser Slack lines through multiline GitHub outputs.

Global setup should save the platform version returned by `api/version/show` to `server_version_file`, as Scheduler does. Missing or invalid version data produces a warning and skips Practitest; tests and report uploads are unaffected.

`verbose` adds diagnostic output without enabling shell tracing. Regular Maven/npm output, failures, warnings and test summaries remain visible when false. When true, service logs are also printed. Commands and services can still emit sensitive values, so avoid logging secrets in their output.

### Practitest

When `practitest_working_directory` is nonempty and the test step finished with success or failure, the workflow does the following:

1. Uses the tested platform version saved by global setup, rather than reading an unrelated plugin's XML version.
2. Runs `npm run <practitest_script>` in `practitest_working_directory` with `MANUAL_BUILD_NUMBER`, `MANUAL_SERVER_CONTEXT`, `MANUAL_API_TOKEN`, optional `PT_USERNAME`, the absolute `PT_ENV_FILE` and, when `practitest_results_dir` is set, the absolute `PT_RESULTS_DIR`. Other uploader settings belong in the env file; a missing env file fails the step. `PLAYWRIGHT_PROJECT` is unset for the uploader so it can group results by browser and server version, as Scheduler does. A failing upload fails the job.
3. Reads `PT_PROJECT_ID` and optional `PT_TESTSET_FILTER_ID` from `PT_ENV_FILE` (Node 20.12+), adds filtered Test Sets links to the job summary and passes the link to Slack. Invalid link configuration fails explicitly.

The uploader must already be installed by the test install step. It owns browser/server test-set grouping; the shared action only supplies its environment contract. Uploaders should load `PT_ENV_FILE` and read results from `PT_RESULTS_DIR` instead of paths relative to their own file, so the same code works as a local folder or as a packaged dependency. For a packaged uploader, point `practitest_working_directory` at the suite, add a script such as `"practitest:upload": "<uploader bin>"` to its `package.json`, and keep the product's settings in the suite:

```yaml
practitest_working_directory: automation
practitest_script: practitest:upload
practitest_env_file: practitest.env
practitest_results_dir: playwright-report
```

The existing optional MS Teams notification still uses `gh-composite-actions` within the test job.

### Shared Actions and Scripts

| Action | Responsibility |
|--------|----------------|
| [`setup-plugin-npm`](../actions/setup-plugin-npm/action.yml) | Shared Git setup, npm detection and registry authentication for build and tests |
| [`build-plugins`](../actions/build-plugins/action.yml) | Maven invocation in `build.sh`, optional JUnit check reporting with transient 404 retries, and summary tracking in `update-summary.sh` |
| [`pentaho-server-fixtures`](../actions/pentaho-server-fixtures/action.yml) | `extract-sql.sh` reads the server image; `stage-fixtures.sh` verifies plugins and generates bind mounts |
| [`install-playwright`](../actions/install-playwright/action.yml) | `install.sh` installs dependencies/browsers in a separately time-limited workflow step |
| [`apply-custom-locales`](../actions/apply-custom-locales/action.yml) | Runs the `copy-custom-locales` bin of `@pentaho/common-automation-resources` (resolved from `working_directory`) against the `pba` service, or any named container, via `docker exec` |
| [`run-playwright`](../actions/run-playwright/action.yml) | `run.sh` invokes the test script; direct callers still install dependencies by default |
| [`playwright-test-summary`](../actions/playwright-test-summary/action.yml) | `summarize.cjs` aggregates counts/version, `check-reports.cjs` resolves report/template paths, and the reporter fetches history, renders the bundled or caller template and uploads processed CTRF |
| [`practitest-publish`](../actions/practitest-publish/action.yml) | `publish.sh` runs the caller's uploader; `link.cjs` reads `PT_ENV_FILE` (default `.env`) and builds result links |
| [`collect-service-logs`](../actions/collect-service-logs/action.yml) | `collect.sh` saves service logs and optionally prints them |
| [`notify-slack`](../actions/notify-slack/action.yml) | One payload builder supports both pull request and integration-test Slack messages; used by `integration-tests-npm.yml` and section 11 |
| [`notify-integration-tests`](../actions/notify-integration-tests/action.yml) | Legacy standalone action; kept for existing callers |

Nontrivial shell is in `.sh` files; JSON/report processing remains in external `.cjs` files. Actions call them through `"$GITHUB_ACTION_PATH/<script>"`, never `${{ github.action_path }}`: the expression yields the runner host path (`/runner/_work/_actions/...`), which does not exist inside job containers (`/__w/_actions/...`).

`script-tests.yml` runs npm build-info unit tests and the plugin workflow script regression suite in separate jobs on pull requests touching their scripts, shared actions or covered workflows. The plugin job uses the Artifactory `node:22-bookworm` image, installs Bash, Python 3 and jq with `apt-get`, runs `.github/scripts/tests/test-plugin-workflows.cjs` with Node's built-in test runner, and runs the report-template tests with the reporter's Handlebars/helper packages. It installs the locked template-test dependencies with `npm ci --prefix .github/scripts/tests`. Python 3 is needed by the build action's shell-argument parser. The runner needs access to the image, Debian package repositories and npm registry. Script tests stub Docker, Maven and npm; no Docker daemon is needed.

While in validation, the build, integration-test and notification workflows reference their shared actions at `@ci-it`, and callers use `@ci-it`. When promoting to `stable`, switch those internal action refs (and the callers) to `@stable` in the same change.

### Required Variables & Secrets

| Name                            | Type   | Description |
|---------------------------------|--------|-------------|
| `vars.ARTIFACTORY_HOST`         | var    | Artifactory host (images and npm registry) |
| `vars.PDIA_AC_CONTAINER_IMAGE`  | var    | Default job image |
| `secrets.PENTAHO_CICD_ONE_USER` | secret | Artifactory username |
| `secrets.PENTAHO_CICD_ONE_KEY`  | secret | Artifactory API key/password |
| `secrets.PRACTITEST_PAT`        | secret | Practitest API token (only when `practitest_working_directory` is set) |
| `secrets.PRACTITEST_USERNAME`   | secret | Practitest username (optional) |
| `secrets.SLACK_TOKEN`           | secret | Slack notifications (optional) |

### Plugin Workflow Usage Examples

**PR build and on-demand run from the project repository:**

```yaml
# .github/workflows/pr.yml (in your project repo)
name: Pull Request
on:
  pull_request:
    branches: [master]
  workflow_dispatch:
    inputs:
      verbose:
        description: Print extra diagnostics and service logs
        type: boolean
        default: false
      server_build_name:
        description: Pentaho Server build name
        type: string
        default: pdia-master
      server_context:
        description: Pentaho Server web application
        type: string
        default: sample
      playwright_project:
        description: Playwright project (all runs every configured project)
        type: string
        default: chrome

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true

permissions:
  contents: read
  actions: read
  checks: write

jobs:
  check-commit-messages:
    if: ${{ github.event_name == 'pull_request' && github.event.pull_request.head.repo.full_name == github.repository }}
    uses: pentaho/actions-common/.github/workflows/check.yml@stable
    secrets: inherit

  build:
    needs: check-commit-messages
    if: >-
      ${{ !cancelled() &&
          (github.event_name == 'workflow_dispatch' ||
           (needs.check-commit-messages.result == 'success' &&
            github.event.pull_request.head.repo.full_name == github.repository)) }}
    uses: pentaho/actions-common/.github/workflows/build-plugins.yml@ci-it
    secrets: inherit
    with:
      additional_mvn_directives: -pl assemblies/my-plugin -am
      run_unit_tests: true
      verbose: ${{ inputs.verbose || false }}

  integration-tests:
    needs: build
    if: ${{ !cancelled() && needs.build.result == 'success' }}
    uses: pentaho/actions-common/.github/workflows/integration-tests-npm.yml@ci-it
    secrets: inherit
    with:
      use_pr_build: true
      required_plugins: my-plugin
      working_directory: automation
      server_build_name: ${{ inputs.server_build_name || 'pdia-master' }}
      server_context: ${{ inputs.server_context || 'sample' }}
      playwright_project: ${{ inputs.playwright_project || 'chrome' }}
      slack_channels: my-plugin-build
      verbose: ${{ inputs.verbose || false }}
```

Replace the module, plugin, test directory and Slack channel with project values. No `pull_request_target`: fork PRs cannot safely consume private registry secrets or these self-hosted runners. Optional `runITs` / `skipRunITs` label gating can remain in this caller. Manual runs use **Actions -> Pull Request -> Run workflow** and the selected branch; publish the caller on the default branch to expose that button.

For Scheduler, the main build's extra directives are `-f pentaho-app-shell-scheduler/pom.xml`; test `working_directory` is `pentaho-app-shell-scheduler/automation` and `required_plugins` is `pas-scheduler,scheduler-plugin`. The legacy `scheduler-plugin` assembly has no `-DbiserverHome` profile, so Scheduler builds and stages it with a caller-owned script:

```yaml
      post_build_command: bash .github/scripts/stage-scheduler-plugin.sh
```

The script receives `MAVEN_SETTINGS_FILE`, `PLUGINS_DIR` and `GITHUB_WORKSPACE`, builds the legacy assembly, extracts its ZIP into `PLUGINS_DIR`, verifies the backend JAR and runs the existing non-blocking frontend checks. For Scheduler, set `node_version: "24.11.1"` and `artifact_retention_days: 10` to retain its pre-migration frontend runtime and plugin retention. Its PR and nightly callers use `summary_format: multiline`; nightly also sets `slack_title: Scheduler PAS Integration Tests` and `slack_status_icons: true`. Analyzer needs no post-build command. Both PR callers select Chrome only through `playwright_project`; their configs honor `PLAYWRIGHT_PROJECT`, so a duplicate `test_args: --project=chrome` is unnecessary.

### Scheduler Migration Parity

| Original capability | Common-workflow equivalent |
|---------------------|----------------------------|
| Commit checks, Maven build/audit and JUnit reporting | `check.yml`, `build-plugins.yml`, `run_unit_tests` |
| PR-built frontend and legacy backend plugins | Fixed `pentaho-plugins` artifact, caller-owned staging command, `required_plugins` and individual plugin mounts |
| Non-blocking frontend checks with pinned Node | Caller staging script plus `node_version` |
| Nightly cron, sequential build/context matrix and browser selection | Scheduler caller matrix and `playwright_project`; scheduled and manual defaults remain unchanged |
| Independently bounded dependency/browser installation | `install-playwright` workflow step with `playwright_install_timeout_minutes: 10` by default |
| Custom server URL | `server_url` plus `server_context` |
| Counts excluding setup and treating expected failures as passed | `playwright-test-summary`; compact and multiline summaries remain separate from raw CTRF counts |
| Custom CTRF report and configurable report title/glob | Bundled `custom-report.hbs`, `report_title`, `ctrf_report_path`, `report_template_path` |
| Local failure inspection guidance | Always-present artifact/HTML/trace instructions and optional verified `report_guide_path` link |
| Browser/version-grouped Practitest upload and filtered links | Caller uploader with the same MANUAL/PT environment contract; success/failure gating and optional username retained |
| PR and nightly Slack fields, status icons and browser lines | Shared `notify-slack`, PR notification workflow, caller-selected title/icons/multiline summary |
| Plugin and test artifact retention | Scheduler selects 10 days for plugins; results remain 5 days |
| Teardown and diagnostic logs | Run-scoped volume cleanup plus separate service-log artifacts |

Infrastructure differences remain explicit: SQL is taken from the tested server image instead of the deleted repository snapshots; arbitrary container names and volume refs are replaced with service IDs and repository/run-scoped paths; artifact names and workflow input/output names use the common contract. The test job retains its 60-minute default timeout, with a separate 10-minute installation limit.

**Lerna monorepo (root script runs every package suite):**

```yaml
permissions:
  contents: read
  actions: read

jobs:
  integration-tests:
    uses: pentaho/actions-common/.github/workflows/integration-tests-npm.yml@ci-it
    secrets: inherit
    with:
      use_pr_build: true
      test_script: playwright:test   # "playwright:test": "lerna run playwright:test"
```

**Server-only nightly or manual run with Practitest upload (no PR build artifact):**

```yaml
on:
  schedule:
    - cron: "0 7 * * *"
  workflow_dispatch:
    inputs:
      verbose:
        type: boolean
        default: false

permissions:
  contents: read
  actions: read

jobs:
  integration-tests:
    uses: pentaho/actions-common/.github/workflows/integration-tests-npm.yml@ci-it
    secrets: inherit
    with:
      working_directory: automation
      practitest_working_directory: automation/utils/playwright-practitest-uploader
      slack_channels: "#my-channel"
      verbose: ${{ inputs.verbose || false }}
```

Migration to the smaller workflow interface:

- Replace `plugins_artifact: pentaho-plugins` with `use_pr_build: true`; omit it for server-only runs.
- Remove `practitest_upload`; supplying `practitest_working_directory` now enables publishing. To disable it, omit the directory.
- Remove `plugin_path`, `cleanup`, `practitest_project_id` and `build_plugin`. The workflow uses standard server paths, always cleans up, and reads the Practitest project from `practitest_env_file` (default `.env`). `practitest_script` remains available (default `upload`), with `practitest_env_file` and `practitest_results_dir` for packaged uploaders. `container_image` remains supported on both build and test workflows.
- Keep project-specific Maven directives, required plugin folders, test directory, npm script/arguments, browser selection, timeout and notification settings when needed. Omit values equal to shared defaults, such as `server_build_name: pdia-master`. The build workflow's inputs remain unchanged: each controls build behavior or infrastructure independently.
- Scheduler's manual nightly inputs now use the shared snake_case names: `server_build_name`, `server_context`, `playwright_project`, `verbose`. The first two remain JSON arrays for its sequential matrix; cron defaults and manual defaults are preserved.

Earlier migration: remove the former `volume_path` and `checkout_ref` inputs. Both build and tests use the event's checkout revision (PR merge commit or manually selected branch), as Scheduler does. Replace `build_number_file` with `server_version_file` when overriding version discovery. Direct users of `practitest-publish` pass `server_version` rather than `server_container` / `build_number_file`, omit `playwright_project`, and consume `sets_url` instead of `build_number` / `skipped`. Browser defaults cover all bundled browsers plus Chrome/Edge, and dependency installation uses Scheduler's `npm install` rather than `npm ci`.

Direct `pentaho-server-fixtures` consumers should use its `mounts` output in Docker service `options` instead of the former JSON `volumes` output.

---

## 10. `build-plugins.yml` — Build & Stage Pentaho Plugins

Builds a Maven project with `-DbiserverHome`, so the plugin assemblies unzip themselves into a `pentaho-solutions/system` folder, and uploads that folder as the `pentaho-plugins` run artifact. `integration-tests-npm.yml` mounts that artifact into the Pentaho Server.

### Jobs

| Job     | Condition | Purpose |
|---------|-----------|---------|
| `build` | always    | Runs `mvn -B -ntp clean install` and uploads the staged plugins as `pentaho-plugins` |

### Staging Conventions

- Maven stages assemblies into `pentaho-build/pentaho-solutions/system` through `-DbiserverHome=<workspace>/pentaho-build`; there is no separate staging step.
- Maven dependency resolution uses the fixed mirror `https://${ARTIFACTORY_HOST}/artifactory/pnt-mvn`; there is no `resolve_repo` input.
- The upload fails when no files are found. Set `required_plugins` on `integration-tests-npm.yml` to verify expected plugin folders and `plugin.xml` files.
- The uploaded artifact is always named `pentaho-plugins` and retained for `artifact_retention_days` (5 by default).
- Unit tests are skipped by default. When `run_unit_tests` is true, the command enables tests and audit, and configures Surefire to fail on test failures unless overridden by additional Maven directives. Earlier successful reactor modules may already be installed in the shared cache.
- When `node_version` is set, Node/npm are installed as the first workflow step, before npm authentication and Maven, and remain available to `post_build_command`. An empty value keeps the container's runtime. Direct `build-plugins` action callers must provide Node/npm when needed by their build or post-build command.
- Unit-test reports use `dorny/test-reporter` pinned to commit `79b4b4400dc2354b89e9dd811ef9caa9bdd4f665`, which retries transient 404 responses while updating a check run created moments earlier. The generic build wrapper's reporter is disabled for this action to avoid duplicate check runs. The caller must grant `checks: write`.
- `post_build_command` (optional) runs after the main build, before the upload, with `bash -euo pipefail` and without automatically enabling shell tracing (`-x`); when verbose, the resulting plugin descriptors are listed instead. It receives `MAVEN_SETTINGS_FILE` and `PLUGINS_DIR` (the uploaded system folder) for assemblies that cannot stage themselves. A missing staging folder after Maven does not prevent this command from creating it, even in verbose mode.
- `mvn install` puts the built SNAPSHOT artifacts in the shared `.m2` runner cache, as the other build workflows do.

### Inputs

| Input                       | Type    | Required | Default | Description |
|-----------------------------|---------|----------|---------|-------------|
| `additional_mvn_directives` | string  | No       | `""`    | Maven arguments (e.g. `-f <pom>`, `-pl <modules> -am`); shell-style quotes and newlines work, shell expansion does not; empty builds the whole reactor |
| `run_unit_tests`            | boolean | No       | `false` | Run and report unit tests (`-DskipTests=false -Daudit -Dmaven.test.failure.ignore=false`) using a pinned `dorny/test-reporter` revision that retries transient 404s when updating a newly created check run. The caller must grant `checks: write` |
| `post_build_command`        | string  | No       | `""`    | Bash commands run after the build with `MAVEN_SETTINGS_FILE` and `PLUGINS_DIR` set (e.g. build and unzip an extra assembly) |
| `node_version`              | string  | No       | `""`    | Install this Node version first, before npm authentication, Maven and the post-build command; no post-build command is required |
| `artifact_retention_days`   | number  | No       | `5`     | Retention of the uploaded plugin artifact |
| `timeout_minutes`           | number  | No       | `60`    | Build job timeout |
| `container_image`           | string  | No       | `vars.PDIA_AC_CONTAINER_IMAGE` | Docker image override |
| `verbose`                   | boolean | No       | `false` | Print Maven version, install directory and staged plugin descriptors; normal Maven output remains visible |

### Usage Example

```yaml
jobs:
  build:
    uses: pentaho/actions-common/.github/workflows/build-plugins.yml@ci-it
    secrets: inherit
    with:
      additional_mvn_directives: -pl assemblies/my-plugin-ee -am
```

See section 9 for chaining it with `integration-tests-npm.yml`.

The build image needs Bash, Maven and Python 3 (used only to split quoted Maven arguments without evaluating shell code), plus npm when the project uses it. The shared Pentaho bootstrap image already includes Python.

---

## 11. `notify-pull-request.yml` — Pull Request Slack Notification

Sends one Slack message summarizing a whole pull request workflow, including jobs that ran before the integration tests. Use it instead of `slack_channels` on `integration-tests-npm.yml` when a commit check or build failure must also be reported, since a skipped test workflow sends nothing.

### Jobs

| Job      | Condition | Purpose |
|----------|-----------|---------|
| `notify` | always    | Resolves the overall status from `results` and posts the message with `hv-actions/slack-action` |

### Message

- Title: `<workflow name> #<pull request number>`.
- Status: `failure ❌` when any result is `failure`, else `cancelled ⚠️` when any is `cancelled`, else `success ✅` (skipped jobs count as success).
- Fields: run link with the event name, status, branch, PR link, `Version: <server_version or unknown>`, `tests_summary` (or `Tests: no results found`) and `jobs_summary`; footer with the actor.

### Inputs

| Input            | Type    | Required | Default | Description |
|------------------|---------|----------|---------|-------------|
| `slack_channels` | string  | Yes      |         | Slack channel(s) |
| `results`        | string  | Yes      |         | Space separated job results, usually `${{ join(needs.*.result, ' ') }}` |
| `jobs_summary`   | string  | No       | `""`    | Job results line shown in the message |
| `tests_summary`  | string  | No       | `""`    | `tests_summary` output of `integration-tests-npm.yml` |
| `server_version` | string  | No       | `""`    | `server_version` output of `integration-tests-npm.yml` |
| `verbose`        | boolean | No       | `false` | Print the resolved status |

Requires `secrets.SLACK_TOKEN` (`secrets: inherit`).

### Usage Example

```yaml
jobs:
  slack-notification:
    needs: [check-commit-messages, build, integration-tests]
    if: ${{ always() }}
    uses: pentaho/actions-common/.github/workflows/notify-pull-request.yml@ci-it
    secrets: inherit
    with:
      slack_channels: my-plugin-build
      results: ${{ join(needs.*.result, ' ') }}
      jobs_summary: "Commit check: ${{ needs.check-commit-messages.result }}, Build: ${{ needs.build.result }}, Integration tests: ${{ needs.integration-tests.result }}"
      tests_summary: ${{ needs.integration-tests.outputs.tests_summary }}
      server_version: ${{ needs.integration-tests.outputs.server_version }}
```

Omit `slack_channels` on `integration-tests-npm.yml` in that caller to avoid a second message.

The reusable workflow and `integration-tests-npm.yml` both use the [`notify-slack` action](../actions/notify-slack/action.yml). Its `pull_request` format keeps this caller's PR fields and overall-job status. Its `integration_tests` format keeps the existing integration-test message, including server/project, optional PractiTest link, and `skipped` status.
