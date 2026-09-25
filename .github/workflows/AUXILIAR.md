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
| `common-job`             | always    | Install dependencies, build, test, Sonar scan, Frogbot scan, notify  |

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

Runs on merge for NPM-based projects: builds and publishes packages to the dev Artifactory registry (`pntprv-npm-dev`).

> **Note:** the `build` and `publish` npm scripts are **required** in the consumer's `package.json` (not run with `--if-present`). If either script is missing, the job fails — a project without a real build/publish step would defeat the purpose of this workflow.

### Jobs

| Job     | Condition | Purpose                                                      |
|---------|-----------|----------------------------------------------------------------|
| `merge` | always    | Install dependencies, build, publish to dev registry, notify  |

### Inputs

| Input                          | Type   | Required | Default                        | Description                                |
|--------------------------------|--------|----------|---------------------------------|---------------------------------------------|
| `container_image`               | string | No       | `vars.PDIA_AC_CONTAINER_IMAGE` | Docker image override                      |
| `slack_channels`                | string | No       |                                 | Slack channel(s) to send notifications to  |
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

> **Note:** the `build`, `publish`, and `dry-run-publish` npm scripts are **required** in the consumer's `package.json` (not run with `--if-present`). If a required script is missing, the job fails — a project without a real build/publish step would defeat the purpose of this workflow.

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
| `dry_run`                       | boolean | No       | `true`                          | Runs `dry-run-publish` instead of `publish` |

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

