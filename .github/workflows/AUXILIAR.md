# Auxiliary GitHub Actions Workflows

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

## 3. `publish-npm.yml` — Publish NPM Modules Workflow

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

## 4. `bootstrap-image.yml` — Build & Push Container Image

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

