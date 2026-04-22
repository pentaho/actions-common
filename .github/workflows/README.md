# Workflows Documentation

This folder contains GitHub Actions workflows and related documentation for Pentaho projects, including both reusable workflows and repository-internal/standalone workflows.
Below is an overview of the available documentation files.

---

## 📄 [COMMON_CHECKS.md](COMMON_CHECKS.md)

Documents the **core CI/CD workflows** that cover the full software delivery lifecycle — from pull request validation through to artifact promotion.

| Workflow | Purpose |
|----------|---------|
| [`pr.yml`](pr.yml) | Runs on every pull request: builds, tests, Sonar code quality scan, and Frogbot security scan. |
| [`merge.yml`](merge.yml) | Runs on merge: deploys SNAPSHOT artifacts and optionally produces a versioned Release Candidate. |
| [`release.yml`](release.yml) | Promotes a Release Candidate artifact from the dev repository to the release repository in Artifactory. |

Also includes:
- An introduction to **what reusable workflows are** and how they work in GitHub Actions.
- Notes on **required project files** (`sonar-project.properties`, `.github/release-versions.properties`).

---

## 📄 [AUXILIAR.md](AUXILIAR.md)

Documents the **auxiliary and supporting workflows** that are either called internally by the core workflows or serve specific standalone purposes.

| Workflow | Purpose |
|----------|---------|
| [`check.yml`](check.yml) | Validates all PR commit messages against the [Conventional Commits](https://www.conventionalcommits.org/) specification. |
| [`update-version.yml`](update-version.yml) | Automatically increments the patch version in `pom.xml` and `package.json` after a release. |
| [`publish-npm.yml`](publish-npm.yml) | Builds and publishes NPM packages to Artifactory, targeting either dev or release registries. |
| [`bootstrap-image.yml`](bootstrap-image.yml) | Builds and pushes the CI runner Docker image to Artifactory for JDK 17 and JDK 21. |

