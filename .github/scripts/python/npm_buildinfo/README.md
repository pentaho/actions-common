# npm_buildinfo

Adds `type: npm` build-info modules for the npm packages bundled into React/Vite web apps, so JFrog Xray scans them (epic DEVO-14562).

Vite/Rollup compiles npm packages into hashed chunks that Xray cannot identify. Each app ships a bundle-aware CycloneDX SBOM (`sbom/bom.json`, from `rollup-plugin-sbom` or `@hitachivantara/app-shell-vite-plugin`). This tool:

1. finds every `sbom/bom.json` inside the given artifacts, through nested zip/jar/war/ear/kar and tar archives up to 5 levels deep (`node_modules/` and `.well-known/sbom` are skipped);
2. looks up each npm package's tarball (`<name>/-/<basename>-<version>.tgz`) in Artifactory with one AQL query per package (non-admin AQL rejects `$or` batches);
3. emits one `type: npm` module per distinct app SBOM, with `tgz` dependencies carrying sha1/md5/sha256. Xray matches these checksums to the npm package. A package whose tarball exists only in local repositories (no remote `*-cache` copy) was published by us: it is reported as first-party and left out of the dependencies.

## Usage

```bash
export ARTIFACTORY_URL=https://repo.pentaho.com
export ARTIFACTORY_TOKEN=...            # or ARTIFACTORY_USER + ARTIFACTORY_PASSWORD
pip install -r requirements.txt

# Print modules + summary
python3 npm_buildinfo.py --build-number 11.1.0.0-442 webttle-plugin-ee-11.1.0.0-442.zip pentaho-server-ee-11.1.0.0-442.zip

# Append the modules to an existing build-info (bare or the GET /api/build envelope); rewritten in place
python3 npm_buildinfo.py --build-number 11.1.0.0-442 --merge-into build-info.json *.zip

# Add the modules to the published build-info and ask Xray to reindex it
python3 npm_buildinfo.py --build-number 11.1.0.0-442 --publish-to pentaho-server-ee-master *.zip
```

| Option | Default | Effect |
|---|---|---|
| `--build-number` | required | Module ids are `<app group/name>:<build number>` |
| `--merge-into FILE` | - | Append modules to this build-info; modules with the same id are replaced, so reruns are idempotent |
| `--publish-to NAME` | - | Fetch build-info `NAME/<build number>`, merge the modules, `PUT` it back with the same name, number and `started` (replacing that run), then `POST /xray/api/v1/forceReindex`. Excludes `--merge-into` |
| `--dry-run` | off | With `--publish-to`: write the merged build-info to `--output` and publish nothing |
| `--output FILE` | stdout | Write the result here |
| `--first-party-scope` | none | npm scope to treat as first-party without a lookup; repeatable. Not needed for packages published to our local npm repositories |
| `--workers` | 12 (max 32) | Parallel AQL lookups |

With no embedded SBOM the tool is a no-op (empty `modules`) and makes no Artifactory call; with `--publish-to` the build-info is left untouched.

`--publish-to` needs a user that can overwrite build-info (deploy/delete on the build) and trigger an Xray reindex. The reindex is always requested: Xray does not reliably rescan a replaced run on its own. The tool does not wait for the scan.

## GitHub Action

[`.github/actions/npm-buildinfo`](../../../actions/npm-buildinfo/action.yml) runs the tool with `--publish-to` after `mvn deploy`. `merge.yml` calls it in the release-candidate job when the caller sets `add_npm_buildinfo: true`:

```yaml
jobs:
  merge:
    uses: pentaho/actions-common/.github/workflows/merge.yml@stable
    secrets: inherit
    with:
      base_version: ${{ inputs.base_version }}
      run_release_candidate: true
      add_npm_buildinfo: true
```

| Input | Default | Effect |
|---|---|---|
| `build_name`, `build_number` | required | The published build (`-Dbuild.name`/`-Dbuild.number`) |
| `artifacts` | `**/target/*.zip`, `**/target/*.tar.gz` | Newline-separated globs of the archives to scan |
| `artifactory_url` | required | Host root, e.g. `https://repo.pentaho.com` |
| `artifactory_user`, `artifactory_password` | required | Credentials with the rights above |
| `dry_run` | `false` | Write the merged build-info to `$RUNNER_TEMP/npm-buildinfo-dry-run.json` and publish nothing |
| `fail_on_error` | `false` | Fail the job on error; by default a warning is emitted and the build continues |

The action installs `requirements.txt` into a venv under `$RUNNER_TEMP` (the CI image blocks system pip installs) and exits cleanly when no archive matches.

## Output

```json
{
  "type": "npm",
  "id": "@pentaho-apps/pentaho-webttle:11.1.0.0-442",
  "properties": {"pdia.npm.artifacts": "pentaho-server-ee-11.1.0.0-442.zip,webttle-plugin-ee-11.1.0.0-442.zip"},
  "dependencies": [
    {"id": "axios:1.19.0", "type": "tgz", "scopes": ["prod"], "sha1": "...", "md5": "...", "sha256": "..."}
  ]
}
```

- `pdia.npm.artifacts` lists the build artifacts the SBOM was found in. pdia-security's sbom-generator uses it to place the packages under those artifacts in the published SBOM.
- An SBOM found unchanged in several artifacts (for example webttle, which ships in its plugin zip, the client zip and pentaho-server-ee) becomes one module.
- Two different SBOMs for the same app get a checksum suffix on their id (`...:<build>:<8 hex>`).
- The summary reports SBOMs, packages, resolved and unresolved packages (with the reason), and skipped first-party packages. Unresolved packages are logged as warnings; the remaining packages are still emitted.

## Safety

- Credentials come from the environment only and are never logged.
- Package names and versions are validated against the npm grammar before they reach AQL, so a crafted SBOM cannot inject a query.
- Archive entry names are never used as filesystem paths. Nested archives are spooled to anonymous temp files.
- Limits:
  - 5M entries and 32 GiB decompressed per artifact;
  - 20 MiB per SBOM;
  - nested archives inflating more than 200x are skipped as zip bombs;
  - pentaho-server-ee 11.1 holds 666k entries and 1.1 GB, which is walked in about 5 s with about 110 MB RSS.
- If a tarball has conflicting checksums across repositories, the remote-cache copy is used. If the conflict can't be settled, the package is reported as unresolved rather than guessed.
- If more than half the AQL lookups fail (expired token, network), the tool exits with an error instead of emitting empty modules.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Run on pull requests by `.github/workflows/script-tests.yml`.
