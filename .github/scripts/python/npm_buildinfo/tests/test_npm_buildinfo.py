#!/usr/bin/env python3
"""Unit tests for npm_buildinfo.py (DEVO-14566).

SBOM and AQL shapes are copied from real data: the rollup-plugin-sbom output
shipped in semantic-model-editor / webttle (pdia-master 11.1.0.0-442) and AQL
responses from repo.pentaho.com.
"""

import fnmatch
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import npm_buildinfo as nb  # noqa: E402

AXIOS_SHA256 = "a511049fdaec40a320368b3ee965079b3e14481f82d052584f746bbdc3f01ede"
REACT_SHA256 = "8d9bed01a672e7ea" + "0" * 48
UIKIT_SHA256 = "a6955b6beb2da1c77d49cc4a9338f1b5580942de283886fee6a00d056c259565"


def _component(group, name, version):
    full = f"%40{group[1:]}/{name}" if group else name
    comp = {
        "type": "library", "name": name, "version": version,
        "purl": f"pkg:npm/{full}@{version}?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Fx%2Fy.git",
        "licenses": [{"license": {"id": "MIT", "acknowledgement": "declared"}}],
    }
    if group:
        comp["group"] = group
    return comp


def _bom(app="webttle", group="@pentaho-apps", components=None):
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {
            "tools": [{"name": "rollup-plugin-sbom", "version": "3.2.3"}],
            "component": {"type": "application", "name": app, "group": group,
                          "purl": f"pkg:npm/%40{group[1:]}/{app}"},
        },
        "components": components if components is not None else [
            _component("", "axios", "1.19.0"),
            _component("@hitachivantara", "uikit-react-core", "5.109.0"),
            _component("@pentaho", "app-shell-utils", "1.0.0"),
        ],
    }


def _zip_bytes(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data if isinstance(data, bytes) else data.encode())
    return buf.getvalue()


class _TmpDir(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = self._td.name

    def tearDown(self):
        self._td.cleanup()

    def write(self, name: str, data: bytes) -> str:
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path


class TestFindEmbeddedSboms(_TmpDir):
    def test_sbom_in_a_jar_inside_a_zip_is_found(self):
        jar = _zip_bytes({"META-INF/MANIFEST.MF": "x", "web/sbom/bom.json": json.dumps(_bom())})
        path = self.write("webttle-plugin-ee-11.1.0.0-442.zip",
                          _zip_bytes({"pentaho-webttle/lib/webttle-web.jar": jar}))

        found = nb.find_embedded_sboms([path])

        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].artifact, "webttle-plugin-ee-11.1.0.0-442.zip")
        self.assertEqual(found[0].inner_path,
                         "pentaho-webttle/lib/webttle-web.jar!/web/sbom/bom.json")
        self.assertEqual(found[0].bom["metadata"]["component"]["name"], "webttle")

    def test_sbom_in_a_tar_gz_is_found(self):
        buf = io.BytesIO()
        data = json.dumps(_bom()).encode()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo("pentaho-server/system/pentaho-webttle/web/sbom/bom.json")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        path = self.write("pentaho-server-ee-11.1.0.0-442.tar.gz", buf.getvalue())

        found = nb.find_embedded_sboms([path])

        self.assertEqual([f.artifact for f in found], ["pentaho-server-ee-11.1.0.0-442.tar.gz"])

    def test_well_known_copy_and_node_modules_are_skipped(self):
        bom = json.dumps(_bom())
        path = self.write("app.zip", _zip_bytes({
            "web/sbom/bom.json": bom,
            "web/.well-known/sbom": bom,
            "web/node_modules/rollup-plugin-sbom/dist/cyclonedx/bom.json": bom,
            "web/node_modules/some-pkg/sbom/bom.json": bom,
        }))

        self.assertEqual([f.inner_path for f in nb.find_embedded_sboms([path])], ["web/sbom/bom.json"])

    def test_non_cyclonedx_or_rootless_json_is_ignored(self):
        path = self.write("app.zip", _zip_bytes({
            "a/sbom/bom.json": json.dumps({"hello": "world"}),
            "b/sbom/bom.json": json.dumps({"bomFormat": "CycloneDX", "components": []}),
            "c/sbom/bom.json": "not json",
        }))

        self.assertEqual(nb.find_embedded_sboms([path]), [])

    def test_depth_limit_stops_recursion(self):
        inner = _zip_bytes({"web/sbom/bom.json": json.dumps(_bom())})
        for i in range(nb.MAX_DEPTH + 1):
            inner = _zip_bytes({f"level{i}.zip": inner})
        path = self.write("deep.zip", inner)

        self.assertEqual(nb.find_embedded_sboms([path]), [])

    def test_zip_bomb_entry_is_skipped(self):
        bomb = _zip_bytes({"web/sbom/bom.json": " " * (nb.MAX_SBOM_BYTES + 1)})
        path = self.write("bomb.zip", bomb)

        self.assertEqual(nb.find_embedded_sboms([path]), [])

    def test_total_size_budget_stops_the_walk(self):
        path = self.write("big.zip", _zip_bytes({"web/sbom/bom.json": json.dumps(_bom())}))
        with patch.object(nb, "MAX_TOTAL_BYTES", 10):
            with self.assertRaises(nb.ArchiveLimitError):
                nb.find_embedded_sboms([path])

    def test_entry_names_are_never_used_as_filesystem_paths(self):
        evil = _zip_bytes({"../../escape/sbom/bom.json": json.dumps(_bom())})
        path = self.write("evil.zip", _zip_bytes({"nested.jar": evil}))

        found = nb.find_embedded_sboms([path])

        self.assertEqual(len(found), 1)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "..", "..", "escape")))

    def test_node_modules_exclusion_holds_across_archive_boundaries(self):
        dep = _zip_bytes({"sbom/bom.json": json.dumps(_bom(app="some-dep", group="@vendor"))})
        path = self.write("app.zip", _zip_bytes({
            "web/sbom/bom.json": json.dumps(_bom()),
            "web/node_modules/pkg/dist.zip": dep,
        }))

        self.assertEqual([f.inner_path for f in nb.find_embedded_sboms([path])], ["web/sbom/bom.json"])

    def _tar_gz(self, members):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, data in members:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def test_skipped_tar_members_count_against_the_budget(self):
        path = self.write("big.tar.gz", self._tar_gz([
            ("pentaho-server/lib/huge.bin", b"\0" * 50_000),
            ("pentaho-server/web/sbom/bom.json", json.dumps(_bom()).encode()),
        ]))
        with patch.object(nb, "MAX_TOTAL_BYTES", 20_000):
            with self.assertRaises(nb.ArchiveLimitError):
                nb.find_embedded_sboms([path])

    def test_tar_member_reads_are_not_double_counted(self):
        bom = json.dumps(_bom()).encode()
        path = self.write("ok.tar.gz", self._tar_gz([("web/sbom/bom.json", bom)]))
        # A single tar block plus header and padding stays under 3x the payload.
        with patch.object(nb, "MAX_TOTAL_BYTES", len(bom) + 3 * 1024):
            self.assertEqual(len(nb.find_embedded_sboms([path])), 1)

    def test_unreadable_artifact_is_skipped_not_fatal(self):
        path = self.write("broken.zip", b"PK\x03\x04 truncated")
        self.assertEqual(nb.find_embedded_sboms([path]), [])


class TestNpmPackages(unittest.TestCase):
    def test_scoped_and_unscoped_names(self):
        self.assertEqual(nb.npm_packages(_bom()), [
            ("@hitachivantara/uikit-react-core", "5.109.0"),
            ("@pentaho/app-shell-utils", "1.0.0"),
            ("axios", "1.19.0"),
        ])

    def test_nested_components_and_non_npm_are_handled(self):
        parent = _component("", "react-dom", "18.3.1")
        parent["components"] = [_component("", "scheduler", "0.23.2")]
        maven = {"type": "library", "name": "x", "version": "1", "purl": "pkg:maven/g/x@1"}
        bom = _bom(components=[parent, maven, {"type": "library", "name": "noversion",
                                               "purl": "pkg:npm/noversion"}])

        self.assertEqual(nb.npm_packages(bom), [("react-dom", "18.3.1"), ("scheduler", "0.23.2")])

    def test_names_that_could_inject_into_aql_are_rejected(self):
        bad = _component("", 'x"}).delete(', "1.0.0")
        self.assertEqual(nb.npm_packages(_bom(components=[bad])), [])
        bad_version = _component("", "ok", '1"0')
        self.assertEqual(nb.npm_packages(_bom(components=[bad_version])), [])


class TestLookupChecksums(unittest.TestCase):
    @staticmethod
    def _client(results_by_name):
        def post(url, data=None, **kwargs):
            resp = MagicMock(status_code=200)
            name = data.split('"name":{"$eq":"', 1)[1].split('"', 1)[0]
            op, value = re.search(r'"path":\{"(\$eq|\$match)":"([^"]*)"\}', data).groups()
            rows = [r for r in results_by_name.get(name, [])
                    if (fnmatch.fnmatchcase(r["path"], value) if op == "$match" else r["path"] == value)]
            resp.json.return_value = {"results": rows}
            return resp
        session = MagicMock()
        session.post.side_effect = post
        return nb.ArtifactoryClient("https://repo.example.com", session=session)

    @staticmethod
    def _row(repo, name, sha256, path="axios/-"):
        return {"repo": repo, "path": path, "name": name, "sha256": sha256,
                "actual_sha1": "1" * 40, "actual_md5": "2" * 32}

    def test_query_targets_the_npm_tarball_path(self):
        client = self._client({"uikit-react-core-5.109.0.tgz": [
            self._row("fontawesome-npm-remote-cache", "uikit-react-core-5.109.0.tgz", UIKIT_SHA256,
                      "@hitachivantara/uikit-react-core/-")]})

        found, problems, _ = nb.lookup_checksums(client, [("@hitachivantara/uikit-react-core", "5.109.0")])

        query = client.session.post.call_args.kwargs["data"]
        self.assertIn('"path":{"$match":"@hitachivantara/uikit-react-core/-*"}', query)
        self.assertIn('"name":{"$eq":"uikit-react-core-5.109.0.tgz"}', query)
        self.assertEqual(found[("@hitachivantara/uikit-react-core", "5.109.0")]["sha256"], UIKIT_SHA256)
        self.assertEqual(problems, {})

    def test_npm_publish_layout_of_local_repositories_is_found(self):
        pkg = ("@pentaho/common-ui", "0.11.0")
        client = self._client({"common-ui-0.11.0.tgz": [
            self._row("uikit-npm-release", "common-ui-0.11.0.tgz", "e" * 64, "@pentaho/common-ui/-/@pentaho")]})

        found, problems, first_party = nb.lookup_checksums(client, [pkg])

        self.assertEqual(first_party, {pkg})
        self.assertEqual(problems, {})

    def test_same_tarball_in_several_caches_resolves(self):
        client = self._client({"react-18.3.1.tgz": [
            self._row("fontawesome-npm-remote-cache", "react-18.3.1.tgz", REACT_SHA256, "react/-"),
            self._row("registry-npm-remote-cache", "react-18.3.1.tgz", REACT_SHA256, "react/-")]})

        found, problems, _ = nb.lookup_checksums(client, [("react", "18.3.1")])

        self.assertEqual(found[("react", "18.3.1")]["sha256"], REACT_SHA256)

    def test_conflicting_checksums_prefer_the_remote_cache(self):
        client = self._client({"react-18.3.1.tgz": [
            self._row("npm-local", "react-18.3.1.tgz", "f" * 64, "react/-"),
            self._row("registry-npm-remote-cache", "react-18.3.1.tgz", REACT_SHA256, "react/-")]})

        found, _, first_party = nb.lookup_checksums(client, [("react", "18.3.1")])

        self.assertEqual(found[("react", "18.3.1")]["sha256"], REACT_SHA256)
        self.assertEqual(first_party, set())

    def test_package_only_in_local_repositories_is_first_party(self):
        pkg = ("@hv-internal/mds-client-ts", "2.1.0")
        client = self._client({"mds-client-ts-2.1.0.tgz": [
            self._row("pdc-npm-dev", "mds-client-ts-2.1.0.tgz", "e" * 64, "@hv-internal/mds-client-ts/-"),
            self._row("pdc-npm-release", "mds-client-ts-2.1.0.tgz", "d" * 64, "@hv-internal/mds-client-ts/-")]})

        found, problems, first_party = nb.lookup_checksums(client, [pkg])

        self.assertEqual(first_party, {pkg})
        self.assertEqual(found, {})
        self.assertEqual(problems, {})

    def test_private_package_in_a_public_scope_is_first_party(self):
        pkg = ("@hitachivantara/redux-saga-map", "1.0.0")
        client = self._client({"redux-saga-map-1.0.0.tgz": [
            self._row("pntprv-npm-release", "redux-saga-map-1.0.0.tgz", "e" * 64,
                      "@hitachivantara/redux-saga-map/-")]})

        _, _, first_party = nb.lookup_checksums(client, [pkg])

        self.assertEqual(first_party, {pkg})

    def test_unresolvable_conflict_is_reported_not_guessed(self):
        client = self._client({"react-18.3.1.tgz": [
            self._row("a-npm-remote-cache", "react-18.3.1.tgz", "e" * 64, "react/-"),
            self._row("b-npm-remote-cache", "react-18.3.1.tgz", REACT_SHA256, "react/-")]})

        found, problems, _ = nb.lookup_checksums(client, [("react", "18.3.1")])

        self.assertNotIn(("react", "18.3.1"), found)
        self.assertIn("conflicting checksums", problems[("react", "18.3.1")])

    def test_cache_rows_without_sha256_are_never_picked(self):
        no_sha = [dict(self._row("a-npm-remote-cache", "react-18.3.1.tgz", None, "react/-"), actual_sha1="1" * 40),
                  dict(self._row("b-npm-remote-cache", "react-18.3.1.tgz", None, "react/-"), actual_sha1="2" * 40)]
        found, problems, _ = nb.lookup_checksums(self._client({"react-18.3.1.tgz": no_sha}), [("react", "18.3.1")])

        self.assertEqual(found, {})
        self.assertIn(("react", "18.3.1"), problems)

    def test_missing_tarball_is_reported(self):
        found, problems, first_party = nb.lookup_checksums(self._client({}), [("left-pad", "1.3.0")])

        self.assertEqual(found, {})
        self.assertEqual(problems, {("left-pad", "1.3.0"): "no tarball in Artifactory"})
        self.assertEqual(first_party, set())

    def test_systemic_failure_raises_instead_of_looking_like_nothing_found(self):
        session = MagicMock()
        session.post.return_value = MagicMock(status_code=401, text="Unauthorized")
        client = nb.ArtifactoryClient("https://repo.example.com", session=session)
        pkgs = [(f"p{i}", "1.0.0") for i in range(10)]

        with self.assertRaisesRegex(RuntimeError, "10/10 AQL"):
            nb.lookup_checksums(client, pkgs)


class TestBuildModules(unittest.TestCase):
    def _sbom(self, artifact, bom, inner="web/sbom/bom.json"):
        return nb.EmbeddedSbom(artifact=artifact, inner_path=inner, bom=bom)

    def _found(self):
        return {
            ("axios", "1.19.0"): {"sha256": AXIOS_SHA256, "actual_sha1": "a" * 40, "actual_md5": "b" * 32},
            ("@hitachivantara/uikit-react-core", "5.109.0"):
                {"sha256": UIKIT_SHA256, "actual_sha1": "c" * 40, "actual_md5": "d" * 32},
        }

    def test_module_format_matches_the_proven_test_build(self):
        sboms = [self._sbom("webttle-plugin-ee-11.1.0.0-442.zip", _bom())]

        modules, _ = nb.build_modules(sboms, self._found(), {}, "11.1.0.0-442")

        self.assertEqual(len(modules), 1)
        mod = modules[0]
        self.assertEqual(mod["type"], "npm")
        self.assertEqual(mod["id"], "@pentaho-apps/webttle:11.1.0.0-442")
        self.assertEqual(mod["properties"], {"pdia.npm.artifacts": "webttle-plugin-ee-11.1.0.0-442.zip"})
        self.assertIn({"id": "axios:1.19.0", "type": "tgz", "scopes": ["prod"],
                       "sha1": "a" * 40, "md5": "b" * 32, "sha256": AXIOS_SHA256},
                      mod["dependencies"])
        self.assertEqual(len(mod["dependencies"]), 2)

    def test_first_party_packages_are_skipped(self):
        modules, summary = nb.build_modules(
            [self._sbom("a.zip", _bom())], self._found(), {}, "1",
            first_party={("@pentaho/app-shell-utils", "1.0.0")})

        ids = [d["id"] for d in modules[0]["dependencies"]]
        self.assertNotIn("@pentaho/app-shell-utils:1.0.0", ids)
        self.assertEqual(summary["first_party_skipped"], ["@pentaho/app-shell-utils@1.0.0"])
        self.assertEqual(summary["unresolved"], {})

    def test_no_scope_is_first_party_by_default(self):
        _, summary = nb.build_modules([self._sbom("a.zip", _bom())], self._found(), {}, "1")

        self.assertEqual(summary["first_party_skipped"], [])
        self.assertIn("@pentaho/app-shell-utils@1.0.0", summary["unresolved"])

    def test_identical_sbom_in_several_artifacts_is_one_module(self):
        bom = _bom()
        sboms = [self._sbom("webttle-plugin-ee-11.1.0.0-442.zip", bom),
                 self._sbom("pentaho-server-ee-11.1.0.0-442.zip", json.loads(json.dumps(bom)),
                            "pentaho-server/pentaho-solutions/system/pentaho-webttle/web/sbom/bom.json"),
                 self._sbom("webttle-plugins-ee-client-11.1.0.0-442.zip", bom)]

        modules, _ = nb.build_modules(sboms, self._found(), {}, "11.1.0.0-442")

        self.assertEqual(len(modules), 1)
        self.assertEqual(modules[0]["properties"]["pdia.npm.artifacts"],
                         "pentaho-server-ee-11.1.0.0-442.zip,webttle-plugin-ee-11.1.0.0-442.zip,"
                         "webttle-plugins-ee-client-11.1.0.0-442.zip")

    def test_different_sboms_of_one_app_get_distinct_stable_ids(self):
        older = _bom(components=[_component("", "axios", "1.19.0")])
        modules, _ = nb.build_modules(
            [self._sbom("a.zip", _bom()), self._sbom("b.zip", older)], self._found(), {}, "7")

        ids = [m["id"] for m in modules]
        self.assertEqual(len(set(ids)), 2)
        self.assertTrue(all(i.startswith("@pentaho-apps/webttle:7") for i in ids))
        again, _ = nb.build_modules(
            [self._sbom("b.zip", older), self._sbom("a.zip", _bom())], self._found(), {}, "7")
        self.assertEqual(sorted(ids), sorted(m["id"] for m in again))

    def test_sbom_without_root_name_uses_the_artifact_name(self):
        bom = _bom()
        bom["metadata"]["component"] = {"type": "application", "name": ""}
        modules, _ = nb.build_modules([self._sbom("login.zip", bom)], self._found(), {}, "3")

        self.assertEqual(modules[0]["id"], "login.zip:3")

    def test_unresolved_third_party_is_counted_and_listed(self):
        problems = {("axios", "1.19.0"): "no tarball in Artifactory"}
        found = {k: v for k, v in self._found().items() if k[0] != "axios"}

        modules, summary = nb.build_modules([self._sbom("a.zip", _bom())], found, problems, "1",
                                            first_party={("@pentaho/app-shell-utils", "1.0.0")})

        self.assertEqual([d["id"] for d in modules[0]["dependencies"]],
                         ["@hitachivantara/uikit-react-core:5.109.0"])
        self.assertEqual(summary["unresolved"], {"axios@1.19.0": "no tarball in Artifactory"})
        self.assertEqual(summary["packages"], 2)
        self.assertEqual(summary["resolved"], 1)


class TestMergeIntoBuildInfo(unittest.TestCase):
    def test_modules_are_appended_and_reruns_replace_them(self):
        build_info = {"name": "pdia-master", "number": "442",
                      "modules": [{"id": "pdia-master-442", "artifacts": [{"name": "a.zip"}]}]}
        first = [{"type": "npm", "id": "@pentaho-apps/webttle:442", "dependencies": []}]
        second = [{"type": "npm", "id": "@pentaho-apps/webttle:442", "dependencies": [{"id": "x:1"}]}]

        merged = nb.merge_into_build_info(nb.merge_into_build_info(build_info, first), second)

        self.assertEqual([m["id"] for m in merged["modules"]],
                         ["pdia-master-442", "@pentaho-apps/webttle:442"])
        self.assertEqual(merged["modules"][1]["dependencies"], [{"id": "x:1"}])

    def test_accepts_the_get_api_build_envelope(self):
        envelope = {"buildInfo": {"name": "b", "number": "1", "modules": []}}
        merged = nb.merge_into_build_info(envelope, [{"type": "npm", "id": "m:1"}])
        self.assertEqual(merged["buildInfo"]["modules"], [{"type": "npm", "id": "m:1"}])


class TestClientCredentials(unittest.TestCase):
    def test_token_takes_precedence_and_is_sent_as_bearer(self):
        env = {"ARTIFACTORY_URL": "https://repo.example.com/", "ARTIFACTORY_TOKEN": "t0k",
               "ARTIFACTORY_USER": "u", "ARTIFACTORY_PASSWORD": "p"}
        with patch.dict(os.environ, env, clear=True):
            client = nb.ArtifactoryClient.from_env()
        self.assertEqual(client.base_url, "https://repo.example.com")
        self.assertEqual(client.session.headers["Authorization"], "Bearer t0k")

    def test_missing_url_fails_clearly(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(SystemExit, "ARTIFACTORY_URL"):
                nb.ArtifactoryClient.from_env()

    def test_credentials_never_appear_in_the_repr(self):
        with patch.dict(os.environ, {"ARTIFACTORY_URL": "https://r", "ARTIFACTORY_USER": "u",
                                     "ARTIFACTORY_PASSWORD": "s3cret"}, clear=True):
            client = nb.ArtifactoryClient.from_env()
        self.assertNotIn("s3cret", repr(client))


class TestCli(_TmpDir):
    def test_end_to_end_writes_modules_and_summary(self):
        path = self.write("webttle-plugin-ee-11.1.0.0-442.zip",
                          _zip_bytes({"pentaho-webttle/web/sbom/bom.json": json.dumps(_bom())}))
        out = os.path.join(self.tmp, "modules.json")
        found = {("axios", "1.19.0"): {"sha256": AXIOS_SHA256, "actual_sha1": "a" * 40,
                                       "actual_md5": "b" * 32}}
        problems = {("@hitachivantara/uikit-react-core", "5.109.0"): "no tarball in Artifactory"}
        first_party = {("@pentaho/app-shell-utils", "1.0.0")}
        with patch.object(nb.ArtifactoryClient, "from_env", return_value=MagicMock()), \
                patch.object(nb, "lookup_checksums", return_value=(found, problems, first_party)):
            rc = nb.main(["--build-number", "11.1.0.0-442", "--output", out, path])

        self.assertEqual(rc, 0)
        result = json.load(open(out))
        self.assertEqual([d["id"] for d in result["modules"][0]["dependencies"]], ["axios:1.19.0"])
        self.assertEqual(result["summary"]["sboms"], 1)
        self.assertEqual(result["summary"]["unresolved"],
                         {"@hitachivantara/uikit-react-core@5.109.0": "no tarball in Artifactory"})
        self.assertEqual(result["summary"]["first_party_skipped"], ["@pentaho/app-shell-utils@1.0.0"])

    def test_first_party_scope_option_skips_the_lookup(self):
        path = self.write("a.zip", _zip_bytes({"web/sbom/bom.json": json.dumps(_bom())}))
        out = os.path.join(self.tmp, "modules.json")
        with patch.object(nb.ArtifactoryClient, "from_env", return_value=MagicMock()), \
                patch.object(nb, "lookup_checksums", return_value=({}, {}, set())) as lookup:
            rc = nb.main(["--build-number", "1", "--output", out, "--first-party-scope", "@pentaho", path])

        self.assertEqual(rc, 0)
        looked_up = lookup.call_args.args[1]
        self.assertNotIn(("@pentaho/app-shell-utils", "1.0.0"), looked_up)
        self.assertEqual(json.load(open(out))["summary"]["first_party_skipped"],
                         ["@pentaho/app-shell-utils@1.0.0"])

    def test_every_package_is_looked_up_by_default(self):
        path = self.write("a.zip", _zip_bytes({"web/sbom/bom.json": json.dumps(_bom())}))
        with patch.object(nb.ArtifactoryClient, "from_env", return_value=MagicMock()), \
                patch.object(nb, "lookup_checksums", return_value=({}, {}, set())) as lookup:
            nb.main(["--build-number", "1", "--output", os.path.join(self.tmp, "o.json"), path])

        self.assertIn(("@pentaho/app-shell-utils", "1.0.0"), lookup.call_args.args[1])

    def test_merge_into_rewrites_the_build_info(self):
        path = self.write("a.zip", _zip_bytes({"web/sbom/bom.json": json.dumps(_bom())}))
        bi = self.write("build-info.json", json.dumps({"name": "b", "number": "1", "modules": []}).encode())
        found = {("axios", "1.19.0"): {"sha256": AXIOS_SHA256, "actual_sha1": "a" * 40,
                                       "actual_md5": "b" * 32}}
        with patch.object(nb.ArtifactoryClient, "from_env", return_value=MagicMock()), \
                patch.object(nb, "lookup_checksums", return_value=(found, {}, set())):
            rc = nb.main(["--build-number", "1", "--merge-into", bi, path])

        self.assertEqual(rc, 0)
        self.assertEqual(json.load(open(bi))["modules"][0]["type"], "npm")

    def test_no_sbom_found_is_a_clean_no_op(self):
        path = self.write("plain.zip", _zip_bytes({"README.txt": "hi"}))
        out = os.path.join(self.tmp, "modules.json")
        with patch.object(nb.ArtifactoryClient, "from_env") as from_env:
            rc = nb.main(["--build-number", "1", "--output", out, path])

        self.assertEqual(rc, 0)
        from_env.assert_not_called()
        self.assertEqual(json.load(open(out))["modules"], [])


if __name__ == "__main__":
    unittest.main()
