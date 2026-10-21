#!/usr/bin/env python3
# ******************************************************************************
#
# Pentaho
#
# Copyright (C) 2026 by Pentaho Canada Inc. : http://www.pentaho.com
#
# Use of this software is governed by the Business Source License included
# in the LICENSE.TXT file.
#
# Change Date: 2030-06-15
# ******************************************************************************
"""Add npm build-info modules from the app SBOMs embedded in build artifacts.

Vite/Rollup bundles npm packages into hashed chunks that Xray cannot identify.
Each web app ships a bundle-aware CycloneDX SBOM (``sbom/bom.json``); this tool
finds those SBOMs inside the build's archives, looks up each package's tarball
checksums in Artifactory and emits ``type: npm`` build-info modules so Xray
scans the bundled packages like any other dependency.

Credentials come from the environment only: ``ARTIFACTORY_URL`` plus either
``ARTIFACTORY_TOKEN`` or ``ARTIFACTORY_USER``/``ARTIFACTORY_PASSWORD``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import sys
import tarfile
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from typing import NamedTuple

import requests

log = logging.getLogger("npm_buildinfo")

MAX_DEPTH = 5
MAX_SBOM_BYTES = 20 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 ** 3
# pentaho-server-ee 11.1 alone holds 666k entries across its nested jars.
MAX_ENTRIES = 5_000_000
# A nested archive inflating more than this is treated as a zip bomb and skipped.
MAX_COMPRESSION_RATIO = 200
_RATIO_CHECK_MIN_BYTES = 10 * 1024 * 1024

_ZIP_SUFFIXES = (".zip", ".jar", ".war", ".ear", ".kar")
# Nested .tgz files are npm tarballs (node_modules caches), never app archives.
_TAR_SUFFIXES = (".tar", ".tar.gz")

ARTIFACTS_PROPERTY = "pdia.npm.artifacts"
_FAILURE_MAX_RATIO = 0.5

# npm package names and versions; anything else is rejected before it can reach AQL.
_NAME_RE = re.compile(r"^(?:@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9._~][A-Za-z0-9._~-]*$")
_VERSION_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]*$")


class ArchiveLimitError(RuntimeError):
    """An archive exceeded the entry-count or decompressed-size budget."""


class EmbeddedSbom(NamedTuple):
    artifact: str
    inner_path: str
    bom: dict


# ── SBOM discovery ──────────────────────────────────────────────────────────

class _Budget:
    def __init__(self) -> None:
        self.bytes = 0
        self.entries = 0

    def entry(self) -> None:
        self.entries += 1
        if self.entries > MAX_ENTRIES:
            raise ArchiveLimitError(f"more than {MAX_ENTRIES} archive entries")

    def read(self, n: int) -> None:
        self.bytes += n
        if self.bytes > MAX_TOTAL_BYTES:
            raise ArchiveLimitError(f"more than {MAX_TOTAL_BYTES} decompressed bytes")


def _is_sbom_entry(name: str) -> bool:
    return name.replace("\\", "/").split("/")[-2:] == ["sbom", "bom.json"]


def _in_node_modules(name: str) -> bool:
    return "node_modules" in name.replace("\\", "/").split("/")


def _nested_kind(name: str) -> str | None:
    lower = name.lower()
    if lower.endswith(_ZIP_SUFFIXES):
        return "zip"
    if lower.endswith(_TAR_SUFFIXES):
        return "tar"
    return None


def _copy_limited(src, dst, budget: _Budget | None, limit: int) -> int:
    total = 0
    while True:
        chunk = src.read(1024 * 1024)
        if not chunk:
            return total
        total += len(chunk)
        if budget is not None:
            budget.read(len(chunk))
        if total > limit:
            raise ValueError("entry larger than declared")
        if dst is not None:
            dst.write(chunk)


def _parse_sbom(data: bytes) -> dict | None:
    try:
        bom = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX":
        return None
    if not isinstance((bom.get("metadata") or {}).get("component"), dict):
        return None
    return bom


def _handle_entry(name, size, packed, opener, artifact, prefix, depth, budget, out, prepaid=False):
    """Inspect one archive member; recurse into nested archives via a temp file.

    *prepaid* members were already charged to the budget (tar members are
    decompressed whether read or skipped).
    """
    path = f"{prefix}{name}"
    # Packages under node_modules may ship their own SBOM, even inside nested archives.
    if _in_node_modules(name):
        return
    charge = None if prepaid else budget
    if _is_sbom_entry(name):
        if size > MAX_SBOM_BYTES:
            log.warning("skipping oversized SBOM %s!/%s (%d bytes)", artifact, path, size)
            return
        with opener() as src:
            buf = tempfile.SpooledTemporaryFile(max_size=MAX_SBOM_BYTES)
            _copy_limited(src, buf, charge, MAX_SBOM_BYTES)
        buf.seek(0)
        bom = _parse_sbom(buf.read())
        if bom is None:
            log.warning("ignoring %s!/%s: not a CycloneDX SBOM with a root component", artifact, path)
            return
        out.append(EmbeddedSbom(artifact, path, bom))
        return

    kind = _nested_kind(name)
    if kind is None or depth >= MAX_DEPTH:
        return
    if packed and size > _RATIO_CHECK_MIN_BYTES and size / packed > MAX_COMPRESSION_RATIO:
        log.warning("skipping %s!/%s: compression ratio %.0f looks like a zip bomb",
                    artifact, path, size / packed)
        return
    with tempfile.TemporaryFile() as tmp:
        with opener() as src:
            _copy_limited(src, tmp, charge, size)
        tmp.seek(0)
        _walk(tmp, kind, artifact, f"{path}!/", depth + 1, budget, out)


def _walk(fileobj, kind, artifact, prefix, depth, budget, out) -> None:
    try:
        if kind == "zip":
            with zipfile.ZipFile(fileobj) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    budget.entry()
                    _handle_entry(info.filename, info.file_size, info.compress_size,
                                  lambda i=info: zf.open(i), artifact, prefix, depth, budget, out)
        else:
            with tarfile.open(fileobj=fileobj, mode="r:*") as tf:
                for member in tf:
                    if not member.isfile():
                        continue
                    budget.entry()
                    budget.read(member.size)
                    _handle_entry(member.name, member.size, 0,
                                  lambda m=member: tf.extractfile(m), artifact, prefix, depth, budget, out,
                                  prepaid=True)
    except ArchiveLimitError:
        raise
    except (zipfile.BadZipFile, tarfile.TarError, OSError, ValueError, EOFError) as exc:
        log.warning("skipping unreadable archive %s!/%s: %s", artifact, prefix, exc)


def find_embedded_sboms(paths: list[str]) -> list[EmbeddedSbom]:
    """Find every ``sbom/bom.json`` inside the given artifacts (nested archives included)."""
    found: list[EmbeddedSbom] = []
    for path in paths:
        artifact = os.path.basename(path)
        if zipfile.is_zipfile(path):
            kind = "zip"
        elif tarfile.is_tarfile(path):
            kind = "tar"
        else:
            log.info("skipping %s: not a zip or tar archive", artifact)
            continue
        with open(path, "rb") as fh:
            _walk(fh, kind, artifact, "", 0, _Budget(), found)
    return found


# ── Package extraction ──────────────────────────────────────────────────────

def _flatten(components):
    for comp in components or []:
        if isinstance(comp, dict):
            yield comp
            yield from _flatten(comp.get("components"))


def npm_packages(bom: dict) -> list[tuple[str, str]]:
    """The npm ``(name, version)`` pairs an SBOM lists (scoped names as ``@scope/name``)."""
    out: set[tuple[str, str]] = set()
    for comp in _flatten(bom.get("components")):
        if not str(comp.get("purl", "")).startswith("pkg:npm/"):
            continue
        group, name, version = comp.get("group") or "", comp.get("name") or "", comp.get("version") or ""
        full = f"{group}/{name}" if group else name
        if not version:
            continue
        if not _NAME_RE.match(full) or not _VERSION_RE.match(version):
            log.warning("ignoring npm component with an invalid name or version: %r@%r", full, version)
            continue
        out.add((full, version))
    return sorted(out)


# ── Artifactory ─────────────────────────────────────────────────────────────

class ArtifactoryClient:
    def __init__(self, base_url: str, session: requests.Session | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        if session is None:
            session = requests.Session()
            session.mount("https://", requests.adapters.HTTPAdapter(pool_maxsize=32))
        self.session = session

    def __repr__(self) -> str:
        return f"ArtifactoryClient({self.base_url!r})"

    @classmethod
    def from_env(cls) -> "ArtifactoryClient":
        url = os.environ.get("ARTIFACTORY_URL", "").strip()
        if not url:
            raise SystemExit("ARTIFACTORY_URL is not set")
        client = cls(url)
        token = os.environ.get("ARTIFACTORY_TOKEN", "")
        if token:
            client.session.headers["Authorization"] = f"Bearer {token}"
        elif os.environ.get("ARTIFACTORY_USER") and os.environ.get("ARTIFACTORY_PASSWORD"):
            client.session.auth = (os.environ["ARTIFACTORY_USER"], os.environ["ARTIFACTORY_PASSWORD"])
        return client

    def aql(self, query: str) -> list[dict]:
        resp = self.session.post(
            f"{self.base_url}/artifactory/api/search/aql", data=query,
            headers={"Content-Type": "text/plain"}, timeout=60,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"AQL HTTP {resp.status_code}")
        return resp.json().get("results", [])


def _tarball_query(name: str, version: str) -> str:
    basename = name.rsplit("/", 1)[-1]
    # Remote caches store <name>/-/<file>; npm publish to a local repo stores <name>/-/<scope>/<file>.
    return (
        f'items.find({{"path":{{"$match":"{name}/-*"}},"name":{{"$eq":"{basename}-{version}.tgz"}}}})'
        '.include("repo","path","name","actual_sha1","actual_md5","sha256")'
    )


def _is_cache(row: dict) -> bool:
    return str(row.get("repo", "")).endswith("-cache")


def _pick(rows: list[dict]) -> tuple[dict | None, str]:
    if not rows:
        return None, "no tarball in Artifactory"
    rows = [r for r in rows if r.get("sha256")]
    if not rows:
        return None, "tarball has no sha256 in Artifactory"
    by_sha = {r["sha256"]: r for r in rows}
    if len(by_sha) == 1:
        return next(iter(by_sha.values())), ""
    cached = {r["sha256"]: r for r in rows if _is_cache(r)}
    if len(cached) == 1:
        return next(iter(cached.values())), ""
    repos = ", ".join(sorted(f"{r.get('repo')}={str(r.get('sha256'))[:12]}" for r in rows))
    return None, f"conflicting checksums: {repos}"


def lookup_checksums(
    client: ArtifactoryClient, pkgs: list[tuple[str, str]], workers: int = 12,
) -> tuple[dict, dict, set]:
    """Resolve each npm tarball's checksums; returns ``(found, problems, first_party)``.

    A package whose tarball exists only in local repositories (never in a remote
    ``*-cache``) was published by us, so it is first-party rather than a dependency.
    One query per package: non-admin AQL rejects ``$or`` batches with HTTP 400.
    """
    def one(pkg):
        try:
            return pkg, client.aql(_tarball_query(*pkg)), None
        except Exception as exc:  # noqa: BLE001 - counted below, never silent
            return pkg, [], exc

    found: dict = {}
    problems: dict = {}
    first_party: set = set()
    failures = 0
    with ThreadPoolExecutor(max(1, workers)) as pool:
        for pkg, rows, exc in pool.map(one, pkgs):
            if exc is not None:
                failures += 1
                problems[pkg] = f"AQL lookup failed: {exc}"
                continue
            if rows and not any(_is_cache(r) for r in rows):
                first_party.add(pkg)
                continue
            row, problem = _pick(rows)
            if row is not None:
                found[pkg] = row
            else:
                problems[pkg] = problem
    if pkgs and failures / len(pkgs) > _FAILURE_MAX_RATIO:
        raise RuntimeError(
            f"{failures}/{len(pkgs)} AQL lookups failed; check ARTIFACTORY_URL and credentials"
        )
    return found, problems, first_party


# ── Build-info modules ──────────────────────────────────────────────────────

def _root_name(bom: dict) -> str:
    root = (bom.get("metadata") or {}).get("component") or {}
    name = (root.get("name") or "").strip()
    group = (root.get("group") or "").strip()
    return f"{group}/{name}" if group and name else name


def _is_first_party(name: str, scopes) -> bool:
    return any(name.startswith(f"{scope}/") for scope in scopes)


def build_modules(
    sboms: list[EmbeddedSbom], found: dict, problems: dict, build_number: str,
    first_party=frozenset(), first_party_scopes=(),
) -> tuple[list[dict], dict]:
    """One ``type: npm`` module per distinct app SBOM, plus a summary."""
    groups: dict[tuple, dict] = {}
    for sbom in sboms:
        pkgs = tuple(npm_packages(sbom.bom))
        root = _root_name(sbom.bom)
        group = groups.setdefault((root, pkgs), {"root": root, "pkgs": pkgs, "artifacts": set()})
        group["artifacts"].add(sbom.artifact)

    for group in groups.values():
        group["base"] = group["root"] or sorted(group["artifacts"])[0]
    bases = [g["base"] for g in groups.values()]

    modules: list[dict] = []
    skipped: set[str] = set()
    third_party: set[tuple[str, str]] = set()
    for group in sorted(groups.values(), key=lambda g: (g["base"], g["pkgs"])):
        mod_id = f"{group['base']}:{build_number}"
        if bases.count(group["base"]) > 1:
            digest = hashlib.sha256(json.dumps(group["pkgs"]).encode()).hexdigest()[:8]
            mod_id = f"{mod_id}:{digest}"
        deps = []
        for name, version in group["pkgs"]:
            if (name, version) in first_party or _is_first_party(name, first_party_scopes):
                skipped.add(f"{name}@{version}")
                continue
            third_party.add((name, version))
            row = found.get((name, version))
            if row:
                deps.append({
                    "id": f"{name}:{version}", "type": "tgz", "scopes": ["prod"],
                    "sha1": row.get("actual_sha1"), "md5": row.get("actual_md5"),
                    "sha256": row.get("sha256"),
                })
        modules.append({
            "type": "npm",
            "id": mod_id,
            "properties": {ARTIFACTS_PROPERTY: ",".join(sorted(group["artifacts"]))},
            "dependencies": deps,
        })

    unresolved = {
        f"{n}@{v}": problems.get((n, v), "no tarball in Artifactory")
        for n, v in sorted(third_party) if (n, v) not in found
    }
    summary = {
        "sboms": len(sboms),
        "modules": len(modules),
        "packages": len(third_party),
        "resolved": len(third_party) - len(unresolved),
        "unresolved": unresolved,
        "first_party_skipped": sorted(skipped),
    }
    return modules, summary


def merge_into_build_info(build_info: dict, modules: list[dict]) -> dict:
    """Append *modules* to a build-info (bare or ``GET /api/build`` envelope); same ids are replaced."""
    target = build_info["buildInfo"] if "buildInfo" in build_info else build_info
    ids = {m["id"] for m in modules}
    target["modules"] = [m for m in target.get("modules") or [] if m.get("id") not in ids] + modules
    return build_info


# ── CLI ─────────────────────────────────────────────────────────────────────

def _parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("artifacts", nargs="+", help="Build artifacts to scan (zip/jar/war/tar.gz)")
    parser.add_argument("--build-number", required=True, help="Build number used in the module ids")
    parser.add_argument("--merge-into", help="Build-info JSON to append the modules to (rewritten in place unless --output)")
    parser.add_argument("--output", help="Write here instead of stdout")
    parser.add_argument("--first-party-scope", action="append", default=[],
                        help="npm scope to treat as first-party without a lookup (repeatable). By default "
                             "a package is first-party when its tarball is only in local repositories")
    parser.add_argument("--workers", type=int, default=12, help="Parallel AQL lookups (default 12, max 32)")
    return parser.parse_args(argv)


def _write(data: dict, path: str | None) -> None:
    text = json.dumps(data, indent=2) + "\n"
    if not path:
        sys.stdout.write(text)
        return
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    shutil.move(tmp, path)


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="[npm-buildinfo] %(message)s", stream=sys.stderr)
    args = _parse_args(argv)
    scopes = tuple(args.first_party_scope)

    try:
        sboms = find_embedded_sboms(args.artifacts)
    except ArchiveLimitError as exc:
        log.error("archive limit exceeded: %s", exc)
        return 2
    for sbom in sboms:
        log.info("found %s in %s!/%s", _root_name(sbom.bom) or "(unnamed app)", sbom.artifact, sbom.inner_path)

    wanted = sorted({p for s in sboms for p in npm_packages(s.bom) if not _is_first_party(p[0], scopes)})
    found, problems, first_party = ({}, {}, set())
    if wanted:
        found, problems, first_party = lookup_checksums(
            ArtifactoryClient.from_env(), wanted, min(args.workers, 32))

    modules, summary = build_modules(sboms, found, problems, args.build_number,
                                     first_party=first_party, first_party_scopes=scopes)
    log.info("%d SBOM(s), %d module(s), %d package(s): %d resolved, %d unresolved, %d first-party skipped",
             summary["sboms"], summary["modules"], summary["packages"], summary["resolved"],
             len(summary["unresolved"]), len(summary["first_party_skipped"]))
    for pkg, problem in summary["unresolved"].items():
        log.warning("unresolved %s: %s", pkg, problem)

    if args.merge_into:
        with open(args.merge_into, encoding="utf-8") as fh:
            build_info = json.load(fh)
        _write(merge_into_build_info(build_info, modules), args.output or args.merge_into)
    else:
        _write({"modules": modules, "summary": summary}, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
