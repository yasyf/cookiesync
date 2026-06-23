"""Fetch, verify, and classify the signed Secure-Enclave key helper ``.app``.

``cookiesync install`` downloads the latest ``helper-v*`` GitHub release asset
(``cookiesync-keyhelper-*-darwin.zip`` plus its ``.sha256``), verifies the checksum,
asserts the bundle carries a valid Developer-ID anchor, and only then unzips it into
:func:`cookiesync.paths.data_dir`. An ad-hoc, unsigned, or wrong-anchor bundle is
refused — never installed, never executed before the anchor check passes — because
macOS 15/26 SIGKILL an ad-hoc signature at exec and refuse it the Secure Enclave.

The Developer-ID anchor check is the same designated-requirement OID
(``1.2.840.113635.100.6.2.6``) the release workflow seals against, so a bundle that
``codesign --verify --strict`` would pass on its own (e.g. an ad-hoc signature) still
classifies as ``UNSIGNED`` here.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import urllib.request
import zipfile
from enum import Enum
from fnmatch import fnmatch
from pathlib import Path
from typing import TYPE_CHECKING

import anyio

from cookiesync import paths

if TYPE_CHECKING:
    from collections.abc import Iterable

GITHUB_REPO = "yasyf/cookiesync"
CODESIGN = "/usr/bin/codesign"
DEVELOPER_ID_REQUIREMENT = "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
HELPER_TAG_PREFIX = "helper-v"
HELPER_ASSET_GLOB = "cookiesync-keyhelper-*-darwin.zip"
GITHUB_API = "https://api.github.com"


class HelperState(Enum):
    OK = "ok"
    UNSIGNED = "unsigned"
    MISSING = "missing"


class HelperInstallError(Exception):
    """The signed key helper could not be fetched, verified, or installed."""


async def developer_id_signed(app_path: Path) -> bool:
    """Whether ``app_path`` has an intact signature anchored to Apple's Developer ID.

    Runs ``codesign --verify --strict`` with the Developer-ID designated-requirement
    OID, so an ad-hoc or wrong-anchor signature (which a bare ``--verify`` would accept)
    returns ``False``.
    """
    result = await anyio.run_process(
        [CODESIGN, "--verify", "--strict", "-R", DEVELOPER_ID_REQUIREMENT, str(app_path)],
        check=False,
    )
    return result.returncode == 0


async def helper_state() -> HelperState:
    """Classify the installed key helper as ``OK`` (Developer-ID signed), ``UNSIGNED``, or ``MISSING``."""
    if not paths.helper_binary().is_file():
        return HelperState.MISSING
    return HelperState.OK if await developer_id_signed(paths.helper_app_path()) else HelperState.UNSIGNED


async def install_helper() -> Path:
    """Fetch, verify, and install the signed Secure-Enclave key helper into the data dir.

    Downloads the latest ``helper-v*`` release's ``cookiesync-keyhelper-*-darwin.zip``
    asset and its ``.sha256``, verifies the checksum, asserts the unzipped bundle is
    Developer-ID signed, and only then moves it into :func:`cookiesync.paths.data_dir`,
    replacing any prior install. Raises :class:`HelperInstallError` on any failure: an
    unverified bundle is never installed, and the downloaded binary is never executed
    before the anchor check passes.

    Returns:
        The installed ``cookiesync-keyhelper.app`` path.
    """
    app_path = paths.helper_app_path()
    data_dir = paths.data_dir()
    await anyio.Path(data_dir).mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(dir=data_dir))
    try:
        zip_path, sha_path = await download_helper_release(staging)
        await verify_checksum(zip_path, sha_path)
        bundle = await extract_bundle(zip_path, staging / "extracted")
        if not await developer_id_signed(bundle):
            raise HelperInstallError(
                f"refusing to install {bundle.name}: it is not Developer-ID-signed "
                "(codesign --verify --strict and the Developer-ID anchor must both pass)"
            )
        if await anyio.Path(app_path).exists():
            shutil.rmtree(app_path)
        shutil.move(str(bundle), str(app_path))
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return app_path


async def verify_checksum(zip_path: Path, sha_path: Path) -> None:
    expected = (await anyio.Path(sha_path).read_text()).split()[0].strip()
    digest = hashlib.sha256(await anyio.Path(zip_path).read_bytes()).hexdigest()
    if digest != expected:
        raise HelperInstallError(f"checksum mismatch for {zip_path.name}: expected {expected}, got {digest}")


async def extract_bundle(zip_path: Path, dest: Path) -> Path:
    await anyio.to_thread.run_sync(lambda: _unzip(zip_path, dest))
    match sorted(dest.glob("*.app")):
        case [bundle]:
            return bundle
        case found:
            raise HelperInstallError(f"expected exactly one .app in {zip_path.name}, found {len(found)}")


async def download_helper_release(dest: Path) -> tuple[Path, Path]:
    if shutil.which("gh"):
        await _download_via_gh(dest)
    else:
        await _download_via_api(dest)
    return _locate_assets(dest)


def _unzip(zip_path: Path, dest: Path) -> None:
    with zipfile.ZipFile(zip_path) as archive:
        archive.extractall(dest)
    for binary in dest.glob("*.app/Contents/MacOS/*"):
        binary.chmod(binary.stat().st_mode | 0o111)


def _locate_assets(dest: Path) -> tuple[Path, Path]:
    match sorted(dest.glob(HELPER_ASSET_GLOB)):
        case [zip_path] if (sha_path := zip_path.with_name(f"{zip_path.name}.sha256")).is_file():
            return zip_path, sha_path
        case [zip_path]:
            raise HelperInstallError(f"missing checksum file {zip_path.name}.sha256 in the release")
        case found:
            raise HelperInstallError(f"expected exactly one helper asset in the release, found {len(found)}")


def _select_helper_tag(tags: Iterable[str]) -> str:
    match next((tag for tag in tags if tag.startswith(HELPER_TAG_PREFIX)), None):
        case None:
            raise HelperInstallError(
                f"no {HELPER_TAG_PREFIX}* release published for {GITHUB_REPO} yet; cannot fetch the signed helper"
            )
        case tag:
            return tag


async def _download_via_gh(dest: Path) -> None:
    tag = _select_helper_tag(await _gh_release_tags())
    result = await anyio.run_process(
        [
            "gh",
            "release",
            "download",
            tag,
            "--repo",
            GITHUB_REPO,
            "--pattern",
            HELPER_ASSET_GLOB,
            "--pattern",
            f"{HELPER_ASSET_GLOB}.sha256",
            "--dir",
            str(dest),
        ],
        check=False,
    )
    if result.returncode != 0:
        raise HelperInstallError(f"gh release download {tag} failed: {result.stderr.decode().strip()}")


async def _gh_release_tags() -> list[str]:
    result = await anyio.run_process(["gh", "release", "list", "--repo", GITHUB_REPO, "--json", "tagName"], check=False)
    if result.returncode != 0:
        raise HelperInstallError(f"could not list {GITHUB_REPO} releases via gh: {result.stderr.decode().strip()}")
    return [entry["tagName"] for entry in json.loads(result.stdout)]


async def _download_via_api(dest: Path) -> None:
    releases = await _get_json(f"{GITHUB_API}/repos/{GITHUB_REPO}/releases?per_page=50")
    match next((r for r in releases if str(r["tag_name"]).startswith(HELPER_TAG_PREFIX)), None):
        case None:
            raise HelperInstallError(
                f"no {HELPER_TAG_PREFIX}* release published for {GITHUB_REPO} yet; cannot fetch the signed helper"
            )
        case release:
            for asset in release["assets"]:
                if fnmatch(asset["name"], HELPER_ASSET_GLOB) or fnmatch(asset["name"], f"{HELPER_ASSET_GLOB}.sha256"):
                    await anyio.Path(dest / asset["name"]).write_bytes(await _get_bytes(asset["browser_download_url"]))


async def _get_json(url: str) -> list:
    return json.loads(await _get_bytes(url))


async def _get_bytes(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"})
    return await anyio.to_thread.run_sync(lambda: _read(request))


def _read(request: urllib.request.Request) -> bytes:
    with urllib.request.urlopen(request) as response:
        return response.read()
