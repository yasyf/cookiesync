"""Tests for the signed key-helper fetch/verify/install and Developer-ID classification.

The network fetch (``download_helper_release``) and the macOS signature check
(``developer_id_signed``) are the only OS-specific seams, so they are doubled; the
security-critical core — sha256 verification, unzip, and the refuse-unless-signed
gate — runs for real against a hand-built zip, with no macOS binary invoked.
"""

from __future__ import annotations

import hashlib
import subprocess
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from cookiesync import helper, paths
from cookiesync.helper import HelperInstallError, HelperState

if TYPE_CHECKING:
    from collections.abc import Sequence

ASSET = "cookiesync-keyhelper-v1.2.3-darwin.zip"
BINARY_ENTRY = "cookiesync-keyhelper.app/Contents/MacOS/cookiesync-keyhelper"


def _build_zip(zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("cookiesync-keyhelper.app/Contents/Info.plist", "<plist/>")
        archive.writestr(BINARY_ENTRY, "#!/bin/sh\nexit 0\n")


def _release_into(dest: Path, *, checksum: str | None = None) -> tuple[Path, Path]:
    zip_path = dest / ASSET
    _build_zip(zip_path)
    digest = checksum or hashlib.sha256(zip_path.read_bytes()).hexdigest()
    sha_path = dest / f"{ASSET}.sha256"
    sha_path.write_text(f"{digest}  {ASSET}\n")
    return zip_path, sha_path


@pytest.fixture
def data_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    return tmp_path / "xdg" / "cookiesync"


def _patch_download(monkeypatch: pytest.MonkeyPatch, *, checksum: str | None = None) -> None:
    async def fake_download(dest: Path) -> tuple[Path, Path]:
        return _release_into(dest, checksum=checksum)

    monkeypatch.setattr(helper, "download_helper_release", fake_download)


def _patch_signature(monkeypatch: pytest.MonkeyPatch, *, signed: bool) -> None:
    async def fake_signed(_app: Path) -> bool:
        return signed

    monkeypatch.setattr(helper, "developer_id_signed", fake_signed)


async def test_install_helper_verifies_and_installs(monkeypatch: pytest.MonkeyPatch, data_home: Path) -> None:
    _patch_download(monkeypatch)
    _patch_signature(monkeypatch, signed=True)

    app = await helper.install_helper()

    assert app == paths.helper_app_path() == data_home / "cookiesync-keyhelper.app"
    assert paths.helper_binary().is_file()
    assert paths.helper_binary().read_text().startswith("#!/bin/sh")
    # The staging temp dir is swept; only the installed bundle remains.
    assert [p.name for p in data_home.iterdir()] == ["cookiesync-keyhelper.app"]


async def test_install_helper_refuses_unsigned_bundle(monkeypatch: pytest.MonkeyPatch, data_home: Path) -> None:
    _patch_download(monkeypatch)
    _patch_signature(monkeypatch, signed=False)

    with pytest.raises(HelperInstallError, match="not Developer-ID-signed"):
        await helper.install_helper()

    assert not paths.helper_app_path().exists()


async def test_install_helper_refuses_bad_checksum(monkeypatch: pytest.MonkeyPatch, data_home: Path) -> None:
    _patch_download(monkeypatch, checksum="0" * 64)
    # Signature would pass, but the checksum gate must trip first and never reach it.
    _patch_signature(monkeypatch, signed=True)

    with pytest.raises(HelperInstallError, match="checksum mismatch"):
        await helper.install_helper()

    assert not paths.helper_app_path().exists()


def test_select_helper_tag_picks_the_latest_helper_release() -> None:
    assert helper._select_helper_tag(["v2.0.0", "helper-v1.4.0", "helper-v1.3.0"]) == "helper-v1.4.0"


def test_select_helper_tag_fails_loud_when_no_helper_release() -> None:
    with pytest.raises(HelperInstallError, match="no helper-v"):
        helper._select_helper_tag(["v2.0.0", "v1.0.0"])


async def test_developer_id_signed_evaluates_the_developer_id_anchor(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[list[str]] = []

    async def fake(command: Sequence[str], *, check: bool = True, **_: object) -> subprocess.CompletedProcess[bytes]:
        captured.append(list(command))
        return subprocess.CompletedProcess(list(command), 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(helper.anyio, "run_process", fake)

    assert await helper.developer_id_signed(Path("/x/cookiesync-keyhelper.app")) is True
    argv = captured[0]
    assert argv[0] == helper.CODESIGN
    assert "--verify" in argv and "--strict" in argv
    assert "-R" in argv and helper.DEVELOPER_ID_REQUIREMENT in argv
    assert "1.2.840.113635.100.6.2.6" in helper.DEVELOPER_ID_REQUIREMENT


async def test_helper_state_reports_unsigned_for_an_adhoc_bundle(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # An ad-hoc bundle passes a bare `codesign --verify --strict` but fails the anchor
    # requirement (nonzero exit), so it must classify as UNSIGNED, never OK.
    binary = tmp_path / "cookiesync-keyhelper.app" / "Contents" / "MacOS" / "cookiesync-keyhelper"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\n")
    monkeypatch.setattr(paths, "helper_binary", lambda: binary)
    monkeypatch.setattr(paths, "helper_app_path", lambda: tmp_path / "cookiesync-keyhelper.app")

    async def adhoc(_command: Sequence[str], *, check: bool = True, **_: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(["codesign"], 3, stdout=b"", stderr=b"requirement not satisfied")

    monkeypatch.setattr(helper.anyio, "run_process", adhoc)

    assert await helper.helper_state() == HelperState.UNSIGNED


async def test_helper_state_missing_when_no_binary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(paths, "helper_binary", lambda: tmp_path / "absent" / "cookiesync-keyhelper")
    assert await helper.helper_state() == HelperState.MISSING
