"""Tests for the brew-cask key-helper install and Developer-ID classification.

``install_helper`` shells out to ``brew install --cask`` and then re-verifies the
installed bundle's Developer-ID anchor; both seams (the brew subprocess and the codesign
check) are doubled, while the fail-closed contract — refuse a missing brew, a failed
install, a missing bundle, or a non-Developer-ID anchor — runs for real.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from cookiesync import helper, paths
from cookiesync.helper import HelperInstallError, HelperState

if TYPE_CHECKING:
    from collections.abc import Sequence

BREW = "/opt/homebrew/bin/brew"


def _patch_brew(monkeypatch: pytest.MonkeyPatch, *, present: bool = True, returncode: int = 0) -> list[list[str]]:
    monkeypatch.setattr(helper.shutil, "which", lambda name: BREW if present and name == "brew" else None)
    calls: list[list[str]] = []

    async def fake_run(
        command: Sequence[str], *, check: bool = True, **_: object
    ) -> subprocess.CompletedProcess[bytes]:
        calls.append(list(command))
        return subprocess.CompletedProcess(list(command), returncode, stdout=b"", stderr=b"brew: install failed")

    monkeypatch.setattr(helper.anyio, "run_process", fake_run)
    return calls


def _patch_signature(monkeypatch: pytest.MonkeyPatch, *, signed: bool) -> None:
    async def fake_signed(_app: Path) -> bool:
        return signed

    monkeypatch.setattr(helper, "developer_id_signed", fake_signed)


def _installed_app(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    app = tmp_path / "Applications" / "cookiesync-keyhelper.app"
    (app / "Contents" / "MacOS").mkdir(parents=True)
    monkeypatch.setattr(paths, "helper_app_path", lambda: app)
    return app


async def test_install_helper_runs_brew_and_verifies_anchor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    app = _installed_app(monkeypatch, tmp_path)
    calls = _patch_brew(monkeypatch)
    _patch_signature(monkeypatch, signed=True)

    assert await helper.install_helper() == app
    assert calls == [[BREW, "install", "--cask", helper.BREW_CASK]]


async def test_install_helper_fails_loud_without_brew(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_brew(monkeypatch, present=False)

    with pytest.raises(HelperInstallError, match="Homebrew is required"):
        await helper.install_helper()


async def test_install_helper_fails_loud_when_brew_install_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_brew(monkeypatch, returncode=1)

    with pytest.raises(HelperInstallError, match="brew install"):
        await helper.install_helper()


async def test_install_helper_fails_loud_when_bundle_absent_after_install(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(paths, "helper_app_path", lambda: tmp_path / "Applications" / "cookiesync-keyhelper.app")
    _patch_brew(monkeypatch)
    _patch_signature(monkeypatch, signed=True)

    with pytest.raises(HelperInstallError, match="no bundle is present"):
        await helper.install_helper()


async def test_install_helper_refuses_non_developer_id_bundle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _installed_app(monkeypatch, tmp_path)
    _patch_brew(monkeypatch)
    _patch_signature(monkeypatch, signed=False)

    with pytest.raises(HelperInstallError, match="not Developer-ID-signed"):
        await helper.install_helper()


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
    # codesign takes the requirement inline as `-R=<req>`; passing it as a separate
    # `-R`, `<req>` makes codesign read the requirement as a (missing) file and reject
    # every bundle, so the exact `-R=` form is the regression guard.
    assert f"-R={helper.DEVELOPER_ID_REQUIREMENT}" in argv
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
