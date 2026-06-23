from __future__ import annotations

from pathlib import Path

import pytest

from cookiesync import paths
from cookiesync.paths import HelperError


def test_data_dir_honors_xdg_data_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", "/xdg/data")
    assert paths.data_dir() == Path("/xdg/data/cookiesync")


def test_data_dir_falls_back_to_local_share(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda _: Path("/home/me")))
    assert paths.data_dir() == Path("/home/me/.local/share/cookiesync")


def test_helper_binary_points_at_the_inner_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", "/xdg/data")
    assert paths.helper_app_path() == Path("/xdg/data/cookiesync/cookiesync-keyhelper.app")
    assert paths.helper_binary() == Path(
        "/xdg/data/cookiesync/cookiesync-keyhelper.app/Contents/MacOS/cookiesync-keyhelper"
    )


def test_require_helper_returns_binary_when_installed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "cookiesync-keyhelper.app" / "Contents" / "MacOS" / "cookiesync-keyhelper"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\n")
    monkeypatch.setattr(paths, "helper_binary", lambda: binary)
    assert paths.require_helper() == binary


def test_require_helper_fails_closed_when_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(paths, "helper_binary", lambda: tmp_path / "absent" / "cookiesync-keyhelper")
    with pytest.raises(HelperError, match="cookiesync install"):
        paths.require_helper()
