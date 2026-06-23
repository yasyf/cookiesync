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


def test_helper_app_path_locates_the_cask_install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # brew installs the `app` cask into /Applications by default, or ~/Applications without
    # admin rights — helper_app_path() returns whichever appdir actually holds the bundle.
    system_apps, user_apps = tmp_path / "Applications", tmp_path / "home" / "Applications"
    (user_apps / paths.HELPER_APP).mkdir(parents=True)
    monkeypatch.setattr(paths, "cask_app_dirs", lambda: (system_apps, user_apps))
    assert paths.helper_app_path() == user_apps / paths.HELPER_APP
    assert paths.helper_binary() == user_apps / paths.HELPER_APP / "Contents" / "MacOS" / "cookiesync-keyhelper"


def test_helper_app_path_falls_back_to_the_default_appdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Nothing installed yet: report the default (first) appdir so errors point somewhere stable.
    system_apps, user_apps = tmp_path / "Applications", tmp_path / "home" / "Applications"
    monkeypatch.setattr(paths, "cask_app_dirs", lambda: (system_apps, user_apps))
    assert paths.helper_app_path() == system_apps / paths.HELPER_APP


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
