from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from cookiesync import cli, paths
from cookiesync.cli import main

if TYPE_CHECKING:
    from collections.abc import Sequence


def test_help_exits_cleanly() -> None:
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    assert result.output.startswith("Usage: main")


def test_help_lists_daemon_commands() -> None:
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    for command in ("watch", "install", "uninstall", "reconcile", "sync", "auth", "cookies", "rpc", "self", "doctor"):
        assert command in result.output


def test_hello_is_gone() -> None:
    result = CliRunner().invoke(main, ["hello"])
    assert result.exit_code != 0


def _codesign_returns(monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    async def fake(command: Sequence[str], *, check: bool = True, **_: object) -> subprocess.CompletedProcess[bytes]:
        assert list(command)[0] == cli.CODESIGN
        return subprocess.CompletedProcess(list(command), code, stdout=b"", stderr=b"")

    monkeypatch.setattr(cli.anyio, "run_process", fake)


def _install_helper(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    binary = tmp_path / "cookiesync-keyhelper.app" / "Contents" / "MacOS" / "cookiesync-keyhelper"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\n")
    monkeypatch.setattr(paths, "helper_binary", lambda: binary)
    monkeypatch.setattr(paths, "helper_app_path", lambda: tmp_path / "cookiesync-keyhelper.app")
    return binary


def test_doctor_reports_ok_when_helper_signed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_helper(monkeypatch, tmp_path)
    _codesign_returns(monkeypatch, 0)
    result = CliRunner().invoke(main, ["doctor"])
    assert result.exit_code == 0
    assert "key helper OK" in result.output


def test_doctor_fails_when_helper_unsigned(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_helper(monkeypatch, tmp_path)
    _codesign_returns(monkeypatch, 1)
    result = CliRunner().invoke(main, ["doctor"])
    assert result.exit_code != 0
    assert "not Developer-ID-signed" in result.output


def test_doctor_fails_when_helper_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(paths, "helper_binary", lambda: tmp_path / "absent" / "cookiesync-keyhelper")
    monkeypatch.setattr(paths, "helper_app_path", lambda: tmp_path / "absent")
    result = CliRunner().invoke(main, ["doctor"])
    assert result.exit_code != 0
    assert "cookiesync install" in result.output
