from __future__ import annotations

import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner

from cookiesync import helper, paths, service
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


def test_version_resolves_the_distribution_name() -> None:
    # --version reads installed distribution metadata; the dist is `cookiesync-cli`
    # while the import package is `cookiesync`, so version_option must name the
    # distribution explicitly or Click raises "'cookiesync' is not installed".
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0, result.output
    assert result.exception is None
    assert "version" in result.output


def _helper_processes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    codesign: int,
    probe: tuple[int, bytes] = (0, b"biometry=false passcode=false vault=false\n"),
) -> list[list[str]]:
    # doctor shells out to codesign (signature) and then the helper binary (`vault-status`
    # contract probe). Route each by argv: codesign returns `codesign`, the probe returns
    # `probe`.
    calls: list[list[str]] = []

    async def fake(command: Sequence[str], *, check: bool = True, **_: object) -> subprocess.CompletedProcess[bytes]:
        argv = list(command)
        calls.append(argv)
        match argv:
            case [helper.CODESIGN, *_]:
                return subprocess.CompletedProcess(argv, codesign, stdout=b"", stderr=b"")
            case [_, "vault-status", helper.PROBE_VAULT]:
                code, stdout = probe
                return subprocess.CompletedProcess(argv, code, stdout=stdout, stderr=b"")
            case _:
                raise AssertionError(f"unexpected helper invocation: {argv}")

    monkeypatch.setattr(helper.anyio, "run_process", fake)
    return calls


def _install_helper(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    binary = tmp_path / "cookiesync-keyhelper.app" / "Contents" / "MacOS" / "cookiesync-keyhelper"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\n")
    monkeypatch.setattr(paths, "helper_binary", lambda: binary)
    monkeypatch.setattr(paths, "helper_app_path", lambda: tmp_path / "cookiesync-keyhelper.app")
    return binary


def test_doctor_reports_ok_when_helper_signed_and_contract_supported(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install_helper(monkeypatch, tmp_path)
    _helper_processes(monkeypatch, codesign=0, probe=(0, b"biometry=true passcode=true vault=false\n"))
    result = CliRunner().invoke(main, ["doctor"])
    assert result.exit_code == 0
    assert "key helper OK" in result.output
    assert "key-helper contract supported" in result.output


def test_doctor_fails_when_helper_contract_unsupported(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # A stale cask: the bundle is present and Developer-ID-signed, but `vault-status` predates
    # the contract — nonzero exit or a stdout line that doesn't match the documented shape.
    _install_helper(monkeypatch, tmp_path)
    _helper_processes(monkeypatch, codesign=0, probe=(0, b"usage: cookiesync-keyhelper <command>\n"))
    result = CliRunner().invoke(main, ["doctor"])
    assert result.exit_code != 0
    assert "does not support the required" in result.output
    assert "cookiesync install" in result.output


def test_doctor_fails_when_helper_unsigned(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _install_helper(monkeypatch, tmp_path)
    _helper_processes(monkeypatch, codesign=1)
    result = CliRunner().invoke(main, ["doctor"])
    assert result.exit_code != 0
    assert "not Developer-ID-signed" in result.output


def test_doctor_fails_when_helper_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(paths, "helper_binary", lambda: tmp_path / "absent" / "cookiesync-keyhelper")
    monkeypatch.setattr(paths, "helper_app_path", lambda: tmp_path / "absent")
    result = CliRunner().invoke(main, ["doctor"])
    assert result.exit_code != 0
    assert "cookiesync install" in result.output


def test_install_fetches_helper_via_brew_then_installs_agents(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # `cookiesync install` finds no signed helper, so it shells out to brew to install the
    # cask, re-verifies the Developer-ID anchor, then lays down the LaunchAgents.
    app = tmp_path / "Applications" / "cookiesync-keyhelper.app"
    (app / "Contents" / "MacOS").mkdir(parents=True)  # bundle dir exists; inner binary does not yet
    monkeypatch.setattr(paths, "helper_app_path", lambda: app)
    monkeypatch.setattr(paths, "helper_binary", lambda: app / "Contents" / "MacOS" / "cookiesync-keyhelper")
    monkeypatch.setattr(helper.shutil, "which", lambda name: "/opt/homebrew/bin/brew")

    brew_calls: list[list[str]] = []

    async def fake_run(
        command: Sequence[str], *, check: bool = True, **_: object
    ) -> subprocess.CompletedProcess[bytes]:
        brew_calls.append(list(command))
        return subprocess.CompletedProcess(list(command), 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(helper.anyio, "run_process", fake_run)

    async def signed(_app: Path) -> bool:
        return True

    monkeypatch.setattr(helper, "developer_id_signed", signed)

    agents: list[bool] = []

    async def fake_service_install(_launcher: object, *, tick_only: bool = False) -> None:
        agents.append(tick_only)

    monkeypatch.setattr(service, "install", fake_service_install)
    monkeypatch.setattr(service, "LaunchctlLauncher", lambda: object())

    result = CliRunner().invoke(main, ["install"])

    assert result.exit_code == 0, result.output
    assert agents == [False]
    assert brew_calls == [["/opt/homebrew/bin/brew", "install", "--cask", helper.BREW_CASK]]


def test_doctor_signature_check_uses_developer_id_anchor(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # M1: an ad-hoc bundle passes a bare `codesign --verify --strict`; doctor must instead
    # assert the Developer-ID anchor OID, so the check fails OPEN for ad-hoc signatures.
    _install_helper(monkeypatch, tmp_path)
    calls = _helper_processes(monkeypatch, codesign=0)
    CliRunner().invoke(main, ["doctor"])
    assert calls, "doctor never ran codesign"
    argv = calls[0]
    assert "-R" in argv
    assert helper.DEVELOPER_ID_REQUIREMENT in argv
    assert "1.2.840.113635.100.6.2.6" in helper.DEVELOPER_ID_REQUIREMENT
