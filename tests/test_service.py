from __future__ import annotations

import plistlib
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from cookiesync import service
from cookiesync.service import (
    DAEMON_PATH,
    RECONCILE_AGENT,
    RECONCILE_LABEL,
    SESSION_TYPE,
    WATCH_AGENT,
    WATCH_LABEL,
    Label,
    LaunchctlLauncher,
    ServiceError,
    install,
    plist_path,
    uninstall,
    write_plist,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

pytestmark = pytest.mark.anyio

INSTALLED_BIN = "/opt/homebrew/bin/cookiesync"


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


@pytest.fixture(autouse=True)
def installed_bin(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(service.shutil, "which", lambda name: INSTALLED_BIN if name == "cookiesync" else None)
    return INSTALLED_BIN


class FakeLauncher:
    def __init__(self) -> None:
        self.bootstrapped: list[Path] = []
        self.booted_out: list[Label] = []

    async def bootstrap(self, plist: Path) -> None:
        self.bootstrapped.append(plist)

    async def bootout(self, label: Label) -> None:
        self.booted_out.append(label)


@pytest.mark.parametrize(
    ("agent", "label", "command", "unique_key", "unique_value", "absent_key"),
    [
        pytest.param(RECONCILE_AGENT, RECONCILE_LABEL, "reconcile", "StartInterval", 900, "KeepAlive", id="reconcile"),
        pytest.param(WATCH_AGENT, WATCH_LABEL, "watch", "KeepAlive", True, "StartInterval", id="watch"),
    ],
)
def test_plist_golden_keys(
    agent: service.AgentSpec,
    label: Label,
    command: str,
    unique_key: str,
    unique_value: object,
    absent_key: str,
) -> None:
    parsed = plistlib.loads(agent.render())

    assert parsed["Label"] == label
    assert parsed["ProgramArguments"] == [INSTALLED_BIN, command]
    assert parsed["EnvironmentVariables"]["PATH"] == DAEMON_PATH
    assert "/opt/homebrew/bin" in parsed["EnvironmentVariables"]["PATH"].split(":")
    assert parsed["LimitLoadToSessionType"] == SESSION_TYPE == "Aqua"
    assert parsed["RunAtLoad"] is True
    assert parsed[unique_key] == unique_value
    assert absent_key not in parsed


def test_reconcile_has_no_keepalive_and_watch_has_no_interval() -> None:
    reconcile = plistlib.loads(RECONCILE_AGENT.render())
    watch = plistlib.loads(WATCH_AGENT.render())

    assert reconcile["StartInterval"] == 900
    assert "KeepAlive" not in reconcile
    assert watch["KeepAlive"] is True
    assert "StartInterval" not in watch


def test_program_path_is_not_symlink_resolved(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    target = tmp_path / "cookiesync-0.4.2"
    target.write_text("#!/bin/sh\n")
    symlink = tmp_path / "cookiesync"
    symlink.symlink_to(target)
    monkeypatch.setattr(service.shutil, "which", lambda name: str(symlink))

    parsed = plistlib.loads(WATCH_AGENT.render())

    # The stable symlink survives verbatim; resolving it would bake the versioned
    # target a uv/brew upgrade purges.
    assert parsed["ProgramArguments"][0] == str(symlink)
    assert parsed["ProgramArguments"][0] != str(target)
    assert service.program_path() == str(symlink)


def test_program_path_falls_back_to_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service.shutil, "which", lambda name: None)
    monkeypatch.setenv("COOKIESYNC_BIN", "/custom/cookiesync")

    assert service.program_path() == "/custom/cookiesync"


def test_program_path_crashes_when_unresolvable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service.shutil, "which", lambda name: None)
    monkeypatch.delenv("COOKIESYNC_BIN", raising=False)

    with pytest.raises(KeyError):
        service.program_path()


async def test_write_plist_writes_to_launch_agents(home: Path) -> None:
    path = await write_plist(WATCH_LABEL, ["watch"])

    assert path == home / "Library" / "LaunchAgents" / "com.github.yasyf.cookiesync.watch.plist"
    assert path.exists()
    assert plistlib.loads(path.read_bytes())["ProgramArguments"] == [INSTALLED_BIN, "watch"]


async def test_write_plist_rejects_mismatched_command(home: Path) -> None:
    with pytest.raises(ServiceError, match="runs 'watch'"):
        await write_plist(WATCH_LABEL, ["reconcile"])


async def test_install_writes_both_plists_and_loads_them(home: Path) -> None:
    launcher = FakeLauncher()

    await install(launcher)

    reconcile = plist_path(RECONCILE_LABEL)
    watch = plist_path(WATCH_LABEL)
    assert reconcile.exists()
    assert watch.exists()
    # Each agent is booted out before bootstrap so a re-install picks up plist changes.
    assert launcher.booted_out == [RECONCILE_LABEL, WATCH_LABEL]
    assert launcher.bootstrapped == [reconcile, watch]


async def test_install_tick_only_skips_watch(home: Path) -> None:
    launcher = FakeLauncher()

    await install(launcher, tick_only=True)

    assert plist_path(RECONCILE_LABEL).exists()
    assert not plist_path(WATCH_LABEL).exists()
    assert launcher.booted_out == [RECONCILE_LABEL]
    assert launcher.bootstrapped == [plist_path(RECONCILE_LABEL)]


async def test_uninstall_boots_out_both_and_removes_plists(home: Path) -> None:
    launcher = FakeLauncher()
    await install(launcher)
    assert plist_path(RECONCILE_LABEL).exists()

    await uninstall(launcher)

    assert not plist_path(RECONCILE_LABEL).exists()
    assert not plist_path(WATCH_LABEL).exists()
    assert set(launcher.booted_out[-2:]) == {RECONCILE_LABEL, WATCH_LABEL}


async def test_uninstall_tolerates_missing_plist(home: Path) -> None:
    launcher = FakeLauncher()

    await uninstall(launcher)

    assert set(launcher.booted_out) == {RECONCILE_LABEL, WATCH_LABEL}


class _Completed:
    def __init__(self, returncode: int, stderr: bytes) -> None:
        self.returncode = returncode
        self.stderr = stderr


class FakeLaunchctl:
    def __init__(self) -> None:
        self.calls: list[Sequence[str]] = []
        self.returncode = 0
        self.stderr = b""

    def fail(self, returncode: int, stderr: bytes) -> None:
        self.returncode = returncode
        self.stderr = stderr

    async def __call__(self, command: Sequence[str], *, check: bool = True, **kwargs: object) -> _Completed:
        self.calls.append(command)
        return _Completed(self.returncode, self.stderr)


@pytest.fixture
def launchctl(monkeypatch: pytest.MonkeyPatch, home: Path) -> FakeLaunchctl:
    monkeypatch.setattr(service.anyio, "run_process", fake := FakeLaunchctl())
    monkeypatch.setattr(service.os, "getuid", lambda: 501)
    return fake


async def test_launchctl_launcher_bootstrap_targets_gui_domain(launchctl: FakeLaunchctl) -> None:
    await LaunchctlLauncher().bootstrap(Path("/x/watch.plist"))

    assert launchctl.calls == [["launchctl", "bootstrap", "gui/501", "/x/watch.plist"]]


async def test_launchctl_launcher_bootout_targets_label_in_gui_domain(launchctl: FakeLaunchctl) -> None:
    await LaunchctlLauncher().bootout(WATCH_LABEL)

    assert launchctl.calls == [["launchctl", "bootout", f"gui/501/{WATCH_LABEL}"]]


async def test_bootstrap_tolerates_already_loaded(launchctl: FakeLaunchctl) -> None:
    launchctl.fail(5, b"service already loaded")

    await LaunchctlLauncher().bootstrap(Path("/x/watch.plist"))


async def test_bootout_tolerates_not_loaded(launchctl: FakeLaunchctl) -> None:
    launchctl.fail(3, b"Could not find specified service")

    await LaunchctlLauncher().bootout(WATCH_LABEL)


async def test_bootout_tolerates_modern_no_such_process(launchctl: FakeLaunchctl) -> None:
    # macOS 13+ reports a not-loaded bootout as exit 3 "Boot-out failed: 3: No such process",
    # not the pre-13 "Could not find specified service"; a fresh install must tolerate it.
    launchctl.fail(3, b"Boot-out failed: 3: No such process")

    await LaunchctlLauncher().bootout(WATCH_LABEL)


async def test_bootstrap_raises_on_other_failure(launchctl: FakeLaunchctl) -> None:
    launchctl.fail(1, b"Bootstrap failed: 5: Input/output error")

    with pytest.raises(ServiceError, match="Input/output error"):
        await LaunchctlLauncher().bootstrap(Path("/x/watch.plist"))
