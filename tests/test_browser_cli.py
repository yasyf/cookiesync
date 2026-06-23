"""End-to-end tests for the ``cookiesync browser`` CLI.

Each command is run as its own ``cookiesync`` subprocess — the way the CLI is used in
practice (one short-lived process per invocation) — against an isolated
``XDG_CONFIG_HOME`` and a fake ``reposync`` on ``PATH`` that emits canned ``--json``
envelopes. Running each command in its own process keeps the real :func:`state.update`
filelock exercised end to end without the cross-process lock leaking across calls.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

COOKIESYNC = Path(sys.executable).with_name("cookiesync")

SELF = "yasyf@yasyf"
PEERS = ("yasyf@yasyf-home", "yasyf@yasyf-work")

FAKE_REPOSYNC = f"""#!/usr/bin/env python3
import json, sys
args = sys.argv[1:]
if args == ["self", "--json"]:
    print(json.dumps({{"version": 1, "self": {SELF!r}}}))
elif args == ["host", "ls", "--json"]:
    print(json.dumps({{"version": 1, "self": {SELF!r}, "hosts": {list(PEERS)!r}}}))
else:
    sys.exit(f"fake reposync: unexpected args {{args}}")
"""


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    (config := tmp_path / "config").mkdir()
    (bindir := tmp_path / "bin").mkdir()
    (shim := bindir / "reposync").write_text(FAKE_REPOSYNC)
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return os.environ | {
        "XDG_CONFIG_HOME": str(config),
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
    }


def run(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(COOKIESYNC), *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def state_file(env: dict[str, str]) -> Path:
    return Path(env["XDG_CONFIG_HOME"]) / "cookiesync" / "state.json"


def saved_browsers(env: dict[str, str]) -> list[dict[str, str]]:
    return json.loads(state_file(env).read_text())["browsers"]


def test_add_writes_endpoint_for_self(env: dict[str, str]) -> None:
    result = run(env, "browser", "add", "yasyf@yasyf", "chrome")

    assert result.returncode == 0, result.stderr
    assert "yasyf@yasyf:chrome:Default" in result.stdout
    assert saved_browsers(env) == [{"host": "yasyf@yasyf", "browser": "chrome", "profile": "Default"}]
    assert json.loads(state_file(env).read_text())["self_target"] == "yasyf@yasyf"


def test_add_writes_endpoint_for_peer_with_profile(env: dict[str, str]) -> None:
    result = run(env, "browser", "add", "yasyf@yasyf-home", "arc", "--profile", "Work")

    assert result.returncode == 0, result.stderr
    assert saved_browsers(env) == [{"host": "yasyf@yasyf-home", "browser": "arc", "profile": "Work"}]


def test_add_dedupes_by_id(env: dict[str, str]) -> None:
    run(env, "browser", "add", "yasyf@yasyf", "chrome")
    result = run(env, "browser", "add", "yasyf@yasyf", "chrome")

    assert result.returncode == 0, result.stderr
    assert saved_browsers(env) == [{"host": "yasyf@yasyf", "browser": "chrome", "profile": "Default"}]


def test_add_unknown_host_errors(env: dict[str, str]) -> None:
    result = run(env, "browser", "add", "stranger@nowhere", "chrome")

    assert result.returncode != 0
    assert "unknown host" in result.stderr
    assert not state_file(env).exists()


def test_add_unknown_browser_errors(env: dict[str, str]) -> None:
    result = run(env, "browser", "add", "yasyf@yasyf", "netscape")

    assert result.returncode != 0
    assert "unknown browser" in result.stderr
    assert not state_file(env).exists()


def test_ls_json_round_trips(env: dict[str, str]) -> None:
    run(env, "browser", "add", "yasyf@yasyf", "chrome")
    run(env, "browser", "add", "yasyf@yasyf-home", "arc", "--profile", "Work")

    result = run(env, "browser", "ls", "--json")

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [
        {"host": "yasyf@yasyf", "browser": "chrome", "profile": "Default"},
        {"host": "yasyf@yasyf-home", "browser": "arc", "profile": "Work"},
    ]


def test_ls_human_lists_ids(env: dict[str, str]) -> None:
    run(env, "browser", "add", "yasyf@yasyf", "chrome")

    result = run(env, "browser", "ls")

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "yasyf@yasyf:chrome:Default"


def test_ls_empty_reports_none(env: dict[str, str]) -> None:
    result = run(env, "browser", "ls")

    assert result.returncode == 0, result.stderr
    assert "No tracked browsers." in result.stdout


def test_add_surfaces_reposync_failure_cleanly(tmp_path: Path) -> None:
    (config := tmp_path / "config").mkdir()
    (bindir := tmp_path / "bin").mkdir()
    (shim := bindir / "reposync").write_text("#!/bin/sh\necho 'unknown flag: --json' >&2\nexit 1\n")
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    env = os.environ | {"XDG_CONFIG_HOME": str(config), "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"}

    result = run(env, "browser", "add", "yasyf@yasyf", "chrome")

    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert "reposync host ls --json failed" in result.stderr
    assert "unknown flag: --json" in result.stderr


def test_rm_removes_matching_endpoint(env: dict[str, str]) -> None:
    run(env, "browser", "add", "yasyf@yasyf", "chrome")
    run(env, "browser", "add", "yasyf@yasyf-home", "arc", "--profile", "Work")

    result = run(env, "browser", "rm", "yasyf@yasyf", "chrome")

    assert result.returncode == 0, result.stderr
    assert "yasyf@yasyf:chrome:Default" in result.stdout
    assert saved_browsers(env) == [{"host": "yasyf@yasyf-home", "browser": "arc", "profile": "Work"}]
