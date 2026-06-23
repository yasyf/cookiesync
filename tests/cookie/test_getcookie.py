from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess
from typing import TYPE_CHECKING

import pytest

from cookiesync.cookie import getcookie
from cookiesync.cookie.getcookie import GetCookieError, command, fetch_cookies, parse
from cookiesync.cookie.models import Host, unix_to_chrome_micros

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

CANNED = [
    {
        "name": "session",
        "value": "deadbeef",
        "domain": ".github.com",
        "path": "/",
        "expiry": 1_900_000_000,
        "meta": {"secure": True, "httpOnly": True, "sameSite": "Lax"},
    },
    {"name": "csrf", "value": "tok123", "domain": "github.com"},
]

# get-cookie prints log lines to stdout before the JSON array; parse must skip them.
NOISY_STDOUT = f"[get-cookie] scanning Chrome...\n[get-cookie] scanning Safari...\n{json.dumps(CANNED)}\n"


class FakeRunProcess:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout.encode("utf-8")
        self.calls: list[Sequence[str]] = []

    async def __call__(self, command: Sequence[str], **kwargs: object) -> CompletedProcess[bytes]:
        self.calls.append(command)
        return CompletedProcess(args=command, returncode=0, stdout=self.stdout, stderr=b"")


@pytest.fixture
def installed(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    async def fake_ensure() -> Path:
        return Path("/cache/cookiesync/node_modules/@mherod/get-cookie/dist/cli.cjs")

    monkeypatch.setattr(getcookie, "ensure_installed", fake_ensure)
    monkeypatch.setattr(getcookie.shutil, "which", lambda name: f"/usr/bin/{name}" if name == "bun" else None)
    yield


def test_command_uses_cached_cli_and_sweeps_all_browsers(installed: None) -> None:
    async def go() -> list[str]:
        return await command(Host("github.com"))

    import anyio

    argv = anyio.run(go)
    assert argv == [
        "/usr/bin/bun",
        "/cache/cookiesync/node_modules/@mherod/get-cookie/dist/cli.cjs",
        "%",
        "github.com",
        "--output",
        "json",
    ]
    assert "--browser" not in argv  # deliberately omitted to sweep every browser


def test_command_falls_back_to_bunx(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_install() -> None:
        return None

    monkeypatch.setattr(getcookie, "ensure_installed", no_install)
    monkeypatch.setattr(getcookie.shutil, "which", lambda name: "/usr/bin/bunx" if name == "bunx" else None)

    import anyio

    argv = anyio.run(lambda: command(Host("github.com")))
    assert argv == ["/usr/bin/bunx", getcookie.PACKAGE, "%", "github.com", "--output", "json"]


def test_command_raises_when_no_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_install() -> None:
        return None

    monkeypatch.setattr(getcookie, "ensure_installed", no_install)
    monkeypatch.setattr(getcookie.shutil, "which", lambda name: None)

    import anyio

    with pytest.raises(GetCookieError, match="neither a cached get-cookie nor bun/bunx"):
        anyio.run(lambda: command(Host("github.com")))


async def test_fetch_cookies_normalizes_canned_json(installed: None, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRunProcess(json.dumps(CANNED))
    monkeypatch.setattr(getcookie.anyio, "run_process", fake)

    cookies = await fetch_cookies(Host("github.com"))

    assert [c.name for c in cookies] == ["session", "csrf"]
    session = cookies[0]
    assert session.host_key == ".github.com"
    assert session.value == "deadbeef"
    assert session.path == "/"
    assert session.is_secure is True
    assert session.is_httponly is True
    assert session.samesite == 1  # Lax
    assert session.expires_utc == unix_to_chrome_micros(1_900_000_000.0)
    # csrf has no domain/path/meta: domain falls back to host, defaults applied.
    csrf = cookies[1]
    assert csrf.host_key == "github.com"
    assert csrf.path == "/"
    assert csrf.samesite == 1


async def test_fetch_cookies_tolerates_leading_log_noise(installed: None, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRunProcess(NOISY_STDOUT)
    monkeypatch.setattr(getcookie.anyio, "run_process", fake)

    cookies = await fetch_cookies(Host("github.com"))

    assert [c.name for c in cookies] == ["session", "csrf"]


def test_parse_skips_noise_before_array() -> None:
    assert parse(NOISY_STDOUT) == CANNED


def test_parse_empty_stdout_is_empty_list() -> None:
    assert parse("   \n") == []


def test_parse_unwraps_cookies_envelope() -> None:
    assert parse(json.dumps({"cookies": CANNED})) == CANNED


def test_parse_unwraps_data_envelope() -> None:
    assert parse(json.dumps({"data": CANNED})) == CANNED


def test_parse_wraps_single_object() -> None:
    assert parse(json.dumps(CANNED[0])) == [CANNED[0]]


def test_parse_raises_on_unparseable() -> None:
    with pytest.raises(GetCookieError, match="could not parse"):
        parse("this is just log output with no json bracket at all")
