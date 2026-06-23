"""End-to-end tests for the daemon-driving CLI: ``cookiesync auth`` and ``cookiesync cookies``.

A real RPC server runs in a background thread on a temp socket, wired with the same dispatcher
the production daemon builds but with fakes for the consent gate, the key cache, and the local
cookie store. The CLI commands are invoked through Click's runner in the main thread, so each
talks to the live daemon exactly as it would in production — ``auth`` primes the key over RPC,
``cookies`` streams a rendered storageState to stdout from the cached key, and the fail-closed
guard surfaces as a clean error. No temp file is written for the cookie payload.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING

import anyio
import pytest
from click.testing import CliRunner

from cookiesync import paths
from cookiesync.cookie.models import AesKey, ChromeMicros, Cookie, HostKey, StorageState
from cookiesync.daemon import server
from cookiesync.daemon.cache import KeyCache
from cookiesync.daemon.rpc import serve
from cookiesync.daemon.server import Daemon
from cookiesync.daemon.session import SessionSnapshot
from cookiesync.state import Settings, SshTarget, State

if TYPE_CHECKING:
    from collections.abc import Iterator

SELF = SshTarget("me@laptop")
KEY = AesKey(bytes(range(32)))
XOR_MASK = 0x5A
BASE = ChromeMicros(13_400_000_000_000_000)


def cookie(name: str, value: str) -> Cookie:
    return Cookie(
        host_key=HostKey(".example.com"),
        name=name,
        value=value,
        path="/",
        expires_utc=ChromeMicros(BASE + 10 * 365 * 24 * 3600 * 1_000_000),
        last_update_utc=BASE,
        creation_utc=BASE,
        is_secure=True,
        is_httponly=False,
        samesite=1,
    )


@dataclass(frozen=True, slots=True)
class FakeWrapper:
    async def wrap(self, plaintext: bytes) -> bytes:
        return bytes(b ^ XOR_MASK for b in plaintext)

    async def unwrap(self, blob: bytes) -> bytes:
        return bytes(b ^ XOR_MASK for b in blob)


@dataclass(slots=True)
class FakeConsent:
    key: AesKey = KEY

    async def obtain_key(self, browser: object, *, reason: str) -> AesKey:
        return self.key


@dataclass(slots=True)
class FakeEngine:
    settings: Settings = field(default_factory=Settings)

    def record_applied(self, endpoint_id: str, digest: str) -> None: ...


ON_CONSOLE = SessionSnapshot(on_console=True, locked=False, console_user="me")


@pytest.fixture(autouse=True)
def login_user(monkeypatch: pytest.MonkeyPatch) -> None:
    from cookiesync.daemon import session

    monkeypatch.setattr(session.getpass, "getuser", lambda: "me")


@pytest.fixture
def cache() -> KeyCache:
    return KeyCache(FakeWrapper())


@dataclass(slots=True)
class RunningDaemon:
    cache: KeyCache
    consent: FakeConsent


@pytest.fixture
def daemon(monkeypatch: pytest.MonkeyPatch, cache: KeyCache) -> Iterator[RunningDaemon]:
    # macOS caps AF_UNIX paths near 104 bytes; a short $TMPDIR socket avoids overflow.
    with TemporaryDirectory(prefix="ckcli-") as d:
        path = Path(d) / "rpc.sock"
        monkeypatch.setattr(paths, "sock_path", lambda: path)

        consent = FakeConsent()
        state = State(SELF, (), Settings(auth_ttl=timedelta(minutes=5)))

        async def load_state() -> State:
            return state

        built = Daemon(
            consent=consent,
            cache=cache,
            engine=FakeEngine(),
            probe=_probe(ON_CONSOLE),
            load_state=load_state,
        )
        ready = threading.Event()

        async def run() -> None:
            async with anyio.create_task_group() as tg:
                await tg.start(serve, built.dispatcher())
                ready.set()
                await anyio.sleep_forever()

        thread = threading.Thread(target=lambda: anyio.run(run), daemon=True)
        thread.start()
        ready.wait(timeout=5)
        yield RunningDaemon(cache, consent)


def _probe(snapshot: SessionSnapshot):
    async def probe() -> SessionSnapshot:
        return snapshot

    return probe


def test_auth_reports_success(daemon: RunningDaemon) -> None:
    from cookiesync.cli import main

    result = CliRunner().invoke(main, ["auth", "--browser", "chrome"])

    assert result.exit_code == 0, result.output
    assert "Authenticated me@laptop:chrome:Default." in result.output


def test_cookies_streams_a_playwright_state_to_stdout(daemon: RunningDaemon, monkeypatch: pytest.MonkeyPatch) -> None:
    from cookiesync.cli import main

    async def fake_extract(url, *, browser, key, backend, profile, **_kw) -> StorageState:
        assert key == KEY  # the daemon decrypts with the cached key, primed below
        return StorageState((cookie("sid", "s3cr3t"), cookie("uid", "42")))

    monkeypatch.setattr(server, "extract", fake_extract)

    CliRunner().invoke(main, ["auth", "--browser", "chrome"])
    result = CliRunner().invoke(main, ["cookies", "https://example.com", "--browser", "chrome"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["origins"] == []
    assert {(c["name"], c["value"]) for c in payload["cookies"]} == {("sid", "s3cr3t"), ("uid", "42")}


def test_cookies_default_format_is_playwright(daemon: RunningDaemon, monkeypatch: pytest.MonkeyPatch) -> None:
    from cookiesync.cli import main

    async def fake_extract(url, *, browser, key, backend, profile, **_kw) -> StorageState:
        return StorageState((cookie("sid", "x"),))

    monkeypatch.setattr(server, "extract", fake_extract)

    CliRunner().invoke(main, ["auth", "--browser", "chrome"])
    result = CliRunner().invoke(main, ["cookies", "https://example.com"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["cookies"][0]["name"] == "sid"


def test_cookies_before_auth_fails_closed(daemon: RunningDaemon) -> None:
    from cookiesync.cli import main

    result = CliRunner().invoke(main, ["cookies", "https://example.com", "--browser", "chrome"])

    assert result.exit_code != 0
    assert "cookiesync auth" in result.output


def test_cookies_netscape_format_renders_header(daemon: RunningDaemon, monkeypatch: pytest.MonkeyPatch) -> None:
    from cookiesync.cli import main

    async def fake_extract(url, *, browser, key, backend, profile, **_kw) -> StorageState:
        return StorageState((cookie("sid", "x"),))

    monkeypatch.setattr(server, "extract", fake_extract)

    CliRunner().invoke(main, ["auth", "--browser", "chrome"])
    result = CliRunner().invoke(main, ["cookies", "https://example.com", "--format", "netscape"])

    assert result.exit_code == 0, result.output
    assert result.output.splitlines()[0] == "# Netscape HTTP Cookie File"
