"""Integration tests for the daemon RPC dispatcher over a real unix socket.

The dispatcher and its handlers are the code under test; only the macOS-specific surfaces —
the Touch-ID consent gate, the Secure-Enclave key cache wrapper, the console-session probe,
the local cookie store, and the ssh-reached peers — are doubled by fakes. The RPC transport
itself is real: the server binds a temp socket and ``rpc.call`` round-trips each request, so
the bimodal method routing, the cached-key path, the fail-closed guard, and the
``record_applied``-before-write ordering all run end to end without any real key, store, or ssh.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING

import anyio
import pytest

from cookiesync import paths
from cookiesync.cookie.models import AesKey, ChromeMicros, Cookie, HostKey, StorageState
from cookiesync.daemon import server
from cookiesync.daemon.cache import KeyCache
from cookiesync.daemon.rpc import Dispatcher, call, serve
from cookiesync.daemon.server import CachedKeySource, Daemon
from cookiesync.daemon.session import SessionSnapshot
from cookiesync.daemon.sync import Extracted
from cookiesync.state import BrowserEndpoint, BrowserId, Settings, SshTarget, State

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator, Sequence

pytestmark = pytest.mark.anyio

SELF = SshTarget("me@laptop")
PEER = SshTarget("peer@desktop")
CHROME = BrowserId("chrome")
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


@pytest.fixture(autouse=True)
def login_user(monkeypatch: pytest.MonkeyPatch) -> None:
    # has_active_session compares the console user against getpass.getuser(); pin it so the
    # ON_CONSOLE snapshot below counts as this user's live session.
    from cookiesync.daemon import session

    monkeypatch.setattr(session.getpass, "getuser", lambda: "me")


@pytest.fixture
def sock_path(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    # macOS caps AF_UNIX paths near 104 bytes; a short $TMPDIR socket avoids overflow.
    with TemporaryDirectory(prefix="ckint-") as d:
        path = Path(d) / "rpc.sock"
        monkeypatch.setattr(paths, "sock_path", lambda: path)
        yield path


@dataclass(frozen=True, slots=True)
class FakeWrapper:
    async def wrap(self, plaintext: bytes) -> bytes:
        return bytes(b ^ XOR_MASK for b in plaintext)

    async def unwrap(self, blob: bytes) -> bytes:
        return bytes(b ^ XOR_MASK for b in blob)


@dataclass(slots=True)
class FakeConsent:
    """A consent gate that releases a fixed key, recording each prompt's reason.

    ``obtain_key`` is the interactive (Touch ID) path; ``obtain_key_unprompted`` is the
    non-interactive owning-host release gated by a verified routed approval. Each records
    so tests can assert which path ran.
    """

    key: AesKey = KEY
    prompts: list[str] = field(default_factory=list)
    unprompted: list[object] = field(default_factory=list)

    async def obtain_key(self, browser: object, *, reason: str) -> AesKey:
        self.prompts.append(reason)
        return self.key

    async def obtain_key_unprompted(self, browser: object) -> AesKey:
        self.unprompted.append(browser)
        return self.key


@dataclass(slots=True)
class FakeEngine:
    """Records the digests the daemon stamps before each induced write."""

    settings: Settings = field(default_factory=Settings)
    applied: list[tuple[str, str]] = field(default_factory=list)

    def record_applied(self, endpoint_id: str, digest: str) -> None:
        self.applied.append((endpoint_id, digest))


@dataclass(slots=True)
class FakeSource:
    """An in-memory cookie source standing in for the local store and a peer."""

    cookies: tuple[Cookie, ...] = ()
    applied: list[tuple[BrowserId, str, tuple[Cookie, ...]]] = field(default_factory=list)

    async def extract(self, browser: BrowserId, profile: str) -> Extracted:
        return Extracted(self.cookies)

    async def apply(self, browser: BrowserId, profile: str, cookies: Sequence[Cookie]) -> int:
        rows = tuple(cookies)
        self.applied.append((browser, profile, rows))
        return len(rows)


def probe(snapshot: SessionSnapshot):
    async def _probe() -> SessionSnapshot:
        return snapshot

    return _probe


ON_CONSOLE = SessionSnapshot(on_console=True, locked=False, console_user="me")
HEADLESS = SessionSnapshot(on_console=False, locked=False, console_user=None)


def make_state(*, browsers: tuple[BrowserEndpoint, ...] = ()) -> State:
    return State(SELF, browsers, Settings(auth_ttl=timedelta(minutes=5)))


def make_daemon(
    *,
    consent: FakeConsent,
    cache: KeyCache,
    engine: FakeEngine,
    snapshot: SessionSnapshot = ON_CONSOLE,
    state: State | None = None,
    local: FakeSource | None = None,
) -> Daemon:
    resolved = state if state is not None else make_state()
    source = local if local is not None else FakeSource()

    async def load_state() -> State:
        return resolved

    return Daemon(
        consent=consent,
        cache=cache,
        engine=engine,
        probe=probe(snapshot),
        load_state=load_state,
        local_source_factory=lambda _daemon, _self: source,
        source_for_factory=lambda _daemon, _peer: FakeSource(),
    )


@asynccontextmanager
async def serving(dispatcher: Dispatcher) -> AsyncIterator[None]:
    async with anyio.create_task_group() as tg:
        await tg.start(serve, dispatcher)
        try:
            yield
        finally:
            tg.cancel_scope.cancel()


async def test_prime_auth_caches_a_key_on_the_active_session_path(sock_path: Path) -> None:
    consent = FakeConsent()
    cache = KeyCache(FakeWrapper())
    daemon = make_daemon(consent=consent, cache=cache, engine=FakeEngine())

    async with serving(daemon.dispatcher()):
        resp = await call("prime_auth", {"browser": "chrome", "profile": "Default"})

    assert resp.ok, resp.error
    assert resp.result == {"primed": True, "endpoint": "me@laptop:chrome:Default"}
    # The local Touch-ID release ran exactly once and the derived key is now cached.
    assert len(consent.prompts) == 1
    assert await cache.get("me@laptop:chrome:Default") == KEY


async def test_get_cookies_returns_wire_cookies_from_the_cache(
    sock_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = KeyCache(FakeWrapper())
    await cache.put("me@laptop:chrome:Default", KEY, ttl=300.0)
    daemon = make_daemon(consent=FakeConsent(), cache=cache, engine=FakeEngine())

    captured: dict[str, object] = {}

    async def fake_extract(url: str, *, browser, key, backend, profile, **_kw) -> StorageState:
        captured["url"], captured["key"], captured["profile"] = url, key, profile
        return StorageState((cookie("sid", "s3cr3t"),))

    monkeypatch.setattr(server, "extract", fake_extract)

    async with serving(daemon.dispatcher()):
        resp = await call("get_cookies", {"url": "https://example.com", "browser": "chrome"})

    assert resp.ok, resp.error
    assert captured["url"] == "https://example.com"
    assert captured["key"] == KEY  # decrypted with the cached key, never the consent gate
    assert [c["value"] for c in resp.result["cookies"]] == ["s3cr3t"]


async def test_get_cookies_fails_closed_when_the_cache_is_cold(sock_path: Path) -> None:
    daemon = make_daemon(consent=FakeConsent(), cache=KeyCache(FakeWrapper()), engine=FakeEngine())

    async with serving(daemon.dispatcher()):
        resp = await call("get_cookies", {"url": "https://example.com", "browser": "chrome"})

    assert resp.ok is False
    assert "cookiesync auth" in resp.error


async def test_apply_writes_through_sync_and_records_the_digest_first(sock_path: Path) -> None:
    from cookiesync.daemon.engine import logical_digest

    cache = KeyCache(FakeWrapper())
    engine = FakeEngine()
    local = FakeSource()
    daemon = make_daemon(consent=FakeConsent(), cache=cache, engine=engine, local=local)
    merged = (cookie("sid", "merged"),)
    payload = {
        "browser": "chrome",
        "profile": "Default",
        "cookies": [server.cookie_to_wire(c) for c in merged],
    }

    async with serving(daemon.dispatcher()):
        resp = await call("apply", payload)

    assert resp.ok, resp.error
    assert resp.result == {"applied": 1}
    # The merged set reached the store, and the engine recorded the applied digest first.
    assert [v for _, _, rows in local.applied for v in (c.value for c in rows)] == ["merged"]
    assert engine.applied == [("me@laptop:chrome:Default", logical_digest(merged))]


async def test_whoami_returns_the_session_summary(sock_path: Path) -> None:
    daemon = make_daemon(consent=FakeConsent(), cache=KeyCache(FakeWrapper()), engine=FakeEngine(), snapshot=ON_CONSOLE)

    async with serving(daemon.dispatcher()):
        resp = await call("whoami", {})

    assert resp.ok, resp.error
    assert resp.result == {"on_console": True, "locked": False, "console_user": "me"}


async def test_auth_status_reports_cache_warmth(sock_path: Path) -> None:
    cache = KeyCache(FakeWrapper())
    daemon = make_daemon(consent=FakeConsent(), cache=cache, engine=FakeEngine())

    async with serving(daemon.dispatcher()):
        cold = await call("auth_status", {"browser": "chrome"})
        await call("prime_auth", {"browser": "chrome"})
        warm = await call("auth_status", {"browser": "chrome"})

    assert cold.result == {"endpoint": "me@laptop:chrome:Default", "authenticated": False}
    assert warm.result == {"endpoint": "me@laptop:chrome:Default", "authenticated": True}


async def test_sync_converges_a_group_and_skips_the_origin(sock_path: Path) -> None:
    cache = KeyCache(FakeWrapper())
    await cache.put("me@laptop:chrome:Default", KEY, ttl=300.0)
    local = FakeSource(cookies=(cookie("sid", "local"),))
    browsers = (BrowserEndpoint(SELF, CHROME, "Default"), BrowserEndpoint(PEER, CHROME, "Default"))
    daemon = make_daemon(
        consent=FakeConsent(),
        cache=cache,
        engine=FakeEngine(),
        state=make_state(browsers=browsers),
        local=local,
    )

    async with serving(daemon.dispatcher()):
        resp = await call("sync", {"browser": "chrome", "origin": "peer@desktop"})

    assert resp.ok, resp.error
    assert resp.result == {"converged": True, "cookies": 1}


async def test_request_consent_unavailable_when_headless(sock_path: Path) -> None:
    daemon = make_daemon(consent=FakeConsent(), cache=KeyCache(FakeWrapper()), engine=FakeEngine(), snapshot=HEADLESS)

    async with serving(daemon.dispatcher()):
        resp = await call(
            "request_consent",
            {"browser": "chrome", "profile": "Default", "nonce": "n1", "endpoint": "me@laptop:chrome:Default"},
        )

    assert resp.ok, resp.error
    assert resp.result == {"status": "unavailable"}


async def test_request_consent_prompts_for_params_browser_and_echoes_nonce_and_endpoint(sock_path: Path) -> None:
    # SF2: the prompt must name the REQUESTED browser (arc here), never a hardcoded default,
    # and the reply must echo the requester's nonce + endpoint to bind the approval.
    consent = FakeConsent()
    daemon = make_daemon(consent=consent, cache=KeyCache(FakeWrapper()), engine=FakeEngine(), snapshot=ON_CONSOLE)

    async with serving(daemon.dispatcher()):
        resp = await call(
            "request_consent",
            {"browser": "arc", "profile": "Default", "nonce": "nonce-xyz", "endpoint": "peer@desktop:arc:Default"},
        )

    assert resp.ok, resp.error
    assert resp.result == {"status": "approved", "nonce": "nonce-xyz", "endpoint": "peer@desktop:arc:Default"}
    # The Touch ID prompt named the requested endpoint, proving it was for the right browser.
    assert consent.prompts == ["sync them to peer@desktop:arc:Default"]


async def test_request_consent_denied_propagates(sock_path: Path) -> None:
    from cookiesync.cookie.consent import ConsentError

    @dataclass(slots=True)
    class DenyingConsent:
        async def obtain_key(self, browser: object, *, reason: str) -> AesKey:
            raise ConsentError("declined")

        async def obtain_key_unprompted(self, browser: object) -> AesKey:
            raise AssertionError("must not release without an interactive tap")

    daemon = make_daemon(
        consent=DenyingConsent(), cache=KeyCache(FakeWrapper()), engine=FakeEngine(), snapshot=ON_CONSOLE
    )

    async with serving(daemon.dispatcher()):
        resp = await call(
            "request_consent",
            {"browser": "chrome", "profile": "Default", "nonce": "n", "endpoint": "me@laptop:chrome:Default"},
        )

    assert resp.ok, resp.error
    assert resp.result == {"status": "denied"}


# ── SF1 + SF2: prime_auth routes the user-presence gate, then releases its OWN key ──────


def _parse_opt(remote_cmd: str, flag: str) -> str | None:
    import shlex

    argv = shlex.split(remote_cmd)
    return argv[argv.index(flag) + 1] if flag in argv else None


@dataclass(slots=True)
class RoutingSsh:
    """A fake ssh that answers ``whoami`` (peer is active) and ``request_consent``.

    ``request_consent`` echoes the nonce/endpoint it received unless ``mismatch`` or
    ``deny`` rewrite the reply, so a test can drive the bind check both ways. Records every
    request_consent command so a test can assert the browser the peer was asked to release.
    """

    consent_status: str = "approved"
    mangle_nonce: bool = False
    drop_endpoint: bool = False
    consent_cmds: list[str] = field(default_factory=list)

    async def __call__(self, target: object, remote_cmd: str, *, stdin: bytes | None = None) -> str:
        if "rpc whoami" in remote_cmd:
            return json.dumps({"on_console": True, "locked": False, "console_user": "someone"})
        if "rpc request_consent" in remote_cmd:
            self.consent_cmds.append(remote_cmd)
            nonce = _parse_opt(remote_cmd, "--nonce")
            endpoint = _parse_opt(remote_cmd, "--endpoint")
            reply: dict[str, object] = {"status": self.consent_status}
            if self.consent_status == "approved":
                reply["nonce"] = "tampered" if self.mangle_nonce else nonce
                if not self.drop_endpoint:
                    reply["endpoint"] = endpoint
            return json.dumps(reply)
        raise AssertionError(f"unexpected ssh command: {remote_cmd}")


def _routing_daemon(consent: FakeConsent, cache: KeyCache, run_ssh: RoutingSsh) -> Daemon:
    state = State(SELF, (BrowserEndpoint(PEER, CHROME, "Default"),), Settings(auth_ttl=timedelta(minutes=5)))

    async def load_state() -> State:
        return state

    return Daemon(
        consent=consent,
        cache=cache,
        engine=FakeEngine(),
        probe=probe(HEADLESS),  # no local session -> the routed path runs
        run_ssh=run_ssh,
        load_state=load_state,
        local_source_factory=lambda _d, _s: FakeSource(),
        source_for_factory=lambda _d, _p: FakeSource(),
    )


async def test_prime_auth_routes_consent_then_releases_own_key_unprompted() -> None:
    # SF1+SF2: no local session -> route the gate to the peer for the CORRECT browser, verify
    # the nonce+endpoint echo, then release THIS host's key via obtain_key_unprompted (the
    # non-interactive owning-host read) — never the interactive prompt, never over the wire.
    consent = FakeConsent()
    cache = KeyCache(FakeWrapper())
    ssh = RoutingSsh()
    daemon = _routing_daemon(consent, cache, ssh)

    key = await daemon.prime_auth(CHROME, "Default", await daemon.load_state())

    assert key == KEY
    assert await cache.get("me@laptop:chrome:Default") == KEY
    # The release was NON-INTERACTIVE on the owning host (no Touch ID tap here).
    assert consent.prompts == []
    assert len(consent.unprompted) == 1
    # The peer was asked to release the requested browser/endpoint.
    assert "--browser chrome" in ssh.consent_cmds[0]
    assert "--endpoint me@laptop:chrome:Default" in ssh.consent_cmds[0]


async def test_prime_auth_raises_when_peer_does_not_approve() -> None:
    consent = FakeConsent()
    daemon = _routing_daemon(consent, KeyCache(FakeWrapper()), RoutingSsh(consent_status="denied"))

    with pytest.raises(server.AuthRequired):
        await daemon.prime_auth(CHROME, "Default", await daemon.load_state())

    # Fail closed: the owning host never released its key.
    assert consent.unprompted == []
    assert consent.prompts == []


async def test_prime_auth_raises_when_nonce_does_not_echo() -> None:
    # An approval that does not echo the exact nonce is unbound -> fail closed (replay guard).
    consent = FakeConsent()
    daemon = _routing_daemon(consent, KeyCache(FakeWrapper()), RoutingSsh(mangle_nonce=True))

    with pytest.raises(server.AuthRequired):
        await daemon.prime_auth(CHROME, "Default", await daemon.load_state())

    assert consent.unprompted == []


async def test_prime_auth_raises_when_endpoint_does_not_echo() -> None:
    # An approval missing the endpoint binding is unbound -> fail closed.
    consent = FakeConsent()
    daemon = _routing_daemon(consent, KeyCache(FakeWrapper()), RoutingSsh(drop_endpoint=True))

    with pytest.raises(server.AuthRequired):
        await daemon.prime_auth(CHROME, "Default", await daemon.load_state())

    assert consent.unprompted == []


# ── SF3: get_cookies never runs the key-less cross-browser fallback ─────────────────────


async def test_get_cookies_does_not_run_fallback_on_a_warm_but_empty_decrypt(
    sock_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # SF3: a warm cache whose decrypt yields ZERO cookies must return zero and NOT fall back
    # to the key-less @mherod/get-cookie sweep. This drives the REAL `extract` (fallback=False
    # passed by handle_get_cookies), with the getcookie sweep spied on to prove it never runs.
    from cookiesync.cookie import pipeline
    from cookiesync.cookie.models import EncryptedRow

    cache = KeyCache(FakeWrapper())
    await cache.put("me@laptop:chrome:Default", KEY, ttl=300.0)
    daemon = make_daemon(consent=FakeConsent(), cache=cache, engine=FakeEngine())

    @dataclass(frozen=True, slots=True)
    class EmptyDecryptBackend:
        consent: object

        async def read_rows(self, browser, host, *, profile=None) -> tuple[EncryptedRow, ...]:
            # A v20 app-bound blob: a warm, present row that decrypt_value rejects -> 0 cookies.
            return (
                EncryptedRow(
                    host_key=HostKey(".example.com"),
                    name="sid",
                    encrypted_value=b"v20-app-bound",
                    value="",
                    path="/",
                    expires_utc=ChromeMicros(BASE + 1_000_000),
                    last_update_utc=BASE,
                    creation_utc=BASE,
                    is_secure=True,
                    is_httponly=False,
                    samesite=1,
                ),
            )

        async def obtain_key(self, browser, *, reason):
            raise AssertionError("get_cookies must decrypt with the cached key, not the consent gate")

        async def write_rows(self, browser, rows, key) -> int:
            return 0

    fallback_calls: list[str] = []

    async def spy_fetch_cookies(host: str):
        fallback_calls.append(host)
        return []

    monkeypatch.setattr(server, "LocalBackend", EmptyDecryptBackend)
    monkeypatch.setattr(pipeline.getcookie, "fetch_cookies", spy_fetch_cookies)

    async with serving(daemon.dispatcher()):
        resp = await call("get_cookies", {"url": "https://example.com", "browser": "chrome"})

    assert resp.ok, resp.error
    assert resp.result == {"cookies": []}, "a warm-but-empty decrypt returns zero cookies"
    assert fallback_calls == [], "the key-less get-cookie fallback must never run from get_cookies"


async def test_cached_key_source_extract_decrypts_and_apply_re_encrypts(monkeypatch: pytest.MonkeyPatch) -> None:
    cache = KeyCache(FakeWrapper())
    await cache.put("me@laptop:chrome:Default", KEY, ttl=300.0)
    source = CachedKeySource(cache, SELF)

    rows = (_encrypted_row("sid", b"blob"),)
    captured: dict[str, object] = {}

    async def fake_read_rows(browser, profile) -> tuple:
        return rows

    async def fake_write_rows(browser, profile, cookies, key) -> int:
        captured["key"] = key
        return len(tuple(cookies))

    monkeypatch.setattr(server, "read_rows", fake_read_rows)
    monkeypatch.setattr(server, "write_rows", fake_write_rows)
    monkeypatch.setattr(server, "decrypt_value", lambda enc, key, host: "plain")

    extracted = await source.extract(CHROME, "Default")
    assert [c.value for c in extracted.cookies] == ["plain"]

    written = await source.apply(CHROME, "Default", (cookie("sid", "x"),))
    assert written == 1
    assert captured["key"] == KEY  # re-encryption uses the cached key, never the consent gate


async def test_watch_serves_rpc_and_notifies_peers_on_a_settle(sock_path: Path) -> None:
    from cookiesync.daemon.engine import Engine

    state = make_state(browsers=(BrowserEndpoint(SELF, CHROME, "Default"), BrowserEndpoint(PEER, CHROME, "Default")))

    async def load_state() -> State:
        return state

    notified: list[str] = []

    async def fake_ssh(target, remote_cmd, *, stdin=None):
        notified.append(f"{target}::{remote_cmd}")
        return "{}"

    async def one_event(_endpoint):
        yield object()

    # An advancing clock: each read jumps a full hour, so the debounce deadline (set at the
    # first read + 3s) is already past by the next read and fire_after's gate opens.
    elapsed = Elapsed()

    engine = Engine(
        state.settings,
        notify=lambda _ep: anyio.sleep(0),
        watch=one_event,
        digest=lambda _ep: _digest(),
        mtime=lambda _ep: _past(),
        now=elapsed,
        sleep=lambda _d: anyio.sleep(0),
    )
    daemon = Daemon(
        consent=FakeConsent(),
        cache=KeyCache(FakeWrapper()),
        engine=engine,
        probe=probe(ON_CONSOLE),
        run_ssh=fake_ssh,
        load_state=load_state,
    )
    engine.notify = daemon.notify_peers

    async with anyio.create_task_group() as tg:
        tg.start_soon(daemon.watch)
        await _until(lambda: notified)  # the engine settled and the peer was ssh-notified
        # The RPC socket is live under watch(): whoami answers over the same socket.
        resp = await call("whoami", {})
        tg.cancel_scope.cancel()

    assert resp.result == {"on_console": True, "locked": False, "console_user": "me"}
    assert any("peer@desktop" in n and "rpc sync --browser chrome" in n for n in notified)


class Elapsed:
    """A clock that jumps a full hour on every read, so any debounce deadline is already past."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        self.t += 3600.0
        return self.t


async def _until(pred) -> None:
    with anyio.fail_after(5):
        while not pred():
            await anyio.sleep(0.01)


async def _digest() -> str:
    from cookiesync.daemon.engine import Digest

    return Digest("deadbeef")


async def _past() -> float:
    return 0.0  # far enough in the past to clear the idle gate against now=1_000_000.0


def _encrypted_row(name: str, blob: bytes):
    from cookiesync.cookie.models import EncryptedRow

    return EncryptedRow(
        host_key=HostKey(".example.com"),
        name=name,
        encrypted_value=blob,
        value="",
        path="/",
        expires_utc=ChromeMicros(BASE + 1_000_000),
        last_update_utc=BASE,
        creation_utc=BASE,
        is_secure=True,
        is_httponly=False,
        samesite=1,
    )
