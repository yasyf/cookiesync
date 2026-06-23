from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from cookiesync.cookie import pipeline
from cookiesync.cookie.backend import AmbiguousProfile
from cookiesync.cookie.browsers import Browser, BrowserName
from cookiesync.cookie.crypto import derive_key, encrypt_value
from cookiesync.cookie.models import (
    AesKey,
    ChromeMicros,
    Cookie,
    EncryptedRow,
    Host,
    HostKey,
    SafeStorageKey,
    StorageState,
    unix_to_chrome_micros,
)
from cookiesync.cookie.pipeline import apply, extract

if TYPE_CHECKING:
    from collections.abc import Sequence

KEY = derive_key(SafeStorageKey("peanuts"))

BROWSER = Browser(
    name=BrowserName("test"),
    display="Test",
    data_root=Path("/nonexistent"),
    keychain_service="Test Safe Storage",
)

FAR_FUTURE = unix_to_chrome_micros(4_000_000_000.0)  # year 2096
LONG_PAST = unix_to_chrome_micros(1_000_000_000.0)  # year 2001


def _row(name: str, value: str, *, host: str = ".x.com", expires: ChromeMicros = FAR_FUTURE) -> EncryptedRow:
    return EncryptedRow(
        host_key=HostKey(host),
        name=name,
        encrypted_value=encrypt_value(value, KEY, HostKey(host)),
        value="",
        path="/",
        expires_utc=expires,
        last_update_utc=ChromeMicros(13_350_000_000_000_000),
        creation_utc=ChromeMicros(13_300_000_000_000_000),
        is_secure=True,
        is_httponly=True,
        samesite=2,
    )


@dataclass
class FakeBackend:
    rows: tuple[EncryptedRow, ...] = ()
    ambiguous: bool = False
    written: list[tuple[Sequence[Cookie], AesKey]] = field(default_factory=list)
    obtain_calls: int = 0
    read_calls: list[tuple[Host, str | None]] = field(default_factory=list)

    async def read_rows(self, browser: Browser, host: Host, *, profile: str | None = None) -> tuple[EncryptedRow, ...]:
        self.read_calls.append((host, profile))
        if self.ambiguous:
            raise AmbiguousProfile("multiple profiles match — pass an explicit profile")
        return self.rows

    async def obtain_key(self, browser: Browser, *, reason: str) -> AesKey:
        self.obtain_calls += 1
        return KEY

    async def write_rows(self, browser: Browser, rows: Sequence[Cookie], key: AesKey) -> int:
        self.written.append((rows, key))
        return len(rows)


async def test_extract_decrypts_rows_into_storage_state() -> None:
    backend = FakeBackend(rows=(_row("sid", "secret"), _row("csrf", "tok")))
    state = await extract("https://x.com", browser=BROWSER, key=KEY, backend=backend)
    assert isinstance(state, StorageState)
    assert {(c.name, c.value) for c in state.cookies} == {("sid", "secret"), ("csrf", "tok")}


async def test_extract_drops_expired_cookies() -> None:
    backend = FakeBackend(rows=(_row("live", "a"), _row("dead", "b", expires=LONG_PAST)))
    state = await extract("https://x.com", browser=BROWSER, key=KEY, backend=backend)
    assert {c.name for c in state.cookies} == {"live"}


async def test_extract_keeps_expired_when_include_expired() -> None:
    backend = FakeBackend(rows=(_row("live", "a"), _row("dead", "b", expires=LONG_PAST)))
    state = await extract("https://x.com", browser=BROWSER, key=KEY, backend=backend, include_expired=True)
    assert {c.name for c in state.cookies} == {"live", "dead"}


async def test_extract_skips_undecryptable_rows() -> None:
    # A v20 app-bound blob and a row encrypted under a different key both fail to decrypt;
    # extract must count-and-skip, not crash.
    other = derive_key(SafeStorageKey("different"))
    bad_key_row = EncryptedRow(
        host_key=HostKey(".x.com"),
        name="badkey",
        encrypted_value=encrypt_value("nope", other, HostKey(".x.com")),
        value="",
        path="/",
        expires_utc=FAR_FUTURE,
        last_update_utc=ChromeMicros(13_350_000_000_000_000),
        creation_utc=ChromeMicros(13_300_000_000_000_000),
        is_secure=True,
        is_httponly=True,
        samesite=2,
    )
    v20_row = EncryptedRow(
        host_key=HostKey(".x.com"),
        name="appbound",
        encrypted_value=b"v20" + b"\x00" * 32,
        value="",
        path="/",
        expires_utc=FAR_FUTURE,
        last_update_utc=ChromeMicros(13_350_000_000_000_000),
        creation_utc=ChromeMicros(13_300_000_000_000_000),
        is_secure=True,
        is_httponly=True,
        samesite=2,
    )
    backend = FakeBackend(rows=(_row("good", "yes"), bad_key_row, v20_row))
    state = await extract("https://x.com", browser=BROWSER, key=KEY, backend=backend, fallback=False)
    assert {c.name for c in state.cookies} == {"good"}


async def test_extract_falls_back_when_self_yields_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    fallback_cookie = Cookie(
        host_key=HostKey(".x.com"),
        name="from_fallback",
        value="fb",
        path="/",
        expires_utc=FAR_FUTURE,
        last_update_utc=ChromeMicros(0),
        creation_utc=ChromeMicros(0),
        is_secure=True,
        is_httponly=False,
        samesite=1,
    )
    seen: list[Host] = []

    async def fake_fetch(host: Host) -> list[Cookie]:
        seen.append(host)
        return [fallback_cookie]

    monkeypatch.setattr(pipeline.getcookie, "fetch_cookies", fake_fetch)
    backend = FakeBackend(rows=())
    state = await extract("https://x.com", browser=BROWSER, key=KEY, backend=backend)
    assert seen == [Host("x.com")]
    assert [c.name for c in state.cookies] == ["from_fallback"]


async def test_extract_no_fallback_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_fetch(host: Host) -> list[Cookie]:
        raise AssertionError("fallback must not run when fallback=False")

    monkeypatch.setattr(pipeline.getcookie, "fetch_cookies", fake_fetch)
    state = await extract("https://x.com", browser=BROWSER, key=KEY, backend=FakeBackend(rows=()), fallback=False)
    assert state.cookies == ()


async def test_extract_raises_on_ambiguous_profile() -> None:
    backend = FakeBackend(ambiguous=True)
    with pytest.raises(AmbiguousProfile):
        await extract("https://x.com", browser=BROWSER, key=KEY, backend=backend)


async def test_extract_never_obtains_key() -> None:
    backend = FakeBackend(rows=(_row("sid", "secret"),))
    await extract("https://x.com", browser=BROWSER, key=KEY, backend=backend)
    assert backend.obtain_calls == 0, "extract receives a key; it must never obtain one"


async def test_extract_forwards_explicit_profile() -> None:
    backend = FakeBackend(rows=(_row("sid", "secret"),))
    await extract("https://x.com", browser=BROWSER, key=KEY, backend=backend, profile="Profile 3")
    assert backend.read_calls == [(Host("x.com"), "Profile 3")]


async def test_apply_calls_write_rows_once() -> None:
    backend = FakeBackend()
    cookie = Cookie(
        host_key=HostKey(".x.com"),
        name="sid",
        value="v",
        path="/",
        expires_utc=FAR_FUTURE,
        last_update_utc=ChromeMicros(13_350_000_000_000_000),
        creation_utc=ChromeMicros(13_300_000_000_000_000),
        is_secure=True,
        is_httponly=True,
        samesite=2,
    )
    written = await apply([cookie], browser=BROWSER, key=KEY, backend=backend)
    assert written == 1
    assert len(backend.written) == 1
    rows, key = backend.written[0]
    assert list(rows) == [cookie]
    assert key == KEY
