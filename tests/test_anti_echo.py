"""Real-store anti-echo convergence test (CF1).

The engine fingerprints the store *after* a write while the sync layer records the digest
of the set it is *about to* write. Both must agree, or every apply echoes forever. This
exercises the REAL write path (``write_rows``), the REAL fingerprint (``read_rows`` +
``logical_digest``), and the REAL ``logical_digest`` the sync layer records — no fakes. It
fails on the old two-function design where ``engine.fingerprint`` hashed raw rows but the
sync/server layers recorded a 13-field ``sync.digest``.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from cookiesync.cookie import merge
from cookiesync.cookie.browsers import Browser, BrowserName
from cookiesync.cookie.crypto import derive_key
from cookiesync.cookie.models import ChromeMicros, Cookie, HostKey, SafeStorageKey
from cookiesync.cookie.stores import write_rows
from cookiesync.daemon import engine as engine_mod
from cookiesync.daemon.engine import fingerprint, logical_digest
from cookiesync.state import BrowserEndpoint, BrowserId, SshTarget

if TYPE_CHECKING:
    from collections.abc import Iterator

pytestmark = pytest.mark.anyio

KEY = derive_key(SafeStorageKey("peanuts"))
BASE = ChromeMicros(13_400_000_000_000_000)

V24_SQL = """
CREATE TABLE cookies (
    creation_utc INTEGER NOT NULL,
    host_key TEXT NOT NULL,
    top_frame_site_key TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    encrypted_value BLOB NOT NULL,
    path TEXT NOT NULL,
    expires_utc INTEGER NOT NULL,
    is_secure INTEGER NOT NULL,
    is_httponly INTEGER NOT NULL,
    last_access_utc INTEGER NOT NULL,
    has_expires INTEGER NOT NULL,
    is_persistent INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    samesite INTEGER NOT NULL,
    source_scheme INTEGER NOT NULL,
    source_port INTEGER NOT NULL,
    last_update_utc INTEGER NOT NULL,
    source_type INTEGER NOT NULL,
    has_cross_site_ancestor INTEGER NOT NULL
);
CREATE UNIQUE INDEX cookies_unique_index ON cookies(
    host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port
);
"""


def cookie(name: str, value: str, *, last_update: ChromeMicros) -> Cookie:
    return Cookie(
        host_key=HostKey(".example.com"),
        name=name,
        value=value,
        path="/",
        expires_utc=ChromeMicros(BASE + 10 * 365 * 24 * 3600 * 1_000_000),
        last_update_utc=last_update,
        creation_utc=BASE,
        is_secure=True,
        is_httponly=False,
        samesite=1,
    )


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[BrowserEndpoint]:
    profile = "Default"
    (tmp_path / profile).mkdir(parents=True, exist_ok=True)
    browser = Browser(
        name=BrowserName("chrome"),
        display="Chrome",
        data_root=tmp_path,
        keychain_service="Chrome Safe Storage",
    )
    con = sqlite3.connect(str(browser.cookies_db(profile)))
    try:
        con.executescript(V24_SQL)
        con.commit()
    finally:
        con.close()
    # fingerprint() resolves the endpoint's browser through engine.REGISTRY; point it at
    # this temp-rooted store so the real read path runs against our fixture.
    monkeypatch.setitem(engine_mod.REGISTRY, BrowserName("chrome"), browser)
    yield BrowserEndpoint(SshTarget("me@laptop"), BrowserId("chrome"), profile)


async def test_fingerprint_after_write_equals_recorded_logical_digest(store: BrowserEndpoint) -> None:
    # Merge two sources, write the winner set to a REAL store, read it back, and assert the
    # store's fingerprint equals the digest the sync layer would have recorded before writing.
    older = cookie("sid", "old", last_update=ChromeMicros(BASE))
    newer = cookie("sid", "new", last_update=ChromeMicros(BASE + 5 * 1_000_000))
    other = cookie("uid", "42", last_update=ChromeMicros(BASE + 2 * 1_000_000))
    merged = merge((older, other), (newer,))

    recorded = logical_digest(merged)  # what sync.apply_to / server.handle_apply record
    written = await write_rows(engine_mod.REGISTRY[BrowserName("chrome")], store.profile, merged, KEY)
    assert written == len(merged)

    after = await fingerprint(store)  # what the watcher computes on the induced event
    assert after == recorded, "the store fingerprint after the write must match the recorded digest"


async def test_rewriting_the_same_set_is_a_stable_fingerprint(store: BrowserEndpoint) -> None:
    # Convergence: writing the same logical set twice yields the same fingerprint, so the
    # anti-echo digest stays matched across repeated applies (no perpetual echo).
    merged = (cookie("sid", "v", last_update=ChromeMicros(BASE + 9 * 1_000_000)),)
    browser = engine_mod.REGISTRY[BrowserName("chrome")]

    await write_rows(browser, store.profile, merged, KEY)
    first = await fingerprint(store)
    await write_rows(browser, store.profile, merged, KEY)
    second = await fingerprint(store)

    assert first == second == logical_digest(merged)
