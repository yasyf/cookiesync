from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from cookiesync.cookie.browsers import Browser, BrowserName
from cookiesync.cookie.crypto import decrypt_value, derive_key, encrypt_value
from cookiesync.cookie.models import (
    ChromeMicros,
    Cookie,
    Host,
    HostKey,
    SafeStorageKey,
)
from cookiesync.cookie.stores import (
    count_applicable,
    list_profile_dirs,
    profile_info,
    read_rows,
    write_rows,
)

KEY = derive_key(SafeStorageKey("peanuts"))

# v18: carries is_same_party; UNIQUE(host_key, top_frame_site_key, name, path); no
# last_update_utc / source_type / has_cross_site_ancestor.
V18_SQL = """
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
    is_same_party INTEGER NOT NULL
);
CREATE UNIQUE INDEX cookies_unique_index ON cookies(host_key, top_frame_site_key, name, path);
"""

# v24: drops is_same_party, adds source_type + has_cross_site_ancestor + last_update_utc;
# UNIQUE(host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port).
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

SCHEMAS = {"v18": V18_SQL, "v24": V24_SQL}


def _make_browser(tmp_path: Path, profile: str = "Default") -> Browser:
    (tmp_path / profile).mkdir(parents=True, exist_ok=True)
    return Browser(
        name=BrowserName("test"),
        display="Test",
        data_root=tmp_path,
        keychain_service="Test Safe Storage",
    )


def _init_db(path: Path, schema_sql: str) -> None:
    con = sqlite3.connect(str(path))
    try:
        con.executescript(schema_sql)
        con.commit()
    finally:
        con.close()


def _has_column(path: Path, column: str) -> bool:
    con = sqlite3.connect(str(path))
    try:
        return column in {c[1] for c in con.execute("PRAGMA table_info(cookies)")}
    finally:
        con.close()


def _insert_native(path: Path, host_key: str, name: str, encrypted: bytes) -> None:
    if _has_column(path, "last_update_utc"):
        _insert_v24(path, host_key, name, encrypted)
    else:
        _insert_v18(path, host_key, name, encrypted)


def _insert_v18_con(con: sqlite3.Connection, host_key: str, name: str, encrypted: bytes, value: str = "") -> None:
    con.execute(
        "INSERT INTO cookies (creation_utc, host_key, top_frame_site_key, name, value, "
        "encrypted_value, path, expires_utc, is_secure, is_httponly, last_access_utc, "
        "has_expires, is_persistent, priority, samesite, source_scheme, source_port, is_same_party) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            13_300_000_000_000_000,
            host_key,
            "",
            name,
            value,
            encrypted,
            "/",
            13_400_000_000_000_000,
            1,
            0,
            13_300_000_000_000_000,
            1,
            1,
            1,
            0,
            2,
            443,
            0,
        ),
    )


def _insert_v18(path: Path, host_key: str, name: str, encrypted: bytes, value: str = "") -> None:
    con = sqlite3.connect(str(path))
    try:
        _insert_v18_con(con, host_key, name, encrypted, value)
        con.commit()
    finally:
        con.close()


@pytest.fixture(params=sorted(SCHEMAS))
def schema(request: pytest.FixtureRequest) -> str:
    return request.param


@pytest.fixture
def cookies_db(tmp_path: Path, schema: str) -> tuple[Browser, str]:
    browser = _make_browser(tmp_path)
    _init_db(browser.cookies_db("Default"), SCHEMAS[schema])
    return browser, "Default"


def _sample_cookie(host: str = ".example.com", name: str = "sid", value: str = "abc123") -> Cookie:
    return Cookie(
        host_key=HostKey(host),
        name=name,
        value=value,
        path="/",
        expires_utc=ChromeMicros(13_400_000_000_000_000),
        last_update_utc=ChromeMicros(13_350_000_000_000_000),
        creation_utc=ChromeMicros(13_300_000_000_000_000),
        is_secure=True,
        is_httponly=True,
        samesite=2,
    )


# --- read ---


async def test_read_rows_returns_inserted_row(cookies_db: tuple[Browser, str]) -> None:
    browser, profile = cookies_db
    blob = encrypt_value("hello", KEY, HostKey(".x.com"))
    _insert_native(browser.cookies_db(profile), ".x.com", "sid", blob)
    rows = await read_rows(browser, profile)
    assert len(rows) == 1
    assert rows[0].host_key == ".x.com"
    assert rows[0].name == "sid"
    assert rows[0].encrypted_value == blob
    assert decrypt_value(rows[0].encrypted_value, KEY, rows[0].host_key) == "hello"


async def test_read_rows_empty_db(cookies_db: tuple[Browser, str]) -> None:
    browser, profile = cookies_db
    assert await read_rows(browser, profile) == ()


async def test_read_sees_wal_sidecar_row(cookies_db: tuple[Browser, str]) -> None:
    browser, profile = cookies_db
    db = browser.cookies_db(profile)
    blob = encrypt_value("wal-only", KEY, HostKey(".w.com"))
    # Insert in WAL mode and pin the WAL with a held read-locked connection so the
    # writer's close can't checkpoint: the row stays in the -wal sidecar, exactly the
    # state a running browser leaves on disk. read_rows must copy + checkpoint it in.
    writer = sqlite3.connect(str(db))
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("PRAGMA wal_autocheckpoint=0")
    writer.commit()
    holder = sqlite3.connect(str(db))
    holder.execute("BEGIN")
    holder.execute("SELECT count(*) FROM cookies").fetchone()
    try:
        if _has_column(db, "last_update_utc"):
            _insert_v24_con(writer, ".w.com", "sid", blob)
        else:
            _insert_v18_con(writer, ".w.com", "sid", blob)
        writer.commit()
        writer.close()
        assert Path(f"{db}-wal").is_file() and Path(f"{db}-wal").stat().st_size > 0
        rows = await read_rows(browser, profile)
    finally:
        holder.close()
    assert [r.name for r in rows] == ["sid"]
    assert decrypt_value(rows[0].encrypted_value, KEY, rows[0].host_key) == "wal-only"


# --- write: insert then upsert ---


async def test_write_inserts_then_upserts_to_single_row(cookies_db: tuple[Browser, str]) -> None:
    browser, profile = cookies_db
    first = _sample_cookie(value="v1")
    assert await write_rows(browser, profile, [first], KEY) == 1
    rows = await read_rows(browser, profile)
    assert len(rows) == 1
    assert decrypt_value(rows[0].encrypted_value, KEY, rows[0].host_key) == "v1"

    second = replace(first, value="v2-newest")
    assert await write_rows(browser, profile, [second], KEY) == 1
    rows = await read_rows(browser, profile)
    assert len(rows) == 1, "conflict on the real unique index must collapse to one row"
    assert decrypt_value(rows[0].encrypted_value, KEY, rows[0].host_key) == "v2-newest"


async def test_write_leaves_plaintext_value_empty(cookies_db: tuple[Browser, str]) -> None:
    browser, profile = cookies_db
    await write_rows(browser, profile, [_sample_cookie(value="secret")], KEY)
    con = sqlite3.connect(str(browser.cookies_db(profile)))
    try:
        value, enc = con.execute("SELECT value, encrypted_value FROM cookies").fetchone()
    finally:
        con.close()
    assert value == ""
    assert enc and enc[:3] == b"v10"
    assert decrypt_value(bytes(enc), KEY, HostKey(".example.com")) == "secret"


async def test_write_preserves_last_update_and_creation(cookies_db: tuple[Browser, str]) -> None:
    browser, profile = cookies_db
    cookie = _sample_cookie()
    await write_rows(browser, profile, [cookie], KEY)
    con = sqlite3.connect(str(browser.cookies_db(profile)))
    try:
        cols = {c[1] for c in con.execute("PRAGMA table_info(cookies)")}
        creation = con.execute("SELECT creation_utc FROM cookies").fetchone()[0]
        assert creation == int(cookie.creation_utc), "creation must be preserved, not stamped now"
        if "last_update_utc" in cols:
            lu = con.execute("SELECT last_update_utc FROM cookies").fetchone()[0]
            assert lu == int(cookie.last_update_utc), "last_update_utc must be preserved, not 'now'"
    finally:
        con.close()


async def test_upsert_updates_expiry_and_flags(cookies_db: tuple[Browser, str]) -> None:
    browser, profile = cookies_db
    await write_rows(browser, profile, [_sample_cookie(value="v1")], KEY)
    refreshed = replace(
        _sample_cookie(value="v2"),
        expires_utc=ChromeMicros(13_999_000_000_000_000),
        is_httponly=False,
        samesite=0,
    )
    await write_rows(browser, profile, [refreshed], KEY)
    con = sqlite3.connect(str(browser.cookies_db(profile)))
    try:
        expires, httponly, samesite = con.execute("SELECT expires_utc, is_httponly, samesite FROM cookies").fetchone()
    finally:
        con.close()
    assert expires == 13_999_000_000_000_000
    assert httponly == 0
    assert samesite == 0


# --- full round-trip on both schemas ---


async def test_full_roundtrip_preserves_value_and_flags(cookies_db: tuple[Browser, str]) -> None:
    browser, profile = cookies_db
    original = _sample_cookie(host=".roundtrip.test", name="auth", value="café—token—😀")
    await write_rows(browser, profile, [original], KEY)

    rows = await read_rows(browser, profile)
    assert len(rows) == 1
    row = rows[0]
    decrypted = decrypt_value(row.encrypted_value, KEY, row.host_key)
    assert decrypted == original.value
    assert row.host_key == original.host_key
    assert row.name == original.name
    assert row.path == original.path
    assert row.expires_utc == original.expires_utc
    assert row.is_secure == original.is_secure
    assert row.is_httponly == original.is_httponly
    assert row.samesite == original.samesite

    # Re-encrypt the decrypted value, write again, re-read: still one row, value intact.
    reencrypted = replace(original, value=decrypted)
    await write_rows(browser, profile, [reencrypted], KEY)
    rows2 = await read_rows(browser, profile)
    assert len(rows2) == 1
    assert decrypt_value(rows2[0].encrypted_value, KEY, rows2[0].host_key) == original.value


async def test_multiple_distinct_cookies_coexist(cookies_db: tuple[Browser, str]) -> None:
    browser, profile = cookies_db
    cookies = [
        _sample_cookie(host=".a.com", name="x", value="1"),
        _sample_cookie(host=".a.com", name="y", value="2"),
        _sample_cookie(host=".b.com", name="x", value="3"),
    ]
    assert await write_rows(browser, profile, cookies, KEY) == 3
    rows = await read_rows(browser, profile)
    assert len(rows) == 3
    assert {decrypt_value(r.encrypted_value, KEY, r.host_key) for r in rows} == {"1", "2", "3"}


# --- count_applicable ---


async def test_count_applicable(cookies_db: tuple[Browser, str]) -> None:
    browser, profile = cookies_db
    await write_rows(
        browser,
        profile,
        [
            _sample_cookie(host=".example.com", name="a", value="1"),
            _sample_cookie(host="sub.example.com", name="b", value="2"),
            _sample_cookie(host=".other.com", name="c", value="3"),
        ],
        KEY,
    )
    assert await count_applicable(browser, profile, Host("www.example.com")) == 1
    assert await count_applicable(browser, profile, Host("sub.example.com")) == 2
    assert await count_applicable(browser, profile, Host("other.com")) == 1


# --- list_profile_dirs & profile_info ---


async def test_list_profile_dirs_only_dirs_with_cookies(tmp_path: Path) -> None:
    browser = _make_browser(tmp_path, "Default")
    _init_db(browser.cookies_db("Default"), V24_SQL)
    (tmp_path / "Profile 1").mkdir()
    _init_db(browser.cookies_db("Profile 1"), V18_SQL)
    (tmp_path / "No Cookies Here").mkdir()  # no Cookies DB -> excluded
    assert await list_profile_dirs(browser) == ("Default", "Profile 1")


async def test_profile_info_reads_info_cache(tmp_path: Path) -> None:
    browser = _make_browser(tmp_path, "Default")
    browser.local_state().write_text(
        json.dumps(
            {
                "profile": {
                    "info_cache": {
                        "Default": {"user_name": "a@x.com", "gaia_name": "Ada"},
                        "Profile 1": {"user_name": "b@x.com", "name": "Backup"},
                    }
                }
            }
        )
    )
    info = await profile_info(browser)
    assert info["Default"] == {"email": "a@x.com", "name": "Ada"}
    assert info["Profile 1"] == {"email": "b@x.com", "name": "Backup"}


# v24 insert helper (defined late so it can sit beside the test that needs it).


def _insert_v24_con(con: sqlite3.Connection, host_key: str, name: str, encrypted: bytes, value: str = "") -> None:
    con.execute(
        "INSERT INTO cookies (creation_utc, host_key, top_frame_site_key, name, value, "
        "encrypted_value, path, expires_utc, is_secure, is_httponly, last_access_utc, "
        "has_expires, is_persistent, priority, samesite, source_scheme, source_port, "
        "last_update_utc, source_type, has_cross_site_ancestor) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            13_300_000_000_000_000,
            host_key,
            "",
            name,
            value,
            encrypted,
            "/",
            13_400_000_000_000_000,
            1,
            0,
            13_300_000_000_000_000,
            1,
            1,
            1,
            0,
            2,
            443,
            13_350_000_000_000_000,
            0,
            0,
        ),
    )


def _insert_v24(path: Path, host_key: str, name: str, encrypted: bytes, value: str = "") -> None:
    con = sqlite3.connect(str(path))
    try:
        _insert_v24_con(con, host_key, name, encrypted, value)
        con.commit()
    finally:
        con.close()
