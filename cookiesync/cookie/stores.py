"""Schema-version-aware async I/O against Chrome's SQLite cookie store.

Reads copy the live ``Cookies`` DB (plus its ``-wal``/``-shm``/``-journal`` sidecars)
into a private temp dir and open the copy read-write, so a running browser is never
disturbed and the WAL checkpoints into the copy before we ``SELECT``. Writes go to the
live DB, best-effort: a short ``busy_timeout`` plus a soft-busy return on a locked DB,
never a forced clobber.

Chrome's cookie schema drifts across versions: v18 carries ``is_same_party`` and a
``UNIQUE(host_key, top_frame_site_key, name, path)`` index, while v24 drops
``is_same_party``, adds ``source_type`` + ``has_cross_site_ancestor``, and widens the
unique index to include ``has_cross_site_ancestor``, ``source_scheme``, and
``source_port``. Every operation introspects the actual table and unique index via
``PRAGMA table_info`` / ``PRAGMA index_list`` / ``PRAGMA index_info`` rather than
hardcoding one column set.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING

import aiosqlite

from cookiesync.cookie.crypto import encrypt_value
from cookiesync.cookie.domains import cookie_applies
from cookiesync.cookie.models import (
    ChromeMicros,
    EncryptedRow,
    Host,
    HostKey,
    unix_to_chrome_micros,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cookiesync.cookie.browsers import Browser
    from cookiesync.cookie.models import AesKey, Cookie

SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")

BUSY_TIMEOUT_MS = 250

ROW_FIELD_DEFAULTS: dict[str, object] = {
    "encrypted_value": b"",
    "value": "",
    "source_scheme": 2,
    "source_port": 443,
    "top_frame_site_key": "",
    "has_cross_site_ancestor": 0,
}


def _to_micros(value: int) -> ChromeMicros:
    return ChromeMicros(int(value))


def _row_from_columns(columns: tuple[str, ...], values: tuple[object, ...]) -> EncryptedRow:
    cells = ROW_FIELD_DEFAULTS | dict(zip(columns, values, strict=True))
    return EncryptedRow(
        host_key=HostKey(cells["host_key"]),
        name=cells["name"],
        encrypted_value=bytes(ev) if (ev := cells["encrypted_value"]) is not None else b"",
        value=cells["value"] or "",
        path=cells["path"],
        expires_utc=_to_micros(cells["expires_utc"]),
        last_update_utc=_to_micros(cells.get("last_update_utc", 0)),
        creation_utc=_to_micros(cells["creation_utc"]),
        is_secure=bool(cells["is_secure"]),
        is_httponly=bool(cells["is_httponly"]),
        samesite=int(cells["samesite"]),
        source_scheme=int(cells["source_scheme"]),
        source_port=int(cells["source_port"]),
        top_frame_site_key=str(cells["top_frame_site_key"]),
        has_cross_site_ancestor=int(cells["has_cross_site_ancestor"]),
    )


async def _table_columns(db: aiosqlite.Connection) -> tuple[str, ...]:
    async with db.execute("PRAGMA table_info(cookies)") as cur:
        return tuple(row[1] for row in await cur.fetchall())


async def _unique_index_columns(db: aiosqlite.Connection) -> tuple[str, ...]:
    async with db.execute("PRAGMA index_list(cookies)") as cur:
        indexes = await cur.fetchall()
    name = next(idx[1] for idx in indexes if idx[2] and not idx[4])
    async with db.execute(f"PRAGMA index_info({name})") as cur:
        return tuple(col[2] for col in await cur.fetchall())


def _copy_with_sidecars(db: Path, dest_dir: Path) -> Path:
    copy = dest_dir / "Cookies"
    shutil.copy2(db, copy)
    for suffix in SIDECAR_SUFFIXES:
        if (side := Path(f"{db}{suffix}")).is_file():
            shutil.copy2(side, f"{copy}{suffix}")
    return copy


async def read_rows(browser: Browser, profile: str) -> tuple[EncryptedRow, ...]:
    """Every cookie row in ``profile`` as raw ``EncryptedRow``s, read off a private copy.

    The live ``Cookies`` DB and its WAL/journal sidecars are copied to a temp dir and the
    copy is opened read-write so SQLite checkpoints the WAL before the read. Only columns
    present in this store's schema are selected; absent columns fall back to their defaults.
    """
    tmpdir = Path(tempfile.mkdtemp(prefix="cookiesync-"))
    try:
        copy = _copy_with_sidecars(browser.cookies_db(profile), tmpdir)
        async with aiosqlite.connect(copy) as db:
            columns = await _table_columns(db)
            async with db.execute(f"SELECT {', '.join(columns)} FROM cookies") as cur:
                rows = await cur.fetchall()
            return tuple(_row_from_columns(columns, tuple(values)) for values in rows)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


async def list_profile_dirs(browser: Browser) -> tuple[str, ...]:
    """Profile directory names under ``browser`` that hold a ``Cookies`` DB, sorted."""
    root = browser.data_root
    return tuple(sorted(c.name for c in root.iterdir() if c.is_dir() and browser.cookies_db(c.name).is_file()))


async def count_applicable(browser: Browser, profile: str, host: Host) -> int:
    """How many cookies in ``profile`` a browser would send to ``host`` (no decryption)."""
    return sum(cookie_applies(row.host_key, host) for row in await read_rows(browser, profile))


async def profile_info(browser: Browser) -> dict[str, dict[str, str]]:
    """Map each profile directory name to its ``{email, name}`` from ``Local State``.

    Read from the browser's ``Local State`` JSON under ``profile.info_cache``: ``email``
    comes from ``user_name`` and ``name`` from ``gaia_name`` (falling back to ``name``).
    """
    cache = json.loads(browser.local_state().read_text()).get("profile", {}).get("info_cache", {})
    return {
        name: {
            "email": info.get("user_name", ""),
            "name": info.get("gaia_name", "") or info.get("name", ""),
        }
        for name, info in cache.items()
    }


def _insert_values(cookie: Cookie, encrypted: bytes) -> dict[str, object]:
    creation = cookie.creation_utc if cookie.creation_utc > 0 else unix_to_chrome_micros(time.time())
    has_expires = int(cookie.expires_utc > 0)
    return {
        "creation_utc": int(creation),
        "host_key": cookie.host_key,
        "top_frame_site_key": cookie.top_frame_site_key,
        "name": cookie.name,
        "value": "",
        "encrypted_value": encrypted,
        "path": cookie.path,
        "expires_utc": int(cookie.expires_utc),
        "is_secure": int(cookie.is_secure),
        "is_httponly": int(cookie.is_httponly),
        "last_access_utc": int(cookie.last_update_utc),
        "has_expires": has_expires,
        "is_persistent": has_expires,
        "priority": 1,
        "samesite": cookie.samesite,
        "source_scheme": cookie.source_scheme,
        "source_port": cookie.source_port,
        "last_update_utc": int(cookie.last_update_utc),
        "source_type": 0,
        "has_cross_site_ancestor": cookie.has_cross_site_ancestor,
        "is_same_party": 0,
    }


def _upsert_sql(columns: tuple[str, ...], conflict: tuple[str, ...]) -> str:
    cols = ", ".join(columns)
    placeholders = ", ".join(f":{c}" for c in columns)
    updates = ", ".join(
        f"{c} = excluded.{c}"
        for c in ("encrypted_value", "value", "expires_utc", "last_update_utc", "is_secure", "is_httponly", "samesite")
        if c in columns
    )
    return (
        f"INSERT INTO cookies ({cols}) VALUES ({placeholders}) "
        f"ON CONFLICT({', '.join(conflict)}) DO UPDATE SET {updates}"
    )


async def write_rows(browser: Browser, profile: str, cookies: Sequence[Cookie], key: AesKey) -> int:
    """Encrypt and upsert ``cookies`` into ``profile``'s live ``Cookies`` DB; return rows written.

    Each value is re-encrypted into a ``v10`` blob (the plaintext ``value`` column is left
    empty) and written with ``INSERT ... ON CONFLICT(<this store's real unique index>) DO
    UPDATE``, so a re-synced cookie collapses onto its existing row. The cookie's own
    ``last_update_utc`` and ``creation_utc`` are preserved, never stamped to "now". On a
    locked database this returns ``-1`` (soft busy) rather than forcing a write.
    """
    db_path = browser.cookies_db(profile)
    async with aiosqlite.connect(db_path) as db:
        await db.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        columns = await _table_columns(db)
        conflict = await _unique_index_columns(db)
        sql = _upsert_sql(columns, conflict)
        try:
            for cookie in cookies:
                values = _insert_values(cookie, encrypt_value(cookie.value, key, cookie.host_key))
                await db.execute(sql, {c: values[c] for c in columns})
            await db.commit()
        except aiosqlite.OperationalError as exc:
            if "locked" not in str(exc):
                raise
            return -1
    return len(cookies)
