"""The extract/apply orchestration over a ``CookieBackend``.

``extract`` decrypts a host's cookies from a backend with an already-obtained key — the
consent gate lives in the backend, not here, so ``extract`` is pure given its key. It
filters to the host (in the backend), decrypts each row, drops expired cookies, and falls
back to the cross-browser ``get-cookie`` sweep when self-decrypt yields nothing. ``apply``
writes a cookie set back through the backend.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from cookiesync.cookie import getcookie
from cookiesync.cookie.crypto import DecryptError, decrypt_value
from cookiesync.cookie.domains import normalize_host
from cookiesync.cookie.models import (
    Cookie,
    StorageState,
    chrome_micros_to_unix,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cookiesync.cookie.backend import CookieBackend
    from cookiesync.cookie.browsers import Browser
    from cookiesync.cookie.models import AesKey, EncryptedRow


def _decrypt_row(row: EncryptedRow, key: AesKey, counts: dict[str, int]) -> Cookie | None:
    try:
        value = decrypt_value(row.encrypted_value, key, row.host_key)
    except DecryptError as exc:
        counts["v20" if "v20" in str(exc) else "failed"] += 1
        return None
    return Cookie(
        host_key=row.host_key,
        name=row.name,
        value=value,
        path=row.path,
        expires_utc=row.expires_utc,
        last_update_utc=row.last_update_utc,
        creation_utc=row.creation_utc,
        is_secure=row.is_secure,
        is_httponly=row.is_httponly,
        samesite=row.samesite,
        source_scheme=row.source_scheme,
        source_port=row.source_port,
        top_frame_site_key=row.top_frame_site_key,
        has_cross_site_ancestor=row.has_cross_site_ancestor,
    )


def _is_live(cookie: Cookie, *, now: float, include_expired: bool) -> bool:
    return include_expired or (expires := chrome_micros_to_unix(cookie.expires_utc)) == -1 or expires >= now


async def extract(
    url: str,
    *,
    browser: Browser,
    key: AesKey,
    backend: CookieBackend,
    profile: str | None = None,
    include_expired: bool = False,
    fallback: bool = True,
) -> StorageState:
    """Decrypt a host's cookies via ``backend`` with an already-obtained ``key``.

    The consent gate is the caller's responsibility — ``key`` is passed in, never obtained
    here. Rows are read and host-filtered by the backend, decrypted with ``key`` (``v20``
    app-bound and undecryptable rows are skipped), and expired cookies are dropped unless
    ``include_expired``. When self-decrypt yields nothing and ``fallback`` is set, the
    cross-browser ``get-cookie`` sweep runs instead.

    Example:
        >>> await extract("https://x.com", browser=chrome, key=key, backend=backend)
    """
    host = normalize_host(url)
    counts = {"v20": 0, "failed": 0}
    now = time.time()
    cookies = tuple(
        cookie
        for row in await backend.read_rows(browser, host, profile=profile)
        if (cookie := _decrypt_row(row, key, counts)) is not None
        and _is_live(cookie, now=now, include_expired=include_expired)
    )
    if not cookies and fallback:
        return StorageState(tuple(await getcookie.fetch_cookies(host)))
    return StorageState(cookies)


async def apply(cookies: Sequence[Cookie], *, browser: Browser, key: AesKey, backend: CookieBackend) -> int:
    """Write ``cookies`` back through ``backend``, returning the number of rows written.

    Example:
        >>> await apply(state.cookies, browser=chrome, key=key, backend=backend)
    """
    return await backend.write_rows(browser, cookies, key)
