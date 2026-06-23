"""Render a ``StorageState`` to stdout in one of four cookie wire formats.

The Playwright/agent-browser format is the load-bearing one: ``agent-browser
--state -`` consumes the standard ``{"cookies": [...], "origins": []}`` storageState
shape. We only carry cookies (the local store has no localStorage), so ``origins``
is always empty. The other formats serve cookies.txt (netscape), a ``Cookie:``
request header, and a raw JSON array of the same per-cookie dicts.

``render`` yields lines so the caller can stream straight to stdout.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import TYPE_CHECKING

from cookiesync.cookie.domains import normalize_host, url_scheme
from cookiesync.cookie.models import (
    ChromeMicros,
    Cookie,
    HostKey,
    chrome_micros_to_unix,
    samesite_to_playwright,
    unix_to_chrome_micros,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cookiesync.cookie.models import StorageState

SAMESITE_GETCOOKIE = {"strict": 2, "lax": 1, "none": 0}


class OutputFormat(StrEnum):
    """The wire format ``render`` emits a ``StorageState`` in.

    Example:
        >>> "".join(render(state, OutputFormat.PLAYWRIGHT))
    """

    PLAYWRIGHT = "playwright"
    NETSCAPE = "netscape"
    HEADER = "header"
    JSON = "json"


def playwright_cookie(cookie: Cookie) -> dict:
    """One Playwright-shaped cookie dict from a Chrome-native ``Cookie``.

    ``sameSite=None`` forces ``secure`` true, since browsers reject the pair otherwise.
    """
    same = samesite_to_playwright(cookie.samesite)
    return {
        "name": cookie.name,
        "value": cookie.value,
        "domain": cookie.host_key,
        "path": cookie.path,
        "expires": chrome_micros_to_unix(cookie.expires_utc),
        "httpOnly": cookie.is_httponly,
        "secure": cookie.is_secure or same == "None",
        "sameSite": same,
    }


def netscape_line(cookie: Cookie) -> str:
    """One cookies.txt row: tab-separated, with the leading-dot subdomain flag."""
    include_subdomains = cookie.host_key.startswith(".")
    expires = chrome_micros_to_unix(cookie.expires_utc)
    return "\t".join(
        (
            cookie.host_key,
            "TRUE" if include_subdomains else "FALSE",
            cookie.path,
            "TRUE" if cookie.is_secure else "FALSE",
            str(0 if expires < 0 else int(expires)),
            cookie.name,
            cookie.value,
        )
    )


def render(state: StorageState, fmt: OutputFormat) -> Iterator[str]:
    """Yield the lines of ``state`` rendered in ``fmt``, ready to stream to stdout."""
    match fmt:
        case OutputFormat.PLAYWRIGHT:
            yield json.dumps({"cookies": [playwright_cookie(c) for c in state.cookies], "origins": []})
        case OutputFormat.JSON:
            yield json.dumps([playwright_cookie(c) for c in state.cookies])
        case OutputFormat.NETSCAPE:
            yield "# Netscape HTTP Cookie File"
            yield from (netscape_line(c) for c in state.cookies)
        case OutputFormat.HEADER:
            yield "; ".join(f"{c.name}={c.value}" for c in state.cookies)


def normalize_getcookie_record(record: dict, url: str) -> Cookie:
    """Map one ``@mherod/get-cookie`` JSON record into the ``Cookie`` model.

    get-cookie reliably emits name/value/domain; the rest varies, so path defaults
    to ``/``, secure follows the URL scheme, and attributes come from a ``meta``
    block when present. A session cookie (no expiry) lands at ``ChromeMicros(0)``.
    """
    meta = record.get("meta") or {}
    host = normalize_host(url)
    host_key = HostKey(record.get("domain") or host)
    return Cookie(
        host_key=host_key,
        name=record["name"],
        value=record["value"],
        path=record.get("path") or "/",
        expires_utc=_record_expiry(record),
        last_update_utc=ChromeMicros(0),
        creation_utc=ChromeMicros(0),
        is_secure=bool(meta.get("secure", url_scheme(url) == "https")),
        is_httponly=bool(meta.get("httpOnly", meta.get("httponly", False))),
        samesite=SAMESITE_GETCOOKIE.get(str(meta.get("sameSite") or meta.get("samesite") or "lax").lower(), 1),
    )


def _record_expiry(record: dict) -> ChromeMicros:
    raw = record.get("expiry", record.get("expires"))
    match raw:
        case bool():
            return ChromeMicros(0)
        case int() | float():
            return unix_to_chrome_micros(float(raw))
        case str() if raw.strip().lstrip("-").isdigit():
            return unix_to_chrome_micros(float(raw))
        case _:
            return ChromeMicros(0)
