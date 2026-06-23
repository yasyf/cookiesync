"""Cross-browser cookie fallback via ``@mherod/get-cookie``, swept across every browser.

Used when Chrome self-decrypt finds nothing — the user is logged in via
Brave/Arc/Edge/Safari/Firefox, or the cookies are app-bound (v20). We deliberately
omit ``--browser`` so get-cookie queries every browser. The package is lazily
``bun add``-ed once into a persistent data dir (it needs the native better-sqlite3
module) and reused; ``bunx`` is the last-resort path.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

import anyio

from cookiesync.cookie.models import Host
from cookiesync.cookie.serialize import normalize_getcookie_record

if TYPE_CHECKING:
    from cookiesync.cookie.models import Cookie

GETCOOKIE_VERSION = "4.4.3"
PACKAGE = f"@mherod/get-cookie@{GETCOOKIE_VERSION}"
PACKAGE_JSON = '{"name":"cookiesync-getcookie-cache","private":true}\n'


class GetCookieError(Exception):
    """The get-cookie fallback could not run or its output could not be parsed."""


def data_dir() -> Path:
    """Persistent cache dir for the lazily installed get-cookie package."""
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "cookiesync"


def cached_cli() -> Path | None:
    cli = data_dir() / "node_modules" / "@mherod" / "get-cookie" / "dist" / "cli.cjs"
    return cli if cli.is_file() else None


async def ensure_installed() -> Path | None:
    """Lazily ``bun add`` get-cookie into the data dir (builds better-sqlite3). Cached."""
    if cli := cached_cli():
        return cli
    if not (bun := shutil.which("bun")):
        return None
    (data := data_dir()).mkdir(parents=True, exist_ok=True)
    if not (pkg := data / "package.json").is_file():
        pkg.write_text(PACKAGE_JSON)
    await anyio.run_process([bun, "add", PACKAGE], cwd=str(data), check=True)
    return cached_cli()


async def command(host: Host) -> list[str]:
    """The argv that runs get-cookie for ``host`` across all browsers (cached CLI, else bunx)."""
    match (await ensure_installed(), shutil.which("bun"), shutil.which("bunx")):
        case (cli, bun, _) if cli and bun:
            return [bun, str(cli), "%", host, "--output", "json"]
        case (_, _, bunx) if bunx:
            return [bunx, PACKAGE, "%", host, "--output", "json"]
        case _:
            raise GetCookieError("neither a cached get-cookie nor bun/bunx is available")


def _decode_anywhere(text: str) -> object | None:
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch in "[{":
            try:
                return decoder.raw_decode(text, i)[0]
            except json.JSONDecodeError:
                continue
    return None


def parse(stdout: str) -> list[dict]:
    """Parse get-cookie JSON, tolerating leading log noise before the JSON value.

    Scans every ``[``/``{`` offset and returns the first that ``raw_decode``s, so log
    lines that themselves contain brackets (e.g. ``[get-cookie] ...``) don't trip it.
    """
    if not (out := stdout.strip()):
        return []
    match _decode_anywhere(out):
        case None:
            raise GetCookieError("could not parse get-cookie JSON output")
        case data:
            ...
    match data:
        case {"cookies": list() as cookies}:
            return cookies
        case {"data": list() as records}:
            return records
        case dict():
            return [data]
        case list():
            return data
        case _:
            return []


async def fetch_cookies(host: Host) -> list[Cookie]:
    """Sweep every browser for ``host`` via get-cookie and return decoded cookies.

    Example:
        >>> await fetch_cookies(Host("github.com"))
    """
    proc = await anyio.run_process(await command(host), check=True)
    return [normalize_getcookie_record(record, host) for record in parse(proc.stdout.decode("utf-8"))]
