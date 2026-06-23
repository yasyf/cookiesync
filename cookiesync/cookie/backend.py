"""The cookie-store seam: where rows are read from, the key obtained, and rows written to.

``CookieBackend`` is the boundary the pipeline talks to, so the same ``extract``/``apply``
flow runs against the local machine today and an ssh-backed remote tomorrow. ``LocalBackend``
wires the seam to this machine's stores: it auto-selects the profile with the most applicable
cookies (raising ``AmbiguousProfile`` when two profiles tie within 50%), filters rows to those
the browser would send to the host, obtains the Safe Storage key through the consent gate, and
upserts re-encrypted rows back into the live store.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from cookiesync.cookie.domains import cookie_applies
from cookiesync.cookie.stores import (
    count_applicable,
    list_profile_dirs,
    profile_info,
    read_rows,
    write_rows,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cookiesync.cookie.browsers import Browser
    from cookiesync.cookie.consent import Consent
    from cookiesync.cookie.models import AesKey, Cookie, EncryptedRow, Host

AMBIGUITY_RATIO = 0.5


class AmbiguousProfile(Exception):
    """Two or more browser profiles match the host within the ambiguity ratio; pass one explicitly."""


class NoMatchingProfile(Exception):
    """No browser profile holds any cookie applicable to the host."""


class CookieBackend(Protocol):
    """Reads encrypted rows, obtains the decryption key, and writes rows for a browser.

    The pipeline holds only this seam, so the local store and a future ssh-backed remote
    are interchangeable. ``read_rows`` returns rows already filtered to the host and picks
    the profile when one is not given.
    """

    async def read_rows(
        self, browser: Browser, host: Host, *, profile: str | None = None
    ) -> tuple[EncryptedRow, ...]: ...

    async def obtain_key(self, browser: Browser, *, reason: str) -> AesKey: ...

    async def write_rows(self, browser: Browser, rows: Sequence[Cookie], key: AesKey) -> int: ...


async def select_profile(browser: Browser, host: Host) -> str:
    scored = sorted(
        (
            (c, d)
            for d in await list_profile_dirs(browser)
            if (c := await count_applicable(browser, profile=d, host=host))
        ),
        reverse=True,
    )
    match scored:
        case []:
            raise NoMatchingProfile(f"no {browser.display} profile has cookies for {host}")
        case [(top, _), (runner, _), *_] if runner >= AMBIGUITY_RATIO * top:
            info = await profile_info(browser)
            cands = "; ".join(f"{d} ({info.get(d, {}).get('email', '?')}: {c})" for c, d in scored)
            raise AmbiguousProfile(
                f"multiple {browser.display} profiles match {host} — pass an explicit profile. Candidates: {cands}"
            )
        case [(_, winner), *_]:
            return winner


@dataclass(frozen=True, slots=True)
class LocalBackend:
    """The local machine's cookie stores behind the consent gate.

    Example:
        >>> await LocalBackend(TouchIDConsent()).read_rows(REGISTRY[BrowserName("chrome")], Host("x.com"))
    """

    consent: Consent

    async def read_rows(self, browser: Browser, host: Host, *, profile: str | None = None) -> tuple[EncryptedRow, ...]:
        chosen = profile or await select_profile(browser, host)
        return tuple(row for row in await read_rows(browser, chosen) if cookie_applies(row.host_key, host))

    async def obtain_key(self, browser: Browser, *, reason: str) -> AesKey:
        return await self.consent.obtain_key(browser, reason=reason)

    async def write_rows(self, browser: Browser, rows: Sequence[Cookie], key: AesKey) -> int:
        return await write_rows(browser, "Default", rows, key)
