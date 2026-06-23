"""Cookie data model: branded primitives, the decrypted ``Cookie``, its raw DB row, and storage state.

Timestamps stay Chrome-native (``ChromeMicros``, µs since 1601) throughout the model;
conversion to Unix seconds and Playwright sameSite strings happens only at serialize time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NewType

Host = NewType("Host", str)
HostKey = NewType("HostKey", str)
SafeStorageKey = NewType("SafeStorageKey", str)
AesKey = NewType("AesKey", bytes)
ChromeMicros = NewType("ChromeMicros", int)

WINDOWS_EPOCH_OFFSET = 11_644_473_600

SAMESITE_PLAYWRIGHT = {-1: "Lax", 0: "None", 1: "Lax", 2: "Strict"}


def chrome_micros_to_unix(micros: ChromeMicros) -> float:
    """Chrome timestamp (µs since 1601) to Unix seconds, or ``-1`` for a session cookie."""
    return -1 if micros <= 0 else micros / 1_000_000 - WINDOWS_EPOCH_OFFSET


def unix_to_chrome_micros(seconds: float) -> ChromeMicros:
    """Unix seconds to a Chrome timestamp (µs since 1601)."""
    return ChromeMicros(round((seconds + WINDOWS_EPOCH_OFFSET) * 1_000_000))


def samesite_to_playwright(samesite: int) -> str:
    """Chrome-native sameSite int (-1/0/1/2) to the Playwright string."""
    return SAMESITE_PLAYWRIGHT[samesite]


@dataclass(frozen=True, slots=True)
class Cookie:
    """One decrypted cookie, with Chrome-native column values.

    Example:
        >>> Cookie(HostKey(".x.com"), "sid", "abc", "/", ChromeMicros(0), ...)
    """

    host_key: HostKey
    name: str
    value: str
    path: str
    expires_utc: ChromeMicros
    last_update_utc: ChromeMicros
    creation_utc: ChromeMicros
    is_secure: bool
    is_httponly: bool
    samesite: int
    source_scheme: int = 2
    source_port: int = 443
    top_frame_site_key: str = ""
    has_cross_site_ancestor: int = 0


@dataclass(frozen=True, slots=True)
class EncryptedRow:
    """A raw, pre-decrypt cookie row straight off the Chrome SQLite store.

    Carries both the ``encrypted_value`` blob and the legacy plaintext ``value`` column.
    """

    host_key: HostKey
    name: str
    encrypted_value: bytes
    value: str
    path: str
    expires_utc: ChromeMicros
    last_update_utc: ChromeMicros
    creation_utc: ChromeMicros
    is_secure: bool
    is_httponly: bool
    samesite: int
    source_scheme: int = 2
    source_port: int = 443
    top_frame_site_key: str = ""
    has_cross_site_ancestor: int = 0


@dataclass(frozen=True, slots=True)
class StorageState:
    """A bundle of decrypted cookies, ready to seed a browser session."""

    cookies: tuple[Cookie, ...]
