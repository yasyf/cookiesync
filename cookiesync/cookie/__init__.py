"""The cookiesync cookie engine: extract, merge, and apply browser cookies across machines."""

from __future__ import annotations

from cookiesync.cookie.backend import CookieBackend, LocalBackend
from cookiesync.cookie.browsers import REGISTRY, Browser
from cookiesync.cookie.consent import Consent, ConsentError, TouchIDConsent
from cookiesync.cookie.crypto import DecryptError, decrypt_value, derive_key, encrypt_value
from cookiesync.cookie.merge import merge
from cookiesync.cookie.models import (
    AesKey,
    Cookie,
    EncryptedRow,
    Host,
    HostKey,
    SafeStorageKey,
    StorageState,
)
from cookiesync.cookie.pipeline import apply, extract
from cookiesync.cookie.serialize import OutputFormat, render
