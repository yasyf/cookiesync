"""Secure-Enclave-bound consent: obtain the Safe Storage AES key behind one Touch ID tap.

The legacy approach was consent theater — a cosmetic ``LAContext`` gate in front of a
sticky "Always Allow" ``/usr/bin/security`` read that goes silent after the first run.
``TouchIDConsent`` instead stores the Safe Storage password in a data-protection
keychain item bound to biometry-or-passcode, so every retrieval forces a genuine
biometric (or device-passcode) evaluation through the keychain. On a host with neither
biometrics nor a passcode (headless, no Touch ID), it falls back to the device-unlock
``security`` read.

The biometric vault and re-store run inside the installed, Developer-ID-signed
``cookiesync-keyhelper.app`` (``vault-status`` / ``vault-retrieve`` / ``vault-enroll``).
An ad-hoc helper is SIGKILLed at exec by AMFI, so a missing helper fails closed rather
than degrading to an unsigned build — see :func:`cookiesync.paths.require_helper`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, NamedTuple, Protocol

import anyio

from cookiesync import paths
from cookiesync.cookie.crypto import derive_key
from cookiesync.cookie.models import AesKey, SafeStorageKey

if TYPE_CHECKING:
    from pathlib import Path

    from cookiesync.cookie.browsers import Browser

SECURITY = "/usr/bin/security"
REASON_CAP = 160


class VaultStatus(NamedTuple):
    returncode: int
    has_passcode: bool
    has_vault: bool


class ConsentError(Exception):
    """The user explicitly declined the Touch ID / passcode prompt, or the vault read failed."""


def compose_reason(host: str, reason: str) -> str:
    """Touch ID prompt text: domain first, the caller's reason as a 'to …' clause.

    ``reason`` is collapsed to a single line and capped, since it surfaces verbatim in
    a security dialog.
    """
    return f"access your {host} session to {' '.join(reason.split())[:REASON_CAP]}"


class Consent(Protocol):
    """Obtains the Safe Storage AES key for a browser, gating on the user's consent."""

    async def obtain_key(self, browser: Browser, *, reason: str) -> AesKey: ...

    async def obtain_key_unprompted(self, browser: Browser) -> AesKey: ...


@dataclass(frozen=True, slots=True)
class TouchIDConsent:
    """A Secure-Enclave-bound key vault: one biometric tap unlocks the cached key.

    Example:
        >>> await TouchIDConsent().obtain_key(REGISTRY[BrowserName("chrome")], reason="post a tweet")
    """

    async def obtain_key_unprompted(self, browser: Browser) -> AesKey:
        """Release ``browser``'s key non-interactively, via a bare Keychain read — no Touch ID.

        For the owning host *only*, and *only* after a verified routed approval from the
        active-session peer has already gated the release: this performs the unlocked
        ``security`` read with no user-presence prompt, so the user-presence check must
        have happened over the routed-consent handshake first.
        """
        return derive_key(await self.read_safe_storage(browser.keychain_service))

    async def obtain_key(self, browser: Browser, *, reason: str) -> AesKey:
        helper = paths.require_helper()
        vault = f"cookiesync.vault.{browser.name}"
        env = os.environ | {"COOKIESYNC_TOUCHID_REASON": compose_reason(browser.display, reason)}

        status = await anyio.run_process([str(helper), "vault-status", vault], check=False)
        match VaultStatus(status.returncode, b"passcode=true" in status.stdout, b"vault=true" in status.stdout):
            case VaultStatus(returncode=2, has_passcode=False):
                return derive_key(await self.read_safe_storage(browser.keychain_service))
            case VaultStatus(has_vault=True):
                return derive_key(await self.retrieve(helper, vault, browser.keychain_service, env=env))
            case _:
                await self.enroll(helper, vault, browser.keychain_service)
                return derive_key(await self.retrieve(helper, vault, browser.keychain_service, env=env))

    async def retrieve(
        self, helper: Path, vault: str, safe_storage_service: str, *, env: dict[str, str]
    ) -> SafeStorageKey:
        result = await anyio.run_process([str(helper), "vault-retrieve", vault], check=False, env=env)
        match result.returncode:
            case 0:
                return SafeStorageKey(result.stdout.decode("utf-8"))
            case 1:
                raise ConsentError("Touch ID authentication was cancelled or denied")
            case _:
                # errSecItemNotFound / errSecAuthFailed: the biometryCurrentSet ACL
                # invalidated (the fingerprint set changed). Re-enroll once, then retry.
                await self.enroll(helper, vault, safe_storage_service)
                second = await anyio.run_process([str(helper), "vault-retrieve", vault], check=False, env=env)
                if second.returncode == 0:
                    return SafeStorageKey(second.stdout.decode("utf-8"))
                raise ConsentError("Touch ID vault retrieval failed after re-enrollment")

    async def enroll(self, helper: Path, vault: str, safe_storage_service: str) -> None:
        result = await anyio.run_process([str(helper), "vault-enroll", vault, safe_storage_service], check=False)
        if result.returncode != 0:
            raise ConsentError(
                f"could not enroll the Touch ID vault for {safe_storage_service!r} "
                f"(exit {result.returncode}: {result.stderr.decode().strip() or 'no detail'})"
            )

    async def read_safe_storage(self, service: str) -> SafeStorageKey:
        result = await anyio.run_process([SECURITY, "find-generic-password", "-w", "-s", service], check=False)
        if result.returncode != 0:
            raise ConsentError(f"could not read '{service}' from the Keychain (denied or missing)")
        return SafeStorageKey(result.stdout.decode("utf-8").strip())
