"""Short-TTL, Secure-Enclave-wrapped cache for derived AES keys.

The sync daemon derives a browser's Safe Storage key behind one Touch ID tap, then
reuses it for a brief window so a burst of operations needs only a single prompt. The
plaintext key lives in process memory for that window, but the AT-REST cache bytes are
Secure-Enclave-wrapped: a leaked cache blob or a core dump is useless off-box, since
only the live per-boot Enclave key can unwrap it.

:class:`SecureEnclaveWrapper` drives ``keycache.swift`` (compiled and ad-hoc signed at
runtime, mirroring ``keyvault.swift``). Tests inject a :class:`Wrapper` double and a
clock, so the cache logic is exercised without any macOS API.
"""

from __future__ import annotations

import os
import secrets
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import anyio

SWIFT_SRC = Path(__file__).parent / "vault" / "keycache.swift"


def data_dir() -> Path:
    """Persistent data dir for the compiled helper; cache fallback off-plugin."""
    if base := os.environ.get("CLAUDE_PLUGIN_DATA"):
        return Path(base)
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "cookiesync"


async def compile_helper() -> Path:
    """Compile (once) and ad-hoc sign the key-cache helper, cached by source mtime."""
    bin_path = data_dir() / "bin" / "keycache"
    if bin_path.is_file() and bin_path.stat().st_mtime >= SWIFT_SRC.stat().st_mtime:
        return bin_path
    bin_path.parent.mkdir(parents=True, exist_ok=True)
    await anyio.run_process(
        [shutil.which("swiftc"), str(SWIFT_SRC), "-framework", "Security", "-o", str(bin_path)],
    )
    await anyio.run_process([shutil.which("codesign"), "-s", "-", "-f", str(bin_path)])
    return bin_path


class Wrapper(Protocol):
    """Wraps and unwraps key bytes so the at-rest cache value is opaque off-box."""

    async def wrap(self, plaintext: bytes) -> bytes: ...

    async def unwrap(self, blob: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class SecureEnclaveWrapper:
    """Wraps key bytes against a per-boot ephemeral Secure-Enclave P-256 key.

    The Enclave key is created in :meth:`open` (one random label per process) and
    destroyed in :meth:`close`, so wrapped blobs are unrecoverable after the daemon
    exits or the machine reboots.

    Example:
        >>> wrapper = await SecureEnclaveWrapper.open()
        >>> blob = await wrapper.wrap(key)
        >>> assert await wrapper.unwrap(blob) == key
        >>> await wrapper.close()
    """

    helper: Path
    label: str = field(default_factory=lambda: secrets.token_hex(8))

    @classmethod
    async def open(cls) -> SecureEnclaveWrapper:
        wrapper = cls(await compile_helper())
        await anyio.run_process([str(wrapper.helper), "newkey", wrapper.label])
        return wrapper

    async def wrap(self, plaintext: bytes) -> bytes:
        return (await anyio.run_process([str(self.helper), "wrap", self.label], stdin=plaintext)).stdout

    async def unwrap(self, blob: bytes) -> bytes:
        return (await anyio.run_process([str(self.helper), "unwrap", self.label], stdin=blob)).stdout

    async def close(self) -> None:
        await anyio.run_process([str(self.helper), "dropkey", self.label])


@dataclass(frozen=True, slots=True)
class Entry:
    blob: bytes
    expires_at: float


@dataclass(slots=True)
class KeyCache:
    """A short-TTL cache of derived AES keys, each stored only as a wrapped blob.

    ``put`` wraps a key and records its expiry; ``get`` unwraps transiently and returns
    ``None`` once the entry is expired or evicted. The plaintext is never persisted to
    disk and never logged. The clock is injectable for tests.

    Example:
        >>> cache = KeyCache(await SecureEnclaveWrapper.open())
        >>> await cache.put(endpoint.id, key, ttl=30.0)
        >>> assert await cache.get(endpoint.id) == key
    """

    wrapper: Wrapper
    now: Callable[[], float] = time.monotonic
    entries: dict[str, Entry] = field(default_factory=dict)

    async def put(self, endpoint_id: str, key: bytes, ttl: float) -> None:
        self.entries[endpoint_id] = Entry(await self.wrapper.wrap(key), self.now() + ttl)

    async def get(self, endpoint_id: str) -> bytes | None:
        match self.entries.get(endpoint_id):
            case None:
                return None
            case Entry(expires_at=expires_at) if self.now() >= expires_at:
                del self.entries[endpoint_id]
                return None
            case Entry(blob=blob):
                return await self.wrapper.unwrap(blob)

    def evict(self, endpoint_id: str) -> None:
        self.entries.pop(endpoint_id, None)

    def evict_all(self) -> None:
        self.entries.clear()
