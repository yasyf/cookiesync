"""Unit tests for the Secure-Enclave-wrapped key cache.

The wrap/unwrap boundary is the only macOS-specific surface, so it is doubled by a
reversible XOR :class:`FakeWrapper` and the clock is injected — the cache logic
(TTL expiry, eviction, storing only the wrapped blob) runs without any real Enclave.
"""

from __future__ import annotations

import stat
from dataclasses import dataclass
from pathlib import Path

import pytest

from cookiesync import paths
from cookiesync.daemon.cache import KeyCache, SecureEnclaveWrapper
from cookiesync.paths import HelperError

ENDPOINT = "yasyf-home:chrome:Default"
OTHER = "yasyf-work:arc:Profile 1"
KEY = bytes(range(32))
XOR_MASK = 0x5A

# A fake cookiesync-keyhelper that emulates the cache-* subcommand contract: an XOR
# round-trip wrapper standing in for the Secure-Enclave ECIES blob, with newkey/dropkey
# as no-op exit-0s and the label recorded to a state file so tests can assert on it.
FAKE_HELPER = f"""#!/usr/bin/env python3
import sys
verb, label = sys.argv[1], sys.argv[2]
state = __import__("os").environ["FAKE_HELPER_STATE"]
if verb in ("cache-newkey", "cache-dropkey"):
    open(state, "a").write(verb + " " + label + "\\n")
    sys.exit(0)
data = sys.stdin.buffer.read()
sys.stdout.buffer.write(bytes(b ^ {XOR_MASK} for b in data))
sys.exit(0)
"""


@dataclass(frozen=True, slots=True)
class FakeWrapper:
    async def wrap(self, plaintext: bytes) -> bytes:
        return bytes(b ^ XOR_MASK for b in plaintext)

    async def unwrap(self, blob: bytes) -> bytes:
        return bytes(b ^ XOR_MASK for b in blob)


@pytest.fixture
def fake_helper(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    binary = tmp_path / "cookiesync-keyhelper.app" / "Contents" / "MacOS" / "cookiesync-keyhelper"
    binary.parent.mkdir(parents=True)
    binary.write_text(FAKE_HELPER)
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setattr(paths, "helper_binary", lambda: binary)
    monkeypatch.setenv("FAKE_HELPER_STATE", str(tmp_path / "helper.log"))
    return binary


async def test_secure_enclave_wrapper_round_trips_via_the_signed_helper(fake_helper: Path, tmp_path: Path) -> None:
    wrapper = await SecureEnclaveWrapper.open()

    blob = await wrapper.wrap(KEY)
    assert blob != KEY
    assert await wrapper.unwrap(blob) == KEY

    await wrapper.close()
    log = (tmp_path / "helper.log").read_text().splitlines()
    assert log[0] == f"cache-newkey {wrapper.label}"
    assert log[-1] == f"cache-dropkey {wrapper.label}"


async def test_secure_enclave_wrapper_fails_closed_when_helper_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(paths, "helper_binary", lambda: tmp_path / "absent" / "cookiesync-keyhelper")
    with pytest.raises(HelperError, match="cookiesync install"):
        await SecureEnclaveWrapper.open()


async def test_key_cache_over_the_signed_helper_wrapper(fake_helper: Path) -> None:
    cache_obj = KeyCache(await SecureEnclaveWrapper.open())
    await cache_obj.put(ENDPOINT, KEY, ttl=30.0)
    assert cache_obj.entries[ENDPOINT].blob != KEY
    assert await cache_obj.get(ENDPOINT) == KEY


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def cache(clock: Clock) -> KeyCache:
    return KeyCache(FakeWrapper(), now=clock)


async def test_put_then_get_returns_the_key(cache: KeyCache) -> None:
    await cache.put(ENDPOINT, KEY, ttl=30.0)
    assert await cache.get(ENDPOINT) == KEY


async def test_get_missing_returns_none(cache: KeyCache) -> None:
    assert await cache.get(ENDPOINT) is None


async def test_get_after_ttl_returns_none(cache: KeyCache, clock: Clock) -> None:
    await cache.put(ENDPOINT, KEY, ttl=30.0)
    clock.t = 29.999
    assert await cache.get(ENDPOINT) == KEY
    clock.t = 30.0
    assert await cache.get(ENDPOINT) is None


async def test_expired_get_evicts_the_entry(cache: KeyCache, clock: Clock) -> None:
    await cache.put(ENDPOINT, KEY, ttl=30.0)
    clock.t = 30.0
    assert await cache.get(ENDPOINT) is None
    assert ENDPOINT not in cache.entries


async def test_evict_clears_one_entry(cache: KeyCache) -> None:
    await cache.put(ENDPOINT, KEY, ttl=30.0)
    await cache.put(OTHER, KEY, ttl=30.0)
    cache.evict(ENDPOINT)
    assert await cache.get(ENDPOINT) is None
    assert await cache.get(OTHER) == KEY


async def test_evict_missing_endpoint_is_a_noop(cache: KeyCache) -> None:
    cache.evict(ENDPOINT)
    assert cache.entries == {}


async def test_evict_all_clears_every_entry(cache: KeyCache) -> None:
    await cache.put(ENDPOINT, KEY, ttl=30.0)
    await cache.put(OTHER, KEY, ttl=30.0)
    cache.evict_all()
    assert cache.entries == {}
    assert await cache.get(ENDPOINT) is None
    assert await cache.get(OTHER) is None


async def test_stored_value_is_the_wrapped_blob_not_the_raw_key(cache: KeyCache) -> None:
    await cache.put(ENDPOINT, KEY, ttl=30.0)
    stored = cache.entries[ENDPOINT].blob
    assert stored != KEY
    assert stored == bytes(b ^ XOR_MASK for b in KEY)
    assert await FakeWrapper().unwrap(stored) == KEY


async def test_put_overwrites_an_existing_entry(cache: KeyCache, clock: Clock) -> None:
    await cache.put(ENDPOINT, KEY, ttl=30.0)
    clock.t = 40.0
    new_key = bytes(reversed(KEY))
    await cache.put(ENDPOINT, new_key, ttl=10.0)
    assert await cache.get(ENDPOINT) == new_key
    clock.t = 50.0
    assert await cache.get(ENDPOINT) is None
