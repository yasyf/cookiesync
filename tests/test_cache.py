"""Unit tests for the Secure-Enclave-wrapped key cache.

The wrap/unwrap boundary is the only macOS-specific surface, so it is doubled by a
reversible XOR :class:`FakeWrapper` and the clock is injected — the cache logic
(TTL expiry, eviction, storing only the wrapped blob) runs without any real Enclave.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from cookiesync.daemon.cache import KeyCache

ENDPOINT = "yasyf-home:chrome:Default"
OTHER = "yasyf-work:arc:Profile 1"
KEY = bytes(range(32))
XOR_MASK = 0x5A


@dataclass(frozen=True, slots=True)
class FakeWrapper:
    async def wrap(self, plaintext: bytes) -> bytes:
        return bytes(b ^ XOR_MASK for b in plaintext)

    async def unwrap(self, blob: bytes) -> bytes:
        return bytes(b ^ XOR_MASK for b in blob)


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
