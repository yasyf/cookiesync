"""The watch engine: debounce a cookie-store write burst into one converge, with anti-echo.

A Chrome/Arc cookie write lands as a burst across the ``Cookies`` DB and its ``-wal``/
``-shm`` sidecars. The engine coalesces that burst, per endpoint, into a single
``evaluate`` once the store has been quiet for ``settings.watch_debounce``, then fires the
injected ``notify`` callback so the sync layer converges that endpoint with its peers.

Two filters keep the engine from chasing its own tail:

* **Anti-echo.** ``evaluate`` fingerprints the endpoint's *logical* cookie set via
  :func:`logical_digest` — sorted ``(host_key, name, path, last_update_utc)`` tuples, cheap
  and decryption-free — and compares it to the last digest the engine acted on. The sync
  layer records the digest of the very set it is about to write via :meth:`record_applied`
  just before writing; because the store preserves each cookie's ``last_update_utc``, the
  self-induced write reproduces that same digest and is recognized as a no-op. Only a
  genuinely new digest is recorded (*before* notifying) and notified.
* **Idle gate.** A store whose ``Cookies`` wall-clock mtime is within
  ``settings.idle_threshold`` is a browser actively writing; the engine debounces but does
  not notify until it settles.

The watcher source, clocks, mtime reader, digest function, and notify callback are all
injected, so the debounce/anti-echo/idle logic runs in unit tests with no real filesystem,
browser, or macOS API.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, NewType, Protocol

import anyio
from loguru import logger

from cookiesync.cookie import REGISTRY
from cookiesync.cookie.browsers import BrowserName
from cookiesync.cookie.stores import read_rows

if TYPE_CHECKING:
    from cookiesync.cookie.browsers import Browser
    from cookiesync.state import BrowserEndpoint, Settings

Digest = NewType("Digest", str)

type AwatchSource = Callable[[BrowserEndpoint], AsyncIterator[object]]
type Notify = Callable[[BrowserEndpoint], Awaitable[None]]
type DigestFn = Callable[[BrowserEndpoint], Awaitable[Digest]]
type Mtime = Callable[[BrowserEndpoint], Awaitable[float]]
type Sleep = Callable[[float], Awaitable[None]]


class LogicalRow(Protocol):
    """The fields :func:`logical_digest` keys on; satisfied by both ``Cookie`` and ``EncryptedRow``."""

    host_key: str
    name: str
    path: str
    last_update_utc: int


def logical_digest(items: Iterable[LogicalRow]) -> Digest:
    """A cheap, decryption-free digest of a cookie set's logical identity.

    Hashes the sorted ``(host_key, name, path, last_update_utc)`` tuples of every item. It
    ignores encrypted values and schema-only columns, so it changes exactly when the logical
    cookie set does. The sync layer digests the set it is about to write and the engine
    fingerprints the store after the write; because ``last_update_utc`` is preserved on write,
    the two agree and the induced filesystem event is recognized as the engine's own echo.
    """
    payload = "\x00".join(
        f"{item.host_key}\x1f{item.name}\x1f{item.path}\x1f{item.last_update_utc}"
        for item in sorted(items, key=lambda i: (i.host_key, i.name, i.path, i.last_update_utc))
    )
    return Digest(hashlib.sha256(payload.encode("utf-8")).hexdigest())


def endpoint_browser(endpoint: BrowserEndpoint) -> Browser:
    """The :class:`~cookiesync.cookie.browsers.Browser` an endpoint names."""
    return REGISTRY[BrowserName(endpoint.browser)]


def watch_dir(endpoint: BrowserEndpoint) -> object:
    """The directory holding an endpoint's ``Cookies`` DB and its WAL/SHM sidecars."""
    return endpoint_browser(endpoint).profile_dir(endpoint.profile)


async def fingerprint(endpoint: BrowserEndpoint) -> Digest:
    """The :func:`logical_digest` of an endpoint's store, read off its raw rows.

    Decryption-free: it reads every ``EncryptedRow`` and digests their logical identity, so
    it changes exactly when the logical cookie set does — which is what the anti-echo
    comparison turns on.
    """
    return logical_digest(await read_rows(endpoint_browser(endpoint), endpoint.profile))


async def cookies_mtime(endpoint: BrowserEndpoint) -> float:
    """The Unix mtime of an endpoint's live ``Cookies`` DB."""
    return (await anyio.Path(endpoint_browser(endpoint).cookies_db(endpoint.profile)).stat()).st_mtime


async def watch_endpoint(endpoint: BrowserEndpoint) -> AsyncIterator[object]:
    """Yield once per ``watchfiles`` change batch on an endpoint's profile directory.

    A local endpoint whose profile directory does not exist yet — e.g. a registered sync
    target this host has not created — has nothing to watch. Log and return rather than let
    ``watchfiles`` raise ``FileNotFoundError`` and tear the whole daemon down.
    """
    from watchfiles import awatch

    directory = watch_dir(endpoint)
    if not await anyio.Path(str(directory)).exists():
        logger.warning("not watching {}: profile dir {} does not exist", endpoint.id, directory)
        return
    async for changes in awatch(directory):
        yield changes


@dataclass(slots=True)
class EndpointState:
    deadline: float = 0.0
    seq: int = 0
    last_applied: Digest | None = None


@dataclass(slots=True)
class Engine:
    """Debounces each local endpoint's cookie-store writes into anti-echoed converges.

    ``run`` opens one watcher per endpoint and, for each, coalesces a burst of filesystem
    events into a single ``evaluate`` after ``settings.watch_debounce`` of quiet. ``evaluate``
    fingerprints the endpoint, skips the self-induced echo and an actively-writing store,
    and otherwise records the new digest before invoking ``notify``. The sync layer calls
    :meth:`record_applied` right before it writes a cookie set back, so the write it triggers
    is recognized as the engine's own echo.

    ``now`` is a monotonic clock for the debounce deadline; ``wall`` is wall-clock time,
    compared against the store's wall-clock mtime for the idle gate. The watcher source,
    both clocks, mtime reader, digest function, and notify callback are injected, so the
    whole core runs in tests without a real store or browser.

    Example:
        >>> engine = Engine(settings, notify=converge)
        >>> async with anyio.create_task_group() as tg:
        ...     tg.start_soon(engine.run, endpoints)
    """

    settings: Settings
    notify: Notify
    watch: AwatchSource = watch_endpoint
    digest: DigestFn = fingerprint
    mtime: Mtime = cookies_mtime
    now: Callable[[], float] = time.monotonic
    wall: Callable[[], float] = time.time
    sleep: Sleep = anyio.sleep
    states: dict[str, EndpointState] = field(default_factory=dict)

    def state(self, endpoint: BrowserEndpoint) -> EndpointState:
        return self.states.setdefault(endpoint.id, EndpointState())

    def current_digest(self, endpoint: BrowserEndpoint) -> Digest | None:
        """The last digest the engine acted on or the sync layer recorded for ``endpoint``."""
        return self.state(endpoint).last_applied

    def record_applied(self, endpoint_id: str, digest: Digest) -> None:
        """Record ``digest`` as the endpoint's applied state so the write it triggers is a no-op.

        The sync layer calls this immediately before it writes a merged cookie set back to a
        store; the watcher event that write produces then fingerprints to ``digest`` and is
        suppressed as the engine's own echo.
        """
        self.states.setdefault(endpoint_id, EndpointState()).last_applied = digest

    async def run(self, endpoints: tuple[BrowserEndpoint, ...]) -> None:
        """Watch every endpoint concurrently until the surrounding task group is cancelled."""
        async with anyio.create_task_group() as tg:
            for endpoint in endpoints:
                tg.start_soon(self.watch_loop, endpoint)

    async def watch_loop(self, endpoint: BrowserEndpoint) -> None:
        debounce = self.settings.watch_debounce.total_seconds()
        state = self.state(endpoint)
        async with anyio.create_task_group() as tg:
            async for _ in self.watch(endpoint):
                state.seq += 1
                state.deadline = self.now() + debounce
                tg.start_soon(self.fire_after, endpoint, state.seq)

    async def fire_after(self, endpoint: BrowserEndpoint, seq: int) -> None:
        state = self.state(endpoint)
        await self.sleep(self.settings.watch_debounce.total_seconds())
        if seq == state.seq and self.now() >= state.deadline:
            await self.evaluate(endpoint)

    async def evaluate(self, endpoint: BrowserEndpoint) -> None:
        digest = await self.digest(endpoint)
        state = self.state(endpoint)
        if digest == state.last_applied:
            return
        if self.wall() - await self.mtime(endpoint) < self.settings.idle_threshold.total_seconds():
            return
        state.last_applied = digest
        await self.notify(endpoint)
