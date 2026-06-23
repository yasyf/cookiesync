"""The sync merge pass: gather every endpoint's cookies, union newest-wins, idempotently apply.

``converge`` runs one merge pass over the union of every tracked endpoint. It decrypts this
host's cookies (via the cached Safe Storage key — never prompting here), pulls each peer's
decrypted cookies over ssh, merges with the pure union newest-wins rule, then writes the
merged set back to any endpoint whose rows differ — preserving the winning
``last_update_utc`` and recording the applied digest with the watch engine *before* the
write, so the induced filesystem event is recognized as a self-echo and skipped.

Cookie ``last_update_utc`` is absolute Chrome time (microseconds since 1601 UTC) and is
host-independent, so a raw newest-wins comparison is convergent across NTP-synced tailnet
machines without any clock-skew correction. The merge preserves each winner's original
``last_update_utc`` on every host, so the anti-echo digest the watch engine records matches
the store's fingerprint after the write.

``reconcile`` is the time-based backup: one ``converge`` over the union of every tracked endpoint.

This host and every peer are reached through the one uniform :class:`Source` seam
(``extract``/``apply``), so the merge logic runs in unit tests against fakes — with the
sources injected — without ssh or a real cookie store.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from loguru import logger

from cookiesync.cookie import merge
from cookiesync.daemon.engine import logical_digest

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

    from cookiesync.cookie.browsers import Browser
    from cookiesync.cookie.models import Cookie
    from cookiesync.daemon.cache import KeyCache
    from cookiesync.state import BrowserEndpoint, BrowserId, SshTarget


class NeedsAuth(Exception):
    """No cached Safe Storage key for the endpoint's browser; a prompt is required first.

    Raised when ``converge`` finds the local key cache cold. ``converge`` never prompts —
    the caller obtains consent and seeds the cache, then retries.
    """


class Engine(Protocol):
    """The watch engine's anti-echo seam: record an endpoint's applied digest before writing.

    Recording the digest first means the filesystem event the write induces is recognized
    as this daemon's own and suppressed, rather than re-triggering a sync.
    """

    def record_applied(self, endpoint_id: str, digest: str) -> None: ...


@dataclass(frozen=True, slots=True)
class Extracted:
    """A source's decrypted cookies for the requested browser profile."""

    cookies: tuple[Cookie, ...]


class Source(Protocol):
    """One endpoint's cookie store, reached the same way whether it is local or a peer.

    Both the in-process local source and the ssh-backed peer satisfy this seam: ``extract``
    returns the decrypted cookies, and ``apply`` writes a merged set back. The Safe Storage
    key never crosses this boundary — the source decrypts and re-encrypts in its own session.
    """

    async def extract(self, browser: BrowserId, profile: str) -> Extracted: ...

    async def apply(self, browser: BrowserId, profile: str, cookies: Sequence[Cookie]) -> int: ...


@dataclass(frozen=True, slots=True)
class Gathered:
    """One endpoint's decrypted cookies for the group, with the source that yielded them."""

    endpoint: BrowserEndpoint
    source: Source
    cookies: tuple[Cookie, ...]


def target_row(cookie: Cookie) -> tuple:
    """The full logical row used to decide whether an endpoint already holds a cookie.

    Covers every value-bearing field, so an idempotent apply skips only when the endpoint's
    stored row matches the winner exactly — including its preserved ``last_update_utc``.
    """
    return (
        cookie.host_key,
        cookie.name,
        cookie.value,
        cookie.path,
        int(cookie.expires_utc),
        int(cookie.last_update_utc),
        cookie.is_secure,
        cookie.is_httponly,
        cookie.samesite,
        cookie.source_scheme,
        cookie.source_port,
        cookie.top_frame_site_key,
        cookie.has_cross_site_ancestor,
    )


def row_set(cookies: Iterable[Cookie]) -> frozenset[tuple]:
    return frozenset(target_row(c) for c in cookies)


async def warm_anchor(
    endpoints: Sequence[BrowserEndpoint], *, self_target: SshTarget, cache: KeyCache
) -> BrowserEndpoint | None:
    """The first local endpoint with a warm key — the anchor a union converge merges onto."""
    for endpoint in endpoints:
        if endpoint.host == self_target and await cache.get(endpoint.id) is not None:
            return endpoint
    return None


async def gather(endpoint: BrowserEndpoint, source: Source) -> Gathered:
    extracted = await source.extract(endpoint.browser, endpoint.profile)
    return Gathered(endpoint, source, extracted.cookies)


async def apply_to(gathered: Gathered, merged: tuple[Cookie, ...], *, engine: Engine) -> bool:
    if row_set(merged) == row_set(gathered.cookies):
        return False
    engine.record_applied(gathered.endpoint.id, logical_digest(merged))
    await gathered.source.apply(gathered.endpoint.browser, gathered.endpoint.profile, merged)
    return True


async def converge(
    endpoint: BrowserEndpoint,
    peers: Sequence[BrowserEndpoint],
    *,
    origin: SshTarget | None = None,
    self_target: SshTarget,
    cache: KeyCache,
    engine: Engine,
    local_source: Source,
    source_for: Callable[[SshTarget], Source],
) -> tuple[Cookie, ...]:
    """Merge the union of every endpoint across this host and its peers, then idempotently apply.

    Gathers ``endpoint``'s decrypted cookies through ``local_source`` (the consent gate is
    the caller's; a cold key cache raises :class:`NeedsAuth` rather than prompting) and each
    peer's cookies through ``source_for(peer.host)``, skipping ``origin`` so a sync is never
    echoed straight back to the host that triggered it, and skipping a same-host peer whose
    key is cold (logged, not silent — its consent never ran). Remote peers are always
    included; their warmth is resolved remotely by the peer's own prime-on-cold extract. The
    union newest-wins :func:`~cookiesync.cookie.merge` selects per cookie by raw
    ``last_update_utc`` — absolute Chrome time, host-independent and convergent on NTP-synced
    machines — and the result is written to any endpoint whose stored rows differ, preserving
    the winning ``last_update_utc`` and recording the applied digest with ``engine`` *before*
    the write, so the induced filesystem event is suppressed. Same-machine endpoints converge
    through ``local_source`` in-process, with no ssh.

    Args:
        endpoint: This host's warm-keyed local anchor endpoint.
        peers: The other tracked endpoints across every browser and host, local or remote.
        origin: The host that triggered this sync, skipped to avoid an echo; ``None`` for a
            time-based reconcile that touches every endpoint.
        self_target: This host's own ssh target; endpoints on it converge in-process.
        cache: The short-TTL key cache; a cold entry for ``endpoint`` raises
            :class:`NeedsAuth`.
        engine: The watch engine, told the applied digest before each write.
        local_source: This machine's cookie source (extract/apply behind the consent gate).
        source_for: Builds the :class:`Source` for a peer target; injected for tests.

    Returns:
        The merged cookie set that was reconciled across the group.

    Raises:
        NeedsAuth: The local key cache is cold for ``endpoint``; obtain consent and retry.

    Example:
        >>> await converge(local, peers, self_target=self, cache=cache, engine=engine,
        ...                local_source=local, source_for=lambda t: SshBackend(t, origin=self))
    """
    if await cache.get(endpoint.id) is None:
        raise NeedsAuth(f"no cached key for {endpoint.id}; obtain consent before converging")
    sources: list[tuple[BrowserEndpoint, Source]] = [(endpoint, local_source)]
    for peer in (p for p in peers if p.host != origin):
        match peer.host == self_target:
            case True if await cache.get(peer.id) is None:
                logger.warning("skipping cold same-host endpoint {} from union converge", peer.id)
            case True:
                sources.append((peer, local_source))
            case False:
                sources.append((peer, source_for(peer.host)))
    gathered = [await gather(ep, src) for ep, src in sources]
    merged = merge(*(g.cookies for g in gathered))
    for g in gathered:
        await apply_to(g, merged, engine=engine)
    return merged


async def reconcile(
    endpoints: Sequence[BrowserEndpoint],
    *,
    self_target: SshTarget,
    registry: dict[BrowserId, Browser],
    cache: KeyCache,
    engine: Engine,
    local_source: Source,
    source_for: Callable[[SshTarget], Source],
) -> dict[str, tuple[Cookie, ...]]:
    """The time-based backup: one :func:`converge` over the union of every tracked endpoint.

    Every registered endpoint — every browser, every host — converges to one union cookie
    set. The pass is anchored on this host's first warm-keyed local endpoint and run with no
    ``origin`` so every endpoint is reconciled. With no warm local anchor there is nothing
    here to merge from, so the pass is skipped.

    Args:
        endpoints: Every tracked endpoint across all hosts and browsers.
        self_target: This host's own ssh target.
        registry: The browser registry, mapping each :class:`~cookiesync.state.BrowserId` to
            its :class:`~cookiesync.cookie.browsers.Browser`; endpoints whose browser is not
            registered are excluded from the union.
        cache: The short-TTL key cache; the anchor is the first local endpoint with a warm key.
        engine: The watch engine, told each applied digest before its write.
        local_source: This machine's cookie source.
        source_for: Builds the :class:`Source` for a peer target; injected for tests.

    Returns:
        The anchor endpoint's id mapped to the merged union, or empty when no warm anchor.

    Example:
        >>> await reconcile(endpoints, self_target=self, registry=REGISTRY, cache=cache,
        ...                 engine=engine, local_source=local, source_for=make_ssh_source)
    """
    group = [e for e in endpoints if e.browser in registry]
    anchor = await warm_anchor(group, self_target=self_target, cache=cache)
    if anchor is None:
        return {}
    return {
        anchor.id: await converge(
            anchor,
            [e for e in group if e is not anchor],
            self_target=self_target,
            cache=cache,
            engine=engine,
            local_source=local_source,
            source_for=source_for,
        )
    }
