"""Unit tests for the sync merge pass.

The two macOS-specific surfaces — the local cookie store and a peer reached over ssh —
are doubled by an in-memory :class:`FakeSource` that records every ``extract``/``apply``
call. So union newest-wins, idempotent apply, the apply-ordering guarantee, the raw
timestamp invariant, and origin-skipping all run without any real store, ssh, or key cache.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest

from cookiesync.cookie.browsers import REGISTRY, BrowserName
from cookiesync.cookie.models import ChromeMicros, Cookie, HostKey
from cookiesync.daemon.engine import logical_digest
from cookiesync.daemon.sync import (
    Extracted,
    NeedsAuth,
    converge,
    reconcile,
)
from cookiesync.state import BrowserEndpoint, BrowserId, SshTarget

if TYPE_CHECKING:
    from collections.abc import Sequence

pytestmark = pytest.mark.anyio

SELF = SshTarget("me@laptop")
PEER = SshTarget("peer@desktop")
THIRD = SshTarget("third@server")
CHROME = BrowserId("chrome")
ARC = BrowserId("arc")

LOCAL = BrowserEndpoint(SELF, CHROME, "Default")
PEER_EP = BrowserEndpoint(PEER, CHROME, "Default")
THIRD_EP = BrowserEndpoint(THIRD, CHROME, "Default")

MICROS = 1_000_000
BASE = ChromeMicros(13_400_000_000_000_000)  # an arbitrary recent Chrome timestamp


def cookie(name: str, value: str, *, last_update: ChromeMicros = BASE) -> Cookie:
    return Cookie(
        host_key=HostKey(".example.com"),
        name=name,
        value=value,
        path="/",
        expires_utc=ChromeMicros(BASE + 10 * 365 * 24 * 3600 * MICROS),
        last_update_utc=last_update,
        creation_utc=BASE,
        is_secure=True,
        is_httponly=False,
        samesite=1,
    )


@dataclass(slots=True)
class FakeSource:
    """An in-memory cookie source recording every extract/apply against a shared log."""

    cookies: tuple[Cookie, ...]
    log: list
    label: str = "src"
    extracted: int = 0
    applied: list[tuple[BrowserId, str, tuple[Cookie, ...]]] = field(default_factory=list)

    async def extract(self, browser: BrowserId, profile: str) -> Extracted:
        self.extracted += 1
        self.log.append(("extract", self.label))
        return Extracted(self.cookies)

    async def apply(self, browser: BrowserId, profile: str, cookies: Sequence[Cookie]) -> int:
        rows = tuple(cookies)
        self.log.append(("apply", self.label))
        self.applied.append((browser, profile, rows))
        return len(rows)


@dataclass(slots=True)
class FakeEngine:
    log: list

    def record_applied(self, endpoint_id: str, digest: str) -> None:
        self.log.append(("record_applied", endpoint_id, digest))


@dataclass(slots=True)
class WarmCache:
    """A key cache that is always warm — converge only checks presence, never the bytes."""

    cold: frozenset[str] = frozenset()

    async def get(self, endpoint_id: str) -> bytes | None:
        return None if endpoint_id in self.cold else b"\x00" * 32


def sources_factory(peers: dict[SshTarget, FakeSource]):
    def make(target: SshTarget) -> FakeSource:
        return peers[target]

    return make


async def test_union_newest_wins_picks_max_last_update_across_two_backends() -> None:
    log: list = []
    older = cookie("sid", "old", last_update=ChromeMicros(BASE))
    newer = cookie("sid", "new", last_update=ChromeMicros(BASE + 5 * MICROS))
    local = FakeSource((older,), log, label="local")
    peer = FakeSource((newer,), log, label="peer")

    merged = await converge(
        LOCAL,
        [PEER_EP],
        self_target=SELF,
        cache=WarmCache(),
        engine=FakeEngine(log),
        local_source=local,
        source_for=sources_factory({PEER: peer}),
    )

    assert {c.value for c in merged} == {"new"}
    # The newer peer value is written back to the local endpoint, which held the older one.
    assert [v for _, _, rows in local.applied for v in (c.value for c in rows)] == ["new"]


async def test_converge_preserves_raw_last_update_on_the_winner() -> None:
    # CF2: gather/converge must NOT mutate last_update_utc. The winning peer cookie is
    # written to the local store with its ORIGINAL absolute Chrome timestamp intact. The
    # winner carries sub-band (non-1e6-aligned) digits, so the deleted quantize() step would
    # have floored them away — proving this asserts on the raw value, not a band-snapped one.
    log: list = []
    winner_ts = ChromeMicros(BASE + 5 * MICROS + 374_829)
    older = cookie("sid", "old", last_update=ChromeMicros(BASE))
    newer = cookie("sid", "new", last_update=winner_ts)
    local = FakeSource((older,), log, label="local")
    peer = FakeSource((newer,), log, label="peer")

    merged = await converge(
        LOCAL,
        [PEER_EP],
        self_target=SELF,
        cache=WarmCache(),
        engine=FakeEngine(log),
        local_source=local,
        source_for=sources_factory({PEER: peer}),
    )

    assert [c.last_update_utc for c in merged] == [winner_ts]
    written = local.applied[0][2][0]
    assert written.last_update_utc == winner_ts, "raw last_update_utc must flow through unchanged"


async def test_two_hosts_store_the_same_timestamp_for_the_same_winner() -> None:
    # CF2: with NO clock-skew normalization, a reconcile (origin=None, every endpoint
    # written) lands the SAME absolute timestamp on both hosts for the shared winner —
    # regardless of either host's wall clock. Divergence is impossible by construction.
    log: list = []
    winner_ts = ChromeMicros(BASE + 7 * MICROS)
    local = FakeSource((cookie("sid", "old", last_update=ChromeMicros(BASE)),), log, label="local")
    peer = FakeSource((cookie("sid", "new", last_update=winner_ts),), log, label="peer")

    await converge(
        LOCAL,
        [PEER_EP],
        self_target=SELF,
        cache=WarmCache(),
        engine=FakeEngine(log),
        local_source=local,
        source_for=sources_factory({PEER: peer}),
    )

    # Local held the loser, so it is rewritten; the peer already held the winner, so it is not.
    assert local.applied[0][2][0].last_update_utc == winner_ts
    assert peer.applied == []
    assert {c.last_update_utc for c in (local.applied[0][2][0],)} == {winner_ts}


async def test_idempotent_apply_writes_nothing_when_sets_already_equal() -> None:
    log: list = []
    same = cookie("sid", "shared", last_update=ChromeMicros(BASE))
    local = FakeSource((same,), log, label="local")
    peer = FakeSource((same,), log, label="peer")
    engine = FakeEngine(log)

    await converge(
        LOCAL,
        [PEER_EP],
        self_target=SELF,
        cache=WarmCache(),
        engine=engine,
        local_source=local,
        source_for=sources_factory({PEER: peer}),
    )

    assert local.applied == []
    assert peer.applied == []
    assert [entry for entry in log if entry[0] == "apply"] == []
    assert [entry for entry in log if entry[0] == "record_applied"] == []


async def test_record_applied_fires_before_write_when_sets_differ() -> None:
    log: list = []
    local = FakeSource((cookie("sid", "old", last_update=ChromeMicros(BASE)),), log, label="local")
    peer = FakeSource((cookie("sid", "new", last_update=ChromeMicros(BASE + 5 * MICROS)),), log, label="peer")

    await converge(
        LOCAL,
        [PEER_EP],
        self_target=SELF,
        cache=WarmCache(),
        engine=FakeEngine(log),
        local_source=local,
        source_for=sources_factory({PEER: peer}),
    )

    record = next(i for i, e in enumerate(log) if e[0] == "record_applied")
    write = next(i for i, e in enumerate(log) if e == ("apply", "local"))
    assert record < write, "engine.record_applied must precede the induced write"
    # The recorded digest is the logical_digest of the merged set actually written.
    recorded = next(e for e in log if e[0] == "record_applied")
    assert recorded[2] == logical_digest(local.applied[0][2])
    assert recorded[1] == LOCAL.id


async def test_origin_host_is_skipped_to_avoid_echo() -> None:
    log: list = []
    local = FakeSource((cookie("sid", "local", last_update=ChromeMicros(BASE)),), log, label="local")
    peer = FakeSource((cookie("sid", "peer", last_update=ChromeMicros(BASE + 9 * MICROS)),), log, label="peer")

    await converge(
        LOCAL,
        [PEER_EP],
        origin=PEER,
        self_target=SELF,
        cache=WarmCache(),
        engine=FakeEngine(log),
        local_source=local,
        source_for=sources_factory({PEER: peer}),
    )

    # The origin peer is neither read nor written — it triggered this very sync.
    assert peer.extracted == 0
    assert peer.applied == []
    assert ("extract", "peer") not in log


async def test_cold_cache_raises_needs_auth_without_prompting() -> None:
    log: list = []
    local = FakeSource((cookie("sid", "x"),), log, label="local")
    with pytest.raises(NeedsAuth):
        await converge(
            LOCAL,
            [],
            self_target=SELF,
            cache=WarmCache(cold=frozenset({LOCAL.id})),
            engine=FakeEngine(log),
            local_source=local,
            source_for=sources_factory({}),
        )
    assert local.extracted == 0


async def test_same_machine_peer_converges_in_process_not_over_ssh() -> None:
    log: list = []
    same_host_other_profile = BrowserEndpoint(SELF, CHROME, "Profile 1")
    local = FakeSource((cookie("sid", "a", last_update=ChromeMicros(BASE)),), log, label="local")

    # A peer on the same host must be reached through local_source, never source_for.
    def boom(_target: SshTarget) -> FakeSource:
        raise AssertionError("same-machine endpoint must not be reached over ssh")

    await converge(
        LOCAL,
        [same_host_other_profile],
        self_target=SELF,
        cache=WarmCache(),
        engine=FakeEngine(log),
        local_source=local,
        source_for=boom,
    )

    # local_source was used for both the anchor and the same-host endpoint.
    assert [e for e in log if e[0] == "extract"] == [("extract", "local"), ("extract", "local")]


async def test_reconcile_runs_converge_over_each_browser_group() -> None:
    log: list = []
    registry = {CHROME: REGISTRY[BrowserName("chrome")], ARC: REGISTRY[BrowserName("arc")]}
    chrome_local = BrowserEndpoint(SELF, CHROME, "Default")
    chrome_peer = BrowserEndpoint(PEER, CHROME, "Default")
    arc_local = BrowserEndpoint(SELF, ARC, "Default")
    arc_peer_only = BrowserEndpoint(PEER, ARC, "Default")

    local = FakeSource((cookie("sid", "v", last_update=ChromeMicros(BASE)),), log, label="local")
    peer = FakeSource((cookie("sid", "v", last_update=ChromeMicros(BASE)),), log, label="peer")

    results = await reconcile(
        [chrome_local, chrome_peer, arc_local, arc_peer_only],
        self_target=SELF,
        registry=registry,
        cache=WarmCache(),
        engine=FakeEngine(log),
        local_source=local,
        source_for=sources_factory({PEER: peer}),
    )

    # Both browser groups have a local anchor on this host, so both are reconciled.
    assert set(results) == {chrome_local.id, arc_local.id}


async def test_reconcile_skips_a_group_with_no_local_anchor() -> None:
    log: list = []
    registry = {CHROME: REGISTRY[BrowserName("chrome")]}
    # Both endpoints live on peers; this host has nothing local to merge from.
    peer_a = BrowserEndpoint(PEER, CHROME, "Default")
    peer_b = BrowserEndpoint(THIRD, CHROME, "Default")
    local = FakeSource((), log, label="local")

    results = await reconcile(
        [peer_a, peer_b],
        self_target=SELF,
        registry=registry,
        cache=WarmCache(),
        engine=FakeEngine(log),
        local_source=local,
        source_for=sources_factory({PEER: FakeSource((), log, label="pa")}),
    )

    assert results == {}
    assert local.extracted == 0
