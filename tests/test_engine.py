"""Unit tests for the watch engine's debounce + anti-echo core.

Every macOS/filesystem boundary is injected: the watcher is a synthetic async iterator,
the digest and mtime are stubs, the clock is a counter, and ``sleep`` is gated by an event
the test releases. So the debounce coalescing, the digest anti-echo, the ``record_applied``
echo suppression, and the idle gate are all exercised without a real store, browser, or fs.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta

import anyio
import pytest

from cookiesync.daemon.engine import Digest, EndpointState, Engine
from cookiesync.state import BrowserEndpoint, BrowserId, Settings, SshTarget

pytestmark = pytest.mark.anyio

ENDPOINT = BrowserEndpoint(SshTarget("me@laptop"), BrowserId("chrome"), "Default")

SETTINGS = Settings(
    watch_debounce=timedelta(seconds=3),
    idle_threshold=timedelta(seconds=5),
)


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def const_digest(value: str):
    async def _digest(_: BrowserEndpoint) -> Digest:
        return Digest(value)

    return _digest


def const_mtime(value: float):
    async def _mtime(_: BrowserEndpoint) -> float:
        return value

    return _mtime


def recording_notify(fired: list[BrowserEndpoint]):
    async def _notify(endpoint: BrowserEndpoint) -> None:
        fired.append(endpoint)

    return _notify


def burst_source(count: int) -> tuple:
    """A watch source yielding ``count`` synthetic events, then ending."""
    started = anyio.Event()

    async def _watch(_: BrowserEndpoint) -> AsyncIterator[object]:
        started.set()
        for n in range(count):
            yield {("modified", f"/Cookies-{n}")}

    return _watch, started


@pytest.fixture
def clock() -> Clock:
    return Clock()


# ── evaluate: anti-echo + idle gate ──────────────────────────────────────────


async def test_unchanged_digest_does_not_notify(clock: Clock) -> None:
    fired: list[BrowserEndpoint] = []
    engine = Engine(
        SETTINGS,
        notify=recording_notify(fired),
        digest=const_digest("same"),
        mtime=const_mtime(0.0),
        now=clock,
    )
    engine.record_applied(ENDPOINT.id, Digest("same"))
    await engine.evaluate(ENDPOINT)
    assert fired == []


async def test_changed_digest_notifies_once_and_records_first(clock: Clock) -> None:
    seen_digest: list[Digest | None] = []

    async def _notify(endpoint: BrowserEndpoint) -> None:
        seen_digest.append(engine.current_digest(endpoint))

    engine = Engine(
        SETTINGS,
        notify=_notify,
        digest=const_digest("new"),
        mtime=const_mtime(0.0),
        now=clock,
    )
    engine.record_applied(ENDPOINT.id, Digest("old"))
    await engine.evaluate(ENDPOINT)
    assert seen_digest == [Digest("new")]
    assert engine.current_digest(ENDPOINT) == Digest("new")


async def test_record_applied_then_matching_event_is_suppressed(clock: Clock) -> None:
    fired: list[BrowserEndpoint] = []
    engine = Engine(
        SETTINGS,
        notify=recording_notify(fired),
        digest=const_digest("after-apply"),
        mtime=const_mtime(0.0),
        now=clock,
    )
    engine.record_applied(ENDPOINT.id, Digest("after-apply"))
    await engine.evaluate(ENDPOINT)
    assert fired == []
    assert engine.current_digest(ENDPOINT) == Digest("after-apply")


async def test_idle_gate_suppresses_when_mtime_fresh(clock: Clock) -> None:
    fired: list[BrowserEndpoint] = []
    engine = Engine(
        SETTINGS,
        notify=recording_notify(fired),
        digest=const_digest("changed"),
        mtime=const_mtime(clock.t - 2.0),
        now=clock,
        wall=clock,
    )
    await engine.evaluate(ENDPOINT)
    assert fired == []
    assert engine.current_digest(ENDPOINT) is None


async def test_idle_gate_passes_when_store_settled(clock: Clock) -> None:
    fired: list[BrowserEndpoint] = []
    engine = Engine(
        SETTINGS,
        notify=recording_notify(fired),
        digest=const_digest("changed"),
        mtime=const_mtime(clock.t - 10.0),
        now=clock,
        wall=clock,
    )
    await engine.evaluate(ENDPOINT)
    assert fired == [ENDPOINT]


async def test_idle_gate_uses_wall_clock_not_monotonic() -> None:
    # CF3: st_mtime is wall-clock (~1.7e9), the debounce clock is monotonic (small). The
    # old gate compared time.monotonic() - st_mtime ~ -1.7e9, always < idle_threshold, so it
    # ALWAYS suppressed and the watcher never notified. The gate must compare wall() - mtime.
    mtime_wall = 1_750_000_000.0  # a realistic recent st_mtime
    monotonic = Clock()  # ~1000.0, stands in for time.monotonic()

    class Wall:
        def __init__(self, t: float) -> None:
            self.t = t

        def __call__(self) -> float:
            return self.t

    wall = Wall(mtime_wall + 1.0)  # store touched 1s ago: still actively writing -> suppress
    fired: list[BrowserEndpoint] = []
    engine = Engine(
        SETTINGS,
        notify=recording_notify(fired),
        digest=const_digest("changed"),
        mtime=const_mtime(mtime_wall),
        now=monotonic,
        wall=wall,
    )
    await engine.evaluate(ENDPOINT)
    assert fired == [], "a store touched 1s ago is still settling and must be suppressed"
    assert engine.current_digest(ENDPOINT) is None

    wall.t = mtime_wall + 10.0  # now 10s settled, past the 5s idle_threshold -> notify
    await engine.evaluate(ENDPOINT)
    assert fired == [ENDPOINT], "a settled store must notify once the idle threshold elapses"


async def test_record_applied_creates_state_for_unseen_endpoint() -> None:
    engine = Engine(SETTINGS, notify=recording_notify([]))
    engine.record_applied(ENDPOINT.id, Digest("d"))
    assert engine.states[ENDPOINT.id] == EndpointState(last_applied=Digest("d"))
    assert engine.current_digest(ENDPOINT) == Digest("d")


# ── watch_loop: debounce coalescing ──────────────────────────────────────────


async def test_burst_of_events_debounces_to_one_evaluate(clock: Clock) -> None:
    gate = anyio.Event()
    evaluated: list[BrowserEndpoint] = []

    async def gated_sleep(_: float) -> None:
        await gate.wait()

    async def counting_digest(endpoint: BrowserEndpoint) -> Digest:
        evaluated.append(endpoint)
        return Digest("d")

    watch, started = burst_source(5)
    engine = Engine(
        SETTINGS,
        notify=recording_notify([]),
        watch=watch,
        digest=counting_digest,
        mtime=const_mtime(0.0),
        now=clock,
        sleep=gated_sleep,
    )

    async with anyio.create_task_group() as tg:
        tg.start_soon(engine.watch_loop, ENDPOINT)
        await started.wait()
        await wait_for(lambda: engine.state(ENDPOINT).seq == 5)
        clock.t += 3.0
        gate.set()
        await wait_for(lambda: len(evaluated) >= 1)
        await anyio.sleep(0)

    assert evaluated == [ENDPOINT]


async def test_late_event_re_arms_and_only_final_fires(clock: Clock) -> None:
    gates = [anyio.Event(), anyio.Event()]
    feed = anyio.Event()
    evaluated: list[BrowserEndpoint] = []
    slept: list[int] = []

    async def staged_sleep(_: float) -> None:
        index = len(slept)
        slept.append(index)
        await gates[min(index, len(gates) - 1)].wait()

    async def counting_digest(endpoint: BrowserEndpoint) -> Digest:
        evaluated.append(endpoint)
        return Digest("d")

    started = anyio.Event()

    async def watch(_: BrowserEndpoint) -> AsyncIterator[object]:
        started.set()
        yield {("modified", "/Cookies")}
        await feed.wait()
        yield {("modified", "/Cookies-wal")}

    engine = Engine(
        SETTINGS,
        notify=recording_notify([]),
        watch=watch,
        digest=counting_digest,
        mtime=const_mtime(0.0),
        now=clock,
        sleep=staged_sleep,
    )

    async with anyio.create_task_group() as tg:
        tg.start_soon(engine.watch_loop, ENDPOINT)
        await started.wait()
        await wait_for(lambda: engine.state(ENDPOINT).seq == 1)
        feed.set()
        await wait_for(lambda: engine.state(ENDPOINT).seq == 2)
        clock.t += 3.0
        gates[0].set()
        gates[1].set()
        await wait_for(lambda: len(evaluated) >= 1)
        await anyio.sleep(0)

    assert evaluated == [ENDPOINT]


async def wait_for(predicate, *, tries: int = 1000) -> None:
    for _ in range(tries):
        if predicate():
            return
        await anyio.sleep(0)
    raise AssertionError("predicate never held")
