"""Load and persist cookiesync's ``state.json``: the self target, tracked browser endpoints, and cadence settings.

Mirrors reposync's on-disk model — Go-style duration strings (``"15m"``, ``"3s"``), an
atomic temp-file-plus-rename save, and a read-modify-write :func:`update` serialized across
processes by a filelock on :func:`cookiesync.paths.lock_path`. Hosts are *not* stored here;
they are read live from reposync elsewhere.
"""

from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from inspect import isawaitable
from tempfile import mkstemp
from typing import TYPE_CHECKING, NewType

import anyio
from filelock import FileLock

from cookiesync.paths import config_dir, lock_path, state_path

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

SshTarget = NewType("SshTarget", str)
BrowserId = NewType("BrowserId", str)

DURATION_UNITS: tuple[tuple[str, int], ...] = (("h", 3600), ("m", 60), ("s", 1))
DURATION_SIZES: dict[str, int] = dict(DURATION_UNITS)


def parse_duration(text: str) -> timedelta:
    """Parse a Go-style duration string such as ``"15m"`` or ``"90s"`` into a :class:`~datetime.timedelta`."""
    return timedelta(seconds=int(text[:-1]) * DURATION_SIZES[text[-1]])


def format_duration(delta: timedelta) -> str:
    """Render a :class:`~datetime.timedelta` as the most compact Go-style string, e.g. ``"15m"`` or ``"90s"``."""
    return next(
        f"{seconds // size}{unit}"
        for unit, size in DURATION_UNITS
        if (seconds := round(delta.total_seconds())) % size == 0
    )


@dataclass(frozen=True, slots=True)
class Settings:
    """Cadence knobs read by the sync, watch, and reconcile loops; serialized as Go-style durations."""

    interval: timedelta = timedelta(minutes=15)
    idle_threshold: timedelta = timedelta(minutes=5)
    watch_debounce: timedelta = timedelta(seconds=3)
    op_timeout: timedelta = timedelta(minutes=2)
    auth_ttl: timedelta = timedelta(minutes=5)

    def to_json(self) -> dict[str, str]:
        return {key: format_duration(value) for key, value in asdict(self).items()}

    @classmethod
    def from_json(cls, raw: dict[str, str]) -> Settings:
        return cls(**{key: parse_duration(value) for key, value in raw.items()})


@dataclass(frozen=True, slots=True)
class BrowserEndpoint:
    """One tracked browser profile on a host, keyed by its :attr:`id`.

    Example:
        >>> BrowserEndpoint(SshTarget("me@laptop"), BrowserId("arc"), "Default").id
        'me@laptop:arc:Default'
    """

    host: SshTarget
    browser: BrowserId
    profile: str

    @property
    def id(self) -> str:
        """The endpoint's stable identity, ``host:browser:profile``."""
        return f"{self.host}:{self.browser}:{self.profile}"

    def to_json(self) -> dict[str, str]:
        return {"host": self.host, "browser": self.browser, "profile": self.profile}

    @classmethod
    def from_json(cls, raw: dict[str, str]) -> BrowserEndpoint:
        return cls(SshTarget(raw["host"]), BrowserId(raw["browser"]), raw["profile"])


@dataclass(frozen=True, slots=True)
class State:
    """The full on-disk cookiesync configuration for this host.

    Example:
        >>> await State(SshTarget("me@laptop")).save()
    """

    self_target: SshTarget
    browsers: tuple[BrowserEndpoint, ...] = ()
    settings: Settings = field(default_factory=Settings)
    consent_route_to: SshTarget | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "self_target": self.self_target,
            "browsers": [endpoint.to_json() for endpoint in self.browsers],
            "settings": self.settings.to_json(),
            "consent_route_to": self.consent_route_to,
        }

    @classmethod
    def from_json(cls, raw: dict[str, object]) -> State:
        return cls(
            SshTarget(raw["self_target"]),
            tuple(BrowserEndpoint.from_json(endpoint) for endpoint in raw["browsers"]),
            Settings.from_json(raw["settings"]),
            SshTarget(route) if (route := raw.get("consent_route_to")) is not None else None,
        )

    async def save(self) -> State:
        """Write this state to :func:`cookiesync.paths.state_path` atomically (temp file, then rename)."""
        await write_json(self.to_json())
        return self


async def read_json() -> dict[str, object] | None:
    return json.loads(await path.read_text()) if await (path := anyio.Path(state_path())).exists() else None


async def write_json(payload: dict[str, object]) -> None:
    await anyio.Path(config_dir()).mkdir(parents=True, exist_ok=True)
    await (tmp := anyio.Path(await anyio.to_thread.run_sync(mktemp_path))).write_text(
        json.dumps(payload, indent=2) + "\n"
    )
    os.replace(tmp, state_path())


def mktemp_path() -> str:
    handle, name = mkstemp(dir=config_dir(), prefix="state-", suffix=".tmp")
    os.close(handle)
    return name


async def load() -> State:
    """Read :func:`cookiesync.paths.state_path`, returning a default :class:`State` when the file is absent."""
    match await read_json():
        case None:
            return State(default_self_target())
        case raw:
            return State.from_json(raw)


async def update(fn: Callable[[State], State | Awaitable[State]]) -> State:
    """Read-modify-write the state under the reconcile flock, then save and return the result."""
    async with hold_lock():
        result = fn(await load())
        return await (await result if isawaitable(result) else result).save()


@asynccontextmanager
async def hold_lock() -> AsyncIterator[None]:
    await anyio.Path(config_dir()).mkdir(parents=True, exist_ok=True)
    lock = FileLock(lock_path())
    await anyio.to_thread.run_sync(lock.acquire)
    try:
        yield
    finally:
        lock.release()


def default_self_target() -> SshTarget:
    return SshTarget(f"{os.environ['USER']}@{os.uname().nodename}")
