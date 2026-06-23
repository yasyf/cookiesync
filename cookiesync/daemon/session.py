"""Detect whether this host has a live, unlocked console GUI session.

A machine is *active* only when a real person is sitting at it: an on-console
GUI session whose screen is unlocked. That is the one moment cookies can be
extracted — Touch ID is reachable and ``WhenUnlocked`` keychain items are
readable. A locked screen, an SSH-only headless box, or another user holding
the console via fast user switching all count as **not** active.

The system probe is :data:`ioreg`'s ``IOConsoleUsers``/``IOConsoleLocked``,
parsed as a plist. It answers from any session — including a daemon launched
under ``launchd`` in a different audit session — so it stays correct headless.
The probe is injected (:func:`probe_session`), so the decision logic runs in
unit tests against synthetic snapshots without touching macOS.
"""

from __future__ import annotations

import getpass
import plistlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, NamedTuple

import anyio

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

IOREG_ARGV = ("ioreg", "-n", "Root", "-d1", "-a")

ON_CONSOLE_KEY = "kCGSSessionOnConsoleKey"
USER_NAME_KEY = "kCGSSessionUserNameKey"
SCREEN_LOCKED_KEY = "CGSSessionScreenIsLocked"


@dataclass(frozen=True, slots=True)
class SessionSnapshot:
    """A point-in-time read of this host's console GUI session.

    Attributes:
        on_console: A GUI session owns the physical console right now.
        locked: The console screen is locked (screensaver or lock screen up).
        console_user: The short username of the console session, or ``None``
            when no GUI session is attached (headless / SSH-only).
    """

    on_console: bool
    locked: bool
    console_user: str | None


class Verdict(NamedTuple):
    on_console: bool
    locked: bool
    is_self: bool


def parse_session(payload: bytes) -> SessionSnapshot:
    root = plistlib.loads(payload)
    match next((s for s in root.get("IOConsoleUsers", ()) if s.get(ON_CONSOLE_KEY)), None):
        case None:
            return SessionSnapshot(on_console=False, locked=False, console_user=None)
        case session:
            return SessionSnapshot(
                on_console=True,
                locked=bool(root.get("IOConsoleLocked", False)) or bool(session.get(SCREEN_LOCKED_KEY, False)),
                console_user=session.get(USER_NAME_KEY),
            )


async def probe_session() -> SessionSnapshot:
    return parse_session((await anyio.run_process(IOREG_ARGV, check=True)).stdout)


async def has_active_session(*, probe: Callable[[], Awaitable[SessionSnapshot]] = probe_session) -> bool:
    """Whether this host has a live, unlocked console GUI session owned by this user.

    True only when a real person is at the keyboard: a GUI session holds the
    console, its screen is unlocked, and the console user is the user this
    process runs as. A locked screen, a headless/SSH-only box, or another user
    holding the console via fast user switching all return False.

    Args:
        probe: The system session reader. Defaults to the real :func:`probe_session`;
            inject a stub to drive the decision in tests.

    Example:
        >>> if await has_active_session():
        ...     await extract(...)
    """
    snapshot = await probe()
    match Verdict(snapshot.on_console, snapshot.locked, snapshot.console_user == getpass.getuser()):
        case Verdict(on_console=True, locked=False, is_self=True):
            return True
        case _:
            return False


async def session_summary(*, probe: Callable[[], Awaitable[SessionSnapshot]] = probe_session) -> dict[str, object]:
    """This host's console session state, shaped for the ``whoami`` RPC.

    Args:
        probe: The system session reader. Defaults to the real :func:`probe_session`;
            inject a stub to drive the result in tests.

    Returns:
        ``{"on_console": bool, "locked": bool, "console_user": str | None}``.

    Example:
        >>> await session_summary()
        {'on_console': True, 'locked': False, 'console_user': 'alice'}
    """
    snapshot = await probe()
    return {
        "on_console": snapshot.on_console,
        "locked": snapshot.locked,
        "console_user": snapshot.console_user,
    }
