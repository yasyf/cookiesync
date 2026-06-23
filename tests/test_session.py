from __future__ import annotations

import plistlib

import pytest

from cookiesync.daemon import session
from cookiesync.daemon.session import (
    SessionSnapshot,
    has_active_session,
    parse_session,
    session_summary,
)

pytestmark = pytest.mark.anyio

ME = "alice"
OTHER = "bob"


def ioreg_payload(*, sessions: list[dict[str, object]], console_locked: bool = False) -> bytes:
    return plistlib.dumps({"IOConsoleLocked": console_locked, "IOConsoleUsers": sessions})


def session_dict(*, on_console: bool, user: str, screen_locked: bool | None = None) -> dict[str, object]:
    entry: dict[str, object] = {"kCGSSessionOnConsoleKey": on_console, "kCGSSessionUserNameKey": user}
    if screen_locked is not None:
        entry["CGSSessionScreenIsLocked"] = screen_locked
    return entry


def probe(snapshot: SessionSnapshot):
    async def _probe() -> SessionSnapshot:
        return snapshot

    return _probe


@pytest.fixture(autouse=True)
def login_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(session.getpass, "getuser", lambda: ME)


@pytest.mark.parametrize(
    ("snapshot", "expected"),
    [
        (SessionSnapshot(on_console=True, locked=False, console_user=ME), True),
        (SessionSnapshot(on_console=True, locked=True, console_user=ME), False),
        (SessionSnapshot(on_console=False, locked=False, console_user=None), False),
        (SessionSnapshot(on_console=True, locked=False, console_user=OTHER), False),
        (SessionSnapshot(on_console=True, locked=True, console_user=OTHER), False),
    ],
    ids=[
        "on-console-unlocked-self",
        "locked",
        "no-console",
        "fast-user-switch",
        "fast-user-switch-locked",
    ],
)
async def test_has_active_session(snapshot: SessionSnapshot, expected: bool) -> None:
    assert await has_active_session(probe=probe(snapshot)) is expected


async def test_session_summary_reports_raw_truth() -> None:
    snapshot = SessionSnapshot(on_console=True, locked=True, console_user=OTHER)
    assert await session_summary(probe=probe(snapshot)) == {
        "on_console": True,
        "locked": True,
        "console_user": OTHER,
    }


async def test_session_summary_headless() -> None:
    snapshot = SessionSnapshot(on_console=False, locked=False, console_user=None)
    assert await session_summary(probe=probe(snapshot)) == {
        "on_console": False,
        "locked": False,
        "console_user": None,
    }


def test_parse_on_console_unlocked() -> None:
    payload = ioreg_payload(sessions=[session_dict(on_console=True, user=ME)])
    assert parse_session(payload) == SessionSnapshot(on_console=True, locked=False, console_user=ME)


def test_parse_root_lock_marks_locked() -> None:
    payload = ioreg_payload(sessions=[session_dict(on_console=True, user=ME)], console_locked=True)
    assert parse_session(payload) == SessionSnapshot(on_console=True, locked=True, console_user=ME)


def test_parse_per_session_lock_marks_locked() -> None:
    payload = ioreg_payload(sessions=[session_dict(on_console=True, user=ME, screen_locked=True)])
    assert parse_session(payload) == SessionSnapshot(on_console=True, locked=True, console_user=ME)


def test_parse_no_console_session() -> None:
    payload = ioreg_payload(sessions=[session_dict(on_console=False, user=ME)])
    assert parse_session(payload) == SessionSnapshot(on_console=False, locked=False, console_user=None)


def test_parse_headless_empty_users() -> None:
    payload = ioreg_payload(sessions=[])
    assert parse_session(payload) == SessionSnapshot(on_console=False, locked=False, console_user=None)


def test_parse_picks_the_console_owner_among_many() -> None:
    payload = ioreg_payload(
        sessions=[
            session_dict(on_console=False, user=ME),
            session_dict(on_console=True, user=OTHER),
        ]
    )
    assert parse_session(payload) == SessionSnapshot(on_console=True, locked=False, console_user=OTHER)


async def test_has_active_session_end_to_end_through_parse() -> None:
    payload = ioreg_payload(sessions=[session_dict(on_console=True, user=ME)])

    async def _probe() -> SessionSnapshot:
        return parse_session(payload)

    assert await has_active_session(probe=_probe) is True
