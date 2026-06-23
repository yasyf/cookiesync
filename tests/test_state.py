from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

import pytest

from cookiesync.paths import config_dir, lock_path, sock_path, state_path
from cookiesync.state import (
    BrowserEndpoint,
    BrowserId,
    Settings,
    SshTarget,
    State,
    format_duration,
    load,
    parse_duration,
    update,
)


@pytest.fixture
def isolated_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    return tmp_path


def sample_state() -> State:
    return State(
        self_target=SshTarget("me@laptop"),
        browsers=(
            BrowserEndpoint(SshTarget("me@laptop"), BrowserId("arc"), "Default"),
            BrowserEndpoint(SshTarget("peer@desktop"), BrowserId("chrome"), "Profile 1"),
        ),
        settings=Settings(interval=timedelta(minutes=30), watch_debounce=timedelta(seconds=90)),
    )


def test_paths_under_isolated_config(isolated_config: Path) -> None:
    assert config_dir() == isolated_config / "cookiesync"
    assert state_path() == isolated_config / "cookiesync" / "state.json"
    assert sock_path() == isolated_config / "cookiesync" / "rpc.sock"
    assert lock_path() == isolated_config / "cookiesync" / "reconcile.lock"


def test_endpoint_id() -> None:
    assert BrowserEndpoint(SshTarget("me@laptop"), BrowserId("arc"), "Default").id == "me@laptop:arc:Default"


async def test_save_load_round_trip(isolated_config: Path) -> None:
    saved = await sample_state().save()
    assert await load() == saved == sample_state()


async def test_load_missing_returns_default(isolated_config: Path) -> None:
    assert not state_path().exists()
    loaded = await load()
    assert loaded.browsers == ()
    assert loaded.settings == Settings()
    assert "@" in loaded.self_target


async def test_update_mutates_and_persists(isolated_config: Path) -> None:
    await sample_state().save()

    new_endpoint = BrowserEndpoint(SshTarget("third@server"), BrowserId("arc"), "Work")
    returned = await update(lambda s: replace(s, browsers=(*s.browsers, new_endpoint)))

    assert new_endpoint in returned.browsers
    assert (await load()).browsers == returned.browsers
    assert new_endpoint in (await load()).browsers


async def test_update_accepts_async_fn(isolated_config: Path) -> None:
    await sample_state().save()

    async def bump(state: State) -> State:
        return replace(state, settings=replace(state.settings, interval=timedelta(hours=24)))

    returned = await update(bump)
    assert returned.settings.interval == timedelta(hours=24)
    assert (await load()).settings.interval == timedelta(hours=24)


async def test_atomic_save_leaves_no_temp_files(isolated_config: Path) -> None:
    await sample_state().save()
    assert state_path().exists()
    assert list(config_dir().glob("state-*.tmp")) == []
    assert list(config_dir().glob("*.tmp")) == []


async def test_durations_serialize_as_go_strings(isolated_config: Path) -> None:
    await State(
        self_target=SshTarget("me@laptop"),
        settings=Settings(
            interval=timedelta(minutes=15),
            idle_threshold=timedelta(minutes=5),
            watch_debounce=timedelta(seconds=3),
            op_timeout=timedelta(minutes=2),
            auth_ttl=timedelta(hours=24),
        ),
    ).save()

    assert json.loads(state_path().read_text()) == {
        "self_target": "me@laptop",
        "browsers": [],
        "settings": {
            "interval": "15m",
            "idle_threshold": "5m",
            "watch_debounce": "3s",
            "op_timeout": "2m",
            "auth_ttl": "24h",
        },
    }


@pytest.mark.parametrize(
    "text",
    ["15m", "5m", "3s", "2m", "24h", "90s"],
    ids=["15m", "5m", "3s", "2m", "24h", "90s"],
)
def test_duration_round_trip(text: str) -> None:
    assert format_duration(parse_duration(text)) == text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("15m", timedelta(minutes=15)),
        ("5m", timedelta(minutes=5)),
        ("3s", timedelta(seconds=3)),
        ("2m", timedelta(minutes=2)),
        ("24h", timedelta(hours=24)),
        ("90s", timedelta(seconds=90)),
    ],
    ids=["15m", "5m", "3s", "2m", "24h", "90s"],
)
def test_parse_duration(text: str, expected: timedelta) -> None:
    assert parse_duration(text) == expected
