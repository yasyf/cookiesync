from __future__ import annotations

import json

import pytest

from cookiesync.cookie.models import (
    ChromeMicros,
    Cookie,
    HostKey,
    StorageState,
    unix_to_chrome_micros,
)
from cookiesync.cookie.serialize import OutputFormat, normalize_getcookie_record, render

PERSISTENT_EXPIRES_UNIX = 2_000_000_000.0

SID = Cookie(
    host_key=HostKey(".example.com"),
    name="sid",
    value="abc",
    path="/",
    expires_utc=unix_to_chrome_micros(PERSISTENT_EXPIRES_UNIX),
    last_update_utc=ChromeMicros(0),
    creation_utc=ChromeMicros(0),
    is_secure=True,
    is_httponly=True,
    samesite=2,
)
TOK = Cookie(
    host_key=HostKey("host.example.com"),
    name="tok",
    value="xyz",
    path="/app",
    expires_utc=ChromeMicros(0),
    last_update_utc=ChromeMicros(0),
    creation_utc=ChromeMicros(0),
    is_secure=False,
    is_httponly=False,
    samesite=0,
)
STATE = StorageState((SID, TOK))

PW_SID = {
    "name": "sid",
    "value": "abc",
    "domain": ".example.com",
    "path": "/",
    "expires": PERSISTENT_EXPIRES_UNIX,
    "httpOnly": True,
    "secure": True,
    "sameSite": "Strict",
}
PW_TOK = {
    "name": "tok",
    "value": "xyz",
    "domain": "host.example.com",
    "path": "/app",
    "expires": -1,
    "httpOnly": False,
    "secure": True,
    "sameSite": "None",
}


@pytest.mark.parametrize(
    ("fmt", "expected"),
    [
        pytest.param(
            OutputFormat.PLAYWRIGHT,
            [json.dumps({"cookies": [PW_SID, PW_TOK], "origins": []})],
            id="playwright",
        ),
        pytest.param(
            OutputFormat.JSON,
            [json.dumps([PW_SID, PW_TOK])],
            id="json",
        ),
        pytest.param(
            OutputFormat.NETSCAPE,
            [
                "# Netscape HTTP Cookie File",
                ".example.com\tTRUE\t/\tTRUE\t2000000000\tsid\tabc",
                "host.example.com\tFALSE\t/app\tFALSE\t0\ttok\txyz",
            ],
            id="netscape",
        ),
        pytest.param(
            OutputFormat.HEADER,
            ["sid=abc; tok=xyz"],
            id="header",
        ),
    ],
)
def test_render_emits_exact_lines(fmt: OutputFormat, expected: list[str]) -> None:
    assert list(render(STATE, fmt)) == expected


def test_playwright_is_valid_storage_state_with_empty_origins() -> None:
    state = json.loads(next(iter(render(STATE, OutputFormat.PLAYWRIGHT))))
    assert state["origins"] == []
    assert [c["name"] for c in state["cookies"]] == ["sid", "tok"]
    assert state["cookies"][0] == PW_SID


def test_json_is_array_of_playwright_cookies() -> None:
    assert json.loads(next(iter(render(STATE, OutputFormat.JSON)))) == [PW_SID, PW_TOK]


def test_netscape_dot_flag_tracks_leading_dot() -> None:
    rows = list(render(STATE, OutputFormat.NETSCAPE))[1:]
    assert rows[0].split("\t")[1] == "TRUE"  # .example.com -> includeSubdomains
    assert rows[1].split("\t")[1] == "FALSE"  # host-only


def test_netscape_session_cookie_expiry_is_zero() -> None:
    assert list(render(STATE, OutputFormat.NETSCAPE))[2].split("\t")[4] == "0"


def test_header_is_name_value_pairs() -> None:
    assert next(iter(render(STATE, OutputFormat.HEADER))) == "sid=abc; tok=xyz"


def test_samesite_none_forces_secure_true() -> None:
    # TOK has is_secure=False and samesite=0 (None); rendering must force secure.
    [pw] = [c for c in json.loads(next(iter(render(STATE, OutputFormat.JSON)))) if c["name"] == "tok"]
    assert pw["sameSite"] == "None"
    assert pw["secure"] is True


def test_session_cookie_expiry_renders_minus_one() -> None:
    [pw] = [c for c in json.loads(next(iter(render(STATE, OutputFormat.JSON)))) if c["name"] == "tok"]
    assert pw["expires"] == -1


def test_render_empty_state_per_format() -> None:
    empty = StorageState(())
    assert list(render(empty, OutputFormat.PLAYWRIGHT)) == [json.dumps({"cookies": [], "origins": []})]
    assert list(render(empty, OutputFormat.JSON)) == ["[]"]
    assert list(render(empty, OutputFormat.NETSCAPE)) == ["# Netscape HTTP Cookie File"]
    assert list(render(empty, OutputFormat.HEADER)) == [""]


def test_normalize_getcookie_record_maps_fields() -> None:
    cookie = normalize_getcookie_record(
        {
            "name": "session",
            "value": "deadbeef",
            "domain": ".github.com",
            "path": "/login",
            "expiry": 1_900_000_000,
            "meta": {"secure": True, "httpOnly": True, "sameSite": "Strict"},
        },
        "https://github.com",
    )
    assert cookie.host_key == ".github.com"
    assert cookie.name == "session"
    assert cookie.value == "deadbeef"
    assert cookie.path == "/login"
    assert cookie.is_secure is True
    assert cookie.is_httponly is True
    assert cookie.samesite == 2
    assert cookie.expires_utc == unix_to_chrome_micros(1_900_000_000.0)


def test_normalize_getcookie_record_defaults_session_cookie_to_minus_one() -> None:
    cookie = normalize_getcookie_record({"name": "n", "value": "v"}, "https://x.com")
    state = StorageState((cookie,))
    [pw] = json.loads(next(iter(render(state, OutputFormat.JSON))))
    assert pw["domain"] == "x.com"  # falls back to the request host
    assert pw["path"] == "/"
    assert pw["expires"] == -1
    assert pw["secure"] is True  # https scheme
    assert pw["sameSite"] == "Lax"  # default
