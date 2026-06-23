from __future__ import annotations

import os
import socket
import sys
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

import anyio
import pytest

from cookiesync import paths
from cookiesync.cookie import Cookie
from cookiesync.cookie.models import ChromeMicros, HostKey
from cookiesync.daemon import rpc
from cookiesync.daemon.rpc import Dispatcher, RpcError, call, peer_uid, serve
from cookiesync.daemon.wire import (
    Request,
    Response,
    cookie_from_wire,
    cookie_to_wire,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator

pytestmark = pytest.mark.anyio

COOKIE = Cookie(
    host_key=HostKey(".example.com"),
    name="sid",
    value="s3cr3t-plaintext",
    path="/",
    expires_utc=ChromeMicros(13_400_000_000_000_000),
    last_update_utc=ChromeMicros(13_390_000_000_000_000),
    creation_utc=ChromeMicros(13_380_000_000_000_000),
    is_secure=True,
    is_httponly=False,
    samesite=1,
    source_scheme=2,
    source_port=443,
    top_frame_site_key="",
    has_cross_site_ancestor=0,
)


@pytest.fixture
def sock_path(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    # macOS caps AF_UNIX paths near 104 bytes, so pytest's deep tmp_path overflows;
    # mkdtemp under $TMPDIR keeps the socket path short.
    with tempfile.TemporaryDirectory(prefix="ckrpc-") as d:
        path = Path(d) / "rpc.sock"
        monkeypatch.setattr(paths, "sock_path", lambda: path)
        yield path


@asynccontextmanager
async def serving(dispatcher: Dispatcher) -> AsyncIterator[None]:
    async with anyio.create_task_group() as tg:
        await tg.start(serve, dispatcher)
        try:
            yield
        finally:
            tg.cancel_scope.cancel()


def test_cookie_wire_round_trips() -> None:
    wire = cookie_to_wire(COOKIE)
    assert isinstance(wire, dict)
    assert wire["host_key"] == ".example.com"
    assert wire["value"] == "s3cr3t-plaintext"
    assert cookie_from_wire(wire) == COOKIE


def test_request_round_trips() -> None:
    req = Request("status", {"endpoint": "host:chrome:Default"})
    assert decode_request(encode_request(req)) == req


def test_request_defaults_empty_params() -> None:
    assert Request("ping").params == {}
    assert decode_request(b'{"method": "ping"}\n') == Request("ping", {})


def test_response_round_trips() -> None:
    for resp in (
        Response(ok=True, result={"applied": 3}),
        Response(ok=True, result=[1, 2, 3]),
        Response(ok=False, error="boom"),
    ):
        assert decode_response(encode_response(resp)) == resp


@pytest.mark.skipif(sys.platform != "darwin", reason="LOCAL_PEERCRED is a macOS-only socket constant")
def test_peer_uid_matches_current_uid() -> None:
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        assert peer_uid(left) == os.getuid()
        assert peer_uid(right) == os.getuid()
    finally:
        left.close()
        right.close()


async def test_call_round_trips_request_to_response(sock_path: Path) -> None:
    dispatcher = Dispatcher()

    async def status(params: dict) -> dict:
        return {"echo": params["endpoint"], "applied": 7}

    dispatcher.register("status", status)

    async with serving(dispatcher):
        resp = await call("status", {"endpoint": "host:chrome:Default"})

    assert resp == Response(ok=True, result={"echo": "host:chrome:Default", "applied": 7})


async def test_unknown_method_returns_error(sock_path: Path) -> None:
    async with serving(Dispatcher()):
        resp = await call("nope", {})

    assert resp.ok is False
    assert resp.error == "unknown method 'nope'"
    assert resp.result is None


async def test_handler_exception_becomes_error_response(sock_path: Path) -> None:
    dispatcher = Dispatcher()

    async def boom(params: dict) -> dict:
        raise ValueError("handler exploded")

    dispatcher.register("boom", boom)

    async with serving(dispatcher):
        resp = await call("boom", {})

    assert resp == Response(ok=False, error="handler exploded")


async def test_dispatch_is_serialized(sock_path: Path) -> None:
    dispatcher = Dispatcher()
    log: list[str] = []
    entered = anyio.Event()
    release = anyio.Event()

    async def slow(params: dict) -> dict:
        log.append(f"enter:{params['id']}")
        if params["id"] == "first":
            entered.set()
            await release.wait()
        log.append(f"exit:{params['id']}")
        return {"id": params["id"]}

    dispatcher.register("slow", slow)

    results: dict[str, Response] = {}

    async def fire(call_id: str) -> None:
        results[call_id] = await call("slow", {"id": call_id})

    async with serving(dispatcher), anyio.create_task_group() as tg:
        tg.start_soon(fire, "first")
        await entered.wait()
        tg.start_soon(fire, "second")
        await anyio.sleep(0.05)
        assert log == ["enter:first"]  # second never entered while first held the lock
        release.set()

    assert log == ["enter:first", "exit:first", "enter:second", "exit:second"]
    assert results["first"] == Response(ok=True, result={"id": "first"})
    assert results["second"] == Response(ok=True, result={"id": "second"})


async def test_call_on_missing_socket_raises_rpc_error(sock_path: Path) -> None:
    with pytest.raises(RpcError):
        await call("status", {})


async def test_serve_unlinks_stale_socket(sock_path: Path) -> None:
    sock_path.parent.mkdir(parents=True, exist_ok=True)
    sock_path.write_text("stale")

    dispatcher = Dispatcher()
    dispatcher.register("ping", lambda params: _pong())

    async with serving(dispatcher):
        resp = await call("ping", {})

    assert resp == Response(ok=True, result={"pong": True})


async def _pong() -> dict:
    return {"pong": True}


@pytest.mark.skipif(sys.platform != "darwin", reason="LOCAL_PEERCRED is a macOS-only socket constant")
def test_peer_uid_helper_uses_local_peercred() -> None:
    assert rpc.SOL_LOCAL == 0
    assert rpc.LOCAL_PEERCRED == socket.LOCAL_PEERCRED
