"""Unix-socket RPC plumbing: a one-shot client and a serialized-dispatch server.

The server listens on ``paths.sock_path()`` and speaks the newline-delimited JSON
protocol from ``wire`` — one request line in, one response line out, then close.
Dispatch is serialized behind an ``anyio.Lock`` so at most one handler runs at a
time and handlers never race the cookie store. Only a same-UID peer is served,
checked via ``LOCAL_PEERCRED`` on the accepted connection.
"""

from __future__ import annotations

import os
import socket
import struct
import sys
from typing import TYPE_CHECKING

import anyio
from anyio.abc import SocketAttribute
from anyio.streams.buffered import BufferedByteReceiveStream

from cookiesync import paths
from cookiesync.daemon.wire import (
    Request,
    Response,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from pathlib import Path

    from anyio.abc import SocketStream, TaskStatus

type Handler = Callable[[dict], Awaitable[dict | list | None]]

READ_TIMEOUT = 30.0
DISPATCH_TIMEOUT = 600.0
MAX_LINE = 16 * 1024 * 1024

SOL_LOCAL = 0
# macOS-only socket constant (value 0x001). This daemon runs only on macOS; the literal
# fallback just keeps the package importable on other platforms (docs build, portable engine).
LOCAL_PEERCRED = getattr(socket, "LOCAL_PEERCRED", 0x001)


class RpcError(Exception):
    """The RPC transport failed to reach or read from the daemon."""


def peer_uid(sock: socket.socket) -> int:
    """The UID of the process on the other end of ``sock``, via ``LOCAL_PEERCRED``.

    Reads the ``xucred`` struct macOS returns and pulls ``cr_uid`` out of it.
    """
    cred = sock.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, struct.calcsize("II") + 256)
    _version, uid = struct.unpack_from("II", cred, 0)
    return uid


class Dispatcher:
    """Routes a method name to the async handler the integrator registered for it.

    Example:
        >>> dispatcher = Dispatcher()
        >>> dispatcher.register("status", handle_status)
    """

    def __init__(self) -> None:
        self.handlers: dict[str, Handler] = {}
        self.lock = anyio.Lock()

    def register(self, method: str, handler: Handler) -> None:
        """Bind ``method`` to ``handler``; the daemon calls it with the request params."""
        self.handlers[method] = handler

    async def dispatch(self, req: Request) -> Response:
        """Run the handler for ``req`` under the serialization lock, with a hard timeout."""
        if (handler := self.handlers.get(req.method)) is None:
            return Response(ok=False, error=f"unknown method {req.method!r}")
        async with self.lock:
            response = Response(ok=False, error=f"method {req.method!r} timed out after {DISPATCH_TIMEOUT:.0f}s")
            with anyio.move_on_after(DISPATCH_TIMEOUT):
                try:
                    response = Response(ok=True, result=await handler(req.params))
                except Exception as exc:  # noqa: BLE001 — surface a handler failure as a typed error to the caller
                    response = Response(ok=False, error=str(exc))
        return response


async def call(method: str, params: dict | None = None, *, sock_path: Path | None = None) -> Response:
    """Send one ``Request`` to the daemon and return its ``Response``.

    Connects to the daemon's unix socket, writes one request line, reads one
    response line, and closes.

    Raises:
        RpcError: the daemon could not be reached or sent no response line.

    Example:
        >>> await call("status", {"endpoint": "host:chrome:Default"})
    """
    path = sock_path or paths.sock_path()
    try:
        stream = await anyio.connect_unix(str(path))
    except OSError as exc:
        raise RpcError(f"connect to daemon at {path}: {exc}") from exc
    async with stream:
        await stream.send(encode_request(Request(method=method, params=params or {})))
        try:
            line = await BufferedByteReceiveStream(stream).receive_until(b"\n", MAX_LINE)
        except anyio.EndOfStream as exc:
            raise RpcError(f"daemon at {path} closed without a response") from exc
    return decode_response(line)


async def serve(dispatcher: Dispatcher, *, task_status: TaskStatus[None] = anyio.TASK_STATUS_IGNORED) -> None:
    """Listen on the daemon socket and dispatch each connection's request.

    Unlinks a stale socket before binding, then serves until the surrounding task
    group is cancelled. Signals readiness via ``task_status`` once the listener is
    bound, so a daemon can ``await tg.start(serve, dispatcher)``.

    Example:
        >>> async with anyio.create_task_group() as tg:
        ...     await tg.start(serve, dispatcher)
    """
    path = paths.sock_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    listener = await anyio.create_unix_listener(str(path))

    async def handle(stream: SocketStream) -> None:
        async with stream:
            # LOCAL_PEERCRED is macOS-only; this daemon runs only on macOS, where the
            # same-uid check is enforced. Off-macOS (CI/import only) the 0700 socket dir
            # is the boundary, so skip the unsupported getsockopt.
            if sys.platform == "darwin" and (uid := peer_uid(stream.extra(SocketAttribute.raw_socket))) != os.getuid():
                await stream.send(encode_response(Response(ok=False, error=f"peer uid {uid} is not {os.getuid()}")))
                return
            with anyio.move_on_after(READ_TIMEOUT) as scope:
                line = await BufferedByteReceiveStream(stream).receive_until(b"\n", MAX_LINE)
            if scope.cancelled_caught:
                await stream.send(encode_response(Response(ok=False, error="request read timed out")))
                return
            await stream.send(encode_response(await dispatcher.dispatch(decode_request(line))))

    async with listener:
        task_status.started()
        await listener.serve(handle)
