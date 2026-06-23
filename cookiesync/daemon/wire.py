"""The newline-delimited JSON wire format the daemon RPC speaks.

One ``Request`` line in, one ``Response`` line out, then the connection closes.
``Cookie`` objects cross the wire as the JSON-safe dict ``dataclasses.asdict``
produces, since every ``Cookie`` field is a ``str``/``int``/``bool``.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field

from cookiesync.cookie import Cookie
from cookiesync.cookie.models import ChromeMicros, HostKey


@dataclass(frozen=True, slots=True)
class Request:
    """A single daemon command, encoded as one JSON line.

    Example:
        >>> Request("status", {"endpoint": "host:chrome:Default"})
    """

    method: str
    params: dict = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Response:
    """The daemon's reply to one ``Request``, encoded as one JSON line.

    ``error`` is set only when the request failed; ``result`` carries the handler's
    return on success.

    Example:
        >>> Response(ok=True, result={"applied": 3})
    """

    ok: bool
    result: dict | list | None = None
    error: str | None = None


def cookie_to_wire(cookie: Cookie) -> dict:
    """A ``Cookie`` as the JSON-safe dict that crosses the wire."""
    return dataclasses.asdict(cookie)


def cookie_from_wire(data: dict) -> Cookie:
    """A wire dict back into a ``Cookie``, re-branding its primitive fields."""
    return Cookie(
        host_key=HostKey(data["host_key"]),
        name=data["name"],
        value=data["value"],
        path=data["path"],
        expires_utc=ChromeMicros(data["expires_utc"]),
        last_update_utc=ChromeMicros(data["last_update_utc"]),
        creation_utc=ChromeMicros(data["creation_utc"]),
        is_secure=data["is_secure"],
        is_httponly=data["is_httponly"],
        samesite=data["samesite"],
        source_scheme=data["source_scheme"],
        source_port=data["source_port"],
        top_frame_site_key=data["top_frame_site_key"],
        has_cross_site_ancestor=data["has_cross_site_ancestor"],
    )


def encode_request(req: Request) -> bytes:
    """A ``Request`` as one newline-terminated JSON line."""
    return json.dumps({"method": req.method, "params": req.params}).encode() + b"\n"


def decode_request(line: bytes) -> Request:
    """One JSON line back into a ``Request``."""
    data = json.loads(line)
    return Request(method=data["method"], params=data.get("params", {}))


def encode_response(resp: Response) -> bytes:
    """A ``Response`` as one newline-terminated JSON line."""
    return json.dumps({"ok": resp.ok, "result": resp.result, "error": resp.error}).encode() + b"\n"


def decode_response(line: bytes) -> Response:
    """One JSON line back into a ``Response``."""
    data = json.loads(line)
    return Response(ok=data["ok"], result=data.get("result"), error=data.get("error"))
