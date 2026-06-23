"""The ssh-backed peer source: drive a remote host's daemon to read and write its cookies.

A peer's cookies never leave its machine encrypted — decryption happens *remotely*, in the
remote daemon's live GUI session, so the Safe Storage key never crosses the wire.
``SshBackend`` is the client side of that exchange and the peer half of the sync
:class:`~cookiesync.daemon.sync.Source` seam: ``extract`` shells out to ``cookiesync rpc
extract`` on the peer and parses the wire cookie records it streams back; ``apply`` pipes
the merged wire payload to ``cookiesync rpc apply`` on the peer's stdin. The remote ``rpc``
command is wired by the integrator; this module owns the client and the payload shape.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cookiesync.daemon.sync import Extracted
from cookiesync.daemon.wire import cookie_from_wire, cookie_to_wire
from cookiesync.transport import shell_quote, ssh

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cookiesync.cookie.models import Cookie
    from cookiesync.state import BrowserId, SshTarget


@dataclass(frozen=True, slots=True)
class SshBackend:
    """A peer host's cookie store, reached by driving its daemon over ssh.

    The peer decrypts in its own GUI session, so cookies cross the wire already decrypted
    and the peer's Safe Storage key never leaves its machine. ``origin`` is this host's own
    target, forwarded on every call so the peer's daemon can suppress the echo back to us.

    Example:
        >>> SshBackend(SshTarget("me@laptop"), origin=self_target)
    """

    target: SshTarget
    origin: SshTarget

    async def extract(self, browser: BrowserId, profile: str) -> Extracted:
        """Extract the peer's decrypted cookies for ``browser``/``profile``."""
        payload = json.loads(
            await ssh(
                self.target,
                "cookiesync rpc extract"
                f" --browser {shell_quote(browser)} --profile {shell_quote(profile)}"
                f" --origin {shell_quote(self.origin)}",
            )
        )
        return Extracted(tuple(cookie_from_wire(c) for c in payload["cookies"]))

    async def apply(self, browser: BrowserId, profile: str, cookies: Sequence[Cookie]) -> int:
        """Apply the merged ``cookies`` to the peer's ``browser``/``profile`` store, returning rows written.

        The merged set is piped as a JSON array of wire records to the peer's
        ``cookiesync rpc apply`` stdin; the peer re-encrypts with its own key.
        """
        return json.loads(
            await ssh(
                self.target,
                "cookiesync rpc apply"
                f" --browser {shell_quote(browser)} --profile {shell_quote(profile)}"
                f" --origin {shell_quote(self.origin)}",
                stdin=json.dumps([cookie_to_wire(c) for c in cookies]).encode(),
            )
        )["applied"]
