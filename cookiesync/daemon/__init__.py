"""The cookiesync sync daemon: active-session detection, the watch/sync loops, and the unix-socket RPC.

Public surface re-exported here is what the CLI and RPC layers call; everything else
in the package stays internal.
"""

from __future__ import annotations

from cookiesync.daemon.rpc import Dispatcher, RpcError, call, serve
from cookiesync.daemon.server import AuthRequired, CachedKeySource, Daemon
from cookiesync.daemon.session import has_active_session, session_summary
from cookiesync.daemon.sync import NeedsAuth, converge, reconcile
from cookiesync.daemon.wire import Request, Response, cookie_from_wire, cookie_to_wire
