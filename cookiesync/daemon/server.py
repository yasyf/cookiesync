"""The cookiesync daemon: wire the watch engine, the sync layer, and the unix-socket RPC into one process.

``Daemon.watch`` runs two things under one :class:`anyio.abc.TaskGroup` — the engine watching
this host's local endpoints (each settle notifies every peer to converge) and ``rpc.serve``
answering the bimodal RPC method set — so the first failure cancels the other. Every method
routes through :meth:`Daemon.dispatcher`.

The method set splits in two:

* **Peer methods** carry an ``origin`` and are how peers drive this host over ssh: ``sync``
  converges one endpoint (suppressing the origin), ``reconcile`` runs a full pass, ``extract``
  returns this host's decrypted cookies as wire records (priming auth if the key is cold),
  ``apply`` ingests a merged wire set (idempotent write plus the engine's anti-echo digest),
  and ``whoami`` reports this host's session.
* **Local methods** are terminal and carry no origin — what the CLI on this box invokes:
  ``prime_auth`` obtains the Safe Storage key (locally behind Touch ID when a session is live,
  else by routing the user-presence gate to the active peer and then releasing this host's
  *own* key non-interactively) and caches it; ``get_cookies`` renders a url's cookies from the
  cached key, failing closed when cold; ``auth_status`` reports cache warmth; ``request_consent``
  shows the Touch-ID prompt for the named browser to the person at *this* machine and echoes the
  requester's nonce + endpoint to bind the approval — the key never crosses hosts.

Every collaborator (consent gate, key cache, watch engine, session probe, ssh runner, cookie
sources, and the clock) is injected, so the whole dispatcher runs in unit tests against fakes
without a real macOS API, ssh, or cookie store.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING

import anyio

from cookiesync import state as state_module
from cookiesync.cookie import LocalBackend, extract
from cookiesync.cookie.browsers import REGISTRY, BrowserName
from cookiesync.cookie.consent import ConsentError
from cookiesync.cookie.crypto import DecryptError, decrypt_value
from cookiesync.cookie.models import AesKey, Cookie
from cookiesync.cookie.stores import read_rows, write_rows
from cookiesync.daemon import rpc
from cookiesync.daemon.backend_ssh import SshBackend
from cookiesync.daemon.engine import Engine, logical_digest
from cookiesync.daemon.rpc import Dispatcher
from cookiesync.daemon.session import has_active_session, probe_session, session_summary
from cookiesync.daemon.sync import Extracted, NeedsAuth, converge, reconcile
from cookiesync.daemon.wire import cookie_from_wire, cookie_to_wire
from cookiesync.state import BrowserId, SshTarget
from cookiesync.transport import shell_quote, ssh

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence

    from cookiesync.cookie.browsers import Browser
    from cookiesync.cookie.consent import Consent
    from cookiesync.cookie.models import EncryptedRow
    from cookiesync.daemon.cache import KeyCache
    from cookiesync.daemon.session import SessionSnapshot
    from cookiesync.daemon.sync import Source
    from cookiesync.state import BrowserEndpoint, State

PEER_METHODS = ("sync", "reconcile", "extract", "apply", "whoami")
LOCAL_METHODS = ("prime_auth", "get_cookies", "auth_status", "request_consent")

CONSENT_REASON = "sync them across your Macs"
DEFAULT_PROFILE = "Default"


class AuthRequired(Exception):
    """The local key cache is cold; the user must run ``cookiesync auth`` first."""


def browser_for(browser_id: BrowserId) -> Browser:
    """The :class:`~cookiesync.cookie.browsers.Browser` a wire ``browser`` id names."""
    return REGISTRY[BrowserName(browser_id)]


def endpoint_id(host: SshTarget, browser: BrowserId, profile: str) -> str:
    return f"{host}:{browser}:{profile}"


@dataclass(frozen=True, slots=True)
class CachedKeySource:
    """The sync :class:`~cookiesync.daemon.sync.Source` for this host, decrypting with the cached key.

    ``extract`` reads every row of the browser profile off a private store copy and decrypts it
    with the cached Safe Storage key — never the consent gate, so the merge pass never prompts;
    a cold cache raises :class:`~cookiesync.daemon.sync.NeedsAuth`. ``apply`` re-encrypts the
    merged set back into the live store with that same key.
    """

    cache: KeyCache
    self_target: SshTarget

    async def key_for(self, browser: BrowserId, profile: str) -> AesKey:
        if (key := await self.cache.get(endpoint_id(self.self_target, browser, profile))) is None:
            raise NeedsAuth(f"no cached key for {endpoint_id(self.self_target, browser, profile)}; run cookiesync auth")
        return AesKey(key)

    async def extract(self, browser: BrowserId, profile: str) -> Extracted:
        key = await self.key_for(browser, profile)
        rows = await read_rows(browser_for(browser), profile)
        return Extracted(tuple(c for row in rows if (c := decrypt_row(row, key)) is not None))

    async def apply(self, browser: BrowserId, profile: str, cookies: Sequence[Cookie]) -> int:
        return await write_rows(browser_for(browser), profile, cookies, await self.key_for(browser, profile))


def decrypt_row(row: EncryptedRow, key: AesKey) -> Cookie | None:
    try:
        value = decrypt_value(row.encrypted_value, key, row.host_key)
    except DecryptError:
        return None
    return Cookie(
        host_key=row.host_key,
        name=row.name,
        value=value,
        path=row.path,
        expires_utc=row.expires_utc,
        last_update_utc=row.last_update_utc,
        creation_utc=row.creation_utc,
        is_secure=row.is_secure,
        is_httponly=row.is_httponly,
        samesite=row.samesite,
        source_scheme=row.source_scheme,
        source_port=row.source_port,
        top_frame_site_key=row.top_frame_site_key,
        has_cross_site_ancestor=row.has_cross_site_ancestor,
    )


@dataclass(slots=True)
class Daemon:
    """The resident cookiesync daemon: the watch loop, the sync layer, and the RPC dispatcher.

    Holds every collaborator behind an injected seam so :meth:`dispatcher` and :meth:`watch`
    run in unit tests against fakes. In production it is built with the real consent gate,
    key cache, watch engine, session probe, and ssh runner.

    Example:
        >>> daemon = await Daemon.build()
        >>> await daemon.watch()
    """

    consent: Consent
    cache: KeyCache
    engine: Engine
    probe: Callable[[], Awaitable[SessionSnapshot]] = probe_session
    run_ssh: Callable[..., Awaitable[str]] = ssh
    load_state: Callable[[], Awaitable[State]] = state_module.load
    local_source_factory: Callable[[Daemon, SshTarget], Source] | None = None
    source_for_factory: Callable[[Daemon, SshTarget], Source] | None = None

    @classmethod
    async def build(cls) -> Daemon:
        """Wire the production daemon: Touch-ID consent, the Enclave-backed cache, and a fresh engine."""
        from cookiesync.cookie.consent import TouchIDConsent
        from cookiesync.daemon.cache import KeyCache, SecureEnclaveWrapper

        settings = (await state_module.load()).settings
        daemon = cls(TouchIDConsent(), KeyCache(await SecureEnclaveWrapper.open()), Engine(settings, notify=_noop))
        daemon.engine.notify = daemon.notify_peers
        return daemon

    def local_source(self, self_target: SshTarget) -> Source:
        if self.local_source_factory is not None:
            return self.local_source_factory(self, self_target)
        return CachedKeySource(self.cache, self_target)

    def source_for(self, self_target: SshTarget) -> Callable[[SshTarget], Source]:
        if self.source_for_factory is not None:
            return lambda peer: self.source_for_factory(self, peer)
        return lambda peer: SshBackend(peer, origin=self_target)

    async def watch(self) -> None:
        """Run the engine over this host's local endpoints and the RPC server until cancelled.

        Under one task group the engine watches each local endpoint (a settle notifies every
        peer to converge) and ``rpc.serve`` answers the bimodal RPC set; the first failure
        cancels the rest.
        """
        state = await self.load_state()
        local_endpoints = tuple(e for e in state.browsers if e.host == state.self_target)
        async with anyio.create_task_group() as tg:
            await tg.start(rpc.serve, self.dispatcher())
            tg.start_soon(self.engine.run, local_endpoints)

    async def notify_peers(self, endpoint: BrowserEndpoint) -> None:
        """A local endpoint settled: ssh every peer to converge that browser, tagged with our origin."""
        state = await self.load_state()
        peers = {e.host for e in state.browsers if e.browser == endpoint.browser and e.host != state.self_target}
        async with anyio.create_task_group() as tg:
            for peer in peers:
                tg.start_soon(self.notify_peer, peer, endpoint.browser, state.self_target)

    async def notify_peer(self, peer: SshTarget, browser: BrowserId, self_target: SshTarget) -> None:
        await self.run_ssh(
            peer,
            f"cookiesync rpc sync --browser {shell_quote(browser)} --origin {shell_quote(self_target)}",
        )

    def dispatcher(self) -> Dispatcher:
        """Build the :class:`~cookiesync.daemon.rpc.Dispatcher` with every peer and local method bound."""
        dispatcher = Dispatcher()
        dispatcher.register("sync", self.handle_sync)
        dispatcher.register("reconcile", self.handle_reconcile)
        dispatcher.register("extract", self.handle_extract)
        dispatcher.register("apply", self.handle_apply)
        dispatcher.register("whoami", self.handle_whoami)
        dispatcher.register("prime_auth", self.handle_prime_auth)
        dispatcher.register("get_cookies", self.handle_get_cookies)
        dispatcher.register("auth_status", self.handle_auth_status)
        dispatcher.register("request_consent", self.handle_request_consent)
        return dispatcher

    async def handle_sync(self, params: dict) -> dict:
        state = await self.load_state()
        browser = BrowserId(params["browser"])
        origin = SshTarget(params["origin"]) if params.get("origin") else None
        group = [e for e in state.browsers if e.browser == browser]
        anchor = next((e for e in group if e.host == state.self_target), None)
        if anchor is None:
            return {"converged": False, "reason": "no local endpoint for this browser"}
        merged = await converge(
            anchor,
            [e for e in group if e is not anchor],
            origin=origin,
            self_target=state.self_target,
            cache=self.cache,
            engine=self.engine,
            local_source=self.local_source(state.self_target),
            source_for=self.source_for(state.self_target),
        )
        return {"converged": True, "cookies": len(merged)}

    async def handle_reconcile(self, params: dict) -> dict:
        state = await self.load_state()
        results = await reconcile(
            state.browsers,
            self_target=state.self_target,
            registry={BrowserId(name): browser for name, browser in REGISTRY.items()},
            cache=self.cache,
            engine=self.engine,
            local_source=self.local_source(state.self_target),
            source_for=self.source_for(state.self_target),
        )
        return {"groups": {anchor_id: len(cookies) for anchor_id, cookies in results.items()}}

    async def handle_extract(self, params: dict) -> dict:
        state = await self.load_state()
        browser = BrowserId(params["browser"])
        profile = params.get("profile", DEFAULT_PROFILE)
        if await self.cache.get(endpoint_id(state.self_target, browser, profile)) is None:
            await self.prime_auth(browser, profile, state)
        extracted = await self.local_source(state.self_target).extract(browser, profile)
        return {"cookies": [cookie_to_wire(c) for c in extracted.cookies]}

    async def handle_apply(self, params: dict) -> dict:
        state = await self.load_state()
        browser = BrowserId(params["browser"])
        profile = params.get("profile", DEFAULT_PROFILE)
        cookies = tuple(cookie_from_wire(c) for c in params["cookies"])
        self.engine.record_applied(endpoint_id(state.self_target, browser, profile), logical_digest(cookies))
        applied = await self.local_source(state.self_target).apply(browser, profile, cookies)
        return {"applied": applied}

    async def handle_whoami(self, params: dict) -> dict:
        return await session_summary(probe=self.probe)

    async def handle_prime_auth(self, params: dict) -> dict:
        state = await self.load_state()
        browser = BrowserId(params["browser"])
        profile = params.get("profile", DEFAULT_PROFILE)
        await self.prime_auth(browser, profile, state, reason=params.get("reason") or CONSENT_REASON)
        return {"primed": True, "endpoint": endpoint_id(state.self_target, browser, profile)}

    async def prime_auth(
        self, browser: BrowserId, profile: str, state: State, *, reason: str = CONSENT_REASON
    ) -> AesKey:
        """Obtain the Safe Storage key and cache it under the endpoint's TTL.

        A live local session releases the key behind one Touch-ID tap here. Otherwise the user
        presence check is *routed* to the active peer via ``request_consent``: the peer shows
        Touch ID for *this exact* browser, and only a reply whose ``nonce`` and ``endpoint``
        echo back the ones this host sent counts as an approval. On a verified approval this
        host releases its *own* key non-interactively — the key never leaves this box. Raises
        :class:`AuthRequired` when no peer can approve or the reply fails to bind.
        """
        if await has_active_session(probe=self.probe):
            key = await self.consent.obtain_key(browser_for(browser), reason=reason)
        else:
            key = await self.routed_release(browser, profile, state)
        await self.cache.put(
            endpoint_id(state.self_target, browser, profile), key, state.settings.auth_ttl.total_seconds()
        )
        return key

    async def routed_release(self, browser: BrowserId, profile: str, state: State) -> AesKey:
        """Route the user-presence gate to the active peer, then release this host's own key.

        The peer's ``request_consent`` reply must echo the exact ``nonce`` and ``endpoint``
        this host sent; otherwise the approval is unbound and we fail closed. Only after that
        verified approval do we read this host's own key non-interactively — it never crosses
        the wire.
        """
        peer = await self.active_peer(state)
        nonce = secrets.token_urlsafe(32)
        endpoint = endpoint_id(state.self_target, browser, profile)
        resp = json.loads(
            await self.run_ssh(
                peer,
                "cookiesync rpc request_consent"
                f" --browser {shell_quote(browser)} --profile {shell_quote(profile)}"
                f" --nonce {shell_quote(nonce)} --endpoint {shell_quote(endpoint)}",
            )
        )
        if not (resp.get("status") == "approved" and resp.get("nonce") == nonce and resp.get("endpoint") == endpoint):
            raise AuthRequired(f"consent {resp.get('status') or 'unavailable'} from {peer}")
        return await self.consent.obtain_key_unprompted(browser_for(browser))

    async def active_peer(self, state: State) -> SshTarget:
        for peer in {e.host for e in state.browsers if e.host != state.self_target}:
            summary = json.loads(await self.run_ssh(peer, "cookiesync rpc whoami"))
            if summary.get("on_console") and not summary.get("locked"):
                return peer
        raise AuthRequired("no peer has a live session to approve consent")

    async def handle_get_cookies(self, params: dict) -> dict:
        state = await self.load_state()
        browser = BrowserId(params["browser"])
        profile = params.get("profile", DEFAULT_PROFILE)
        if (key := await self.cache.get(endpoint_id(state.self_target, browser, profile))) is None:
            raise AuthRequired(
                f"no cached key for {endpoint_id(state.self_target, browser, profile)}; run cookiesync auth"
            )
        result = await extract(
            params["url"],
            browser=browser_for(browser),
            key=AesKey(key),
            backend=LocalBackend(self.consent),
            profile=profile,
            fallback=False,
        )
        return {"cookies": [cookie_to_wire(c) for c in result.cookies]}

    async def handle_auth_status(self, params: dict) -> dict:
        state = await self.load_state()
        browser = BrowserId(params["browser"])
        profile = params.get("profile", DEFAULT_PROFILE)
        endpoint = endpoint_id(state.self_target, browser, profile)
        return {"endpoint": endpoint, "authenticated": await self.cache.get(endpoint) is not None}

    async def handle_request_consent(self, params: dict) -> dict:
        """Show the Touch-ID prompt to the person at *this* machine for the requesting endpoint.

        The prompt names the exact browser the requester asked to release, so the user sees
        what they are approving. The reply echoes the requester's ``nonce`` and ``endpoint``,
        binding the approval to that one request — no key crosses the wire.

        Returns ``{"status": "approved", "nonce": ..., "endpoint": ...}`` on a live tap,
        ``{"status": "denied"}`` when the prompt was declined, or ``{"status": "unavailable"}``
        when this host has no live session to prompt.
        """
        browser = BrowserId(params["browser"])
        nonce = params["nonce"]
        endpoint = params["endpoint"]
        if not await has_active_session(probe=self.probe):
            return {"status": "unavailable"}
        try:
            await self.consent.obtain_key(browser_for(browser), reason=f"sync them to {endpoint}")
        except ConsentError:
            return {"status": "denied"}
        return {"status": "approved", "nonce": nonce, "endpoint": endpoint}


async def _noop(_endpoint: BrowserEndpoint) -> None:
    return None
