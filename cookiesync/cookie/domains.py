"""Host parsing and the cookie send-rule: what the browser would send to a host.

No public-suffix list: ``cookie_applies`` implements the actual domain-match the
browser uses, which is all we need to pick the cookies for one target host.
"""

from __future__ import annotations

from cookiesync.cookie.models import Host, HostKey


def normalize_host(url: str) -> Host:
    """Lowercase bare host from a URL or domain (strip scheme, path, query, port, leading dot)."""
    v = url.strip().lower()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0].split("?", 1)[0]
    if "@" in v:
        v = v.split("@", 1)[1]
    if ":" in v:
        v = v.split(":", 1)[0]
    return Host(v.strip("."))


def url_scheme(url: str, *, default: str = "https") -> str:
    """Scheme of a URL, or ``default`` for a bare domain."""
    return url.split("://", 1)[0].lower() if "://" in url else default


def cookie_applies(host_key: HostKey, host: Host) -> bool:
    """Would a browser send a cookie with this ``host_key`` to ``host``?

    Domain cookies (leading dot) match the base host and any subdomain; host-only
    cookies match exactly. Mirrors the browser's own send rule.
    """
    hk = host_key.lower()
    rh = host.lower()
    return (rh == hk[1:] or rh.endswith(hk)) if hk.startswith(".") else rh == hk
