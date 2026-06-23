from __future__ import annotations

import pytest

from cookiesync.cookie.domains import cookie_applies, normalize_host, url_scheme
from cookiesync.cookie.models import Host, HostKey


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param("x.com", "x.com", id="bare"),
        pytest.param("https://x.com", "x.com", id="strip-scheme"),
        pytest.param("https://x.com/path/to?q=1", "x.com", id="strip-path-query"),
        pytest.param("https://x.com:8443", "x.com", id="strip-port"),
        pytest.param("https://user:pw@x.com/p", "x.com", id="strip-userinfo"),
        pytest.param(".x.com", "x.com", id="strip-leading-dot"),
        pytest.param("  HTTPS://X.COM/  ", "x.com", id="trim-and-lowercase"),
        pytest.param("sub.x.com", "sub.x.com", id="subdomain-kept"),
    ],
)
def test_normalize_host(raw: str, expected: str) -> None:
    assert normalize_host(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        pytest.param("https://x.com", "https", id="https"),
        pytest.param("http://x.com", "http", id="http"),
        pytest.param("HTTP://X.COM", "http", id="lowercased"),
        pytest.param("x.com", "https", id="bare-defaults-https"),
    ],
)
def test_url_scheme(raw: str, expected: str) -> None:
    assert url_scheme(raw) == expected


def test_url_scheme_custom_default() -> None:
    assert url_scheme("x.com", default="http") == "http"


@pytest.mark.parametrize(
    ("host_key", "host", "applies"),
    [
        pytest.param(".x.com", "x.com", True, id="dot-domain-matches-base"),
        pytest.param(".x.com", "sub.x.com", True, id="dot-domain-matches-subdomain"),
        pytest.param(".x.com", "deep.sub.x.com", True, id="dot-domain-matches-deep-subdomain"),
        pytest.param(".x.com", "notx.com", False, id="dot-domain-rejects-suffix-imposter"),
        pytest.param(".x.com", "y.com", False, id="dot-domain-rejects-other"),
        pytest.param("x.com", "x.com", True, id="host-only-exact"),
        pytest.param("x.com", "sub.x.com", False, id="host-only-rejects-subdomain"),
        pytest.param("x.com", "y.com", False, id="host-only-rejects-other"),
        pytest.param(".X.COM", "sub.x.com", True, id="case-insensitive"),
    ],
)
def test_cookie_applies(host_key: str, host: str, applies: bool) -> None:
    assert cookie_applies(HostKey(host_key), Host(host)) is applies
