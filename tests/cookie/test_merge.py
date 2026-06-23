from __future__ import annotations

from cookiesync.cookie.merge import merge, merge_key
from cookiesync.cookie.models import ChromeMicros, Cookie, HostKey


def _cookie(
    *,
    host: str = ".x.com",
    name: str = "sid",
    value: str = "v",
    path: str = "/",
    last_update: int = 13_350_000_000_000_000,
    source_port: int = 443,
    source_scheme: int = 2,
    top_frame_site_key: str = "",
    has_cross_site_ancestor: int = 0,
) -> Cookie:
    return Cookie(
        host_key=HostKey(host),
        name=name,
        value=value,
        path=path,
        expires_utc=ChromeMicros(13_400_000_000_000_000),
        last_update_utc=ChromeMicros(last_update),
        creation_utc=ChromeMicros(13_300_000_000_000_000),
        is_secure=True,
        is_httponly=True,
        samesite=2,
        source_scheme=source_scheme,
        source_port=source_port,
        top_frame_site_key=top_frame_site_key,
        has_cross_site_ancestor=has_cross_site_ancestor,
    )


def test_empty_sources_yield_empty() -> None:
    assert merge() == ()
    assert merge([], [], []) == ()


def test_newest_last_update_wins() -> None:
    old = _cookie(value="old", last_update=13_300_000_000_000_000)
    new = _cookie(value="new", last_update=13_399_000_000_000_000)
    assert merge([old], [new]) == (new,)
    # Order of sources must not matter: newest wins either way.
    assert merge([new], [old]) == (new,)


def test_disjoint_union_keeps_every_cookie() -> None:
    a = _cookie(host=".a.com", name="a")
    b = _cookie(host=".b.com", name="b")
    c = _cookie(host=".c.com", name="c")
    merged = merge([a], [b, c])
    assert len(merged) == 3
    assert {cookie.host_key for cookie in merged} == {".a.com", ".b.com", ".c.com"}


def test_same_logical_key_across_three_sources_collapses_to_one() -> None:
    s1 = _cookie(value="1", last_update=13_310_000_000_000_000)
    s2 = _cookie(value="2", last_update=13_320_000_000_000_000)
    s3 = _cookie(value="3", last_update=13_330_000_000_000_000)
    merged = merge([s1], [s2], [s3])
    assert len(merged) == 1
    assert merged[0].value == "3"  # newest last_update across all three sources


def test_full_uniqueness_tuple_distinguishes_source_port() -> None:
    a = _cookie(name="sid", path="/", source_port=443)
    b = _cookie(name="sid", path="/", source_port=8443)
    merged = merge([a], [b])
    assert len(merged) == 2, "same name+path but different source_port are DISTINCT keys"
    assert {cookie.source_port for cookie in merged} == {443, 8443}


def test_full_uniqueness_tuple_distinguishes_top_frame_site_key() -> None:
    a = _cookie(name="sid", path="/", top_frame_site_key="")
    b = _cookie(name="sid", path="/", top_frame_site_key="https://embed.example")
    merged = merge([a], [b])
    assert len(merged) == 2, "same name+path but different top_frame_site_key are DISTINCT keys"
    assert {cookie.top_frame_site_key for cookie in merged} == {"", "https://embed.example"}


def test_deterministic_tie_break_on_equal_last_update() -> None:
    # Same logical key, identical last_update, different values: the winner must be a
    # deterministic function of content, independent of source order.
    left = _cookie(value="alpha", last_update=13_350_000_000_000_000)
    right = _cookie(value="omega", last_update=13_350_000_000_000_000)
    assert merge_key(left) == merge_key(right)
    forward = merge([left], [right])
    reverse = merge([right], [left])
    assert len(forward) == 1 and len(reverse) == 1
    assert forward[0].value == reverse[0].value, "tie-break must not depend on source order"
