"""Pure union merge of cookie sets across machines: newest-wins, no tombstones.

Per the product decision, deletions are union-only — a cookie absent from one source is
never treated as a delete, so the merge is a plain union keyed by the cookie's logical
identity. The key is the *schema-superset* uniqueness tuple
``(host_key, top_frame_site_key, name, path, source_scheme, source_port,
has_cross_site_ancestor)``; a ``Cookie`` from a v18 store (which lacks the last three
columns) already carries the model's sentinel defaults for them, so heterogeneous
v18/v24 cookies share one logical key space. Within a key, the winner is the max by
``(last_update_utc, content_hash, endpoint_id)`` with a deterministic, content-derived
final tie-break, so the result is independent of source order.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from cookiesync.cookie.models import Cookie

if TYPE_CHECKING:
    from collections.abc import Iterable

MergeKey = tuple[str, str, str, str, int, int, int]
MergeRank = tuple[int, str, str]


def merge_key(cookie: Cookie) -> MergeKey:
    return (
        cookie.host_key,
        cookie.top_frame_site_key,
        cookie.name,
        cookie.path,
        cookie.source_scheme,
        cookie.source_port,
        cookie.has_cross_site_ancestor,
    )


def content_hash(cookie: Cookie) -> str:
    return hashlib.sha256(
        "\x00".join(
            (
                cookie.value,
                str(cookie.expires_utc),
                str(cookie.samesite),
                str(int(cookie.is_secure)),
                str(int(cookie.is_httponly)),
            )
        ).encode("utf-8")
    ).hexdigest()


def merge_rank(cookie: Cookie) -> MergeRank:
    return (int(cookie.last_update_utc), (h := content_hash(cookie)), f"{merge_key(cookie)}\x00{h}")


def merge(*sources: Iterable[Cookie]) -> tuple[Cookie, ...]:
    """Union all ``sources`` into one cookie set, keeping the newest per logical key.

    Each cookie is keyed by its schema-superset uniqueness tuple; for each key the winner
    is the cookie with the greatest ``(last_update_utc, content_hash, content-derived
    fallback)``, so the result is deterministic regardless of source order. No tombstones:
    a cookie missing from a source is never a deletion.

    Example:
        >>> merge(machine_a_cookies, machine_b_cookies)
    """
    winners: dict[MergeKey, Cookie] = {}
    for cookie in (c for source in sources for c in source):
        if (key := merge_key(cookie)) not in winners or merge_rank(cookie) > merge_rank(winners[key]):
            winners[key] = cookie
    return tuple(winners.values())
