package cookie

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// Pure union merge of cookie sets across machines: newest-wins, no tombstones.
//
// Deletions are union-only — a cookie absent from one source is never treated as a
// delete, so the merge is a plain union keyed by the cookie's logical identity. The
// key is the schema-superset uniqueness tuple (host_key, top_frame_site_key, name,
// path, source_scheme, source_port, has_cross_site_ancestor); a Cookie from a v18
// store (which lacks the last three columns) already carries the model's defaults
// for them, so heterogeneous v18/v24 cookies share one logical key space. Within a
// key the winner is the max by (last_update_utc, content_hash): the hash breaks a
// timestamp tie deterministically from the cookie's value and flags, so the result
// is independent of source order, and two cookies with identical content collapse to
// the same stored row.

// mergeKey is the schema-superset uniqueness tuple that identifies one logical cookie.
type mergeKey struct {
	hostKey              HostKey
	topFrameSiteKey      string
	name                 string
	path                 string
	sourceScheme         int
	sourcePort           int
	hasCrossSiteAncestor int
}

// mergeRank orders two cookies sharing a key: newer last_update_utc wins, ties broken
// by the content hash so the winner is independent of source order.
type mergeRank struct {
	lastUpdateUTC ChromeMicros
	contentHash   string
}

func keyOf(c Cookie) mergeKey {
	return mergeKey{
		hostKey:              c.HostKey,
		topFrameSiteKey:      c.TopFrameSiteKey,
		name:                 c.Name,
		path:                 c.Path,
		sourceScheme:         c.SourceScheme,
		sourcePort:           c.SourcePort,
		hasCrossSiteAncestor: c.HasCrossSiteAncestor,
	}
}

// ContentHash is the deterministic tie-break digest for a cookie: the lowercase hex
// SHA256 of value, expires_utc, samesite, is_secure, and is_httponly joined by NUL
// bytes. It matches the Python serialization byte-for-byte so the hash is stable
// across the two implementations.
func ContentHash(c Cookie) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		c.Value,
		strconv.FormatInt(int64(c.ExpiresUTC), 10),
		strconv.Itoa(c.SameSite),
		boolDigit(c.IsSecure),
		boolDigit(c.IsHTTPOnly),
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

func boolDigit(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func rankOf(c Cookie) mergeRank {
	return mergeRank{lastUpdateUTC: c.LastUpdateUTC, contentHash: ContentHash(c)}
}

func (r mergeRank) less(other mergeRank) bool {
	if r.lastUpdateUTC != other.lastUpdateUTC {
		return r.lastUpdateUTC < other.lastUpdateUTC
	}
	return r.contentHash < other.contentHash
}

// Merge unions all sources into one cookie set, keeping the newest cookie per logical
// key. Each cookie is keyed by its schema-superset uniqueness tuple; for each key the
// winner is the cookie with the greatest (last_update_utc, content_hash), so the
// result is deterministic regardless of source order. There are no tombstones: a
// cookie missing from a source is never a deletion.
func Merge(sources ...[]Cookie) []Cookie {
	winners := map[mergeKey]Cookie{}
	for _, source := range sources {
		for _, cookie := range source {
			key := keyOf(cookie)
			if existing, ok := winners[key]; !ok || rankOf(existing).less(rankOf(cookie)) {
				winners[key] = cookie
			}
		}
	}
	out := make([]Cookie, 0, len(winners))
	for _, cookie := range winners {
		out = append(out, cookie)
	}
	return out
}
