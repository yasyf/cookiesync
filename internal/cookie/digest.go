package cookie

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"
)

// The anti-echo digest: a cheap, decryption-free fingerprint of a cookie set's
// logical identity, and the seam the sync layer records it through before a write.
//
// LogicalDigest hashes the sorted (host_key, name, path, last_update_utc) tuples of
// every cookie, ignoring encrypted values and schema-only columns, so it changes
// exactly when the logical cookie set does. The sync layer digests the set it is
// about to write and a watch loop fingerprints the store after the write; because
// last_update_utc is preserved on write, the two agree and the induced filesystem
// event is recognized as the daemon's own echo and suppressed. The hash is
// byte-stable and host-independent (it keys only on absolute Chrome time and the
// cookie's identity), so two hosts that hold the same logical set agree on the digest.

// Digest is a logical cookie-set fingerprint: the lowercase-hex SHA256 produced by
// LogicalDigest. It is a distinct type so a logical digest is never confused with a
// content hash or an arbitrary string.
type Digest string

// LogicalRow is the field set LogicalDigest keys on; both Cookie and EncryptedRow
// satisfy it, so a digest can be taken over decrypted cookies or raw rows alike.
type LogicalRow interface {
	logicalKey() (hostKey string, name string, path string, lastUpdate ChromeMicros)
}

func (c Cookie) logicalKey() (string, string, string, ChromeMicros) {
	return string(c.HostKey), c.Name, c.Path, c.LastUpdateUTC
}

func (r EncryptedRow) logicalKey() (string, string, string, ChromeMicros) {
	return string(r.HostKey), r.Name, r.Path, r.LastUpdateUTC
}

// LogicalDigest returns the decryption-free digest of a cookie set: the SHA256 of
// the sorted (host_key, name, path, last_update_utc) tuples joined with the same NUL
// and unit-separator framing as the Python engine, so the hex output is identical
// across the two implementations. The result is independent of input order.
func LogicalDigest[T LogicalRow](items []T) Digest {
	type key struct {
		hostKey, name, path string
		lastUpdate          ChromeMicros
	}
	keys := make([]key, len(items))
	for i, item := range items {
		h, n, p, u := item.logicalKey()
		keys[i] = key{h, n, p, u}
	}
	slices.SortFunc(keys, func(a, b key) int {
		if c := cmp.Compare(a.hostKey, b.hostKey); c != 0 {
			return c
		}
		if c := cmp.Compare(a.name, b.name); c != 0 {
			return c
		}
		if c := cmp.Compare(a.path, b.path); c != 0 {
			return c
		}
		return cmp.Compare(a.lastUpdate, b.lastUpdate)
	})
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k.hostKey + "\x1f" + k.name + "\x1f" + k.path + "\x1f" + strconv.FormatInt(int64(k.lastUpdate), 10)
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return Digest(hex.EncodeToString(sum[:]))
}

// Recorder is the anti-echo seam the sync layer records an endpoint's applied digest
// through, immediately before writing a merged cookie set back to that endpoint's
// store. Recording the digest first means the filesystem event the write induces
// fingerprints to the recorded digest and is suppressed as the daemon's own echo
// rather than re-triggering a sync. Defined where it is consumed (the converge pass);
// the watch daemon supplies the implementation.
type Recorder interface {
	// RecordApplied records digest as endpointID's applied state, so the write it
	// triggers is recognized as a no-op.
	RecordApplied(endpointID string, digest Digest)
}
