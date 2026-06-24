package cookie

import "testing"

// digestCookie builds a cookie whose only digest-significant fields (host_key, name,
// path, last_update_utc) are set; the rest are noise the digest must ignore.
func digestCookie(hostKey, name, path string, lastUpdate ChromeMicros) Cookie {
	return Cookie{
		HostKey:       HostKey(hostKey),
		Name:          name,
		Path:          path,
		LastUpdateUTC: lastUpdate,
		// noise the digest must not key on:
		Value:      "ignored",
		ExpiresUTC: 123,
		IsSecure:   true,
		SameSite:   2,
	}
}

// TestLogicalDigestMatchesPythonBytes pins LogicalDigest to the exact hex digests the
// recovered Python engine.logical_digest emits for the same logical cookie sets, so
// the anti-echo fingerprint is byte-identical across the two implementations.
func TestLogicalDigestMatchesPythonBytes(t *testing.T) {
	cases := []struct {
		name    string
		cookies []Cookie
		want    Digest
	}{
		{
			"empty",
			nil,
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			"single",
			[]Cookie{digestCookie(".x.com", "sid", "/", 13_350_000_000_000_000)},
			"870ba14d0ed97422ff00f1c9271eea0f891a47ff71a4447594b8b41f1c44a9bb",
		},
		{
			"multi-sorted",
			[]Cookie{
				digestCookie(".x.com", "sid", "/", 13_350_000_000_000_000),
				digestCookie("a.com", "k", "/p", 10),
				digestCookie(".x.com", "aaa", "/", 1),
			},
			"c0cabea782a58bbd8729df83198f94032c72335c3791851b7aef1f5c90c78515",
		},
		{
			"two-endpoints",
			[]Cookie{
				digestCookie(".x.com", "sid", "/", 13_350_000_000_000_000),
				digestCookie(".y.com", "tok", "/app", 13_350_000_000_000_000),
			},
			"a5dd2ddf883ed4d8083350b191e7d7fd4e40b7299a65e401f17a6509c930cb8d",
		},
		{
			"unicode-name",
			[]Cookie{digestCookie(".x.com", "sé😀d", "/", 5)},
			"c83e7e59f38fa8f28c62b16a98abd23851c669bda7cf434d8fe38dac8a4e9d20",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LogicalDigest(tc.cookies); got != tc.want {
				t.Fatalf("LogicalDigest = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestLogicalDigestOrderIndependent proves the digest depends only on the set, not on
// input order: a shuffled set yields the identical digest.
func TestLogicalDigestOrderIndependent(t *testing.T) {
	a := []Cookie{
		digestCookie(".x.com", "sid", "/", 13_350_000_000_000_000),
		digestCookie(".y.com", "tok", "/app", 13_350_000_000_000_000),
	}
	b := []Cookie{a[1], a[0]}
	if LogicalDigest(a) != LogicalDigest(b) {
		t.Fatalf("digest changed with input order: %s vs %s", LogicalDigest(a), LogicalDigest(b))
	}
}

// TestLogicalDigestSortsByTimestamp proves two rows that differ only by
// last_update_utc are ordered by that timestamp, matching the Python sort key.
func TestLogicalDigestSortsByTimestamp(t *testing.T) {
	cookies := []Cookie{
		digestCookie(".x.com", "sid", "/", 2),
		digestCookie(".x.com", "sid", "/", 1),
	}
	const want Digest = "013fcec65c8ac1d96ecb3c8bd540ee75c35bc5dbe28662c0c94fcaf277b85702"
	if got := LogicalDigest(cookies); got != want {
		t.Fatalf("LogicalDigest = %s, want %s", got, want)
	}
}

// TestLogicalDigestOverEncryptedRows proves a raw EncryptedRow yields the same digest
// as the Cookie it decrypts to, since both key on the same logical fields — which is
// what lets the watch loop fingerprint a store without decrypting.
func TestLogicalDigestOverEncryptedRows(t *testing.T) {
	rows := []EncryptedRow{
		{HostKey: ".x.com", Name: "sid", Path: "/", LastUpdateUTC: 13_350_000_000_000_000},
	}
	cookies := []Cookie{digestCookie(".x.com", "sid", "/", 13_350_000_000_000_000)}
	if LogicalDigest(rows) != LogicalDigest(cookies) {
		t.Fatalf("row digest %s != cookie digest %s", LogicalDigest(rows), LogicalDigest(cookies))
	}
}
