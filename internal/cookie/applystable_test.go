package cookie

import (
	"context"
	"testing"
)

// TestLogicalDigestApplyStable proves the anti-echo invariant synckitd relies on: a
// self-induced apply preserves the logical digest. Because Apply preserves
// last_update_utc (the digest keys on host_key, name, path, last_update_utc), reading
// back what Apply wrote reproduces the digest the sync layer recorded —
// LogicalDigest(read(apply(read(S)))) == LogicalDigest(S). That is what lets synckitd
// dedup cookiesync's own write via `cookiesync list --json` without a cross-process
// seed. Run against a real ephemeral SQLite store for each Chrome schema.
func TestLogicalDigestApplyStable(t *testing.T) {
	forEachSchema(t, func(t *testing.T, browser Browser, profile string) {
		ctx := context.Background()
		key := testKey(t)

		// Seed the store S with a few cookies through the real apply path.
		seed := []Cookie{
			sampleCookie(".x.com", "sid", "abc"),
			sampleCookie(".y.com", "tok", "xyz"),
			sampleCookie(".x.com", "pref", "dark"),
		}
		if _, err := Apply(ctx, seed, browser, profile, key); err != nil {
			t.Fatalf("seed apply: %v", err)
		}

		// The reference digest of S, taken over the raw rows (never decrypting).
		rowsS, err := Read(ctx, browser, profile)
		if err != nil {
			t.Fatalf("read S: %v", err)
		}
		want := LogicalDigest(rowsS)
		if len(rowsS) != len(seed) {
			t.Fatalf("seeded %d cookies, store holds %d rows", len(seed), len(rowsS))
		}

		// Re-apply exactly what S holds (decrypt(S) -> apply), the shape a converge that
		// merges in no new cookies writes back.
		reapply := make([]Cookie, 0, len(rowsS))
		for _, row := range rowsS {
			c, ok := DecryptRow(row, key)
			if !ok {
				t.Fatalf("decrypt row %s/%s failed", row.HostKey, row.Name)
			}
			reapply = append(reapply, c)
		}
		if _, err := Apply(ctx, reapply, browser, profile, key); err != nil {
			t.Fatalf("re-apply: %v", err)
		}

		// The digest after the self-induced write is identical — the write is a no-op to
		// the anti-echo ledger.
		rowsAfter, err := Read(ctx, browser, profile)
		if err != nil {
			t.Fatalf("read after re-apply: %v", err)
		}
		got := LogicalDigest(rowsAfter)
		if got != want {
			t.Fatalf("apply-stability broken: digest changed across a self-induced write\n before: %s\n  after: %s", want, got)
		}
	})
}
