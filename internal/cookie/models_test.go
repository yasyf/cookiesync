package cookie

import "testing"

// TestChromeMicrosToUnixPrecision pins the conversion for large (>2^53 µs) Chrome
// timestamps — every real cookie expiry. The naive float64(micros)/1e6 double-rounds
// (int64->float64 loses precision above 2^53) and diverges from Python's exact-int
// division: it flips 1715527399 -> 1715527400 and drops sub-second remainders.
func TestChromeMicrosToUnixPrecision(t *testing.T) {
	cases := []struct {
		micros   ChromeMicros
		wantSecs int64 // int64 truncation — exact, matches the Python oracle
	}{
		{13360000999999999, 1715527399},
		{13409999123456789, 1765525523},
		{13400000000000001, 1755526400},
	}
	for _, tc := range cases {
		got, session := chromeMicrosToUnix(tc.micros)
		if session {
			t.Fatalf("chromeMicrosToUnix(%d) reported session", tc.micros)
		}
		if int64(got) != tc.wantSecs {
			t.Errorf("chromeMicrosToUnix(%d) = %.6f, want truncated %d", tc.micros, got, tc.wantSecs)
		}
	}
	// The naive double-rounding path collapses this to exactly 1755526400.0, losing
	// the +0.000002 remainder; the exact-rational path preserves it.
	if got, _ := chromeMicrosToUnix(13400000000000001); got == 1755526400.0 {
		t.Error("chromeMicrosToUnix lost the sub-second remainder (double-rounding regressed)")
	}
}
