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

func TestChromeMicrosFromUnixInvertsTheRenderedSeconds(t *testing.T) {
	tests := []struct {
		name       string
		micros     ChromeMicros
		wantMicros ChromeMicros
	}{
		{name: "odd microsecond above 2^53", micros: 15746918400015625, wantMicros: 15746918400015625},
		{name: "whole second", micros: 15746918400000000, wantMicros: 15746918400000000},
		{name: "one microsecond past a second", micros: 13400000000000001, wantMicros: 13400000000000002},
		{name: "one microsecond short of a second", micros: 13400000000999999, wantMicros: 13400000000999998},
		{name: "just below 2^34 seconds since 1601", micros: 17179869183999999, wantMicros: 17179869183999998},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seconds, session := chromeMicrosToUnix(tt.micros)
			if session {
				t.Fatalf("chromeMicrosToUnix(%d) reported session", tt.micros)
			}
			got := chromeMicrosFromUnix(seconds)
			if got != tt.wantMicros {
				t.Fatalf("chromeMicrosFromUnix(%v) = %d, want %d", seconds, got, tt.wantMicros)
			}
			if back, _ := chromeMicrosToUnix(got); back != seconds {
				t.Fatalf("chromeMicrosToUnix(%d) = %v, want the rendered %v", got, back, seconds)
			}
		})
	}
}

func TestChromeMicrosFromUnixRoundsHalfToEven(t *testing.T) {
	tests := []struct {
		name    string
		seconds float64
		want    ChromeMicros
	}{
		{name: "exact odd microsecond", seconds: 4102444800.015625, want: 15746918400015625},
		{name: "whole second", seconds: 4102444800.0, want: 15746918400000000},
		{name: "tie rounds down to even", seconds: 4102444800.0078125, want: 15746918400007812},
		{name: "tie rounds up to even", seconds: 4102444800.0234375, want: 15746918400023438},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := chromeMicrosFromUnix(tt.seconds); got != tt.want {
				t.Fatalf("chromeMicrosFromUnix(%v) = %d, want %d", tt.seconds, got, tt.want)
			}
		})
	}
}
