package bridge

import "testing"

// TestSeedableOrigin proves only http(s) origins are replayed: privileged schemes
// (chrome-extension://, chrome://, devtools://) deny a localStorage write and must
// be skipped, not fail the whole seed.
func TestSeedableOrigin(t *testing.T) {
	tests := []struct {
		origin string
		want   bool
	}{
		{"https://mail.google.com", true},
		{"http://localhost:3000", true},
		{"chrome-extension://aeblfdkhhhdcdjpifhhbdiojplfjncoa", false},
		{"chrome://newtab", false},
		{"devtools://devtools", false},
		{"about:blank", false},
		{"file:///Users/x", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := seedableOrigin(tc.origin); got != tc.want {
			t.Errorf("seedableOrigin(%q) = %v, want %v", tc.origin, got, tc.want)
		}
	}
}
