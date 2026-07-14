package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/synckit/presence"
)

// TestEffectiveTTLDerivation proves the single TTL derivation point: the
// configured AuthTTL rules while the release published Enclave-wrapped, and a
// reported degraded publish caps it at 5m without ever raising a shorter
// configured value.
func TestEffectiveTTLDerivation(t *testing.T) {
	tests := []struct {
		name              string
		publishedDegraded bool
		configured        time.Duration
		want              time.Duration
	}{
		{"healthy publish uses the configured hour", false, time.Hour, time.Hour},
		{"degraded publish caps to 5m", true, time.Hour, degradedAuthTTL},
		{"degraded publish keeps a shorter configured value", true, 3 * time.Minute, 3 * time.Minute},
		{"healthy publish keeps a custom value", false, 7 * time.Minute, 7 * time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveTTL(tc.configured, tc.publishedDegraded); got != tc.want {
				t.Fatalf("effectiveTTL(%v, %v) = %v, want %v", tc.configured, tc.publishedDegraded, got, tc.want)
			}
		})
	}
}

// TestReleaseUsesEffectiveTTLForCacheAndGrant proves one release derives both
// sides from the Puts' reported publish outcome: the cached entry TTL and the
// grant window are the 1h default when the keys published Enclave-wrapped and
// the 5m cap when they published degraded.
func TestReleaseUsesEffectiveTTLForCacheAndGrant(t *testing.T) {
	tests := []struct {
		name     string
		degraded bool
		want     time.Duration
	}{
		{"healthy uses the 1h default", false, time.Hour},
		{"degraded caps both at 5m", true, degradedAuthTTL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			self := "me@laptop"
			fakeMesh(t, self)
			st := stateWith(self, "")
			consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
			cache := newFakeCache()
			cache.degraded = tc.degraded
			b := newTestBroker(consent, cache, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, st)

			before := time.Now()
			if _, _, err := b.Key(ctx, Req{Requestor: "local", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal}); err != nil {
				t.Fatalf("Key: %v", err)
			}
			if got := cache.putTTL(endpointID(self, "chrome", "Default")); got != tc.want {
				t.Fatalf("cache.Put ttl = %v, want %v", got, tc.want)
			}
			b.grantMu.Lock()
			expiry, ok := b.grants["local:chrome"]
			b.grantMu.Unlock()
			if !ok {
				t.Fatalf("the release must grant local:chrome")
			}
			if window := expiry.Sub(before); window <= tc.want-time.Minute || window > tc.want+time.Minute {
				t.Fatalf("grant window = %v, want ~%v", window, tc.want)
			}
		})
	}
}

// TestCapGrantOnlyShortens proves the cap-only grants operation: a longer live
// grant is pulled in to now + ttl, a grant already expiring sooner is left
// untouched, and with no grant on file CapGrant creates nothing — it can never
// mint or extend authority.
func TestCapGrantOnlyShortens(t *testing.T) {
	tests := []struct {
		name       string
		existing   time.Duration
		hasGrant   bool
		cap        time.Duration
		wantGrant  bool
		wantWindow time.Duration
	}{
		{"longer grant capped to the degraded window", time.Hour, true, degradedAuthTTL, true, degradedAuthTTL},
		{"near-expiry grant never extended", time.Minute, true, degradedAuthTTL, true, time.Minute},
		{"no grant creates nothing", 0, false, degradedAuthTTL, false, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := NewBroker(&fakeConsent{}, newFakeCache(), staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{})
			before := time.Now()
			if tc.hasGrant {
				b.Grant("local", []cookie.BrowserName{"chrome"}, tc.existing)
			}
			b.CapGrant("local", "chrome", tc.cap)
			b.grantMu.Lock()
			expiry, ok := b.grants["local:chrome"]
			b.grantMu.Unlock()
			if ok != tc.wantGrant {
				t.Fatalf("grant present = %v, want %v", ok, tc.wantGrant)
			}
			if !tc.wantGrant {
				return
			}
			if window := expiry.Sub(before); window <= tc.wantWindow-time.Second || window > tc.wantWindow+time.Second {
				t.Fatalf("grant window = %v, want ~%v", window, tc.wantWindow)
			}
		})
	}
}

// TestRequestorReasonNamesTheProcess proves the best-effort prompt polish: a "req:"
// requestor names itself from its token with zero subprocess (proven by feeding a live
// pid it must ignore), a captured peer pid resolves the calling process's name, and
// every failure or nameless requestor leaves the reason untouched.
func TestRequestorReasonNamesTheProcess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve executable: %v", err)
	}
	tests := []struct {
		name      string
		requestor string
		pid       int
		hasPID    bool
		want      string
	}{
		{"req token names itself with zero subprocess", "req:claude", os.Getpid(), true, testConsentReason + " for claude"},
		{"req composite token renders verbatim", "req:Claude Code · a3283ae1", os.Getpid(), true, testConsentReason + " for Claude Code · a3283ae1"},
		{"sid requestor with a live pid gains the process name", "sid:1", os.Getpid(), true, testConsentReason + " for " + filepath.Base(exe)},
		{"sid requestor with no pid unchanged", "sid:1", 0, false, testConsentReason},
		{"sid requestor with a dead pid unchanged", "sid:1", 99999999, true, testConsentReason},
		{"local with no pid unchanged", "local", 0, false, testConsentReason},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := requestorReason(context.Background(), tc.requestor, testConsentReason, tc.pid, tc.hasPID); got != tc.want {
				t.Fatalf("requestorReason(%q, pid=%d/%v) = %q, want %q", tc.requestor, tc.pid, tc.hasPID, got, tc.want)
			}
		})
	}
}

// TestKeybagLocked proves keybagLocked scopes to the daemon user's own unlocked
// console: an attended session is available, but a locked screen, a console held by
// another user via fast user switching, and a session-absent box are all
// keybag-locked. Unlike presence.Attended it ignores ScreenShared — a mirrored
// unlocked session still decrypts.
func TestKeybagLocked(t *testing.T) {
	me := currentUser(t)
	attendedShared := liveSession(me)
	attendedShared.ScreenShared = true

	tests := []struct {
		name string
		snap presence.SessionSnapshot
		want bool
	}{
		{"attended", liveSession(me), false},
		{"attended while screen-shared", attendedShared, false},
		{"locked screen", presence.SessionSnapshot{OnConsole: true, Locked: true, ConsoleUser: me}, true},
		{"another user via fast user switching", presence.SessionSnapshot{OnConsole: true, Locked: false, ConsoleUser: me + "-other"}, true},
		{"session absent", presence.SessionSnapshot{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := keybagLocked(tc.snap)
			if err != nil {
				t.Fatalf("keybagLocked: %v", err)
			}
			if got != tc.want {
				t.Fatalf("keybagLocked(%+v) = %v, want %v", tc.snap, got, tc.want)
			}
		})
	}
}
