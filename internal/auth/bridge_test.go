package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/synckit/presence"
)

// bridgeTestKey is the key ObtainKeyBiometric hands back; cookieTestKey is the
// distinct key the passcode-capable ObtainKeys path yields, so a test can tell a
// bridge release from a cookie release by value.
var (
	bridgeTestKey = cookie.DeriveKey(cookie.SafeStorageKey("bridge-secret"))
	cookieTestKey = cookie.DeriveKey(cookie.SafeStorageKey("cookie-secret"))
)

// bridgeRun carries one ReleaseBridge invocation and its collaborators to a
// case's assertions.
type bridgeRun struct {
	t       *testing.T
	ctx     context.Context
	b       *Broker
	consent *fakeConsent
	cache   *fakeCache
	req     Req
	key     cookie.AesKey
	surface Surface
	ttl     time.Duration
	err     error
}

// TestReleaseBridge exercises the strict-biometric CDP-bridge release: it gates
// on ObtainKeyBiometric alone (never the passcode-capable ObtainKey/ObtainKeys),
// never reads or writes the cookie grant store or key cache, fails closed when
// biometrics are unavailable, and refuses to release on a cold (routed) host.
func TestReleaseBridge(t *testing.T) {
	tests := []struct {
		name     string
		attended bool
		consent  *fakeConsent
		check    func(r bridgeRun)
	}{
		{
			name:     "local attended success",
			attended: true,
			consent:  &fakeConsent{key: cookieTestKey, biometricKey: bridgeTestKey},
			check: func(r bridgeRun) {
				if r.err != nil {
					r.t.Fatalf("ReleaseBridge on an attended host: %v", r.err)
				}
				if string(r.key) != string(bridgeTestKey) {
					r.t.Fatalf("key = %q, want the biometric bridge key", r.key)
				}
				if r.surface != SurfaceLocal {
					r.t.Fatalf("surface = %v, want SurfaceLocal", r.surface)
				}
				want := effectiveTTL(bridgeAuthTTL, false)
				if r.ttl != want {
					r.t.Fatalf("ttl = %v, want %v (effectiveTTL over a non-degraded cache)", r.ttl, want)
				}
				if r.ttl <= 0 {
					r.t.Fatalf("ttl = %v, want a positive lease", r.ttl)
				}
				// The bridge must not create a cookie grant, cache the key, or
				// take the passcode-capable path.
				if r.b.Granted(r.req.Requestor, cookie.BrowserName(r.req.Browser)) {
					r.t.Fatalf("ReleaseBridge created a cookie grant; it must never touch b.grants")
				}
				if got := len(r.cache.putOrder()); got != 0 {
					r.t.Fatalf("ReleaseBridge did %d cache Puts; it must never cache the bridge key", got)
				}
				if got := r.consent.biometricCount(); got != 1 {
					r.t.Fatalf("ObtainKeyBiometric calls = %d, want 1", got)
				}
				if got := r.consent.promptCount(); got != 0 {
					r.t.Fatalf("passcode-capable ObtainKey/ObtainKeys calls = %d, want 0", got)
				}
				// The cookie-grant warm path is unaffected: a normal Key still
				// runs a fresh consent flight and yields the distinct cookie key,
				// proving ReleaseBridge left no warm grant behind.
				ck, surface, err := r.b.Key(r.ctx, r.req)
				if err != nil {
					r.t.Fatalf("cookie Key after ReleaseBridge: %v", err)
				}
				if string(ck) != string(cookieTestKey) {
					r.t.Fatalf("cookie Key = %q, want the cookie key from a fresh flight", ck)
				}
				if surface != SurfaceLocal {
					r.t.Fatalf("cookie Key surface = %v, want SurfaceLocal", surface)
				}
				if got := len(r.consent.batchCalls); got != 1 {
					r.t.Fatalf("cookie Key consent flights = %d, want exactly 1 (bridge left no warm grant)", got)
				}
			},
		},
		{
			name:     "fail-closed on unavailable biometrics",
			attended: true,
			consent: &fakeConsent{biometricErr: &cookie.ConsentError{
				Msg: "biometric authentication unavailable",
				Err: cookie.ErrKeybagLocked,
			}},
			check: func(r bridgeRun) {
				if r.err == nil {
					r.t.Fatalf("ReleaseBridge must fail closed when biometrics are unavailable")
				}
				if !errors.Is(r.err, cookie.ErrKeybagLocked) {
					r.t.Fatalf("err = %v, want it to wrap ErrKeybagLocked", r.err)
				}
				if r.key != nil {
					r.t.Fatalf("key = %q, want nil on a fail-closed release", r.key)
				}
				if r.surface != SurfaceNone {
					r.t.Fatalf("surface = %v, want SurfaceNone", r.surface)
				}
				if r.ttl != 0 {
					r.t.Fatalf("ttl = %v, want 0 on failure", r.ttl)
				}
				if got := r.consent.biometricCount(); got != 1 {
					r.t.Fatalf("ObtainKeyBiometric calls = %d, want 1", got)
				}
				if got := r.consent.promptCount(); got != 0 {
					r.t.Fatalf("passcode-capable calls = %d, want 0 (no fallback after a strict-biometric failure)", got)
				}
			},
		},
		{
			name:     "routed host fails with AuthRequired",
			attended: false,
			consent:  &fakeConsent{key: cookieTestKey, biometricKey: bridgeTestKey},
			check: func(r bridgeRun) {
				var authErr *AuthRequired
				if !errors.As(r.err, &authErr) {
					r.t.Fatalf("err = %v, want *AuthRequired on a cold (routed) host", r.err)
				}
				if r.key != nil {
					r.t.Fatalf("key = %q, want nil when routing is unavailable", r.key)
				}
				if r.surface != SurfaceNone {
					r.t.Fatalf("surface = %v, want SurfaceNone", r.surface)
				}
				if r.ttl != 0 {
					r.t.Fatalf("ttl = %v, want 0", r.ttl)
				}
				if got := r.consent.biometricCount(); got != 0 {
					r.t.Fatalf("ObtainKeyBiometric calls = %d, want 0 (a routed host must not prompt locally)", got)
				}
				if got := r.consent.promptCount(); got != 0 {
					r.t.Fatalf("passcode-capable calls = %d, want 0", got)
				}
				if got := len(r.cache.putOrder()); got != 0 {
					r.t.Fatalf("cache Puts = %d, want 0", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			self := "me@laptop"
			fakeMesh(t, self)
			st := stateWith(self, "", stateEndpoint(self, "chrome", "Default"))
			fc := newFakeCache()
			probe := staticProbe(liveSession(currentUser(t)))
			if !tt.attended {
				probe = staticProbe(presence.SessionSnapshot{OnConsole: true, Locked: true, ConsoleUser: currentUser(t)})
			}
			b := newTestBroker(tt.consent, fc, probe, &recordingRunner{}, st)
			req := Req{Requestor: "req:claude", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal}
			ctx := context.Background()
			key, surface, ttl, err := b.ReleaseBridge(ctx, st, req)
			tt.check(bridgeRun{
				t: t, ctx: ctx, b: b, consent: tt.consent, cache: fc, req: req,
				key: key, surface: surface, ttl: ttl, err: err,
			})
		})
	}
}
