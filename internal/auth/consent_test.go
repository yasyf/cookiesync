package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/presence"
)

// pinnedNonce wires the broker's routed-consent nonce source to a fixed value,
// so a test can assert the approval binds to exactly that nonce. The nonce now
// lives on the generic Router.
func pinnedNonce(b *Broker, nonce string) {
	b.Router.Nonce = func() (string, error) { return nonce, nil }
}

// routedChrome drives one routedRelease for chrome:Default over runner with a
// pinned nonce, returning the released key and error.
func routedChrome(t *testing.T, st *state.State, consent *fakeConsent, runner SSHRunner, nonce string) (cookie.AesKey, error) {
	t.Helper()
	b := newTestBroker(consent, newFakeCache(), staticProbe(presence.SessionSnapshot{}), runner, st)
	pinnedNonce(b, nonce)
	browser, err := cookie.Lookup("chrome")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	return b.routedRelease(context.Background(), browser, "chrome", "Default")
}

// TestRoutedReleaseApprovedReleasesUnpromptedKey proves the happy path: with no
// local session, the broker routes consent to a live peer through the generic
// Router, and on the bound approval releases its OWN key non-interactively (no
// local Touch ID) — the key never crosses the wire. The nonce/endpoint echo
// binding itself is proven in synckit's route_test.go; here we prove cookiesync
// wires ObtainKeyUnprompted onto a bound approval and leaks nothing.
func TestRoutedReleaseApprovedReleasesUnpromptedKey(t *testing.T) {
	self := "me@laptop"
	peer := "you@desktop"
	endpoint := endpointID(self, "chrome", "Default")
	nonce := "fixed-nonce-abc"

	fakeMesh(t, self, peer)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_consent": approvedReply(t, nonce, endpoint)},
	}
	st := stateWith(self, "", stateEndpoint(peer, "chrome", "Default"))
	b := newTestBroker(consent, newFakeCache(), staticProbe(presence.SessionSnapshot{}), runner, st)
	pinnedNonce(b, nonce)

	browser, err := cookie.Lookup("chrome")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	key, err := b.routedRelease(context.Background(), browser, "chrome", "Default")
	if err != nil {
		t.Fatalf("routedRelease: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("routedRelease returned the wrong key")
	}
	if consent.unpromptedCalled != 1 {
		t.Fatalf("routed approval must release via ObtainKeyUnprompted exactly once, got %d", consent.unpromptedCalled)
	}
	if len(consent.promptedReasons) != 0 {
		t.Fatalf("routed approval must NOT prompt Touch ID locally, got prompts %v", consent.promptedReasons)
	}
	// The key never appears in any ssh payload — only the request_consent handshake
	// crosses the wire.
	for _, c := range runner.calls {
		if strings.Contains(c.cmd, string(consent.key)) {
			t.Fatalf("the Safe Storage key leaked into an ssh command: %q", c.cmd)
		}
	}
}

// TestRoutedReleaseRouteToShortCircuits proves cookiesync's candidate
// composition puts a live consent_route_to first and stops there: only the
// routed target is probed and asked for consent, never the rest of the mesh.
func TestRoutedReleaseRouteToShortCircuits(t *testing.T) {
	self := "me@laptop"
	routed := "router@box"
	other := "other@box"
	nonce := "route-to-nonce"
	endpoint := endpointID(self, "chrome", "Default")

	fakeMesh(t, self, routed, other)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &approverMesh{
		whoami:  map[string]string{routed: liveWhoami, other: liveWhoami},
		consent: map[string]string{routed: approvedReply(t, nonce, endpoint)},
	}
	st := stateWith(self, routed, stateEndpoint(routed, "chrome", "Default"), stateEndpoint(other, "chrome", "Default"))

	key, err := routedChrome(t, st, consent, runner, nonce)
	if err != nil {
		t.Fatalf("routedRelease: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("routedRelease returned the wrong key")
	}
	if probed := runner.probedTargets(); len(probed) != 1 || probed[0] != routed {
		t.Fatalf("whoami probes = %v, want only the routed target %q", probed, routed)
	}
	if asked := runner.consentTargets(); len(asked) != 1 || asked[0] != routed {
		t.Fatalf("request_consent dials = %v, want only the routed target %q", asked, routed)
	}
}

// TestRoutedReleaseRouteToOfflineFallsBackToScan proves an offline routed target
// does not short-circuit: cookiesync's candidate list scans the mesh and the
// first live peer approves.
func TestRoutedReleaseRouteToOfflineFallsBackToScan(t *testing.T) {
	self := "me@laptop"
	routed := "router@box"
	live := "live@box"
	nonce := "scan-nonce"
	endpoint := endpointID(self, "chrome", "Default")

	fakeMesh(t, self, routed, live)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &approverMesh{
		whoami:  map[string]string{live: liveWhoami},
		consent: map[string]string{live: approvedReply(t, nonce, endpoint)},
	}
	st := stateWith(self, routed, stateEndpoint(routed, "chrome", "Default"), stateEndpoint(live, "chrome", "Default"))

	key, err := routedChrome(t, st, consent, runner, nonce)
	if err != nil {
		t.Fatalf("routedRelease: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("routedRelease returned the wrong key")
	}
	if asked := runner.consentTargets(); len(asked) != 1 || asked[0] != live {
		t.Fatalf("request_consent dials = %v, want only the live scanned peer %q", asked, live)
	}
}
