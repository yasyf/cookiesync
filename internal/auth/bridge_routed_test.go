package auth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
	consentkit "github.com/yasyf/synckit/consent"
	"github.com/yasyf/synckit/presence"
)

// routedBridgeChrome drives one routedBridgeRelease for chrome:Default over
// runner with a pinned nonce, returning the released key and error.
func routedBridgeChrome(t *testing.T, st *state.State, consent *fakeConsent, runner SSHRunner, nonce string) (cookie.AesKey, error) {
	t.Helper()
	b := newTestBroker(consent, newFakeCache(), staticProbe(presence.SessionSnapshot{}), runner, st)
	pinnedNonce(b, nonce)
	browser, err := cookie.Lookup("chrome")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	return b.routedBridgeRelease(context.Background(), browser, "chrome", "Default")
}

// TestRoutedBridgeReleaseApprovedShellsBridgeConsent proves the bridge routed
// release shells request_bridge_consent (never request_consent), binds the
// approval to the exact nonce + endpoint, releases this host's own key
// non-interactively, and never leaks the key onto the wire.
func TestRoutedBridgeReleaseApprovedShellsBridgeConsent(t *testing.T) {
	self := "me@laptop"
	peer := "you@desktop"
	endpoint := endpointID(self, "chrome", "Default")
	nonce := "bridge-nonce-abc"

	fakeMesh(t, self, peer)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_bridge_consent": approvedReply(t, nonce, endpoint)},
	}
	st := stateWith(self, "", stateEndpoint(peer, "chrome", "Default"))

	key, err := routedBridgeChrome(t, st, consent, runner, nonce)
	if err != nil {
		t.Fatalf("routedBridgeRelease: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("routedBridgeRelease returned the wrong key")
	}
	if consent.unpromptedCalled != 1 {
		t.Fatalf("bridge approval must release via ObtainKeyUnprompted exactly once, got %d", consent.unpromptedCalled)
	}
	if consent.biometricCount() != 0 || consent.promptCount() != 0 {
		t.Fatalf("a routing origin must NOT tap Touch ID locally (biometric=%d, prompt=%d)", consent.biometricCount(), consent.promptCount())
	}
	sawBridge := false
	for _, c := range runner.calls {
		if strings.Contains(c.cmd, "request_bridge_consent") {
			sawBridge = true
		}
		if strings.Contains(c.cmd, "request_consent") {
			t.Fatalf("bridge release shelled the cookie request_consent verb: %q", c.cmd)
		}
		if strings.Contains(c.cmd, string(consent.key)) {
			t.Fatalf("the Safe Storage key leaked into an ssh command: %q", c.cmd)
		}
	}
	if !sawBridge {
		t.Fatalf("no request_bridge_consent dial was made: %+v", runner.calls)
	}
}

// TestRoutedBridgeReleaseNonceMismatchIsBindingMismatch proves an approval that
// does not echo the exact nonce is a fatal *consentkit.BindingMismatch — an
// attack/corruption signal that stops the request, never a retryable
// AuthRequired — and the local key is never released.
func TestRoutedBridgeReleaseNonceMismatchIsBindingMismatch(t *testing.T) {
	self := "me@laptop"
	peer := "you@desktop"
	endpoint := endpointID(self, "chrome", "Default")

	fakeMesh(t, self, peer)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_bridge_consent": approvedReply(t, "WRONG-nonce", endpoint)},
	}
	st := stateWith(self, "", stateEndpoint(peer, "chrome", "Default"))

	_, err := routedBridgeChrome(t, st, consent, runner, "the-real-nonce")
	var mismatch *consentkit.BindingMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("nonce mismatch = %v, want *consentkit.BindingMismatch", err)
	}
	if got := Classify(err); got != consentkit.VerdictFatal {
		t.Fatalf("Classify(binding mismatch) = %v, want VerdictFatal (never retryable)", got)
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("an unbound approval must NOT release the key, got %d", consent.unpromptedCalled)
	}
}

// TestRoutedBridgeReleaseUnavailableRoutesOn proves a peer that answers
// unavailable is routed around: the next live candidate is asked and approves.
func TestRoutedBridgeReleaseUnavailableRoutesOn(t *testing.T) {
	self := "me@laptop"
	down := "down@box"
	live := "live@box"
	nonce := "route-on-nonce"
	endpoint := endpointID(self, "chrome", "Default")

	fakeMesh(t, self, down, live)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &approverMesh{
		whoami:  map[string]string{down: liveWhoami, live: liveWhoami},
		consent: map[string]string{down: `{"status":"unavailable"}`, live: approvedReply(t, nonce, endpoint)},
	}
	st := stateWith(self, "", stateEndpoint(down, "chrome", "Default"), stateEndpoint(live, "chrome", "Default"))

	key, err := routedBridgeChrome(t, st, consent, runner, nonce)
	if err != nil {
		t.Fatalf("routedBridgeRelease: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("routedBridgeRelease returned the wrong key")
	}
	if asked := runner.consentTargetsFor("request_bridge_consent"); len(asked) != 2 || asked[0] != down || asked[1] != live {
		t.Fatalf("consent dials = %v, want [%s %s] (route on past unavailable)", asked, down, live)
	}
}

// TestRoutedBridgeReleaseDenialIsTerminal proves a human decline ends the loop:
// no further peer is asked and the release surfaces the Router's terminal
// *consentkit.Denied (denied is terminal; ClassifyBridgeApproval maps it to
// VerdictDenied).
func TestRoutedBridgeReleaseDenialIsTerminal(t *testing.T) {
	self := "me@laptop"
	first := "first@box"
	second := "second@box"
	nonce := "deny-nonce"

	fakeMesh(t, self, first, second)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &approverMesh{
		whoami:  map[string]string{first: liveWhoami, second: liveWhoami},
		consent: map[string]string{first: `{"status":"denied"}`, second: approvedReply(t, nonce, endpointID(self, "chrome", "Default"))},
	}
	st := stateWith(self, "", stateEndpoint(first, "chrome", "Default"), stateEndpoint(second, "chrome", "Default"))

	_, err := routedBridgeChrome(t, st, consent, runner, nonce)
	var denied *consentkit.Denied
	if !errors.As(err, &denied) {
		t.Fatalf("denial = %v, want *consentkit.Denied", err)
	}
	if asked := runner.consentTargetsFor("request_bridge_consent"); len(asked) != 1 || asked[0] != first {
		t.Fatalf("consent dials = %v, want only the denying peer %s (denial is terminal)", asked, first)
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("a denial must not release the key, got %d", consent.unpromptedCalled)
	}
}

// TestReleaseBridgeRoutedGoesThroughHandshake proves ReleaseBridge on a cold
// (routed) host drives the bridge handshake, returns SurfaceRouted and a positive
// TTL, and never taps locally, caches, or grants.
func TestReleaseBridgeRoutedGoesThroughHandshake(t *testing.T) {
	self := "me@laptop"
	peer := "you@desktop"
	endpoint := endpointID(self, "chrome", "Default")
	nonce := "release-routed-nonce"

	fakeMesh(t, self, peer)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts")), biometricKey: bridgeTestKey}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_bridge_consent": approvedReply(t, nonce, endpoint)},
	}
	fc := newFakeCache()
	// A locked local session forces routing.
	probe := staticProbe(presence.SessionSnapshot{OnConsole: true, Locked: true, ConsoleUser: currentUser(t)})
	st := stateWith(self, "", stateEndpoint(peer, "chrome", "Default"))
	b := newTestBroker(consent, fc, probe, runner, st)
	pinnedNonce(b, nonce)

	req := Req{Requestor: "req:claude", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal}
	key, surface, ttl, err := b.ReleaseBridge(context.Background(), st, req)
	if err != nil {
		t.Fatalf("ReleaseBridge routed: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("routed ReleaseBridge returned the wrong key (unprompted own-key)")
	}
	if surface != SurfaceRouted {
		t.Fatalf("surface = %v, want SurfaceRouted", surface)
	}
	if ttl <= 0 {
		t.Fatalf("ttl = %v, want a positive lease", ttl)
	}
	if consent.biometricCount() != 0 {
		t.Fatalf("a routed release must not tap a local biometric, got %d", consent.biometricCount())
	}
	if got := len(fc.putOrder()); got != 0 {
		t.Fatalf("a bridge release must never cache the key, got %d puts", got)
	}
	if b.Granted(req.Requestor, cookie.BrowserName(req.Browser)) {
		t.Fatalf("a bridge release must never create a grant")
	}
}
