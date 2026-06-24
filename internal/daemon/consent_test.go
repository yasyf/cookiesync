package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// approvedReply is a peer's request_consent JSON echoing nonce and endpoint.
func approvedReply(t *testing.T, nonce, endpoint string) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{"status": "approved", "nonce": nonce, "endpoint": endpoint})
	if err != nil {
		t.Fatalf("marshal approved reply: %v", err)
	}
	return string(data)
}

// liveWhoami is a peer whoami reply for an on-console, unlocked session.
const liveWhoami = `{"on_console":true,"locked":false,"console_user":"peer"}`

// deadWhoami is a peer whoami reply for a locked session.
const deadWhoami = `{"on_console":true,"locked":true,"console_user":"peer"}`

// pinnedNonce wires a daemon's nonce source to a fixed value, so a test can assert the
// approval binds to exactly that nonce.
func pinnedNonce(d *Daemon, nonce string) {
	d.newNonce = func() (string, error) { return nonce, nil }
}

// TestRoutedReleaseApprovedReleasesUnpromptedKey proves the happy path: with no local
// session, the daemon routes consent to a live peer, the peer's reply echoes the exact
// nonce and endpoint, and the daemon then releases its OWN key non-interactively (no
// local Touch ID) — the key never crosses the wire.
func TestRoutedReleaseApprovedReleasesUnpromptedKey(t *testing.T) {
	self := "me@laptop"
	peer := "you@desktop"
	endpoint := endpointID(self, "chrome", "Default")
	nonce := "fixed-nonce-abc"

	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_consent": approvedReply(t, nonce, endpoint)},
	}
	st := stateWith(self, "", stateEndpoint(peer, "chrome", "Default"))
	d := New(consent, newFakeCache(), nil, staticProbe(SessionSnapshot{}), runner, fixedState{st: st})
	pinnedNonce(d, nonce)

	browser, err := cookie.Lookup("chrome")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	key, err := d.routedRelease(context.Background(), browser, "chrome", "Default")
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

// TestRoutedReleaseNonceMismatchIsAuthRequired proves a reply whose nonce does not echo
// the one sent is rejected as a security failure (AuthRequired), not retried, and the
// local key is never released.
func TestRoutedReleaseNonceMismatchIsAuthRequired(t *testing.T) {
	self := "me@laptop"
	peer := "you@desktop"
	endpoint := endpointID(self, "chrome", "Default")

	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_consent": approvedReply(t, "WRONG-nonce", endpoint)},
	}
	st := stateWith(self, "", stateEndpoint(peer, "chrome", "Default"))
	d := New(consent, newFakeCache(), nil, staticProbe(SessionSnapshot{}), runner, fixedState{st: st})
	pinnedNonce(d, "the-real-nonce")

	browser, _ := cookie.Lookup("chrome")
	_, err := d.routedRelease(context.Background(), browser, "chrome", "Default")
	var authErr *AuthRequired
	if !errors.As(err, &authErr) {
		t.Fatalf("nonce mismatch = %v, want *AuthRequired", err)
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("an unbound approval must NOT release the key, got %d releases", consent.unpromptedCalled)
	}
}

// TestRoutedReleaseEndpointMismatchIsAuthRequired proves a reply whose endpoint does
// not echo the one sent is rejected as AuthRequired even when the nonce matches — both
// must bind.
func TestRoutedReleaseEndpointMismatchIsAuthRequired(t *testing.T) {
	self := "me@laptop"
	peer := "you@desktop"
	nonce := "n1"

	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_consent": approvedReply(t, nonce, "someone-else@host:chrome:Default")},
	}
	st := stateWith(self, "", stateEndpoint(peer, "chrome", "Default"))
	d := New(consent, newFakeCache(), nil, staticProbe(SessionSnapshot{}), runner, fixedState{st: st})
	pinnedNonce(d, nonce)

	browser, _ := cookie.Lookup("chrome")
	_, err := d.routedRelease(context.Background(), browser, "chrome", "Default")
	var authErr *AuthRequired
	if !errors.As(err, &authErr) {
		t.Fatalf("endpoint mismatch = %v, want *AuthRequired", err)
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("an unbound approval must NOT release the key")
	}
}

// TestActivePeerRouteToShortCircuits proves a live consent_route_to is returned without
// scanning the rest of the mesh: only the routed target is probed for liveness.
func TestActivePeerRouteToShortCircuits(t *testing.T) {
	self := "me@laptop"
	routed := "router@box"
	other := "other@box"

	runner := &recordingRunner{replies: map[string]string{"cookiesync rpc whoami": liveWhoami}}
	st := stateWith(self, routed, stateEndpoint(routed, "chrome", "Default"), stateEndpoint(other, "chrome", "Default"))
	d := New(&fakeConsent{}, newFakeCache(), nil, staticProbe(SessionSnapshot{}), runner, fixedState{st: st})

	peer, err := d.activePeer(context.Background(), st)
	if err != nil {
		t.Fatalf("activePeer: %v", err)
	}
	if peer != routed {
		t.Fatalf("activePeer = %q, want the routed target %q", peer, routed)
	}
	// Only the routed target was probed — the scan short-circuited.
	if len(runner.calls) != 1 {
		t.Fatalf("expected exactly one whoami probe (the routed target), got %d: %+v", len(runner.calls), runner.calls)
	}
	if runner.calls[0].target != routed {
		t.Fatalf("probed %q, want the routed target %q", runner.calls[0].target, routed)
	}
}

// TestActivePeerRouteToOfflineFallsBackToScan proves an offline routed target does not
// short-circuit: the mesh is scanned and the first live peer wins.
func TestActivePeerRouteToOfflineFallsBackToScan(t *testing.T) {
	self := "me@laptop"
	routed := "router@box"
	live := "live@box"

	runner := &recordingRunner{replies: map[string]string{}}
	// The routed target is locked; the other peer is live.
	runner.byMethod = map[string]string{}
	runner.replies = map[string]string{}
	runner.perTarget = map[string]string{routed: deadWhoami, live: liveWhoami}
	st := stateWith(self, routed, stateEndpoint(routed, "chrome", "Default"), stateEndpoint(live, "chrome", "Default"))
	d := New(&fakeConsent{}, newFakeCache(), nil, staticProbe(SessionSnapshot{}), runner, fixedState{st: st})

	peer, err := d.activePeer(context.Background(), st)
	if err != nil {
		t.Fatalf("activePeer: %v", err)
	}
	if peer != live {
		t.Fatalf("activePeer = %q, want the live scanned peer %q", peer, live)
	}
}

// TestActivePeerNoLiveSessionIsAuthRequired proves a mesh with no live peer fails
// closed with AuthRequired.
func TestActivePeerNoLiveSessionIsAuthRequired(t *testing.T) {
	self := "me@laptop"
	peer := "you@desktop"

	runner := &recordingRunner{replies: map[string]string{"cookiesync rpc whoami": deadWhoami}}
	st := stateWith(self, "", stateEndpoint(peer, "chrome", "Default"))
	d := New(&fakeConsent{}, newFakeCache(), nil, staticProbe(SessionSnapshot{}), runner, fixedState{st: st})

	_, err := d.activePeer(context.Background(), st)
	var authErr *AuthRequired
	if !errors.As(err, &authErr) {
		t.Fatalf("no live peer = %v, want *AuthRequired", err)
	}
}

// TestHandleRequestConsentUnavailableWithoutSession proves request_consent returns
// {"status":"unavailable"} when this host has no live session to prompt, and never
// touches the consent gate.
func TestHandleRequestConsentUnavailableWithoutSession(t *testing.T) {
	consent := &fakeConsent{}
	d := New(consent, newFakeCache(), nil, staticProbe(SessionSnapshot{OnConsole: false}), &recordingRunner{}, fixedState{})

	got, err := d.handleRequestConsent(context.Background(), map[string]any{
		"browser": "chrome", "nonce": "n", "endpoint": "e",
	})
	if err != nil {
		t.Fatalf("handleRequestConsent: %v", err)
	}
	if marshalResult(t, got) != `{"status":"unavailable"}` {
		t.Fatalf("unavailable = %s", marshalResult(t, got))
	}
	if len(consent.promptedReasons) != 0 {
		t.Fatalf("unavailable must not prompt, got %v", consent.promptedReasons)
	}
}

// TestHandleRequestConsentDeniedOnDecline proves a declined Touch ID prompt yields
// {"status":"denied"} with no nonce or endpoint echo.
func TestHandleRequestConsentDeniedOnDecline(t *testing.T) {
	me := currentUser(t)
	consent := &fakeConsent{obtainErr: &cookie.ConsentError{Msg: "Touch ID authentication was cancelled or denied"}}
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(me)), &recordingRunner{}, fixedState{})

	got, err := d.handleRequestConsent(context.Background(), map[string]any{
		"browser": "chrome", "nonce": "n", "endpoint": "e",
	})
	if err != nil {
		t.Fatalf("handleRequestConsent: %v", err)
	}
	if marshalResult(t, got) != `{"status":"denied"}` {
		t.Fatalf("denied = %s", marshalResult(t, got))
	}
}

// TestHandleRequestConsentApprovedEchoesExactly proves an approved prompt echoes the
// requester's nonce and endpoint VERBATIM, binding the approval to that one request.
func TestHandleRequestConsentApprovedEchoesExactly(t *testing.T) {
	me := currentUser(t)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(me)), &recordingRunner{}, fixedState{})

	nonce := "nonce-xyz-123"
	endpoint := "them@host:chrome:Work"
	got, err := d.handleRequestConsent(context.Background(), map[string]any{
		"browser": "chrome", "nonce": nonce, "endpoint": endpoint,
	})
	if err != nil {
		t.Fatalf("handleRequestConsent: %v", err)
	}
	want := `{"endpoint":"them@host:chrome:Work","nonce":"nonce-xyz-123","status":"approved"}`
	if marshalResult(t, got) != want {
		t.Fatalf("approved = %s, want %s", marshalResult(t, got), want)
	}
	// The prompt names the exact requesting endpoint.
	if len(consent.promptedReasons) != 1 || consent.promptedReasons[0] != "sync them to "+endpoint {
		t.Fatalf("prompt reason = %v, want [sync them to %s]", consent.promptedReasons, endpoint)
	}
}

// TestNonceFreshnessPerRelease proves a fresh nonce is minted on every routed release
// (no reuse), so a captured approval cannot be replayed against a later request.
func TestNonceFreshnessPerRelease(t *testing.T) {
	seen := map[string]int{}
	for range 200 {
		n, err := newNonce()
		if err != nil {
			t.Fatalf("newNonce: %v", err)
		}
		// secrets.token_urlsafe(32)/RawURLEncoding of 24 bytes is 32 chars.
		if len(n) != 32 {
			t.Fatalf("nonce %q has length %d, want 32 (url-safe base64 of 24 bytes)", n, len(n))
		}
		seen[n]++
	}
	if len(seen) != 200 {
		t.Fatalf("expected 200 distinct nonces, got %d (reuse detected)", len(seen))
	}
}
