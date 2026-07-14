package auth

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/hostregistry"
	"github.com/yasyf/synckit/presence"
)

// pinnedNonce wires a broker's nonce source to a fixed value, so a test can
// assert the approval binds to exactly that nonce.
func pinnedNonce(b *Broker, nonce string) {
	b.Nonce = func() (string, error) { return nonce, nil }
}

// TestRoutedReleaseApprovedReleasesUnpromptedKey proves the happy path: with no local
// session, the broker routes consent to a live peer, the peer's reply echoes the exact
// nonce and endpoint, and the broker then releases its OWN key non-interactively (no
// local Touch ID) — the key never crosses the wire.
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

// TestRoutedReleaseNonceMismatchIsAuthRequired proves a reply whose nonce does not echo
// the one sent is rejected as a security failure (AuthRequired), not retried, and the
// local key is never released.
func TestRoutedReleaseNonceMismatchIsAuthRequired(t *testing.T) {
	self := "me@laptop"
	peer := "you@desktop"
	endpoint := endpointID(self, "chrome", "Default")

	fakeMesh(t, self, peer)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_consent": approvedReply(t, "WRONG-nonce", endpoint)},
	}
	st := stateWith(self, "", stateEndpoint(peer, "chrome", "Default"))
	b := newTestBroker(consent, newFakeCache(), staticProbe(presence.SessionSnapshot{}), runner, st)
	pinnedNonce(b, "the-real-nonce")

	browser, _ := cookie.Lookup("chrome")
	_, err := b.routedRelease(context.Background(), browser, "chrome", "Default")
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

	fakeMesh(t, self, peer)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_consent": approvedReply(t, nonce, "someone-else@host:chrome:Default")},
	}
	st := stateWith(self, "", stateEndpoint(peer, "chrome", "Default"))
	b := newTestBroker(consent, newFakeCache(), staticProbe(presence.SessionSnapshot{}), runner, st)
	pinnedNonce(b, nonce)

	browser, _ := cookie.Lookup("chrome")
	_, err := b.routedRelease(context.Background(), browser, "chrome", "Default")
	var authErr *AuthRequired
	if !errors.As(err, &authErr) {
		t.Fatalf("endpoint mismatch = %v, want *AuthRequired", err)
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("an unbound approval must NOT release the key")
	}
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

// TestRoutedReleaseRouteToShortCircuits proves a live consent_route_to is tried
// without scanning the rest of the mesh: only the routed target is probed and
// asked for consent.
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
// does not short-circuit: the mesh is scanned and the first live peer approves.
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

// TestRoutedReleaseNoLiveApproverIsAuthRequired proves a mesh with no live peer
// fails closed with AuthRequired and never asks for consent.
func TestRoutedReleaseNoLiveApproverIsAuthRequired(t *testing.T) {
	self := "me@laptop"
	peer := "you@desktop"

	fakeMesh(t, self, peer)
	consent := &fakeConsent{}
	runner := &approverMesh{whoami: map[string]string{peer: deadWhoami}}
	st := stateWith(self, "", stateEndpoint(peer, "chrome", "Default"))

	_, err := routedChrome(t, st, consent, runner, "n")
	var authErr *AuthRequired
	if !errors.As(err, &authErr) {
		t.Fatalf("no live peer = %v, want *AuthRequired", err)
	}
	if asked := runner.consentTargets(); len(asked) != 0 {
		t.Fatalf("request_consent dials = %v, want none", asked)
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("no approval must release no key")
	}
}

// TestRoutedReleaseFailsOverUnavailableApprover proves the failover the
// unavailable rendering exists for: a live approver that answers unavailable is
// routed around and the next live approver's approval releases the key.
func TestRoutedReleaseFailsOverUnavailableApprover(t *testing.T) {
	self := "me@laptop"
	broken := "broken@box"
	healthy := "healthy@box"
	nonce := "failover-nonce"
	endpoint := endpointID(self, "chrome", "Default")

	fakeMesh(t, self, broken, healthy)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &approverMesh{
		whoami: map[string]string{broken: liveWhoami, healthy: liveWhoami},
		consent: map[string]string{
			broken:  `{"status":"unavailable"}`,
			healthy: approvedReply(t, nonce, endpoint),
		},
	}
	st := stateWith(self, "", stateEndpoint(broken, "chrome", "Default"), stateEndpoint(healthy, "chrome", "Default"))

	key, err := routedChrome(t, st, consent, runner, nonce)
	if err != nil {
		t.Fatalf("routedRelease across an unavailable approver: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("routedRelease returned the wrong key")
	}
	if asked := runner.consentTargets(); len(asked) != 2 || asked[0] != broken || asked[1] != healthy {
		t.Fatalf("request_consent dials = %v, want [%s %s]", asked, broken, healthy)
	}
	if consent.unpromptedCalled != 1 {
		t.Fatalf("unprompted releases = %d, want 1", consent.unpromptedCalled)
	}
}

// TestRoutedReleaseFailsOverUnreachableApprover proves a transport failure on
// the consent leg advances to the next live approver instead of failing the
// release.
func TestRoutedReleaseFailsOverUnreachableApprover(t *testing.T) {
	self := "me@laptop"
	unreachable := "unreachable@box"
	healthy := "healthy@box"
	nonce := "transport-nonce"
	endpoint := endpointID(self, "chrome", "Default")

	fakeMesh(t, self, unreachable, healthy)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &approverMesh{
		// unreachable answers whoami live but has no consent reply scripted, so
		// its request_consent leg fails at the transport.
		whoami:  map[string]string{unreachable: liveWhoami, healthy: liveWhoami},
		consent: map[string]string{healthy: approvedReply(t, nonce, endpoint)},
	}
	st := stateWith(self, "", stateEndpoint(unreachable, "chrome", "Default"), stateEndpoint(healthy, "chrome", "Default"))

	key, err := routedChrome(t, st, consent, runner, nonce)
	if err != nil {
		t.Fatalf("routedRelease across an unreachable approver: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("routedRelease returned the wrong key")
	}
	if asked := runner.consentTargets(); len(asked) != 2 || asked[1] != healthy {
		t.Fatalf("request_consent dials = %v, want the failover to %s", asked, healthy)
	}
}

// TestRoutedReleaseAdvancesPastWedgedProbe proves a peerIsLive probe timeout
// routes around the wedged candidate: the next live approver is probed, asked,
// and its approval releases the key.
func TestRoutedReleaseAdvancesPastWedgedProbe(t *testing.T) {
	restore := probeLiveTimeout
	probeLiveTimeout = 25 * time.Millisecond
	t.Cleanup(func() { probeLiveTimeout = restore })

	self := "me@laptop"
	wedged := "wedged@box"
	healthy := "healthy@box"
	nonce := "wedged-probe-nonce"
	endpoint := endpointID(self, "chrome", "Default")

	fakeMesh(t, self, wedged, healthy)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &approverMesh{
		wedgedWhoami: wedged,
		whoami:       map[string]string{healthy: liveWhoami},
		consent:      map[string]string{healthy: approvedReply(t, nonce, endpoint)},
	}
	st := stateWith(self, wedged, stateEndpoint(wedged, "chrome", "Default"), stateEndpoint(healthy, "chrome", "Default"))

	key, err := routedChrome(t, st, consent, runner, nonce)
	if err != nil {
		t.Fatalf("routedRelease across a wedged probe: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("routedRelease returned the wrong key")
	}
	if probed := runner.probedTargets(); len(probed) != 2 || probed[0] != wedged || probed[1] != healthy {
		t.Fatalf("whoami probes = %v, want [%s %s]", probed, wedged, healthy)
	}
	if asked := runner.consentTargets(); len(asked) != 1 || asked[0] != healthy {
		t.Fatalf("request_consent dials = %v, want only %s (the wedged probe is routed around)", asked, healthy)
	}
}

// TestRoutedReleaseAdvancesPastWedgedConsentLeg proves a consent leg that
// outruns consentTimeout routes around the wedged approver: the next live
// approver's approval releases the key.
func TestRoutedReleaseAdvancesPastWedgedConsentLeg(t *testing.T) {
	restore := consentTimeout
	consentTimeout = 25 * time.Millisecond
	t.Cleanup(func() { consentTimeout = restore })

	self := "me@laptop"
	slow := "slow@box"
	healthy := "healthy@box"
	nonce := "wedged-consent-nonce"
	endpoint := endpointID(self, "chrome", "Default")

	fakeMesh(t, self, slow, healthy)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &approverMesh{
		wedgedConsent: slow,
		whoami:        map[string]string{slow: liveWhoami, healthy: liveWhoami},
		consent:       map[string]string{healthy: approvedReply(t, nonce, endpoint)},
	}
	st := stateWith(self, "", stateEndpoint(slow, "chrome", "Default"), stateEndpoint(healthy, "chrome", "Default"))

	key, err := routedChrome(t, st, consent, runner, nonce)
	if err != nil {
		t.Fatalf("routedRelease across a wedged consent leg: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("routedRelease returned the wrong key")
	}
	if asked := runner.consentTargets(); len(asked) != 2 || asked[0] != slow || asked[1] != healthy {
		t.Fatalf("request_consent dials = %v, want [%s %s]", asked, slow, healthy)
	}
	if consent.unpromptedCalled != 1 {
		t.Fatalf("unprompted releases = %d, want 1", consent.unpromptedCalled)
	}
}

// TestRoutedReleaseNon255SSHErrorIsFatal proves a consent-leg SSHError wrapping
// a real remote exit (not ssh's own exit-255 connection failure) propagates
// fatally: no later approver is asked and no key is released.
func TestRoutedReleaseNon255SSHErrorIsFatal(t *testing.T) {
	self := "me@laptop"
	broken := "broken@box"
	next := "next@box"

	fakeMesh(t, self, broken, next)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	exit1 := exec.Command("/bin/sh", "-c", "exit 1").Run()
	var exitErr *exec.ExitError
	if !errors.As(exit1, &exitErr) {
		t.Fatalf("fabricate exit-1: %v", exit1)
	}
	runner := &approverMesh{
		whoami:     map[string]string{broken: liveWhoami, next: liveWhoami},
		consentErr: map[string]error{broken: &hostregistry.SSHError{Addr: broken, Stderr: "remote command failed", Err: exit1}},
		consent:    map[string]string{next: approvedReply(t, "n", endpointID(self, "chrome", "Default"))},
	}
	st := stateWith(self, "", stateEndpoint(broken, "chrome", "Default"), stateEndpoint(next, "chrome", "Default"))

	_, err := routedChrome(t, st, consent, runner, "n")
	if err == nil || !strings.Contains(err.Error(), "request_consent to") {
		t.Fatalf("non-255 SSHError = %v, want the fatal request_consent failure", err)
	}
	var sshErr *hostregistry.SSHError
	if !errors.As(err, &sshErr) {
		t.Fatalf("non-255 SSHError = %v, want the wrapped *hostregistry.SSHError", err)
	}
	if asked := runner.consentTargets(); len(asked) != 1 || asked[0] != broken {
		t.Fatalf("request_consent dials = %v, want only %s (a real remote exit is fatal, not a skip)", asked, broken)
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("a fatal consent leg must release no key")
	}
}

// TestRoutedReleaseMalformedWhoamiIsFatal proves a whoami reply that does not
// parse propagates as a fatal error — never silently routed around as
// peer-offline — so a protocol bug in a peer's daemon cannot hide behind the
// failover.
func TestRoutedReleaseMalformedWhoamiIsFatal(t *testing.T) {
	self := "me@laptop"
	broken := "broken@box"
	healthy := "healthy@box"

	fakeMesh(t, self, broken, healthy)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &approverMesh{
		whoami:  map[string]string{broken: `{"on_console": tru`, healthy: liveWhoami},
		consent: map[string]string{healthy: approvedReply(t, "n", endpointID(self, "chrome", "Default"))},
	}
	st := stateWith(self, "", stateEndpoint(broken, "chrome", "Default"), stateEndpoint(healthy, "chrome", "Default"))

	_, err := routedChrome(t, st, consent, runner, "n")
	if err == nil || !strings.Contains(err.Error(), "parse whoami") {
		t.Fatalf("malformed whoami = %v, want the parse failure to propagate", err)
	}
	if asked := runner.consentTargets(); len(asked) != 0 {
		t.Fatalf("request_consent dials = %v, want none (a protocol failure is fatal, not a skip)", asked)
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("a fatal probe must release no key")
	}
}

// TestRoutedReleaseMalformedConsentReplyIsFatal proves a consent reply that
// does not parse propagates as a fatal error and never advances to the next
// approver.
func TestRoutedReleaseMalformedConsentReplyIsFatal(t *testing.T) {
	self := "me@laptop"
	broken := "broken@box"
	next := "next@box"

	fakeMesh(t, self, broken, next)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &approverMesh{
		whoami: map[string]string{broken: liveWhoami, next: liveWhoami},
		consent: map[string]string{
			broken: `{not json`,
			next:   approvedReply(t, "n", endpointID(self, "chrome", "Default")),
		},
	}
	st := stateWith(self, "", stateEndpoint(broken, "chrome", "Default"), stateEndpoint(next, "chrome", "Default"))

	_, err := routedChrome(t, st, consent, runner, "n")
	if err == nil || !strings.Contains(err.Error(), "parse request_consent") {
		t.Fatalf("malformed consent reply = %v, want the parse failure to propagate", err)
	}
	if asked := runner.consentTargets(); len(asked) != 1 || asked[0] != broken {
		t.Fatalf("request_consent dials = %v, want only %s (a protocol failure is fatal, not a skip)", asked, broken)
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("a fatal consent leg must release no key")
	}
}

// TestRoutedReleaseDeniedIsTerminal proves a human denial short-circuits the
// failover: no later approver is ever asked and no key is released.
func TestRoutedReleaseDeniedIsTerminal(t *testing.T) {
	self := "me@laptop"
	denier := "denier@box"
	next := "next@box"

	fakeMesh(t, self, denier, next)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &approverMesh{
		whoami: map[string]string{denier: liveWhoami, next: liveWhoami},
		consent: map[string]string{
			denier: `{"status":"denied"}`,
			next:   approvedReply(t, "denied-nonce", endpointID(self, "chrome", "Default")),
		},
	}
	st := stateWith(self, "", stateEndpoint(denier, "chrome", "Default"), stateEndpoint(next, "chrome", "Default"))

	_, err := routedChrome(t, st, consent, runner, "denied-nonce")
	var authErr *AuthRequired
	if !errors.As(err, &authErr) || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("denied consent = %v, want *AuthRequired carrying the denial", err)
	}
	if asked := runner.consentTargets(); len(asked) != 1 || asked[0] != denier {
		t.Fatalf("request_consent dials = %v, want only the denier %s (a denial is terminal)", asked, denier)
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("a denial must release no key")
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

// TestPeerIsLiveExcludesScreenSharedPeer proves peerIsLive treats a peer whose whoami
// reports screen_shared:true as not live — its Touch ID prompt could be tapped by the
// remote viewer, not the physically-present human — while an on-console, unlocked,
// un-shared peer is live.
func TestPeerIsLiveExcludesScreenSharedPeer(t *testing.T) {
	peer := "you@desktop"
	tests := []struct {
		name   string
		whoami string
		want   bool
	}{
		{
			name:   "on-console unlocked un-shared is live",
			whoami: `{"on_console":true,"locked":false,"console_user":"peer","screen_shared":false}`,
			want:   true,
		},
		{
			name:   "screen-shared peer is not live",
			whoami: `{"on_console":true,"locked":false,"console_user":"peer","screen_shared":true}`,
			want:   false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &recordingRunner{replies: map[string]string{"cookiesync rpc whoami": tc.whoami}}
			b := newTestBroker(&fakeConsent{}, newFakeCache(), staticProbe(presence.SessionSnapshot{}), runner, nil)
			got, err := b.peerIsLive(context.Background(), peer)
			if err != nil {
				t.Fatalf("peerIsLive: %v", err)
			}
			if got != tc.want {
				t.Fatalf("peerIsLive = %v, want %v", got, tc.want)
			}
		})
	}
}

// blockingRunner parks every Run until its context dies, then reports the kill
// — the double for a wedged peer whoami.
type blockingRunner struct{}

func (blockingRunner) Run(ctx context.Context, _, _ string, _ []byte) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

// TestPeerIsLiveBoundedByProbeTimeout proves the liveness probe carries its own
// short bound: a wedged peer fails the probe in probeLiveTimeout instead of
// riding the release flight's whole consent-window deadline.
func TestPeerIsLiveBoundedByProbeTimeout(t *testing.T) {
	restore := probeLiveTimeout
	probeLiveTimeout = 25 * time.Millisecond
	t.Cleanup(func() { probeLiveTimeout = restore })

	b := newTestBroker(&fakeConsent{}, newFakeCache(), staticProbe(presence.SessionSnapshot{}), blockingRunner{}, nil)

	start := time.Now()
	live, err := b.peerIsLive(context.Background(), "wedged@desktop")
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("peerIsLive took %v; probeLiveTimeout must bound the probe near %v", elapsed, probeLiveTimeout)
	}
	if live {
		t.Fatalf("a wedged peer must not read as live")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("peerIsLive = %v, want the probe deadline", err)
	}
}
