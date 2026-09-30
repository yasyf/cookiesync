package auth

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	consentkit "github.com/yasyf/synckit/consent"
	"github.com/yasyf/synckit/hostregistry"
	"github.com/yasyf/synckit/presence"
)

// TestDegradedRePutNeverExtendsNearExpiryGrant pins the cap-only re-Put
// regression: a requestor rides releaseAndCacheKey's already-granted warm-key
// fast path (batch ttl = the full configured hour) into a post-flight degraded
// re-Put, and its near-expiry grant must stay near expiry — never silently
// extended to the degraded window with zero fresh consent.
func TestDegradedRePutNeverExtendsNearExpiryGrant(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	keyCache := newFakeCache()
	keyCache.degraded = true
	id := endpointID(self, "chrome", "Default")
	if _, err := keyCache.Put(ctx, id, []byte(consent.key), time.Minute); err != nil {
		t.Fatalf("seed Put: %v", err)
	}
	// Key's probe misses (flight leads), the flight's re-probe hits (warm fast
	// path), the post-flight probe misses (degraded re-Put).
	keyCache.missGets = map[int]bool{1: true, 3: true}
	b := newTestBroker(consent, keyCache, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, st)

	before := time.Now()
	b.Grant("local", []cookie.BrowserName{"chrome"}, time.Minute)
	key, _, err := b.Key(ctx, Req{Requestor: "local", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal})
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("Key returned the wrong key")
	}
	if len(consent.promptedReasons) != 0 {
		t.Fatalf("the warm-key fast path must not prompt, got %v", consent.promptedReasons)
	}
	if puts := keyCache.putOrder(); len(puts) != 2 || puts[1] != id {
		t.Fatalf("puts = %v, want the seed then the re-Put of %s", puts, id)
	}
	expiry, granted := b.grants.Granted("local", "chrome")
	if !granted {
		t.Fatalf("the near-expiry grant must survive the re-Put")
	}
	if window := expiry.Sub(before); window > time.Minute+time.Second {
		t.Fatalf("grant window = %v, want the pre-existing ~1m — a degraded re-Put must never extend a grant", window)
	}
}

// TestRoutedBatchBulkCachesSiblingProfiles proves a routed approval bulk-warms
// the browser's sibling profiles exactly like a local release does — every
// profile shares one Safe Storage key — with the requested endpoint put LAST so
// it survives any heal a sibling Put triggers, while another browser's endpoint
// stays cold (a routed approval gates one browser).
func TestRoutedBatchBulkCachesSiblingProfiles(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peer := "you@desktop"
	nonce := "bulk-route-nonce"
	fakeMesh(t, self, peer)
	st := stateWith(self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "chrome", "Work"),
		stateEndpoint(self, "arc", "Default"),
	)
	requested := endpointID(self, "chrome", "Default")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_consent": approvedReply(t, nonce, requested)},
	}
	cache := newFakeCache()
	b := newTestBroker(consent, cache, staticProbe(presence.SessionSnapshot{}), runner, st)
	pinnedNonce(b, nonce)

	key, surface, err := b.Key(ctx, Req{Requestor: "local", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal})
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if surface != SurfaceRouted {
		t.Fatalf("surface = %v, want SurfaceRouted", surface)
	}
	for _, id := range []string{requested, endpointID(self, "chrome", "Work")} {
		got, ok, _ := cache.Get(ctx, id)
		if !ok || string(got) != string(key) {
			t.Errorf("endpoint %s not bulk-warmed by the routed release", id)
		}
	}
	if _, ok, _ := cache.Get(ctx, endpointID(self, "arc", "Default")); ok {
		t.Errorf("a routed approval gates one browser; arc must stay cold")
	}
	puts := cache.putOrder()
	if len(puts) == 0 || puts[len(puts)-1] != requested {
		t.Fatalf("cache puts = %v, want the requested endpoint %s put last", puts, requested)
	}
}

// TestKeyApproverProbeErrorClassifiesUnavailable proves an approver-mode probe
// failure classifies Unavailable — the flake fails over instead of killing the
// requesting host's routed release.
func TestKeyApproverProbeErrorClassifiesUnavailable(t *testing.T) {
	probeErr := errors.New("ioreg: signal: killed")
	probe := func(context.Context) (presence.SessionSnapshot, error) {
		return presence.SessionSnapshot{}, probeErr
	}
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	b := newTestBroker(consent, newFakeCache(), probe, &recordingRunner{}, stateWith("me@laptop", ""))

	_, _, err := b.Key(context.Background(), Req{Requestor: "host:them", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeApprover})
	if !errors.Is(err, probeErr) {
		t.Fatalf("Key over a failed probe = %v, want it to wrap %v", err, probeErr)
	}
	if got := Classify(err); got != consentkit.VerdictUnavailable {
		t.Fatalf("Classify(probe error) = %v, want VerdictUnavailable", got)
	}
	if len(consent.promptedReasons) != 0 {
		t.Fatalf("a failed probe must not prompt, got %v", consent.promptedReasons)
	}
}

// TestKeyLocalProbeErrorDegradesToLocalGate proves a ModeLocal release whose
// presence probe fails to run (a starved ioreg) attempts the local Touch ID
// gate instead of dying: one prompt, key released and cached, no error.
func TestKeyLocalProbeErrorDegradesToLocalGate(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	probeErr := errors.New("ioreg: signal: killed")
	probe := func(context.Context) (presence.SessionSnapshot, error) {
		return presence.SessionSnapshot{}, probeErr
	}
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	cache := newFakeCache()
	b := newTestBroker(consent, cache, probe, &recordingRunner{}, stateWith(self, ""))

	key, surface, err := b.Key(ctx, Req{Requestor: "local", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal})
	if err != nil {
		t.Fatalf("Key over a failed probe must attempt the local gate, got %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("Key = %q, want the released key %q", key, consent.key)
	}
	if surface != SurfaceLocal {
		t.Fatalf("surface = %v, want SurfaceLocal", surface)
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("consent evaluations = %d, want exactly 1 local prompt", len(consent.batchCalls))
	}
	got, ok, err := cache.Get(ctx, endpointID(self, "chrome", "Default"))
	if err != nil || !ok || string(got) != string(key) {
		t.Fatalf("post-release Get = %q, %v, %v, want the key cached warm", got, ok, err)
	}
}

// localReleaseOutcome is every observable a hard-route ModeLocal release
// leaves behind, comparable across runner scenarios.
type localReleaseOutcome struct {
	key        string
	surface    Surface
	errText    string
	prompts    []string
	unprompted int
	cachedKey  string
	warm       bool
}

// hardRouteLocalRelease runs one ModeLocal Key release for chrome with a hard
// consent route to you@desktop and an attended local session, over the given
// runner.
func hardRouteLocalRelease(t *testing.T, runner SSHRunner) localReleaseOutcome {
	t.Helper()
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self, "you@desktop")
	st := stateWith(self, "you@desktop", stateEndpoint(self, "chrome", "Default"))
	st.ConsentRouteHard = true
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	c := newFakeCache()
	b := newTestBroker(consent, c, staticProbe(liveSession(currentUser(t))), runner, st)

	key, surface, err := b.Key(ctx, Req{Requestor: "local", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal})
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	cached, warm, cerr := c.Get(ctx, endpointID(self, "chrome", "Default"))
	if cerr != nil {
		t.Fatalf("cache get: %v", cerr)
	}
	return localReleaseOutcome{
		key:        string(key),
		surface:    surface,
		errText:    errText,
		prompts:    append([]string(nil), consent.promptedReasons...),
		unprompted: consent.unpromptedCalled,
		cachedKey:  string(cached),
		warm:       warm,
	}
}

// TestKeyHardRouteWhoamiSSHErrorMatchesNotLivePeer proves a hard consent route
// whose whoami probe fails with an SSHError — even a non-255 remote exit, the
// shape a transport flake produces — counts as peer-not-live: the local
// release proceeds through Touch ID exactly as it does when the peer answers a
// locked whoami, instead of bricking every local release on this host.
func TestKeyHardRouteWhoamiSSHErrorMatchesNotLivePeer(t *testing.T) {
	exit1 := exec.Command("/bin/sh", "-c", "exit 1").Run()
	var exitErr *exec.ExitError
	if !errors.As(exit1, &exitErr) {
		t.Fatalf("fabricate exit-1: %v", exit1)
	}
	notLive := &approverMesh{}
	flaky := &whoamiErrMesh{
		approverMesh: &approverMesh{},
		target:       "you@desktop",
		err:          &hostregistry.SSHError{Addr: "you@desktop", Stderr: "whoami failed remotely", Err: exit1},
	}

	baseline := hardRouteLocalRelease(t, notLive)
	if baseline.errText != "" || baseline.surface != SurfaceLocal || len(baseline.prompts) != 1 {
		t.Fatalf("peer-not-live baseline must release locally, got %+v", baseline)
	}
	flaked := hardRouteLocalRelease(t, flaky)
	if !reflect.DeepEqual(flaked, baseline) {
		t.Fatalf("whoami ssh-error outcome = %+v, want the peer-not-live outcome %+v", flaked, baseline)
	}
	if asked := flaky.consentTargets(); len(asked) != 0 {
		t.Fatalf("request_consent dials = %v, want none", asked)
	}
}

// TestKeyHardRouteMalformedWhoamiIsFatal proves the probe-shaped carve-out
// stays narrow: a hard-routed peer whose whoami reply does not parse fails the
// release outright — no Touch ID prompt, no cached key.
func TestKeyHardRouteMalformedWhoamiIsFatal(t *testing.T) {
	runner := &approverMesh{whoami: map[string]string{"you@desktop": "not json"}}

	got := hardRouteLocalRelease(t, runner)
	if got.errText == "" || !strings.Contains(got.errText, "parse presence from you@desktop") {
		t.Fatalf("malformed whoami err = %q, want a fatal parse failure", got.errText)
	}
	if len(got.prompts) != 0 || got.unprompted != 0 {
		t.Fatalf("a fatal probe failure must not prompt, got %+v", got)
	}
	if got.warm {
		t.Fatalf("a fatal probe failure must not cache a key")
	}
}
