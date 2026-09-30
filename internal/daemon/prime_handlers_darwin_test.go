package daemon

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// primeAllReply decodes the browser-less prime_auth wire shape.
type primeAllReply struct {
	Primed    bool     `json:"primed"`
	Endpoints []string `json:"endpoints"`
	Warnings  []string `json:"warnings"`
}

// decodePrimeAll renders a handler result through the wire transport and decodes the
// all-mode prime_auth reply, asserting the envelope shape.
func decodePrimeAll(t *testing.T, result any) primeAllReply {
	t.Helper()
	var reply primeAllReply
	if err := json.Unmarshal([]byte(marshalResult(t, result)), &reply); err != nil {
		t.Fatalf("decode prime_auth all reply: %v", err)
	}
	return reply
}

// partialGateConsent gates the batch like gateConsent — each ObtainKeys parks
// until release closes — and reports one named browser as failed (Missing, or
// Err when failErr is set) while every other browser releases OK. batches
// counts ObtainKeys invocations, so a test asserts exactly how many flights
// evaluated consent. A canceled flight ctx is a whole-batch failure, returned
// as ctx.Err().
type partialGateConsent struct {
	key     cookie.AesKey
	failFor cookie.BrowserName
	failErr error

	entered chan struct{}
	release chan struct{}
	batches atomic.Int32
}

func (c *partialGateConsent) ObtainKey(_ context.Context, _ cookie.Browser, _ string) (cookie.AesKey, error) {
	panic("partialGateConsent: unexpected single ObtainKey")
}

func (c *partialGateConsent) ObtainKeys(ctx context.Context, browsers []cookie.Browser, _ string) ([]cookie.KeyOutcome, error) {
	c.batches.Add(1)
	c.entered <- struct{}{}
	select {
	case <-c.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	outcomes := make([]cookie.KeyOutcome, len(browsers))
	for i, b := range browsers {
		switch {
		case b.Name != c.failFor:
			outcomes[i] = cookie.KeyOutcome{Browser: b, Key: c.key}
		case c.failErr != nil:
			outcomes[i] = cookie.KeyOutcome{Browser: b, Err: c.failErr}
		default:
			outcomes[i] = cookie.KeyOutcome{Browser: b, Missing: true}
		}
	}
	return outcomes, nil
}

func (c *partialGateConsent) ObtainKeyUnprompted(_ context.Context, _ cookie.Browser) (cookie.AesKey, error) {
	panic("partialGateConsent: unexpected unprompted release")
}

func (c *partialGateConsent) ObtainKeyBiometric(_ context.Context, _ cookie.Browser, _ string) (cookie.AesKey, error) {
	panic("partialGateConsent: unexpected biometric release")
}

// flipProbe returns first on the initial probe call and rest on every later one — the
// session double for a console whose presence flips mid-call.
func flipProbe(first, rest SessionSnapshot) Probe {
	var calls atomic.Int32
	return func(_ context.Context) (SessionSnapshot, error) {
		if calls.Add(1) == 1 {
			return first, nil
		}
		return rest, nil
	}
}

// TestPrimeAuthAllLivePrimesEveryBrowserInOneEvaluation proves the browser-less
// prime_auth over a live session runs exactly ONE consent evaluation covering every
// tracked local browser and reports every tracked local endpoint id (all profiles
// warmed by the single batch), never a peer endpoint.
func TestPrimeAuthAllLivePrimesEveryBrowserInOneEvaluation(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(
		self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "chrome", "Work"),
		stateEndpoint(self, "arc", "Default"),
		stateEndpoint("you@desktop", "chrome", "Default"),
	)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handlePrimeAuth(ctx, map[string]any{})
	if err != nil {
		t.Fatalf("handlePrimeAuth all: %v", err)
	}
	reply := decodePrimeAll(t, got)
	if !reply.Primed {
		t.Fatalf("primed = false, want true")
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("consent evaluations = %d, want 1 (all-mode over a live session costs one sheet)", len(consent.batchCalls))
	}
	want := []string{
		endpointID(self, "arc", "Default"),
		endpointID(self, "chrome", "Default"),
		endpointID(self, "chrome", "Work"),
	}
	if !slices.Equal(reply.Endpoints, want) {
		t.Fatalf("endpoints = %v, want %v (every tracked local endpoint, sorted)", reply.Endpoints, want)
	}
	if len(reply.Warnings) != 0 {
		t.Fatalf("warnings = %v, want none", reply.Warnings)
	}
	for _, id := range want {
		if _, ok, _ := cache.Get(ctx, id); !ok {
			t.Errorf("endpoint %s not warmed by the all-mode prime", id)
		}
	}
	if _, ok, _ := cache.Get(ctx, endpointID("you@desktop", "chrome", "Default")); ok {
		t.Errorf("a peer endpoint must never be warmed by a local all-mode prime")
	}
}

// TestPrimeAuthAllMissingBrowserWarnsWithoutSecondSheet proves the never-a-second-sheet
// invariant: when the one batch reports a browser Missing, the all-mode prime surfaces a
// warning naming it and still runs exactly ONE consent evaluation, priming the released
// browser.
func TestPrimeAuthAllMissingBrowserWarnsWithoutSecondSheet(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(
		self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "arc", "Default"),
	)
	consent := &partialGateConsent{
		key:     cookie.DeriveKey(cookie.SafeStorageKey("peanuts")),
		failFor: "arc",
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	close(consent.release)
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handlePrimeAuth(ctx, map[string]any{})
	if err != nil {
		t.Fatalf("handlePrimeAuth all: %v", err)
	}
	reply := decodePrimeAll(t, got)
	if n := consent.batches.Load(); n != 1 {
		t.Fatalf("consent evaluations = %d, want 1 (a Missing browser must not start a second sheet)", n)
	}
	if !slices.Equal(reply.Endpoints, []string{endpointID(self, "chrome", "Default")}) {
		t.Fatalf("endpoints = %v, want only the released chrome endpoint", reply.Endpoints)
	}
	if len(reply.Warnings) != 1 || !strings.Contains(reply.Warnings[0], "arc") {
		t.Fatalf("warnings = %v, want one naming arc", reply.Warnings)
	}
	if _, ok, _ := cache.Get(ctx, endpointID(self, "arc", "Default")); ok {
		t.Errorf("the Missing browser must not be warmed")
	}
}

// TestPrimeAuthAllColdRoutesConsentPerBrowser proves the cold-session path: with no live
// local session each per-browser prime re-derives the routed split and routes consent per
// distinct browser to a live peer (one request_consent each, never per profile),
// bulk-caching a browser's other tracked profiles under the routed key.
func TestPrimeAuthAllColdRoutesConsentPerBrowser(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peer := "you@desktop"
	nonce := "all-route-nonce"
	fakeMesh(t, self, peer)
	st := stateWith(
		self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "chrome", "Work"),
		stateEndpoint(self, "arc", "Default"),
	)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies: map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{
			endpointID(self, "arc", "Default"):    approvedReply(t, nonce, endpointID(self, "arc", "Default")),
			endpointID(self, "chrome", "Default"): approvedReply(t, nonce, endpointID(self, "chrome", "Default")),
		},
	}
	cache := newFakeCache()
	// A cold, unattended local session forces the routed path.
	d := New(consent, cache, nil, staticProbe(SessionSnapshot{}), runner, fixedState{st: st}, fixedState{st: st})
	pinnedNonce(d, nonce)

	got, err := d.handlePrimeAuth(ctx, map[string]any{})
	if err != nil {
		t.Fatalf("handlePrimeAuth all cold: %v", err)
	}
	reply := decodePrimeAll(t, got)
	consents := 0
	for _, call := range runner.calls {
		if strings.Contains(call.cmd, "request_consent") {
			consents++
		}
	}
	if consents != 2 {
		t.Fatalf("routed request_consent calls = %d, want 2 (one per distinct browser)", consents)
	}
	if consent.unpromptedCalled != 2 {
		t.Fatalf("routed unprompted releases = %d, want 2 (one per browser)", consent.unpromptedCalled)
	}
	want := []string{
		endpointID(self, "arc", "Default"),
		endpointID(self, "chrome", "Default"),
		endpointID(self, "chrome", "Work"),
	}
	if !slices.Equal(reply.Endpoints, want) {
		t.Fatalf("endpoints = %v, want %v", reply.Endpoints, want)
	}
	if _, ok, _ := cache.Get(ctx, endpointID(self, "chrome", "Work")); !ok {
		t.Errorf("chrome:Work must be warmed by the bulk Put after chrome's routed prime")
	}
}

// TestPrimeAuthAllColdToLiveFlipKeepsOneSheet proves the loop keys off each flight's
// ACTUAL consent surface, never a call-start routing snapshot: the console is cold when
// the call starts — arc's flight routes consent to the live peer — and flips live before
// chrome's flight, which leads exactly ONE local batch (where chrome is Missing). A
// stale routed snapshot would disable the one-sheet guard and let the Missing browser
// fire a second local sheet; here the flip costs one routed approval plus one local
// evaluation, and the Missing browser is a skip warning.
func TestPrimeAuthAllColdToLiveFlipKeepsOneSheet(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peer := "you@desktop"
	nonce := "flip-live-nonce"
	fakeMesh(t, self, peer)
	st := stateWith(
		self, "",
		stateEndpoint(self, "arc", "Default"),
		stateEndpoint(self, "chrome", "Default"),
	)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts")), missingFor: "chrome"}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_consent": approvedReply(t, nonce, endpointID(self, "arc", "Default"))},
	}
	cache := newFakeCache()
	d := New(consent, cache, nil, flipProbe(SessionSnapshot{}, liveSession(currentUser(t))), runner, fixedState{st: st}, fixedState{st: st})
	pinnedNonce(d, nonce)

	got, err := d.handlePrimeAuth(ctx, map[string]any{})
	if err != nil {
		t.Fatalf("handlePrimeAuth all: %v", err)
	}
	reply := decodePrimeAll(t, got)
	consents := 0
	for _, call := range runner.calls {
		if strings.Contains(call.cmd, "request_consent") {
			consents++
		}
	}
	if consents != 1 {
		t.Fatalf("routed request_consent calls = %d, want 1 (only arc's flight saw the cold console)", consents)
	}
	if consent.unpromptedCalled != 1 {
		t.Fatalf("routed unprompted releases = %d, want 1", consent.unpromptedCalled)
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("local consent evaluations = %d, want 1 (a Missing browser after the flip must never fire a second sheet)", len(consent.batchCalls))
	}
	if !slices.Equal(reply.Endpoints, []string{endpointID(self, "arc", "Default")}) {
		t.Fatalf("endpoints = %v, want only the arc endpoint", reply.Endpoints)
	}
	if len(reply.Warnings) != 1 || !strings.Contains(reply.Warnings[0], "skip chrome") {
		t.Fatalf("warnings = %v, want one skipping chrome", reply.Warnings)
	}
	if _, ok, _ := cache.Get(ctx, endpointID(self, "chrome", "Default")); ok {
		t.Errorf("the Missing browser must not be warmed")
	}
}

// TestPrimeAuthAllHardRouteFlipDoesNotSkipLaterBrowsers proves the mirror flip: the
// hard-route peer is dead when the first flight derives routing — so that flight leads
// ONE local batch covering every tracked browser — and comes alive right after. Later
// browsers ride the batch's grant: none may be skipped as "not released by the one-tap
// batch" (the stale live-at-start snapshot regression), no consent is routed, and the
// batch bulk-caches every profile.
func TestPrimeAuthAllHardRouteFlipDoesNotSkipLaterBrowsers(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peer := "you@desktop"
	nonce := "hard-route-flip-nonce"
	fakeMesh(t, self, peer)
	st := stateWith(
		self, peer,
		stateEndpoint(self, "arc", "Default"),
		stateEndpoint(self, "arc", "Work"),
		stateEndpoint(self, "chrome", "Default"),
	)
	st.ConsentRouteHard = true
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		onceByMethod: map[string]string{"rpc whoami": deadWhoami},
		replies:      map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod:     map[string]string{"request_consent": approvedReply(t, nonce, endpointID(self, "arc", "Default"))},
	}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), runner, fixedState{st: st}, fixedState{st: st})
	pinnedNonce(d, nonce)

	got, err := d.handlePrimeAuth(ctx, map[string]any{})
	if err != nil {
		t.Fatalf("handlePrimeAuth all: %v", err)
	}
	reply := decodePrimeAll(t, got)
	if len(reply.Warnings) != 0 {
		t.Fatalf("warnings = %v, want none (a routed flip must not skip later browsers)", reply.Warnings)
	}
	want := []string{
		endpointID(self, "arc", "Default"),
		endpointID(self, "arc", "Work"),
		endpointID(self, "chrome", "Default"),
	}
	if !slices.Equal(reply.Endpoints, want) {
		t.Fatalf("endpoints = %v, want %v (every tracked endpoint primed by the one batch)", reply.Endpoints, want)
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("local consent evaluations = %d, want 1", len(consent.batchCalls))
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("unprompted releases = %d, want 0 (the dead-peer flight must release locally)", consent.unpromptedCalled)
	}
	for _, call := range runner.calls {
		if strings.Contains(call.cmd, "request_consent") {
			t.Fatalf("no consent may be routed after the local batch covered every browser, got %+v", runner.calls)
		}
	}
}
