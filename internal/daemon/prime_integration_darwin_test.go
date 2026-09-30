package daemon

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// TestColdPrimeWarmsAllLocalEndpointsInOneEvaluation proves the batch prime: one cold
// prime for one endpoint runs ONE consent evaluation covering every tracked local
// browser — the requested browser leading — and caches the released keys under every
// tracked local endpoint id (each profile of a browser shares its Safe Storage key),
// with the requested endpoint id put LAST. Peer endpoints never join the batch.
func TestColdPrimeWarmsAllLocalEndpointsInOneEvaluation(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "chrome", "Work"),
		stateEndpoint(self, "arc", "Default"),
		stateEndpoint("you@desktop", "chrome", "Default"),
	)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handlePrimeAuth(ctx, map[string]any{"browser": "chrome"})
	if err != nil {
		t.Fatalf("handlePrimeAuth: %v", err)
	}
	if marshalResult(t, got) != `{"endpoint":"me@laptop:chrome:Default","primed":true}` {
		t.Fatalf("prime_auth = %s", marshalResult(t, got))
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("consent evaluations = %d, want 1 batch for the whole local set", len(consent.batchCalls))
	}
	call := consent.batchCalls[0]
	if call.reason != consentReason {
		t.Fatalf("batch reason = %q, want %q", call.reason, consentReason)
	}
	if len(call.browsers) != 2 || call.browsers[0] != "chrome" || call.browsers[1] != "arc" {
		t.Fatalf("batch browsers = %v, want the requested chrome leading arc", call.browsers)
	}
	requested := endpointID(self, "chrome", "Default")
	for _, id := range []string{requested, endpointID(self, "chrome", "Work"), endpointID(self, "arc", "Default")} {
		if _, ok, _ := cache.Get(ctx, id); !ok {
			t.Errorf("local endpoint %s not warmed by the batch prime", id)
		}
	}
	if _, ok, _ := cache.Get(ctx, endpointID("you@desktop", "chrome", "Default")); ok {
		t.Errorf("a peer endpoint must never be cached by a local prime")
	}
	if len(cache.puts) != 3 || cache.puts[2] != requested {
		t.Fatalf("cache puts = %v, want 3 with the requested endpoint %s last", cache.puts, requested)
	}
}

// TestConcurrentDistinctBrowserPrimesLeadOwnFlights pins the per-browser flight
// key: one requestor primes two DISTINCT browsers concurrently, so each leads
// its own flight — the leader's denial (chrome Missing) is its own outcome,
// never delivered to the arc prime, which releases via its own evaluation once
// promptGate serializes it behind the leader's sheet.
func TestConcurrentDistinctBrowserPrimesLeadOwnFlights(t *testing.T) {
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "arc", "Default"),
	)
	consent := &partialGateConsent{
		key:     cookie.DeriveKey(cookie.SafeStorageKey("peanuts")),
		failFor: "chrome",
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	cache := newFakeCache()
	var probes atomic.Int32
	probe := func(_ context.Context) (SessionSnapshot, error) {
		probes.Add(1)
		return liveSession(currentUser(t)), nil
	}
	d := New(consent, cache, nil, probe, &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	leaderDone := make(chan error, 1)
	go func() {
		_, _, err := d.primeAuth(context.Background(), "sid:1", "chrome", "Default", consentReason, releaseLocal)
		leaderDone <- err
	}()
	select {
	case <-consent.entered:
	case err := <-leaderDone:
		t.Fatalf("leader prime returned before consent evaluated: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("leader prime never reached consent evaluation")
	}

	waiterDone := make(chan error, 1)
	go func() {
		key, _, err := d.primeAuth(context.Background(), "sid:1", "arc", "Default", consentReason, releaseLocal)
		if err == nil && string(key) != string(consent.key) {
			err = errors.New("arc prime got the wrong key")
		}
		waiterDone <- err
	}()
	// The arc flight's routing probe fires after its grant re-probe, so once it
	// lands the flight is committed to its own evaluation.
	waitFor(t, func() bool { return probes.Load() >= 2 })
	close(consent.release)

	var declined *cookie.ConsentError
	if leaderErr := <-leaderDone; !errors.As(leaderErr, &declined) {
		t.Fatalf("leader prime for the denied browser = %v, want *cookie.ConsentError", leaderErr)
	}
	if err := <-waiterDone; err != nil {
		t.Fatalf("concurrent prime for the released browser: %v", err)
	}
	if got := consent.batches.Load(); got != 2 {
		t.Errorf("consent evaluations = %d, want 2 (distinct browsers lead their own flights)", got)
	}
	if _, ok, _ := cache.Get(context.Background(), endpointID(self, "arc", "Default")); !ok {
		t.Errorf("the arc flight must warm its own browser")
	}
	if _, ok, _ := cache.Get(context.Background(), endpointID(self, "chrome", "Default")); ok {
		t.Errorf("the denied browser must not be cached")
	}
}
