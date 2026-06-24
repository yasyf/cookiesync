package engine

import (
	"context"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/converge"
	"github.com/yasyf/synckit/cregistry"
	"github.com/yasyf/synckit/hostregistry"
)

// newStore builds a real state.Store rooted at a temp XDG dir, so the Driver writes
// through the genuine flock + foreign-key-preserving raw writer — which is what the
// no-self-deadlock proof needs.
func newStore(t *testing.T) *state.Store {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	return state.NewWithClock(hostregistry.Config{Name: "cookiesync"}, func() time.Time {
		return time.Unix(1_700_000_000, 0)
	})
}

// fakeFetcher serves a fixed per-peer registry and records every Fetch. It has NO
// write method — that absence is the structural loop guard: the converge orchestration
// can only ever read a peer, never mutate it.
type fakeFetcher struct {
	regs    map[string]cregistry.Registry[state.EndpointMeta]
	fetched []string
}

func (f *fakeFetcher) Fetch(_ context.Context, peer string) (cregistry.Registry[state.EndpointMeta], error) {
	f.fetched = append(f.fetched, peer)
	return f.regs[peer], nil
}

// TestDriverLoadSaveRoundTrip proves the Driver reads the registry it wrote back
// through the real store, tombstones and all.
func TestDriverLoadSaveRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	driver := NewDriver(store, "me@laptop", ConvergeDeps{Cache: warmCache{}})

	reg := cregistry.New[state.EndpointMeta]()
	present := state.Endpoint{Host: "me@laptop", Browser: "chrome", Profile: "Default"}
	gone := state.Endpoint{Host: "you@desktop", Browser: "arc", Profile: "Default"}
	reg.Add(string(present.ID()), present.Meta(), 100)
	reg.Add(string(gone.ID()), gone.Meta(), 100)
	reg.Remove(string(gone.ID()), 200)

	if err := driver.SaveRegistry(ctx, reg); err != nil {
		t.Fatalf("SaveRegistry: %v", err)
	}
	got, err := driver.LoadRegistry(ctx)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("round-trip registry has %d entries (incl tombstone), want 2", len(got))
	}
	if got[string(gone.ID())].Present() {
		t.Fatalf("tombstone should not be present after round-trip")
	}
	if !got[string(present.ID())].Present() {
		t.Fatalf("present endpoint lost in round-trip")
	}
}

// TestDriverSaveRegistryNoSelfDeadlockInLock proves SaveRegistry-as-called-by-the-
// orchestration does not self-deadlock when invoked inside a held WithLock: the Driver
// writes through the store's *Unlocked path, so the non-reentrant flock is acquired
// exactly once (by the orchestration), never re-entered.
func TestDriverSaveRegistryNoSelfDeadlockInLock(t *testing.T) {
	store := newStore(t)
	driver := NewDriver(store, "me@laptop", ConvergeDeps{Cache: warmCache{}})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	reg := cregistry.New[state.EndpointMeta]()
	ep := state.Endpoint{Host: "me@laptop", Browser: "chrome", Profile: "Default"}
	reg.Add(string(ep.ID()), ep.Meta(), 100)

	done := make(chan error, 1)
	go func() {
		// Mirror the converge orchestration: hold the lock around a load + save.
		done <- store.WithLock(ctx, func() error {
			if _, err := driver.LoadRegistry(ctx); err != nil {
				return err
			}
			return driver.SaveRegistry(ctx, reg)
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Driver SaveRegistry inside WithLock: %v", err)
		}
	case <-ctx.Done():
		t.Fatalf("Driver.SaveRegistry self-deadlocked inside WithLock")
	}
}

// TestReconcilePassConvergesWarmLocalSkipsRemote drives synckit's pull-only
// converge.Reconcile end to end with the cookie Driver and a read-only fake Fetcher:
// the local + peer registries merge and persist, the warm LOCAL endpoint converges
// (its store written), the REMOTE endpoint is skipped (reconciled in-place as a peer,
// never written through this Driver), and the Fetcher is only ever read.
func TestReconcilePassConvergesWarmLocalSkipsRemote(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	self := "me@laptop"
	peerHost := "you@desktop"

	// Seed the local registry with just the local endpoint.
	localEP := state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"}
	if err := store.AddBrowser(ctx, self, localEP); err != nil {
		t.Fatalf("AddBrowser: %v", err)
	}

	// The peer advertises its own endpoint via the fetcher, so the merge learns it.
	peerEP := state.Endpoint{Host: peerHost, Browser: "chrome", Profile: "Default"}
	peerReg := cregistry.New[state.EndpointMeta]()
	peerReg.Add(string(peerEP.ID()), peerEP.Meta(), 150)
	fetcher := &fakeFetcher{regs: map[string]cregistry.Registry[state.EndpointMeta]{peerHost: peerReg}}

	local := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "old", 100)}}
	peer := &fakeSource{cookies: []cookie.Cookie{ck(".x.com", "sid", "new", 200)}}
	deps := ConvergeDeps{
		SelfTarget:  self,
		Cache:       warmCache{},
		Recorder:    &countingRecorder{},
		LocalSource: local,
		SourceFor:   func(string) Source { return peer },
	}
	driver := NewDriver(store, self, deps)

	results, err := converge.Reconcile(ctx, store.WithLock, driver, fetcher, []string{peerHost}, "")
	if err != nil {
		t.Fatalf("converge.Reconcile: %v", err)
	}

	// The merged registry persisted both endpoints.
	st, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := st.Browsers[string(peerEP.ID())]; !ok {
		t.Fatalf("peer endpoint not merged into local registry")
	}

	// Outcomes: local converged, remote skipped.
	outcomes := map[string]converge.Outcome{}
	for _, r := range results {
		if r.Err != nil {
			t.Fatalf("item %s errored: %v", r.ID, r.Err)
		}
		outcomes[r.ID] = r.Outcome
	}
	if outcomes[string(localEP.ID())] != OutcomeConverged {
		t.Fatalf("local endpoint outcome = %q, want converged", outcomes[string(localEP.ID())])
	}
	if outcomes[string(peerEP.ID())] != OutcomeSkippedRemote {
		t.Fatalf("remote endpoint outcome = %q, want skipped-remote", outcomes[string(peerEP.ID())])
	}

	// The local endpoint's store was written (old -> new), the peer's too (as a sibling
	// of the local converge), but the Driver never reconciled the remote item itself.
	if len(local.applies) != 1 {
		t.Fatalf("local endpoint should have been written once, got %d", len(local.applies))
	}
	if len(fetcher.fetched) == 0 {
		t.Fatalf("fetcher should have been read for the peer registry")
	}
}

// TestReconcileSkipsColdLocal proves a cold local endpoint is reported skipped-cold and
// never converged (no prompt, no write) until the user authenticates.
func TestReconcileSkipsColdLocal(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	self := "me@laptop"
	localEP := state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"}
	if err := store.AddBrowser(ctx, self, localEP); err != nil {
		t.Fatalf("AddBrowser: %v", err)
	}

	deps := ConvergeDeps{
		SelfTarget:  self,
		Cache:       warmCache{cold: map[string]bool{string(localEP.ID()): true}},
		Recorder:    &countingRecorder{},
		LocalSource: &fakeSource{},
		SourceFor:   func(string) Source { return &fakeSource{} },
	}
	driver := NewDriver(store, self, deps)

	results, err := converge.Reconcile(ctx, store.WithLock, driver, &fakeFetcher{}, nil, "")
	if err != nil {
		t.Fatalf("converge.Reconcile: %v", err)
	}
	if len(results) != 1 || results[0].Outcome != OutcomeSkippedCold {
		t.Fatalf("expected one skipped-cold result, got %+v", results)
	}
}
