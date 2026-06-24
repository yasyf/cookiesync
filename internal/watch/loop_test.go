package watch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/state"
)

// TestRunConvergesOnExternalWriteThenSuppressesSelfApply is the end-to-end anti-echo
// proof through a real fsnotify watcher and the real store fingerprint: an external
// write to the live cookie store drives exactly one converge, and a self-induced apply
// — its digest recorded first, then the store rewritten to the same logical content —
// produces no further converge, so the loop terminates against real filesystem events.
func TestRunConvergesOnExternalWriteThenSuppressesSelfApply(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	browser := chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	endpoint := state.Endpoint{Host: "me@laptop", Browser: "chrome", Profile: "Default"}
	store := fixedStore{st: stateWith("me@laptop", endpoint)}

	converger := newFakeConverger()
	runner := &fakeRunner{}
	// A short debounce keeps the test fast while still coalescing a write burst across
	// the Cookies DB and its sidecars.
	eng := NewEngine(store, "me@laptop", []string{"me@laptop"}, 60*time.Millisecond, runner)
	eng.SetConverger(converger)
	recorder := eng.Recorder()

	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, store) }()
	// Give the watcher a moment to register the profile directory before writing.
	waitForWatch(t)

	// External write: a real cookie lands in the store. The watch loop must converge
	// exactly once.
	external := []cookie.Cookie{
		{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, IsSecure: true, SourceScheme: 2, SourcePort: 443},
	}
	if _, err := cookie.Apply(ctx, external, browser, "Default", key); err != nil {
		t.Fatalf("external write: %v", err)
	}
	waitFor(t, func() bool { return converger.count() == 1 }, "one converge after the external write")

	// Self-induced apply: record the digest of the set about to be written, then write
	// the SAME logical content (same cookie, same last_update_utc → same digest). The
	// induced filesystem event must fingerprint to the recorded digest and be
	// suppressed — no second converge.
	rows, err := cookie.Read(ctx, browser, "Default")
	if err != nil {
		t.Fatalf("read for digest: %v", err)
	}
	recorder.RecordApplied(string(endpoint.ID()), cookie.LogicalDigest(rows))
	if _, err := cookie.Apply(ctx, external, browser, "Default", key); err != nil {
		t.Fatalf("self write: %v", err)
	}

	// The converge count must stay at 1 across the debounce window plus slack.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := converger.count(); got != 1 {
			t.Fatalf("converges = %d, want 1 (self-induced apply must be suppressed)", got)
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return within 2s of cancel")
	}
}

// waitForWatch gives the fsnotify watcher time to install its kqueue/inotify watch on
// the profile directory before the first write, so the first event is not missed.
func waitForWatch(t *testing.T) {
	t.Helper()
	time.Sleep(150 * time.Millisecond)
}

// assert the fake converger satisfies the LocalConverger seam at compile time.
var _ LocalConverger = (*fakeConverger)(nil)

// assert the fake runner satisfies the SSHRunner seam at compile time.
var _ engine.SSHRunner = (*fakeRunner)(nil)
