package engine

import (
	"context"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
)

// fixedRunner serves a canned reply for any ssh call, recording every command so a test
// can assert which value-union (extract/apply) commands the orchestration issued — the
// peer registry read no longer goes through the runner, it goes through the typed fetcher.
type fixedRunner struct {
	reply string
	calls []string
}

func (r *fixedRunner) Run(_ context.Context, _, remoteCmd string, _ []byte) (string, error) {
	r.calls = append(r.calls, remoteCmd)
	return r.reply, nil
}

// TestEngineSyncReconcilesAppliedRegistry proves the engine reads only the registry
// already applied by Synckit and performs product convergence without opening a second
// product-level registry transport.
func TestEngineSyncReconcilesAppliedRegistry(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	self := "me@laptop"
	peerHost := "you@desktop"

	fakeMesh(t, self, peerHost)

	// This host tracks a remote endpoint (added via browser add), recorded in the
	// convergent registry the merge unions against.
	remoteEP := state.Endpoint{Host: peerHost, Browser: "chrome", Profile: "Default"}
	if err := store.AddBrowser(ctx, self, remoteEP); err != nil {
		t.Fatalf("AddBrowser: %v", err)
	}

	runner := &fixedRunner{}

	eng := New(store, warmCache{}, runner, NewDigestRecorder())
	results, err := eng.Sync(ctx, "")
	if err != nil {
		t.Fatalf("Engine.Sync: %v", err)
	}

	// The remote endpoint is skipped locally; its registry already arrived through Apply.
	for _, r := range results {
		if r.Err != nil {
			t.Fatalf("item %s errored: %v", r.ID, r.Err)
		}
		if r.Outcome != OutcomeSkippedRemote {
			t.Fatalf("item %s outcome = %q, want skipped-remote", r.ID, r.Outcome)
		}
	}

	if len(runner.calls) != 0 {
		t.Fatalf("value-union runner issued commands %v for an all-remote pass; want none", runner.calls)
	}
}

// TestEngineReconcileRunsWithNoOrigin proves Reconcile drives the pass with an empty
// origin (the time-based backup that touches every endpoint), and that the engine's
// recorder is the one shared with callers.
func TestEngineReconcileRunsWithNoOrigin(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	fakeMesh(t, "me@laptop", "you@desktop")
	if err := store.AddBrowser(ctx, "me@laptop", state.Endpoint{Host: "you@desktop", Browser: "chrome", Profile: "Default"}); err != nil {
		t.Fatalf("AddBrowser: %v", err)
	}
	rec := NewDigestRecorder()
	eng := New(store, warmCache{}, &fixedRunner{}, rec)

	results, err := eng.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Engine.Reconcile: %v", err)
	}
	if len(results) != 1 || results[0].Outcome != OutcomeSkippedRemote {
		t.Fatalf("expected one skipped-remote result, got %+v", results)
	}
	if eng.Recorder() != cookie.Recorder(rec) {
		t.Fatalf("Recorder() should return the recorder the engine was built with")
	}
}

// TestDigestRecorderRoundTrip proves the recorder stores and reads back the last digest
// per endpoint — the anti-echo ledger the converge pass writes before each store write
// and the watch loop reads to suppress its own echo.
func TestDigestRecorderRoundTrip(t *testing.T) {
	rec := NewDigestRecorder()
	if _, ok := rec.Applied("ep"); ok {
		t.Fatalf("empty recorder should report no applied digest")
	}
	d := cookie.LogicalDigest([]cookie.Cookie{ck(".x.com", "sid", "v", 1)})
	rec.RecordApplied("ep", d)
	got, ok := rec.Applied("ep")
	if !ok || got != d {
		t.Fatalf("Applied = (%s, %v), want (%s, true)", got, ok, d)
	}
}
