package engine

import (
	"context"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/cregistry"
)

// fixedRunner serves a canned reply for the peer registry read (and any other ssh
// call), recording every command so a test can assert the orchestration only ever
// reads peers — never writes them.
type fixedRunner struct {
	reply string
	calls []string
}

func (r *fixedRunner) Run(_ context.Context, _, remoteCmd string, _ []byte) (string, error) {
	r.calls = append(r.calls, remoteCmd)
	return r.reply, nil
}

// TestEngineSyncDrivesConvergePass proves the Engine wires the cookie Driver, the ssh
// peer-registry Fetcher, the state flock, and the peer mesh into synckit's pull-only
// converge.Reconcile: a Sync merges the peer's advertised registry, persists it, reports
// the remote endpoint skipped-remote, and only ever READS the peer (the loop guard).
// The local store is never touched because this host tracks only a remote endpoint.
func TestEngineSyncDrivesConvergePass(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	self := "me@laptop"
	peerHost := "you@desktop"

	// The host mesh comes from reposync: this host plus the peer. The peer is pull-merged
	// even though this host has no local endpoint to converge — the bootstrap the mesh
	// bridge fixes.
	fakeMesh(t, self, peerHost)

	// This host tracks a remote endpoint (added via browser add), recorded in the
	// convergent registry the merge unions against.
	remoteEP := state.Endpoint{Host: peerHost, Browser: "chrome", Profile: "Default"}
	if err := store.AddBrowser(ctx, self, remoteEP); err != nil {
		t.Fatalf("AddBrowser: %v", err)
	}

	// The peer advertises a second endpoint via its registry read, which the merge
	// learns and persists locally.
	peerExtra := state.Endpoint{Host: peerHost, Browser: "arc", Profile: "Work"}
	peerReg := cregistry.New[state.EndpointMeta]()
	peerReg.Add(string(peerExtra.ID()), peerExtra.Meta(), 500)
	body, err := MarshalRegistry(peerReg)
	if err != nil {
		t.Fatalf("MarshalRegistry: %v", err)
	}
	runner := &fixedRunner{reply: string(body)}

	eng := New(store, warmCache{}, runner, NewDigestRecorder())
	results, err := eng.Sync(ctx, "")
	if err != nil {
		t.Fatalf("Engine.Sync: %v", err)
	}

	// The merged registry persisted both the originally-tracked and the peer-advertised
	// endpoint.
	st, err := store.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := st.Browsers[string(peerExtra.ID())]; !ok {
		t.Fatalf("peer-advertised endpoint not merged into local registry")
	}

	// Both endpoints are remote, so both are skipped-remote — none converged here.
	for _, r := range results {
		if r.Err != nil {
			t.Fatalf("item %s errored: %v", r.ID, r.Err)
		}
		if r.Outcome != OutcomeSkippedRemote {
			t.Fatalf("item %s outcome = %q, want skipped-remote", r.ID, r.Outcome)
		}
	}

	// The orchestration only ever read the peer registry — never a write command.
	for _, cmd := range runner.calls {
		if cmd != registryReadCmd {
			t.Fatalf("orchestration issued non-read ssh command %q; loop guard violated", cmd)
		}
	}
	if len(runner.calls) == 0 {
		t.Fatalf("expected the peer registry to be fetched")
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
	eng := New(store, warmCache{}, &fixedRunner{reply: "{}"}, rec)

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
