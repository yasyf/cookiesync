package engine

import (
	"context"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/converge"
	"github.com/yasyf/synckit/cregistry"
	"github.com/yasyf/synckit/syncservice"
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

// recordingFetcher serves a canned peer registry and records each peer it read, so a
// test asserts the converge pass pulled the peer. It has NO write method — the structural
// loop guard: a fetcher cannot mutate a peer.
type recordingFetcher struct {
	reg   cregistry.Registry[state.EndpointMeta]
	peers []string
}

func (f *recordingFetcher) Fetch(_ context.Context, peer string) (cregistry.Registry[state.EndpointMeta], error) {
	f.peers = append(f.peers, peer)
	return f.reg, nil
}

// withFetcher swaps the package fetcher seam for the duration of a test, restoring it on
// cleanup, so a converge pass reads a fake peer registry instead of spawning ssh.
func withFetcher(t *testing.T, f converge.Fetcher[state.EndpointMeta]) {
	t.Helper()
	prev := newFetcher
	newFetcher = func(syncservice.TransportRunner) converge.Fetcher[state.EndpointMeta] { return f }
	t.Cleanup(func() { newFetcher = prev })
}

// TestEngineSyncDrivesConvergePass proves the Engine wires the cookie Driver, the typed
// peer-registry Fetcher, the state flock, and the peer mesh into synckit's pull-only
// converge.Reconcile: a Sync merges the peer's advertised registry, persists it, reports
// the remote endpoint skipped-remote, and only ever READS the peer (the structural loop
// guard — the fetcher has no write method). The local store is never touched because this
// host tracks only a remote endpoint, so the value-union runner issues no commands.
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

	// The peer advertises a second endpoint via its typed svc.get_state, which the merge
	// learns and persists locally.
	peerExtra := state.Endpoint{Host: peerHost, Browser: "arc", Profile: "Work"}
	peerReg := cregistry.New[state.EndpointMeta]()
	peerReg.Add(string(peerExtra.ID()), peerExtra.Meta(), 500)
	fetcher := &recordingFetcher{reg: peerReg}
	withFetcher(t, fetcher)
	runner := &fixedRunner{}

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

	// The peer registry was pulled exactly once, and the value-union runner issued no
	// command at all — both endpoints are remote, so nothing extracts or applies here, and
	// the fetcher (no write method) is the only peer contact.
	if len(fetcher.peers) != 1 || fetcher.peers[0] != peerHost {
		t.Fatalf("fetcher read peers %v, want [%s]", fetcher.peers, peerHost)
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
	withFetcher(t, &recordingFetcher{reg: cregistry.New[state.EndpointMeta]()})
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
