package engine

import (
	"context"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/converge"
)

// Store is the slice of the state store the orchestration needs: the convergent
// registry read/write paths the Driver consumes, plus the flock the whole pass runs
// under and a full load to seed self-target and the peer mesh.
type Store interface {
	registryStore
	WithLock(ctx context.Context, fn func() error) error
	Load(ctx context.Context) (*state.State, error)
}

// Engine ties the cookie Driver, the ssh peer-registry Fetcher, and the state store
// into the two convergent-reconcile entry points (Sync and Reconcile). It builds the
// converge collaborators from injected seams — the key cache, the ssh runner, and the
// anti-echo recorder — so the whole orchestration runs in tests against fakes.
type Engine struct {
	store    Store
	cache    KeyCache
	runner   SSHRunner
	recorder cookie.Recorder
}

// New builds the sync engine over the state store and the injected collaborators.
func New(store Store, cache KeyCache, runner SSHRunner, recorder cookie.Recorder) *Engine {
	return &Engine{store: store, cache: cache, runner: runner, recorder: recorder}
}

// Recorder is the anti-echo ledger the engine records applied digests through; the
// daemon shares it with the watch loop.
func (e *Engine) Recorder() cookie.Recorder { return e.recorder }

// Sync runs one convergent-reconcile pass tagged with origin — the notifying peer's
// target, skipped inside every union so a sync is never echoed straight back. It
// returns one ItemResult per present endpoint.
func (e *Engine) Sync(ctx context.Context, origin string) ([]converge.ItemResult, error) {
	return e.run(ctx, origin)
}

// Reconcile runs the time-based backup: one convergent-reconcile pass over every
// tracked endpoint with no origin, so every endpoint is reconciled.
func (e *Engine) Reconcile(ctx context.Context) ([]converge.ItemResult, error) {
	return e.run(ctx, "")
}

// run loads the local registry to seed the self-target and peer mesh, then drives
// synckit's pull-only converge.Reconcile under the state flock with the cookie Driver
// and the ssh peer-registry Fetcher.
func (e *Engine) run(ctx context.Context, origin string) ([]converge.ItemResult, error) {
	st, err := e.store.Load(ctx)
	if err != nil {
		return nil, err
	}
	deps := ConvergeDeps{
		SelfTarget:  st.SelfTarget,
		Cache:       e.cache,
		Recorder:    e.recorder,
		LocalSource: NewCachedKeySource(e.cache, st.SelfTarget),
		SourceFor:   func(peer string) Source { return NewSSHBackend(e.runner, peer, st.SelfTarget) },
	}
	driver := NewDriver(e.store, st.SelfTarget, deps)
	fetcher := NewSSHFetcher(e.runner)
	peers := PeerHosts(st.Browsers, st.SelfTarget)
	return converge.Reconcile(ctx, e.store.WithLock, driver, fetcher, peers, origin)
}
