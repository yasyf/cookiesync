package engine

import (
	"context"
	"sync"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/synckit/converge"
)

// Store is the slice of the state store the orchestration needs: the convergent
// registry read/write paths the Driver consumes, the rowcount ledger the mass-drop
// quarantine consults, plus the flock the whole pass runs under. The self target and
// peer mesh come from reposync, not this store.
type Store interface {
	registryStore
	BaselineStore
	WithLock(ctx context.Context, fn func() error) error
}

// Engine ties the cookie Driver and applied registry state into the two
// convergent-reconcile entry points (Sync and Reconcile). It builds the
// converge collaborators from injected seams — the key cache, the ssh runner, and the
// anti-echo recorder — so the whole orchestration runs in tests against fakes.
type Engine struct {
	store    Store
	cache    KeyCache
	runner   SSHRunner
	recorder cookie.Recorder

	// applyLocks serializes writes to one endpoint's local store: the daemon's apply
	// handler and a converge pass's local applies hold the same per-endpoint mutex, so
	// the anti-echo digest is always recorded against the store's final content.
	applyLocks keyedLocks
}

// New builds the sync engine over the state store and the injected collaborators.
func New(store Store, cache KeyCache, runner SSHRunner, recorder cookie.Recorder) *Engine {
	return &Engine{store: store, cache: cache, runner: runner, recorder: recorder}
}

// Recorder is the anti-echo ledger the engine records applied digests through; the
// daemon shares it with the watch loop.
func (e *Engine) Recorder() cookie.Recorder { return e.recorder }

// ApplyLock acquires endpointID's apply mutex and returns it held for the caller to
// Unlock. The daemon's apply handler and a converge pass's local writes serialize
// behind the same lock; it is never held across a peer call.
func (e *Engine) ApplyLock(endpointID string) *sync.Mutex {
	return e.applyLocks.lock(endpointID)
}

// Result is one endpoint's reconcile outcome enriched with the merged cookie count of
// its converged group. Cookies is the size of the union written this pass for a
// converged endpoint, and 0 for a skipped one — the per-group size the daemon's
// sync/reconcile responses report.
type Result struct {
	converge.ItemResult
	Cookies int
}

// Sync runs one convergent-reconcile pass tagged with origin — the notifying peer's
// target, skipped inside every union so a sync is never echoed straight back. It
// returns one Result per present endpoint, each carrying its merged cookie count.
func (e *Engine) Sync(ctx context.Context, origin string) ([]Result, error) {
	return e.run(ctx, origin)
}

// Reconcile runs the time-based backup: one convergent-reconcile pass over every
// tracked endpoint with no origin, so every endpoint is reconciled.
func (e *Engine) Reconcile(ctx context.Context) ([]Result, error) {
	return e.run(ctx, "")
}

// run resolves the self target and peer mesh from Synckit's host registry, then
// reconciles the authoritative registry already applied by the transfer service. The
// state flock pins one immutable registry snapshot for the complete pass.
func (e *Engine) run(ctx context.Context, origin string) ([]Result, error) {
	self, peers, err := mesh.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	deps := ConvergeDeps{
		SelfTarget:  self,
		Cache:       e.cache,
		Recorder:    e.recorder,
		Baselines:   e.store,
		LocalSource: NewCachedKeySource(e.cache, self),
		SourceFor:   func(peer string) Source { return NewSSHBackend(e.runner, peer, self) },
		LockFor:     e.ApplyLock,
	}
	driver := NewDriver(e.store, self, deps)
	var items []converge.ItemResult
	err = e.store.WithLock(ctx, func() error {
		registry, err := driver.LoadRegistry(ctx)
		if err != nil {
			return err
		}
		driver.useRegistry(registry)
		items = make([]converge.ItemResult, 0, len(registry))
		for id, entry := range registry.Present() {
			outcome, itemErr := driver.Reconcile(ctx, id, entry, peers, origin)
			items = append(items, converge.ItemResult{ID: id, Outcome: outcome, Err: itemErr})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	counts := driver.Counts()
	results := make([]Result, len(items))
	for i, item := range items {
		results[i] = Result{ItemResult: item, Cookies: counts[item.ID]}
	}
	return results, nil
}
