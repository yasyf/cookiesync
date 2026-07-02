package engine

import (
	"context"
	"sync"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/converge"
)

// newFetcher builds the pull-only peer-registry fetcher a converge pass reads peers
// through. Production dials each peer's rpc-serve bridge over ssh-stdio; it is a package
// var so a test substitutes a fake fetcher and drives the merge without spawning ssh.
var newFetcher = func() converge.Fetcher[state.EndpointMeta] { return NewSSHFetcher() }

// Store is the slice of the state store the orchestration needs: the convergent
// registry read/write paths the Driver consumes, plus the flock the whole pass runs
// under. The self target and peer mesh come from reposync, not this store.
type Store interface {
	registryStore
	WithLock(ctx context.Context, fn func() error) error
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

// run resolves the self target and peer mesh from reposync — cookiesync rides reposync's
// host registry, so the hosts to pull peer registries from (and the self target threaded
// into the Driver and sources) come from the mesh, not this host's own state, which is
// empty on a freshly-installed host. It then drives synckit's pull-only converge.Reconcile
// under the state flock with the cookie Driver and the ssh peer-registry Fetcher, zipping
// each present endpoint's ItemResult with the merged cookie count the Driver recorded for
// it.
func (e *Engine) run(ctx context.Context, origin string) ([]Result, error) {
	self, peers, err := mesh.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	deps := ConvergeDeps{
		SelfTarget:  self,
		Cache:       e.cache,
		Recorder:    e.recorder,
		LocalSource: NewCachedKeySource(e.cache, self),
		SourceFor:   func(peer string) Source { return NewSSHBackend(e.runner, peer, self) },
		LockFor:     e.ApplyLock,
	}
	driver := NewDriver(e.store, self, deps)
	items, err := converge.Reconcile(ctx, e.store.WithLock, driver, newFetcher(), peers, origin)
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
