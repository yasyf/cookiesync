package daemon

import (
	"context"

	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/cregistry"
	"github.com/yasyf/synckit/syncservice"
)

// RegistryLoader reads the convergent endpoint registry out of state.json — the
// read side svc.get_state serves a peer's pull-merge from. It is the seam the
// consumer adapter reads the registry through, injected so the contract runs against
// a fixture store. Defined here, where the adapter consumes it.
type RegistryLoader interface {
	LoadRegistry(ctx context.Context) (cregistry.Registry[state.EndpointMeta], error)
}

// syncConsumer adapts cookiesync's engine and state store to the typed
// syncservice.SyncConsumer contract synckitd drives over the resident RPC socket.
// Every method runs IN the warm-key resident helper, so a cross-host svc.sync reuses
// this host's already-primed Secure-Enclave key — the SE seam stays resident, never
// re-primed by a fresh subprocess.
type syncConsumer struct {
	engine   *engine.Engine
	state    StateLoader
	registry RegistryLoader
}

// newSyncConsumer builds the consumer adapter over the daemon's engine, state loader,
// and registry loader.
func newSyncConsumer(eng *engine.Engine, st StateLoader, reg RegistryLoader) syncConsumer {
	return syncConsumer{engine: eng, state: st, registry: reg}
}

// Capabilities reports cookiesync's typed-contract self-description.
func (c syncConsumer) Capabilities(_ context.Context) (syncservice.Capabilities, error) {
	return syncservice.DefaultCapabilities("cookiesync"), nil
}

// List enumerates this host's local watch items — id, watch dirs, and the apply-stable
// logical digest of each tracked cookie store — read decryption-free in-process, so it
// needs no SE key.
func (c syncConsumer) List(ctx context.Context) ([]syncservice.WatchItem, error) {
	return engine.WatchItems(ctx, c.state)
}

// Reconcile runs a full reconcile pass over every tracked endpoint. cookiesync's engine
// reconcile takes no origin — it is a full pass and synckitd always sends origin="" — so
// the origin is ignored. It returns the count of endpoints that converged a group.
func (c syncConsumer) Reconcile(ctx context.Context, _ string) (syncservice.ReconcileResult, error) {
	results, err := c.engine.Reconcile(ctx)
	if err != nil {
		return syncservice.ReconcileResult{}, err
	}
	converged := 0
	for _, r := range results {
		if r.Outcome == engine.OutcomeConverged {
			converged++
		}
	}
	return syncservice.ReconcileResult{Converged: converged}, nil
}

// Sync converges the union of every tracked endpoint, suppressing origin so a sync is
// never echoed straight back to the notifying peer. It returns the count of endpoints
// that converged a group this pass.
func (c syncConsumer) Sync(ctx context.Context, origin string) (syncservice.SyncResult, error) {
	results, err := c.engine.Sync(ctx, origin)
	if err != nil {
		return syncservice.SyncResult{}, err
	}
	converged := 0
	for _, r := range results {
		if r.Outcome == engine.OutcomeConverged {
			converged++
		}
	}
	return syncservice.SyncResult{Converged: converged}, nil
}

// GetState returns the current convergent endpoint registry as opaque JSON — the
// peer-registry read a converge pull-merges. It is read-only and never decodes the
// registry, so its int64 CRDT stamps round-trip byte-exact.
func (c syncConsumer) GetState(ctx context.Context) (syncservice.RawRegistry, error) {
	reg, err := c.registry.LoadRegistry(ctx)
	if err != nil {
		return nil, err
	}
	raw, err := engine.MarshalRegistry(reg)
	if err != nil {
		return nil, err
	}
	return syncservice.RawRegistry(raw), nil
}
