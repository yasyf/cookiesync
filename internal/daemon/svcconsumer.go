package daemon

import (
	"context"

	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/transfer"
	"github.com/yasyf/synckit/syncservice"
)

// syncConsumer adapts cookiesync's engine and state store to the typed
// syncservice.SyncConsumer contract synckitd drives over the resident RPC socket.
// Every method runs in the warm-key resident helper, so reconciliation reuses
// this host's already-primed Secure-Enclave key — the SE seam stays resident, never
// re-primed by a fresh subprocess.
type syncConsumer struct {
	engine   *engine.Engine
	state    StateLoader
	transfer transfer.Service
}

// newSyncConsumer builds the consumer adapter over the daemon's engine, state loader,
// and authoritative registry store.
func newSyncConsumer(eng *engine.Engine, st StateLoader, registry transfer.RegistryStore) syncConsumer {
	return syncConsumer{
		engine: eng, state: st,
		transfer: transfer.Service{
			Store: registry,
			AfterApply: func(ctx context.Context, origin string) error {
				_, err := eng.Sync(ctx, origin)
				return err
			},
		},
	}
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

func (c syncConsumer) Export(ctx context.Context, request syncservice.ExportRequest) (syncservice.ChangeEnvelope, error) {
	return c.transfer.Export(ctx, request)
}

func (c syncConsumer) Apply(ctx context.Context, change syncservice.ChangeEnvelope) (syncservice.ApplyResult, error) {
	return c.transfer.Apply(ctx, change)
}
