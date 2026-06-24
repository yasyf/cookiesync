package engine

import (
	"context"
	"sync"

	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/converge"
	"github.com/yasyf/synckit/cregistry"
)

// Reconcile outcomes a cookie Driver reports back through synckit's converge loop.
const (
	// OutcomeConverged means the endpoint anchored a union converge this pass.
	OutcomeConverged converge.Outcome = "converged"
	// OutcomeSkippedRemote means the endpoint is on a peer host, so it is reconciled
	// in-place as a peer of a local converge, not anchored here.
	OutcomeSkippedRemote converge.Outcome = "skipped-remote"
	// OutcomeSkippedCold means the local endpoint's key cache is cold, so it cannot
	// anchor a converge until the user authenticates.
	OutcomeSkippedCold converge.Outcome = "skipped-cold"
)

// registryStore is the slice of the state store the Driver needs: the convergent
// registry read/write split into the lock-free paths the converge orchestration
// requires, since it already holds the flock around the whole pass.
type registryStore interface {
	LoadRegistry(ctx context.Context) (cregistry.Registry[state.EndpointMeta], error)
	SaveRegistryUnlocked(ctx context.Context, reg cregistry.Registry[state.EndpointMeta]) error
}

// Driver is cookiesync's converge.Driver: it reads and writes the convergent endpoint
// registry inside state.json and reconciles each present endpoint by running a
// value-union Converge anchored on it.
//
// synckit's converge.Reconcile calls SaveRegistry once with the merged registry, then
// Reconcile per present endpoint. The Driver stashes that merged registry so each
// Reconcile can enumerate the sibling endpoints that form the union. Only a warm local
// endpoint anchors a converge; a remote or cold endpoint is skipped here, because a
// remote endpoint is reconciled in-place as a peer when a local endpoint converges, and
// a cold one needs auth first. This preserves the Python anchor invariant inside the
// per-item loop.
//
// It writes through SaveRegistryUnlocked and never re-acquires the flock, since the
// converge orchestration wraps the whole pass in the (non-reentrant) lock.
type Driver struct {
	store      registryStore
	selfTarget string
	deps       ConvergeDeps

	mu     sync.Mutex
	merged cregistry.Registry[state.EndpointMeta]
	counts map[string]int
}

// NewDriver builds the cookie Driver over store and the converge collaborators.
func NewDriver(store registryStore, selfTarget string, deps ConvergeDeps) *Driver {
	return &Driver{store: store, selfTarget: selfTarget, deps: deps, counts: map[string]int{}}
}

// Counts returns a copy of the merged cookie count recorded for each endpoint this
// Driver converged this pass, keyed by endpoint id. It is the per-group size the
// daemon's sync/reconcile responses report; a skipped endpoint has no entry.
func (d *Driver) Counts() map[string]int {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[string]int, len(d.counts))
	for id, n := range d.counts {
		out[id] = n
	}
	return out
}

// LoadRegistry reads the convergent endpoint registry — including tombstones — out of
// state.json.
func (d *Driver) LoadRegistry(ctx context.Context) (cregistry.Registry[state.EndpointMeta], error) {
	return d.store.LoadRegistry(ctx)
}

// SaveRegistry persists the merged registry back into state.json through the lock-free
// path (the orchestration already holds the flock) and stashes it so Reconcile can
// enumerate sibling endpoints.
func (d *Driver) SaveRegistry(ctx context.Context, reg cregistry.Registry[state.EndpointMeta]) error {
	if err := d.store.SaveRegistryUnlocked(ctx, reg); err != nil {
		return err
	}
	d.mu.Lock()
	d.merged = reg
	d.mu.Unlock()
	return nil
}

// presentSiblings returns the present endpoints in the stashed merged registry other
// than the one with id.
func (d *Driver) presentSiblings(id string) []state.Endpoint {
	d.mu.Lock()
	defer d.mu.Unlock()
	var siblings []state.Endpoint
	for sid, entry := range d.merged.Present() {
		if sid == id {
			continue
		}
		siblings = append(siblings, state.Endpoint{
			Host:    entry.Value.Host,
			Browser: entry.Value.Browser,
			Profile: entry.Value.Profile,
		})
	}
	return siblings
}

// Reconcile converges the endpoint named by id against every present sibling endpoint,
// anchored on this endpoint. A remote endpoint is skipped (it converges in-place as a
// peer of a local converge); a cold local endpoint is skipped until the user
// authenticates. origin is the anti-echo provenance — the peer that triggered the pass,
// skipped inside the union.
func (d *Driver) Reconcile(
	ctx context.Context,
	id string,
	entry cregistry.Entry[state.EndpointMeta],
	_ []string,
	origin string,
) (converge.Outcome, error) {
	endpoint := state.Endpoint{
		Host:    entry.Value.Host,
		Browser: entry.Value.Browser,
		Profile: entry.Value.Profile,
	}
	if endpoint.Host != d.selfTarget {
		return OutcomeSkippedRemote, nil
	}
	if _, ok, err := d.deps.Cache.Get(ctx, id); err != nil {
		return "", err
	} else if !ok {
		return OutcomeSkippedCold, nil
	}
	merged, err := Converge(ctx, endpoint, d.presentSiblings(id), origin, d.deps)
	if err != nil {
		return "", err
	}
	d.mu.Lock()
	d.counts[id] = len(merged)
	d.mu.Unlock()
	return OutcomeConverged, nil
}
