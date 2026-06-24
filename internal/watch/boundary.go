package watch

import (
	"context"
	"fmt"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/hostregistry"
)

// storeResolver resolves an endpoint id to the decryption-free logical digest of its
// local cookie store. It reads every raw EncryptedRow and digests the sorted
// (host_key, name, path, last_update_utc) tuples — never decrypting — so the digest
// changes exactly when the logical cookie set does, and a self-induced write (which
// preserves last_update_utc) reproduces the digest the sync layer recorded. It
// resolves the endpoint's browser and profile from the live registry, keyed by id.
type storeResolver struct {
	store EndpointLookup
}

// Resolve returns the logical digest of the endpoint's cookie store. A missing
// endpoint (removed from the registry between the event and the resolve) or an
// unreadable store is an error, which the engine logs and skips — it never notifies
// on a digest it could not compute.
func (r storeResolver) Resolve(ctx context.Context, id string) (string, error) {
	st, err := r.store.Load(ctx)
	if err != nil {
		return "", err
	}
	endpoint, ok := lookupEndpoint(st, id)
	if !ok {
		return "", fmt.Errorf("endpoint %s is no longer tracked", id)
	}
	browser, err := cookie.Lookup(cookie.BrowserName(endpoint.Browser))
	if err != nil {
		return "", err
	}
	rows, err := cookie.Read(ctx, browser, endpoint.Profile)
	if err != nil {
		return "", fmt.Errorf("fingerprint %s: %w", id, err)
	}
	return string(cookie.LogicalDigest(rows)), nil
}

// lookupEndpoint finds the present endpoint with the given id in the live state.
func lookupEndpoint(st *state.State, id string) (state.Endpoint, bool) {
	for _, e := range st.Endpoints() {
		if string(e.ID()) == id {
			return e, true
		}
	}
	return state.Endpoint{}, false
}

// rpcNotifier converges this host and its peers when a local endpoint settles. For
// the self entry it runs a local convergent-reconcile pass in-process; for a peer it
// ssh-es the peer's resident daemon to converge over its rpc socket, tagging the call
// with this host's target as the origin so the peer suppresses the redundant return
// hop. This mirrors the Python notify_peers: local sync first, then a peer sync per
// host. The endpoint id is not forwarded — a converge reconciles the whole union, not
// one endpoint — matching the Python sync RPC.
type rpcNotifier struct {
	self      string
	converger LocalConverger
	runner    engine.SSHRunner
}

// Notify converges peer. peer == self runs the local pass; any other peer is driven
// over ssh. The engine fans these out concurrently, isolating a down peer.
func (n *rpcNotifier) Notify(ctx context.Context, peer string, _ string) error {
	if peer == n.self {
		if _, err := n.converger.Sync(ctx, ""); err != nil {
			return fmt.Errorf("local converge: %w", err)
		}
		return nil
	}
	cmd := fmt.Sprintf("cookiesync rpc sync --origin %s", hostregistry.ShellQuote(n.self))
	if _, err := n.runner.Run(ctx, peer, cmd, nil); err != nil {
		return fmt.Errorf("ssh %s: %w", peer, err)
	}
	return nil
}
