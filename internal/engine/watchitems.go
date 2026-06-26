package engine

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/syncservice"
)

// WatchItems resolves this host's local endpoints from the mesh self, fingerprints each
// present one's cookie store decryption-free, and returns the watch items synckitd's
// watch supervisor drives. It is a pure read — no daemon, no Secure Enclave, no key — so
// the resident helper serves it freely behind svc.list. An endpoint whose profile
// directory does not exist yet (a registered target this host has not created) is
// skipped, matching the watch supervisor's per-id "no item" treatment. A per-endpoint
// read error is logged to stderr and the endpoint skipped, never failing the whole pass
// nor leaking onto the framing stdout. The items are sorted by id so the output is stable
// across the registry's unordered map.
func WatchItems(ctx context.Context, store StateLoader) ([]syncservice.WatchItem, error) {
	self, _, err := mesh.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	st, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}
	items := make([]syncservice.WatchItem, 0)
	for _, ep := range st.Endpoints() {
		if ep.Host != self {
			continue
		}
		item, ok, err := watchItem(ctx, ep)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cookiesync: skip watch item %s: %v\n", ep.ID(), err)
			continue
		}
		if !ok {
			continue
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items, nil
}

// StateLoader loads cookiesync's state. It is the read seam WatchItems resolves the
// tracked endpoints through, injected so the listing runs against a fixture state.
type StateLoader interface {
	Load(ctx context.Context) (*state.State, error)
}

// watchItem builds one endpoint's watch item: its id, its profile directory (which holds
// the Cookies DB and its -wal/-shm sidecars, so a write burst across all three is
// observed), and the apply-stable logical digest of its cookie store. The digest keys on
// (host_key, name, path, last_update_utc) and never decrypts, so a self-induced write
// (which preserves last_update_utc) reproduces it — that is what lets synckitd dedup
// cookiesync's own apply without a cross-process seed. An absent profile dir yields
// ok=false.
func watchItem(ctx context.Context, ep state.Endpoint) (syncservice.WatchItem, bool, error) {
	browser, err := cookie.Lookup(cookie.BrowserName(ep.Browser))
	if err != nil {
		return syncservice.WatchItem{}, false, err
	}
	dir := browser.ProfileDir(ep.Profile)
	if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
		return syncservice.WatchItem{}, false, nil
	}
	rows, err := cookie.Read(ctx, browser, ep.Profile)
	if err != nil {
		return syncservice.WatchItem{}, false, err
	}
	return syncservice.WatchItem{
		ID:          string(ep.ID()),
		WatchDirs:   []string{dir},
		Fingerprint: string(cookie.LogicalDigest(rows)),
	}, true, nil
}
