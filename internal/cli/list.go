package cli

import (
	"context"
	"encoding/json"
	"os"
	"sort"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/manifest"
)

func newListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Emit this host's watch items — the local endpoints synckitd watches and fingerprints.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runList(cmd, asJSON)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit the watch items as JSON.")
	return cmd
}

// runList resolves this host's local endpoints from the mesh self, fingerprints each
// present one's cookie store decryption-free, and emits the watch items synckitd's
// watch supervisor drives. It is a pure read — no daemon, no Secure Enclave, no key —
// so synckitd can shell it freely. An endpoint whose profile directory does not exist
// yet (a registered target this host has not created) is skipped, matching the watch
// supervisor's per-id "no item" treatment.
func runList(cmd *cobra.Command, asJSON bool) error {
	ctx := cmd.Context()
	self, _, err := mesh.Resolve(ctx)
	if err != nil {
		return err
	}
	st, err := state.New(paths.Config).Load(ctx)
	if err != nil {
		return err
	}
	items := make([]manifest.WatchItem, 0)
	for _, ep := range st.Endpoints() {
		if ep.Host != self {
			continue
		}
		item, ok, err := watchItem(ctx, ep)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		items = append(items, item)
	}
	if !asJSON {
		for _, item := range sortedItems(items) {
			cmd.Println(item.ID)
		}
		return nil
	}
	out, err := json.MarshalIndent(sortedItems(items), "", "  ")
	if err != nil {
		return err
	}
	_, err = cmd.OutOrStdout().Write(append(out, '\n'))
	return err
}

// watchItem builds one endpoint's watch item: its id, its profile directory (which
// holds the Cookies DB and its -wal/-shm sidecars, so a write burst across all three is
// observed), and the apply-stable logical digest of its cookie store. The digest keys
// on (host_key, name, path, last_update_utc) and never decrypts, so a self-induced write
// (which preserves last_update_utc) reproduces it — that is what lets synckitd dedup
// cookiesync's own apply without a cross-process seed. An absent profile dir yields
// ok=false.
func watchItem(ctx context.Context, ep state.Endpoint) (manifest.WatchItem, bool, error) {
	browser, err := cookie.Lookup(cookie.BrowserName(ep.Browser))
	if err != nil {
		return manifest.WatchItem{}, false, err
	}
	dir := browser.ProfileDir(ep.Profile)
	if info, statErr := os.Stat(dir); statErr != nil || !info.IsDir() {
		return manifest.WatchItem{}, false, nil
	}
	rows, err := cookie.Read(ctx, browser, ep.Profile)
	if err != nil {
		return manifest.WatchItem{}, false, err
	}
	return manifest.WatchItem{
		ID:          string(ep.ID()),
		WatchDirs:   []string{dir},
		Fingerprint: string(cookie.LogicalDigest(rows)),
	}, true, nil
}

// sortedItems returns the watch items ordered by id so the output is stable across the
// registry's unordered map.
func sortedItems(in []manifest.WatchItem) []manifest.WatchItem {
	out := append([]manifest.WatchItem(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
