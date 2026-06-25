package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
)

func newBrowserCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "browser",
		Short: "Track the browser profiles cookiesync syncs across hosts.",
	}
	cmd.AddCommand(newBrowserAddCmd(), newBrowserLsCmd(), newBrowserRmCmd())
	return cmd
}

func newBrowserAddCmd() *cobra.Command {
	var profile string
	cmd := &cobra.Command{
		Use:   "add <host> <browser>",
		Short: "Track a browser profile on HOST for syncing.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBrowserAdd(cmd, args[0], args[1], profile)
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "Default", "Profile directory name.")
	return cmd
}

func newBrowserLsCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List the tracked browser endpoints.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBrowserLs(cmd, asJSON)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit the endpoints as JSON.")
	return cmd
}

func newBrowserRmCmd() *cobra.Command {
	var profile string
	cmd := &cobra.Command{
		Use:   "rm <host> <browser>",
		Short: "Stop tracking a browser profile on HOST.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBrowserRm(cmd, args[0], args[1], profile)
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "Default", "Profile directory name.")
	return cmd
}

// runBrowserAdd validates the browser and host, then admits the endpoint into the
// convergent registry (stamping added_at so the add propagates and wins over an older
// view) and records self_target. The convergent registry converges to peers on the
// next reconcile, so the add is daemon-independent. Mirrors the Python add_endpoint.
func runBrowserAdd(cmd *cobra.Command, host, browserName, profile string) error {
	if err := validateBrowser(browserName); err != nil {
		return err
	}
	self, peers, err := mesh.Resolve(cmd.Context())
	if err != nil {
		return err
	}
	if host != self && !contains(peers, host) {
		return fmt.Errorf("unknown host %q; choose from %s", host, strings.Join(append([]string{self}, peers...), ", "))
	}
	endpoint := state.Endpoint{Host: host, Browser: browserName, Profile: profile}
	if err := state.New(paths.Config).AddBrowser(cmd.Context(), self, endpoint); err != nil {
		return err
	}
	cmd.Printf("Tracking %s\n", endpoint.ID())
	return nil
}

// runBrowserLs lists the present (non-tombstoned) tracked endpoints. JSON emits the
// frozen [{"host","browser","profile"}, ...] array (indented); text emits one endpoint
// id per line, or "No tracked browsers." when empty. Mirrors the Python list_endpoints.
func runBrowserLs(cmd *cobra.Command, asJSON bool) error {
	st, err := state.New(paths.Config).Load(cmd.Context())
	if err != nil {
		return err
	}
	endpoints := sortedEndpoints(st.Endpoints())
	if asJSON {
		payload := make([]endpointJSON, len(endpoints))
		for i, e := range endpoints {
			payload[i] = endpointJSON{Host: e.Host, Browser: e.Browser, Profile: e.Profile}
		}
		out, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(append(out, '\n'))
		return err
	}
	if len(endpoints) == 0 {
		cmd.Println("No tracked browsers.")
		return nil
	}
	ids := make([]string, len(endpoints))
	for i, e := range endpoints {
		ids[i] = string(e.ID())
	}
	cmd.Println(strings.Join(ids, "\n"))
	return nil
}

// runBrowserRm tombstones the endpoint in the convergent registry (stamping removed_at
// so the delete propagates and survives a sync with a host that never saw it). Mirrors
// the Python remove_endpoint.
func runBrowserRm(cmd *cobra.Command, host, browserName, profile string) error {
	endpoint := state.Endpoint{Host: host, Browser: browserName, Profile: profile}
	if err := state.New(paths.Config).RemoveBrowser(cmd.Context(), endpoint); err != nil {
		return err
	}
	cmd.Printf("Untracked %s\n", endpoint.ID())
	return nil
}

// endpointJSON is the frozen browser-ls JSON object: host, browser, profile in that
// field order, matching the Python BrowserEndpoint.to_json.
type endpointJSON struct {
	Host    string `json:"host"`
	Browser string `json:"browser"`
	Profile string `json:"profile"`
}

// validateBrowser rejects a browser not in the registry, listing the known ones, so a
// typo fails before any state write. Mirrors the Python "unknown browser" guard.
func validateBrowser(name string) error {
	registry, err := cookie.Registry()
	if err != nil {
		return err
	}
	if _, ok := registry[cookie.BrowserName(name)]; ok {
		return nil
	}
	known := make([]string, 0, len(registry))
	for n := range registry {
		known = append(known, string(n))
	}
	sort.Strings(known)
	return fmt.Errorf("unknown browser %q; choose from %s", name, strings.Join(known, ", "))
}

// sortedEndpoints returns endpoints ordered by id, so ls output is stable across the
// registry's unordered map.
func sortedEndpoints(in []state.Endpoint) []state.Endpoint {
	out := append([]state.Endpoint(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
