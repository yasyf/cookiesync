package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/daemon"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/codec"
	"github.com/yasyf/synckit/hostregistry"
	"github.com/yasyf/synckit/manifest"
	"github.com/yasyf/synckit/rpc"
)

// watchDebounce is the settle window synckitd holds a local store's write burst for
// before converging cookiesync — long enough for a rollback-journal commit's writes to
// the Cookies DB to land as one change.
const watchDebounce = 3 * time.Second

func newHelperServeCmd(build string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "helper-serve",
		Short: "Run the resident cookiesync helper: serve the SE key cache and Touch ID consent over the RPC socket.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return daemon.Serve(cmd.Context(), build)
		},
	}
	return cmd
}

// newRPCServeCmd builds the stdin/stdout bridge synckitd starts as cookiesync's typed
// sync service: it forwards each rpc frame on stdin to the resident helper's unix socket
// and writes the response frame back on stdout, byte-exact (it never decodes the payload,
// so a get_state response's int64 CRDT stamps survive). It is NOT a fresh daemon — it
// never primes a Secure-Enclave key nor prompts Touch ID; it bridges to the warm resident
// helper, so a cross-host svc.sync/svc.get_state reuses that peer's already-primed key.
// stdout is the framing channel, so nothing may log there on this path.
func newRPCServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rpc-serve",
		Short: "Bridge typed sync RPC frames from stdin/stdout to the resident helper's socket (used by synckitd).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sock, err := paths.SockPath()
			if err != nil {
				return err
			}
			return rpc.Proxy(cmd.Context(), os.Stdin, os.Stdout, sock)
		},
	}
	return cmd
}

func newInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Note the signed key helper, then register cookiesync's synckit manifest.",
		Args:  cobra.NoArgs,
		RunE:  runInstall,
	}
	return cmd
}

// cookiesyncManifest is the synckit manifest synckitd reads to drive cookiesync: the
// watch backend that fingerprints local stores, the typed service block synckitd drives
// reconcile/sync/state over (the rpc-serve bridge to the resident socket), and the
// resident helper to keep alive. synckitd dials the service socket directly and speaks
// the typed svc.* contract — no shell, no argv templating.
func cookiesyncManifest() (manifest.Manifest, error) {
	sock, err := paths.SockPath()
	if err != nil {
		return manifest.Manifest{}, err
	}
	return manifest.Manifest{
		Name:   "cookiesync",
		Binary: "cookiesync",
		Brew:   "yasyf/tap/cookiesync",
		Watch: manifest.WatchSpec{
			Debounce: codec.Duration(watchDebounce),
		},
		Service: manifest.ServiceSpec{
			Transport: "socket",
			ServeArgs: []string{"rpc-serve"},
			Sock:      sock,
		},
		Helper: &manifest.HelperSpec{
			Command:     "helper-serve",
			SessionType: manifest.SessionTypeAqua,
		},
	}, nil
}

// manifestPath is the file synckitd discovers cookiesync's manifest at,
// ~/.config/synckit/manifests/cookiesync.json.
func manifestPath() (string, error) {
	dir, err := hostregistry.Mesh.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "manifests", "cookiesync.json"), nil
}

// runInstall notes the signed key helper's presence, then writes cookiesync's synckit
// manifest. The helper is fetched via Homebrew (brew install yasyf/tap/cookiesync) and
// is what the helper's Secure-Enclave key vault runs inside; a missing helper is
// surfaced here (run doctor to recheck) but does not block the manifest. Convergence is
// driven by synckitd, which the user installs separately.
func runInstall(cmd *cobra.Command, _ []string) error {
	if err := state.New(paths.Config).Initialize(cmd.Context()); err != nil {
		return fmt.Errorf("initialize cookie-sync state: %w", err)
	}
	noteHelper(cmd)
	m, err := cookiesyncManifest()
	if err != nil {
		return err
	}
	if err := writeManifest(m); err != nil {
		return err
	}
	path, err := manifestPath()
	if err != nil {
		return err
	}
	cmd.Printf("Registered cookiesync manifest at %s.\n", path)
	cmd.Println("Run 'synckitd install' to start the host mesh, watch supervisor, and reconcile tick.")
	return nil
}

// writeManifest validates and writes the manifest to its synckit discovery path with
// 0o600 perms, creating the manifests dir.
func writeManifest(m manifest.Manifest) error {
	if err := m.Validate(); err != nil {
		return fmt.Errorf("build cookiesync manifest: %w", err)
	}
	path, err := manifestPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create manifests dir: %w", err)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode cookiesync manifest: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write cookiesync manifest %s: %w", path, err)
	}
	return nil
}

func newUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove cookiesync's synckit manifest.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := manifestPath()
			if err != nil {
				return err
			}
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove cookiesync manifest %s: %w", path, err)
			}
			cmd.Println("Removed cookiesync manifest. Run 'synckitd' to stop driving it.")
			return nil
		},
	}
	return cmd
}
