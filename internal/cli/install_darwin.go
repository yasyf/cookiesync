package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/cookiesync/internal/transfer"
	"github.com/yasyf/synckit/codec"
	"github.com/yasyf/synckit/hostregistry"
	"github.com/yasyf/synckit/manifest"
)

const (
	helperServeShort = "Run the resident cookiesync helper: serve the SE key cache and Touch ID consent over the RPC socket."
	installShort     = "Note the signed key helper, register cookiesync's synckit manifest, then converge synckitd's agents."
	uninstallShort   = "Remove cookiesync's synckit manifest."
)

// watchDebounce is the settle window synckitd holds a local store's write burst for
// before converging cookiesync — long enough for a rollback-journal commit's writes to
// the Cookies DB to land as one change.
const watchDebounce = 3 * time.Second

// cookiesyncManifest is the synckit manifest synckitd reads to drive cookiesync: the
// watch backend that fingerprints local stores, the exact resident transfer service,
// and the resident helper to keep alive. The service declares no socket: synckitd
// derives it from the helper's launchd label.
func cookiesyncManifest() manifest.Manifest {
	return manifest.Manifest{
		Name:   "cookiesync",
		Binary: "cookiesync",
		Brew:   "yasyf/tap/cookiesync",
		Watch: manifest.WatchSpec{
			Debounce: codec.Duration(watchDebounce),
		},
		Service: manifest.ServiceSpec{
			Kind: "resident", SchemaFingerprint: transfer.Fingerprint,
		},
		Helper: &manifest.HelperSpec{
			Command:     "helper-serve",
			SessionType: manifest.SessionTypeAqua,
		},
	}
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

// runInstall notes the signed key helper's presence, writes cookiesync's synckit
// manifest, then runs 'synckitd install' when synckitd is on PATH. That rerenders the
// resident helper's plist against the cookiesync binary PATH resolves now, so a cask
// upgrade that deleted the previous bundle leaves no plist naming it. Without synckitd,
// install points the user at it instead.
func runInstall(cmd *cobra.Command, _ []string) error {
	if err := state.New(paths.Config).Initialize(cmd.Context()); err != nil {
		return fmt.Errorf("initialize cookie-sync state: %w", err)
	}
	noteHelper(cmd)
	if err := writeManifest(cookiesyncManifest()); err != nil {
		return err
	}
	path, err := manifestPath()
	if err != nil {
		return err
	}
	cmd.Printf("Registered cookiesync manifest at %s.\n", path)
	return convergeSynckitd(cmd)
}

func convergeSynckitd(cmd *cobra.Command) error {
	synckitd, err := exec.LookPath("synckitd")
	if errors.Is(err, exec.ErrNotFound) {
		cmd.Println("Run 'synckitd install' to start the host mesh, watch supervisor, and reconcile tick.")
		return nil
	}
	if err != nil {
		return fmt.Errorf("resolve synckitd: %w", err)
	}
	install := exec.CommandContext(cmd.Context(), synckitd, "install") //nolint:gosec // synckitd resolved from PATH
	install.Stdout = cmd.OutOrStdout()
	install.Stderr = cmd.ErrOrStderr()
	if err := install.Run(); err != nil {
		return fmt.Errorf("converge synckitd agents with %s install: %w", synckitd, err)
	}
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

func runUninstall(cmd *cobra.Command, _ []string) error {
	path, err := manifestPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove cookiesync manifest %s: %w", path, err)
	}
	cmd.Println("Removed cookiesync manifest. Run 'synckitd' to stop driving it.")
	return nil
}
