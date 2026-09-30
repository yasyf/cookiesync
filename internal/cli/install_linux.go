package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/rpc"
	"github.com/yasyf/cookiesync/internal/state"
)

const (
	helperServeShort = "Run the resident cookiesync helper: serve the in-memory key cache and routed consent over the RPC socket."
	installShort     = "Initialize state, then ensure the resident helper under the running 'cookiesync supervise'."
	uninstallShort   = "Stop the resident helper and remove it from 'cookiesync supervise'."
)

func runInstall(cmd *cobra.Command, _ []string) error {
	if err := state.New(paths.Config).Initialize(cmd.Context()); err != nil {
		return fmt.Errorf("initialize cookie-sync state: %w", err)
	}
	ensured, err := rpc.Ensure(cmd.Context())
	if err != nil {
		return fmt.Errorf("ensure the resident helper: %w", err)
	}
	cmd.Printf("Resident helper serving under 'cookiesync supervise' (%s).\n", ensured.Did)
	return nil
}

func runUninstall(cmd *cobra.Command, _ []string) error {
	if err := rpc.Stop(cmd.Context()); err != nil {
		return fmt.Errorf("stop the resident helper: %w", err)
	}
	cmd.Println("Stopped the resident helper; 'cookiesync supervise' no longer runs it.")
	return nil
}
