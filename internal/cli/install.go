package cli

import (
	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/daemon"
	"github.com/yasyf/cookiesync/internal/service"
)

// newLauncher builds the launchctl boundary install/uninstall drive. It is a package
// var so a test can swap in a fake launcher and assert the rendered plists without
// loading a real LaunchAgent on the live system; production uses launchctl.
var newLauncher = service.NewLauncher

func newWatchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Run the resident sync daemon: watch local stores and serve the RPC socket.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return daemon.Serve(cmd.Context())
		},
	}
	return cmd
}

func newInstallCmd() *cobra.Command {
	var tickOnly bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Fetch the signed key helper, then install the cookiesync LaunchAgents (watch daemon and reconcile tick).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInstall(cmd, tickOnly)
		},
	}
	cmd.Flags().BoolVar(&tickOnly, "tick-only", false, "Install only the periodic reconcile tick, not the watch daemon.")
	return cmd
}

// runInstall notes the signed key helper's presence, installs the LaunchAgents, and
// reports the frozen line. The helper is fetched via Homebrew at install
// (brew install yasyf/tap/cookiesync-keyhelper) and is what the daemon's Secure-Enclave
// key vault runs inside; a missing helper is surfaced here (run doctor to recheck) but
// does not block the agents, which fail closed at runtime if the helper is absent.
func runInstall(cmd *cobra.Command, tickOnly bool) error {
	noteHelper(cmd)
	if err := service.Install(cmd.Context(), newLauncher(), tickOnly); err != nil {
		return err
	}
	if tickOnly {
		cmd.Println("Installed the cookiesync reconcile tick.")
		return nil
	}
	cmd.Println("Installed cookiesync agents.")
	return nil
}

func newUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the cookiesync LaunchAgents.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := service.Uninstall(cmd.Context(), newLauncher()); err != nil {
				return err
			}
			cmd.Println("Uninstalled cookiesync agents.")
			return nil
		},
	}
	return cmd
}
