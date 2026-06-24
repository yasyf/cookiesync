package cli

import (
	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/daemon"
)

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
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
	cmd.Flags().BoolVar(&tickOnly, "tick-only", false, "Install only the periodic reconcile tick, not the watch daemon.")
	return cmd
}

func newUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the cookiesync LaunchAgents.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
	return cmd
}

func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check that the signed Secure-Enclave key helper is installed and Developer-ID-signed.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
	return cmd
}
