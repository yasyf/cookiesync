package cli

import (
	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/daemon"
)

func newHelperServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "helper-serve",
		Short: helperServeShort,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return daemon.Serve(cmd.Context())
		},
	}
	return cmd
}

func newInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: installShort,
		Args:  cobra.NoArgs,
		RunE:  runInstall,
	}
	return cmd
}

func newUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: uninstallShort,
		Args:  cobra.NoArgs,
		RunE:  runUninstall,
	}
	return cmd
}
