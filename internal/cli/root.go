// Package cli wires the cookiesync cobra command tree.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/yasyf/daemonkit/version"

	"github.com/yasyf/cookiesync/internal/tui"
)

// statusError carries a process exit code out of a command so a remote command's
// exit status can propagate to cookiesync's own exit code. Its message is empty
// so Execute prints nothing extra when honoring the code.
type statusError int

func (e statusError) Error() string { return "" }

// Execute builds and runs the cookiesync root command under a context canceled on
// SIGINT/SIGTERM, exiting non-zero on error.
func Execute(stampedVersion string) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	root := newRoot(version.Running(stampedVersion))
	err := root.ExecuteContext(ctx)
	if err == nil {
		return
	}
	var status statusError
	if errors.As(err, &status) {
		os.Exit(int(status))
	}
	fmt.Fprintf(os.Stderr, "cookiesync: %v\n", err)
	os.Exit(1)
}

func newRoot(version string) *cobra.Command {
	root := &cobra.Command{
		Use:           "cookiesync",
		Short:         "Sync your browser cookies across your Macs.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !isInteractive() {
				return cmd.Help()
			}
			return tui.Run(cmd.Context(), version)
		},
	}
	root.AddCommand(
		newBrowserCmd(),
		newAuthCmd(),
		newCookiesCmd(),
		newBridgeCmd(),
		newRouteConsentCmd(),
		newSelfCmd(),
		newRequestorCmd(),
		newRPCCmd(),
		newRPCServeCmd(),
		newHelperServeCmd(version),
		newInstallCmd(),
		newUninstallCmd(),
		newDoctorCmd(),
		newTUICmd(version),
	)
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	return root
}
