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
)

// errNotImplemented marks a command whose subsystem (crypto, sqlite, merge,
// swift-integration, driver, watch) lands in a later cycle. The scaffold pins
// the command surface now; the handler fails loudly until it is filled in.
var errNotImplemented = errors.New("not implemented yet (phase 3)")

// statusError carries a process exit code out of a command so a remote command's
// exit status can propagate to cookiesync's own exit code. Its message is empty
// so Execute prints nothing extra when honoring the code.
type statusError int

func (e statusError) Error() string { return "" }

// Execute builds and runs the cookiesync root command under a context canceled on
// SIGINT/SIGTERM, exiting non-zero on error.
func Execute(version string) {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	root := newRoot(version)
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
			return cmd.Help()
		},
	}
	root.AddCommand(
		newBrowserCmd(),
		newAuthCmd(),
		newCookiesCmd(),
		newSyncCmd(),
		newReconcileCmd(),
		newRouteConsentCmd(),
		newSelfCmd(),
		newRPCCmd(),
		newWatchCmd(),
		newInstallCmd(),
		newUninstallCmd(),
		newDoctorCmd(),
	)
	return root
}
