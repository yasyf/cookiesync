package cli

import (
	"github.com/spf13/cobra"
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
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
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
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
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
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
	cmd.Flags().StringVar(&profile, "profile", "Default", "Profile directory name.")
	return cmd
}
