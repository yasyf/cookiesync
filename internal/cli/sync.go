package cli

import (
	"github.com/spf13/cobra"
)

func newSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Ask the daemon to converge the union of every tracked endpoint across this host and its peers.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
	return cmd
}

func newReconcileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reconcile",
		Short: "Ask the daemon to run a full reconcile pass over every tracked browser group.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
	return cmd
}

func newRouteConsentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "route-consent <target>",
		Short: "Route the consent gate to TARGET first when it has a live, unlocked session.",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
	return cmd
}

func newSelfCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "self",
		Short: "Print this host's own SSH target, as reposync reports it.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
	return cmd
}
