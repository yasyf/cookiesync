package cli

import (
	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
)

func newRouteConsentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "route-consent <target>",
		Short: "Route the consent gate to TARGET first when it has a live, unlocked session.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			if err := state.New(paths.Config).SetConsentRoute(cmd.Context(), target); err != nil {
				return err
			}
			cmd.Printf("Routing consent to %s.\n", target)
			return nil
		},
	}
	return cmd
}

func newSelfCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "self",
		Short: "Print this host's own SSH target, as the synckit host mesh reports it.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			self, _, err := mesh.Resolve(cmd.Context())
			if err != nil {
				return err
			}
			cmd.Println(self)
			return nil
		},
	}
	return cmd
}
