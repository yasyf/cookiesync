package cli

import (
	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
)

func newRouteConsentCmd() *cobra.Command {
	var hard bool
	cmd := &cobra.Command{
		Use:   "route-consent <target>",
		Short: "Route the consent gate to TARGET first when it has a live, unlocked session.",
		Long: "Route the consent gate to TARGET first when it has a live, unlocked session.\n\n" +
			"By default the gate still prefers this host when it looks locally attended. With\n" +
			"--hard, always route the consent gate to TARGET when TARGET has a live, unlocked,\n" +
			"un-shared session, even if this host looks locally attended.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			store := state.New(paths.Config)
			if err := store.SetConsentRoute(cmd.Context(), target); err != nil {
				return err
			}
			if err := store.SetConsentRouteHard(cmd.Context(), hard); err != nil {
				return err
			}
			if hard {
				cmd.Printf("Routing consent to %s (hard: overrides local presence).\n", target)
				return nil
			}
			cmd.Printf("Routing consent to %s.\n", target)
			return nil
		},
	}
	cmd.Flags().BoolVar(&hard, "hard", false, "always route the consent gate to TARGET when TARGET has a live, unlocked, un-shared session, even if this host looks locally attended")
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
