package cli

import (
	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
)

func newStateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "state",
		Short: "Inspect cookiesync's on-disk state.",
	}
	cmd.AddCommand(newStateGetJSONCmd())
	return cmd
}

func newStateGetJSONCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get-json",
		Short: "Emit the convergent browser-endpoint registry as JSON (the peer-registry read a converge pull-merges).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Read state.json directly, daemon-independent: a peer's converge shells this
			// over ssh to pull-merge our registry, so it must answer even when the local
			// daemon is down.
			reg, err := state.New(paths.Config).LoadRegistry(cmd.Context())
			if err != nil {
				return err
			}
			out, err := engine.MarshalRegistry(reg)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(append(out, '\n'))
			return err
		},
	}
	return cmd
}
