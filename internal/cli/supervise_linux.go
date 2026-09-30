package cli

import (
	"github.com/spf13/cobra"
	"github.com/yasyf/daemonkit"

	"github.com/yasyf/cookiesync/internal/daemon"
)

func platformCmds() []*cobra.Command {
	return []*cobra.Command{newSuperviseCmd()}
}

func newSuperviseCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "supervise",
		Short:  "Supervise the resident cookiesync helper in the foreground.",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			spec, err := daemon.HelperSpec()
			if err != nil {
				return err
			}
			return daemonkit.Supervise(cmd.Context(), spec.Label)
		},
	}
}
