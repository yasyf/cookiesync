package cli

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/bridge"
)

func newBridgeChromeChildCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "_bridge-chrome-child <binary> <data-dir> <headed>",
		Hidden: true,
		Args:   cobra.ExactArgs(3),
		RunE: func(_ *cobra.Command, args []string) error {
			headed, err := strconv.ParseBool(args[2])
			if err != nil {
				return err
			}
			return bridge.RunChromeChild(args[0], args[1], headed)
		},
	}
}
