package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
)

func newSettingsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "settings",
		Short: "Change the cadence settings stored in this host's state.json.",
	}
	cmd.AddCommand(newSettingsWatchDebounceCmd())
	return cmd
}

func newSettingsWatchDebounceCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "watch-debounce <duration>",
		Short: "Store the watch debounce (Go-style duration, e.g. 10s) that 'cookiesync install' writes into the synckit manifest.",
		Long: "Store the watch debounce (Go-style duration, e.g. 10s) that 'cookiesync install' writes into the synckit manifest.\n\n" +
			"Writes only cookie_sync.settings.watch_debounce in state.json. The manifest and the\n" +
			"running services are left alone until the next 'cookiesync install'.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSettingsWatchDebounce(cmd, args[0])
		},
	}
}

func runSettingsWatchDebounce(cmd *cobra.Command, text string) error {
	debounce, err := state.ParseDuration(text)
	if err != nil {
		return err
	}
	if debounce <= 0 {
		return fmt.Errorf("watch debounce %s must be positive", text)
	}
	if err := state.New(paths.Config).SetWatchDebounce(cmd.Context(), debounce); err != nil {
		return err
	}
	cmd.Printf("Stored watch debounce %s in state.json.\n", state.FormatDuration(debounce))
	return nil
}
