package cli

import (
	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/rpc"
	"github.com/yasyf/cookiesync/internal/state"
)

// printDaemonJSON calls method on the resident daemon and writes its result as
// indented JSON, matching the Python `click.echo(json.dumps(result, indent=2))`.
func printDaemonJSON(cmd *cobra.Command, method string, params map[string]any) error {
	result, err := rpc.Call(cmd.Context(), method, params)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	_, err = cmd.OutOrStdout().Write(append(out, '\n'))
	return err
}

func newSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Ask the daemon to converge the union of every tracked endpoint across this host and its peers.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printDaemonJSON(cmd, "sync", map[string]any{})
		},
	}
	return cmd
}

func newReconcileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reconcile",
		Short: "Ask the daemon to run a full reconcile pass over every tracked browser group.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return printDaemonJSON(cmd, "reconcile", map[string]any{})
		},
	}
	return cmd
}

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
		Short: "Print this host's own SSH target, as the host registry reports it.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			reg, err := paths.Config.Load()
			if err != nil {
				return err
			}
			cmd.Println(reg.Self)
			return nil
		},
	}
	return cmd
}
