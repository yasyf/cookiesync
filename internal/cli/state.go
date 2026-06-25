package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/cregistry"
)

func newStateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "state",
		Short: "Inspect and converge cookiesync's on-disk state.",
	}
	cmd.AddCommand(newStateGetJSONCmd(), newStateApplyJSONCmd())
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
			// helper is down.
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

func newStateApplyJSONCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apply-json",
		Short: "Merge a convergent browser-endpoint registry from stdin into local state (the apply side of a converge).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// synckitd pipes the merged registry to stdin; merge it (an LWW-set, so the
			// join is never destructive) into local state through the foreign-key-preserving
			// writer, which preserves self_target, settings, consent_route_to, and the host
			// registry's own keys. Daemon-independent: a converge writes our registry without
			// the resident helper.
			raw, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("read registry from stdin: %w", err)
			}
			incoming := cregistry.New[state.EndpointMeta]()
			if err := json.Unmarshal(raw, &incoming); err != nil {
				return fmt.Errorf("parse registry from stdin: %w", err)
			}
			merged, err := state.New(paths.Config).MergeRegistry(cmd.Context(), incoming)
			if err != nil {
				return err
			}
			out, err := json.Marshal(map[string]any{"applied": len(merged.Present())})
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(append(out, '\n'))
			return err
		},
	}
	return cmd
}
