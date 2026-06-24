package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/rpc"
)

func newRPCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rpc",
		Short: "Low-level RPC client: drive the resident daemon over its unix socket.",
	}
	cmd.AddCommand(
		newRPCExtractCmd(),
		newRPCApplyCmd(),
		newRPCSyncCmd(),
		newRPCReconcileCmd(),
		newRPCWhoamiCmd(),
		newRPCRequestConsentCmd(),
	)
	return cmd
}

// rpcPassthrough calls method on the resident daemon and writes the result as one
// compact JSON line to the command's stdout — the frozen shape peers and the
// agent-browser skill parse off ssh.
func rpcPassthrough(cmd *cobra.Command, method string, params map[string]any) error {
	result, err := rpc.Call(cmd.Context(), method, params)
	if err != nil {
		return err
	}
	line, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = cmd.OutOrStdout().Write(append(line, '\n'))
	return err
}

// readWireCookies reads the bare JSON array of wire cookies the rpc apply stdin
// contract carries, returning it as the generic slice the apply param forwards to the
// daemon unchanged.
func readWireCookies(r io.Reader) ([]any, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var cookies []any
	if err := json.Unmarshal(data, &cookies); err != nil {
		return nil, fmt.Errorf("parse cookies from stdin: %w", err)
	}
	return cookies, nil
}

func newRPCExtractCmd() *cobra.Command {
	var browser, profile, origin string
	cmd := &cobra.Command{
		Use:   "extract",
		Short: "Return this host's decrypted cookies for a browser as wire records (used by peers over ssh).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// A passthrough to the resident daemon: it extracts with the cached key
			// (priming behind consent when cold), so a peer's pull reuses the warm key
			// and never prompts a fresh tap per sync. origin is carried for symmetry; a
			// direct extract has no echo to suppress.
			return rpcPassthrough(cmd, "extract", map[string]any{"browser": browser, "profile": profile, "origin": origin})
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "", "The browser to extract cookies from.")
	cmd.Flags().StringVar(&profile, "profile", "Default", "The profile to extract cookies from.")
	cmd.Flags().StringVar(&origin, "origin", "", "Anti-echo provenance tag from the notifying peer.")
	_ = cmd.MarkFlagRequired("browser")
	return cmd
}

func newRPCApplyCmd() *cobra.Command {
	var browser, profile, origin string
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Ingest a merged wire cookie array from stdin into this host's store (used by peers over ssh).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cookies, err := readWireCookies(cmd.InOrStdin())
			if err != nil {
				return err
			}
			// A passthrough to the resident daemon: it records the anti-echo digest and
			// writes with the cached key. origin is carried for symmetry.
			return rpcPassthrough(cmd, "apply", map[string]any{
				"browser": browser, "profile": profile, "origin": origin, "cookies": cookies,
			})
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "", "The browser to apply cookies to.")
	cmd.Flags().StringVar(&profile, "profile", "Default", "The profile to apply cookies to.")
	cmd.Flags().StringVar(&origin, "origin", "", "Anti-echo provenance tag from the notifying peer.")
	_ = cmd.MarkFlagRequired("browser")
	return cmd
}

func newRPCSyncCmd() *cobra.Command {
	var origin string
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Ask the daemon to converge the union of every tracked endpoint, tagged with the notifying peer's origin.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return rpcPassthrough(cmd, "sync", map[string]any{"origin": origin})
		},
	}
	cmd.Flags().StringVar(&origin, "origin", "", "Anti-echo provenance tag from the notifying peer.")
	return cmd
}

func newRPCReconcileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reconcile",
		Short: "Ask the daemon to run a full reconcile pass.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return rpcPassthrough(cmd, "reconcile", map[string]any{})
		},
	}
	return cmd
}

func newRPCWhoamiCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Report this host's console session state.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return rpcPassthrough(cmd, "whoami", map[string]any{})
		},
	}
	return cmd
}

func newRPCRequestConsentCmd() *cobra.Command {
	var browser, profile, nonce, endpoint string
	cmd := &cobra.Command{
		Use:   "request_consent",
		Short: "Show the Touch ID prompt for BROWSER here and echo the requester's nonce + endpoint.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return rpcPassthrough(cmd, "request_consent", map[string]any{
				"browser":  browser,
				"profile":  profile,
				"nonce":    nonce,
				"endpoint": endpoint,
			})
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "", "The browser to release the key for.")
	cmd.Flags().StringVar(&profile, "profile", "Default", "The profile to release the key for.")
	cmd.Flags().StringVar(&nonce, "nonce", "", "Opaque nonce the peer echoes back to bind the request.")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "The endpoint id the consent is bound to.")
	_ = cmd.MarkFlagRequired("browser")
	_ = cmd.MarkFlagRequired("nonce")
	_ = cmd.MarkFlagRequired("endpoint")
	return cmd
}
