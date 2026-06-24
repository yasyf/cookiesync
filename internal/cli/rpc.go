package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/paths"
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

// rpcNotImplemented resolves the daemon socket path (the real dependency every
// rpc subcommand will dial) and folds it into the not-implemented error, so the
// path logic is pinned now and the message names the socket the later cycle wires.
func rpcNotImplemented(method string) error {
	sock, err := paths.SockPath()
	if err != nil {
		return err
	}
	return fmt.Errorf("rpc %s via %s: %w", method, sock, errNotImplemented)
}

func newRPCExtractCmd() *cobra.Command {
	var browser, profile, origin string
	cmd := &cobra.Command{
		Use:   "extract",
		Short: "Return this host's decrypted cookies for a browser as wire records (used by peers over ssh).",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return rpcNotImplemented("extract")
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
		RunE: func(_ *cobra.Command, _ []string) error {
			return rpcNotImplemented("apply")
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
		RunE: func(_ *cobra.Command, _ []string) error {
			return rpcNotImplemented("sync")
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
		RunE: func(_ *cobra.Command, _ []string) error {
			return rpcNotImplemented("reconcile")
		},
	}
	return cmd
}

func newRPCWhoamiCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Report this host's console session state.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return rpcNotImplemented("whoami")
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
		RunE: func(_ *cobra.Command, _ []string) error {
			return rpcNotImplemented("request_consent")
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
