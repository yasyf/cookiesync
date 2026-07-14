package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

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
		newRPCGetCookiesCmd(),
		newRPCGetWebStorageCmd(),
		newRPCApplyCmd(),
		newRPCSyncCmd(),
		newRPCReconcileCmd(),
		newRPCWhoamiCmd(),
		newRPCRequestConsentCmd(),
		newRPCBridgeConsentCmd(),
		newRPCBridgeOpenCmd(),
		newRPCBridgeCloseCmd(),
		newRPCBridgeKeepaliveCmd(),
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
			params := map[string]any{"browser": browser, "profile": profile, "origin": origin}
			if r, ok := resolveRequestor(); ok {
				params["requestor"] = r
			}
			return rpcPassthrough(cmd, "extract", params)
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "", "The browser to extract cookies from.")
	cmd.Flags().StringVar(&profile, "profile", "Default", "The profile to extract cookies from.")
	cmd.Flags().StringVar(&origin, "origin", "", "Anti-echo provenance tag from the notifying peer.")
	_ = cmd.MarkFlagRequired("browser")
	return cmd
}

func newRPCGetCookiesCmd() *cobra.Command {
	var browser, profile, origin string
	cmd := &cobra.Command{
		Use:   "get_cookies <url>...",
		Short: "Return this host's decrypted cookies for one or more urls as wire records (used by peers over ssh).",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// A passthrough to the resident daemon's single-browser path. --browser is
			// required and must be non-empty: the recursion guard so a peer daemon always
			// takes the single path and never re-fans-out the union over ssh
			// (MarkFlagRequired only proves the flag was set, so a bare "" would slip past
			// it into the union branch). origin keys the host grant like extract, so a
			// union caller's first pull prompts the peer once and the grant window keeps
			// the rest silent.
			if browser == "" {
				return fmt.Errorf("--browser must not be empty")
			}
			params := map[string]any{
				"browser": browser, "profile": profile, "origin": origin,
				"url": args[0], "urls": asAnySlice(args),
			}
			if r, ok := resolveRequestor(); ok {
				params["requestor"] = r
			}
			return rpcPassthrough(cmd, "get_cookies", params)
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "", "The browser to read cookies from.")
	cmd.Flags().StringVar(&profile, "profile", "Default", "The profile to read cookies from.")
	cmd.Flags().StringVar(&origin, "origin", "", "Anti-echo provenance tag from the notifying peer.")
	_ = cmd.MarkFlagRequired("browser")
	return cmd
}

func newRPCGetWebStorageCmd() *cobra.Command {
	var browser, profile string
	cmd := &cobra.Command{
		Use:   "get_web_storage <url>...",
		Short: "Return this host's localStorage + sessionStorage for one or more urls' origins (local browsers only).",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// A passthrough to the resident daemon's local-only web-storage read. It is
			// consent-gated like get_cookies; web storage is never pulled across hosts, so
			// there is no ssh fan-out. --browser scopes to one browser (else every local
			// browser is unioned), pairing with the same-browser cookies read.
			params := map[string]any{"url": args[0], "urls": asAnySlice(args)}
			if browser != "" {
				params["browser"] = browser
				params["profile"] = profile
			}
			if r, ok := resolveRequestor(); ok {
				params["requestor"] = r
			}
			return rpcPassthrough(cmd, "get_web_storage", params)
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "", "The browser to read web storage from; omitted unions every registered local browser.")
	cmd.Flags().StringVar(&profile, "profile", "Default", "The profile to read web storage from (requires --browser).")
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

func newRPCBridgeConsentCmd() *cobra.Command {
	var browser, profile, nonce, endpoint string
	cmd := &cobra.Command{
		Use:   "request_bridge_consent",
		Short: "Approve a live browser bridge here behind a strict biometric tap and echo the requester's nonce + endpoint.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return rpcPassthrough(cmd, "request_bridge_consent", map[string]any{
				"browser":  browser,
				"profile":  profile,
				"nonce":    nonce,
				"endpoint": endpoint,
			})
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "", "The browser to gate the bridge seed for.")
	cmd.Flags().StringVar(&profile, "profile", "Default", "The profile to gate the bridge seed for.")
	cmd.Flags().StringVar(&nonce, "nonce", "", "Opaque nonce the peer echoes back to bind the request.")
	cmd.Flags().StringVar(&endpoint, "endpoint", "", "The endpoint id the consent is bound to.")
	_ = cmd.MarkFlagRequired("browser")
	_ = cmd.MarkFlagRequired("nonce")
	_ = cmd.MarkFlagRequired("endpoint")
	return cmd
}

func newRPCBridgeOpenCmd() *cobra.Command {
	var browser, profile, host, origin, advertise string
	var headless bool
	cmd := &cobra.Command{
		Use:   "bridge_open",
		Short: "Ask the daemon to open a cookie-seeded CDP bridge and return its ws endpoint.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return rpcPassthrough(cmd, "bridge_open", map[string]any{
				"host":      host,
				"browser":   browser,
				"profile":   profile,
				"headed":    !headless,
				"origin":    origin,
				"advertise": advertise,
			})
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "", "The browser to seed the bridge from.")
	cmd.Flags().StringVar(&profile, "profile", "Default", "The profile to seed the bridge from.")
	cmd.Flags().StringVar(&host, "host", "", "The host that owns the browser (empty = local).")
	cmd.Flags().BoolVar(&headless, "headless", false, "Run Chrome headless.")
	cmd.Flags().StringVar(&origin, "origin", "", "Originating host named in the bridge consent prompt (display only).")
	cmd.Flags().StringVar(&advertise, "advertise", "", "host:port baked into /json/version for a cross-host ssh -L client.")
	_ = cmd.MarkFlagRequired("browser")
	return cmd
}

func newRPCBridgeKeepaliveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bridge_keepalive",
		Short: "Hold a cross-host bridge alive: read its capability from stdin, then block until the origin closes the pipe.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBridgeKeepalive(cmd)
		},
	}
	return cmd
}

// runBridgeKeepalive reads the bridge capability off stdin (never argv), holds the
// daemon-side supervisor open, and exits — closing the socket so the peer reaps the
// bridge — on the first of the origin closing our stdin (its EOF) or the hold
// returning (the peer's daemon restarted or timed out; without this the ssh child
// would linger and the origin would never see the drop).
func runBridgeKeepalive(cmd *cobra.Command) error {
	reader := bufio.NewReader(cmd.InOrStdin())
	line, err := reader.ReadString('\n')
	capability := strings.TrimSpace(line)
	if capability == "" {
		if err != nil {
			return fmt.Errorf("read bridge capability from stdin: %w", err)
		}
		return errors.New("bridge_keepalive: empty capability on stdin")
	}
	callDone := make(chan struct{})
	go func() {
		_, _ = rpc.Call(context.Background(), "bridge_keepalive", map[string]any{"capability": capability})
		close(callDone)
	}()
	stdinDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, reader)
		close(stdinDone)
	}()
	select {
	case <-callDone:
	case <-stdinDone:
	}
	return nil
}

func newRPCBridgeCloseCmd() *cobra.Command {
	var capability string
	cmd := &cobra.Command{
		Use:   "bridge_close",
		Short: "Ask the daemon to tear down a bridge session by its capability (--capability, or on stdin when omitted).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolved, err := bridgeCapability(cmd, capability)
			if err != nil {
				return err
			}
			return rpcPassthrough(cmd, "bridge_close", map[string]any{"capability": resolved})
		},
	}
	cmd.Flags().StringVar(&capability, "capability", "", "The bridge capability to close (omit to read it from stdin).")
	return cmd
}

// bridgeCapability resolves the bridge capability from the --capability flag or, when
// empty, one line of stdin — the cross-host close path pipes it over ssh stdin so it
// never appears in the peer's process args; the local path passes the flag.
func bridgeCapability(cmd *cobra.Command, flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	capability := strings.TrimSpace(line)
	if capability == "" {
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read bridge capability from stdin: %w", err)
		}
		return "", errors.New("bridge_close: a --capability or a stdin capability is required")
	}
	return capability, nil
}
