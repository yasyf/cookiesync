package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/rpc"
)

// bridgeDefaultProfile is the profile a bridge target assumes when none is
// given, matching the daemon default.
const bridgeDefaultProfile = "Default"

// bridgeOpenResult is the frozen bridge_open reply.
type bridgeOpenResult struct {
	ProtocolVersion uint64     `json:"protocol_version"`
	URL             string     `json:"url"`
	Endpoint        string     `json:"endpoint"`
	Browser         string     `json:"browser"`
	Profile         string     `json:"profile"`
	Capability      string     `json:"capability"`
	ExpiresIn       float64    `json:"expires_in"`
	Seed            seedReport `json:"seed"`
}

// seedReport mirrors the daemon's per-cause seed breakdown: Attempted ==
// Seeded + Undecryptable + Expired + CDPRejected, and Skipped is their sum.
type seedReport struct {
	Attempted     int              `json:"attempted"`
	Seeded        int              `json:"seeded"`
	Skipped       int              `json:"skipped"`
	Undecryptable int              `json:"undecryptable"`
	Expired       int              `json:"expired"`
	CDPRejected   int              `json:"cdp_rejected"`
	Rejected      []rejectedCookie `json:"rejected,omitempty"`
}

// rejectedCookie is a cookie Chrome refused during seeding and the reason.
type rejectedCookie struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Reason string `json:"reason"`
}

// bridgeOpenJSON is the `bridge open --json` shape: the endpoint fields a consumer
// needs, without the management capability openBridge persists client-side.
type bridgeOpenJSON struct {
	ProtocolVersion uint64  `json:"protocol_version"`
	URL             string  `json:"url"`
	Endpoint        string  `json:"endpoint"`
	Browser         string  `json:"browser"`
	Profile         string  `json:"profile"`
	ExpiresIn       float64 `json:"expires_in"`
}

// bridgeStatusResult is the frozen bridge_status reply; empty when the session
// is gone.
type bridgeStatusResult struct {
	ProtocolVersion uint64  `json:"protocol_version"`
	Endpoint        string  `json:"endpoint"`
	Browser         string  `json:"browser"`
	Profile         string  `json:"profile"`
	ExpiresIn       float64 `json:"expires_in"`
	PID             int     `json:"pid"`
}

// bridgeStopResult is the --json shape of a completed stop: the endpoint torn
// down and the closed flag.
type bridgeStopResult struct {
	ProtocolVersion uint64 `json:"protocol_version"`
	Endpoint        string `json:"endpoint"`
	Closed          bool   `json:"closed"`
}

type bridgeListJSON struct {
	ProtocolVersion uint64               `json:"protocol_version"`
	Sessions        []bridgeStatusResult `json:"sessions"`
}

// openBridge runs the tapped, consent-gated bridge_open behind both `bridge
// open` and the plugin's browser.launch, persisting the capability and tearing
// the session down if it can't be saved. A package var for the plugin tests' stub.
var openBridge = func(ctx context.Context, host, browser, profile string, headed bool) (bridgeOpenResult, error) {
	key := bridgeCapKey(host, browser, profile)
	params := map[string]any{
		"browser": browser,
		"profile": profile,
		"host":    host,
		"headed":  headed,
	}
	if r, ok := resolveRequestor(); ok {
		params["requestor"] = r
	}
	if capability, ok := loadCap(key); ok {
		params["capability"] = capability
	}
	var resp bridgeOpenResult
	if err := rpc.CallJSON(ctx, "bridge_open", params, &resp); err != nil {
		return bridgeOpenResult{}, err
	}
	if resp.ProtocolVersion != cookie.ProtocolVersion {
		return bridgeOpenResult{}, fmt.Errorf("bridge protocol version %d, want %d", resp.ProtocolVersion, cookie.ProtocolVersion)
	}
	if err := saveCap(key, resp.Capability); err != nil {
		var closed struct {
			ProtocolVersion uint64 `json:"protocol_version"`
			Closed          bool   `json:"closed"`
		}
		_ = rpc.CallJSON(ctx, "bridge_close", map[string]any{"capability": resp.Capability}, &closed)
		return bridgeOpenResult{}, err
	}
	return resp, nil
}

// stopBridge closes the saved bridge for key host:browser:profile and drops its
// capability, behind both `bridge stop` and the plugin's browser.close.
var stopBridge = func(ctx context.Context, key string) error {
	capability, ok := loadCap(key)
	if !ok {
		return fmt.Errorf("no saved bridge for %s", key)
	}
	var resp struct {
		ProtocolVersion uint64 `json:"protocol_version"`
		Closed          bool   `json:"closed"`
	}
	if err := rpc.CallJSON(ctx, "bridge_close", map[string]any{"capability": capability}, &resp); err != nil {
		return err
	}
	if resp.ProtocolVersion != cookie.ProtocolVersion {
		return fmt.Errorf("bridge protocol version %d, want %d", resp.ProtocolVersion, cookie.ProtocolVersion)
	}
	return removeCap(key)
}

// newBridgeCmd builds the bridge command tree: open a live, cookie-seeded Chrome
// DevTools bridge, list running sessions, and stop one.
func newBridgeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bridge",
		Short: "Open a live, cookie-seeded Chrome DevTools bridge for agent-browser.",
	}
	cmd.AddCommand(newBridgeOpenCmd(), newBridgeLsCmd(), newBridgeStopCmd(), newBridgePluginCmd())
	return cmd
}

func newBridgeOpenCmd() *cobra.Command {
	var headed, headless, asJSON bool
	var browser, profile string
	cmd := &cobra.Command{
		Use:   "open [host:browser:profile]",
		Short: "Launch a throwaway Chrome seeded with your cookies and print its ws:// endpoint.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host, br, prof, err := parseBridgeTarget(arg(args), browser, profile)
			if err != nil {
				return err
			}
			resp, err := openBridge(cmd.Context(), host, br, prof, headed && !headless)
			if err != nil {
				return err
			}
			if asJSON {
				return writeBridgeJSON(cmd.OutOrStdout(), bridgeOpenJSON{
					ProtocolVersion: cookie.ProtocolVersion,
					URL:             resp.URL,
					Endpoint:        resp.Endpoint,
					Browser:         resp.Browser,
					Profile:         resp.Profile,
					ExpiresIn:       resp.ExpiresIn,
				})
			}
			printBridgeReady(cmd, resp)
			return nil
		},
	}
	cmd.Flags().BoolVar(&headed, "headed", true, "Run Chrome headed (default) for fidelity.")
	cmd.Flags().BoolVar(&headless, "headless", false, "Run Chrome headless (--headless=new).")
	cmd.Flags().StringVar(&browser, "browser", "", "The browser to seed the bridge from.")
	cmd.Flags().StringVar(&profile, "profile", "", "The profile to seed the bridge from.")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit the bridge endpoint as JSON.")
	return cmd
}

func newBridgeLsCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List live bridge sessions.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			caps, err := listCaps()
			if err != nil {
				return err
			}
			live := []bridgeStatusResult{}
			for _, entry := range caps {
				var st bridgeStatusResult
				if err := rpc.CallJSON(cmd.Context(), "bridge_status", map[string]any{"capability": entry.capability}, &st); err != nil {
					return err
				}
				if st.ProtocolVersion != cookie.ProtocolVersion {
					return fmt.Errorf("bridge protocol version %d, want %d", st.ProtocolVersion, cookie.ProtocolVersion)
				}
				if st.Endpoint == "" {
					_ = os.Remove(entry.path)
					continue
				}
				live = append(live, st)
			}
			if asJSON {
				return writeBridgeJSON(cmd.OutOrStdout(), bridgeListJSON{
					ProtocolVersion: cookie.ProtocolVersion, Sessions: live,
				})
			}
			for _, st := range live {
				cmd.Printf("%s · expires in %s · pid %d\n", st.Endpoint, formatTTL(st.ExpiresIn), st.PID)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit the live bridge sessions as JSON.")
	return cmd
}

func newBridgeStopCmd() *cobra.Command {
	var browser, profile string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "stop [host:browser:profile]",
		Short: "Tear down a live bridge session.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			host, br, prof, err := parseBridgeTarget(arg(args), browser, profile)
			if err != nil {
				return err
			}
			key := bridgeCapKey(host, br, prof)
			if err := stopBridge(cmd.Context(), key); err != nil {
				return err
			}
			if asJSON {
				return writeBridgeJSON(cmd.OutOrStdout(), bridgeStopResult{
					ProtocolVersion: cookie.ProtocolVersion, Endpoint: key, Closed: true,
				})
			}
			cmd.Printf("bridge closed · %s\n", key)
			return nil
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "", "The browser whose bridge to stop.")
	cmd.Flags().StringVar(&profile, "profile", "", "The profile whose bridge to stop.")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit the closed endpoint as JSON.")
	return cmd
}

// arg returns the single optional positional, or "".
func arg(args []string) string {
	if len(args) == 1 {
		return args[0]
	}
	return ""
}

// parseBridgeTarget resolves a "[host:]browser[:profile]" target, with the
// --browser/--profile flags filling the fields the positional omits.
func parseBridgeTarget(target, browser, profile string) (host, br, prof string, err error) {
	br, prof = browser, profile
	if target != "" {
		parts := strings.SplitN(target, ":", 3)
		switch len(parts) {
		case 1:
			br = parts[0]
		case 2:
			host, br = parts[0], parts[1]
		case 3:
			host, br, prof = parts[0], parts[1], parts[2]
		}
	}
	if br == "" {
		return "", "", "", errors.New(`bridge: a browser is required (as "[host:]browser[:profile]" or --browser)`)
	}
	if prof == "" {
		prof = bridgeDefaultProfile
	}
	return host, br, prof, nil
}

// bridgeCapKey is the stable client-side lookup key for a target's capability.
func bridgeCapKey(host, browser, profile string) string {
	return host + ":" + browser + ":" + profile
}

func printBridgeReady(cmd *cobra.Command, r bridgeOpenResult) {
	s := r.Seed
	cmd.Printf("bridge ready · %s/%s   (expires in %s)\n", r.Browser, r.Profile, formatTTL(r.ExpiresIn))
	cmd.Printf("  seeded %d/%d cookies · skipped=%d (undecryptable=%d, expired=%d, cdp-rejected=%d)\n",
		s.Seeded, s.Attempted, s.Skipped, s.Undecryptable, s.Expired, s.CDPRejected)
	for _, rc := range s.Rejected {
		cmd.Printf("    rejected %s @ %s: %s\n", rc.Name, rc.Domain, rc.Reason)
	}
	cmd.Printf("  agent-browser connect '%s'\n", r.URL)
	cmd.Printf("  # or:  export AGENT_BROWSER_CDP='%s'\n", r.URL)
	cmd.Printf("  # raw Playwright:  chromium.connectOverCDP('%s')\n", r.URL)
	cmd.Printf("  # drive the existing page — a fresh default-context page won't see your cookies\n")
}

func formatTTL(seconds float64) string {
	return time.Duration(seconds * float64(time.Second)).Round(time.Second).String()
}

// writeBridgeJSON marshals v as indented JSON with a trailing newline — the
// --json shape across the bridge subcommands, mirroring browser ls --json.
func writeBridgeJSON(w io.Writer, v any) error {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(out, '\n'))
	return err
}

// capEntry is one saved capability file and its contents, for ls.
type capEntry struct {
	path       string
	capability string
}

type capState struct {
	ProtocolVersion uint64 `json:"protocol_version"`
	Capability      string `json:"capability"`
}

func capsDir() (string, error) {
	dir, err := paths.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "bridge", "caps"), nil
}

func capFile(key string) (string, error) {
	dir, err := capsDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(dir, hex.EncodeToString(sum[:])), nil
}

// loadCap reads the saved capability for a target key, if any.
func loadCap(key string) (string, bool) {
	path, err := capFile(key)
	if err != nil {
		return "", false
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is a sha256 name under our own 0700 config dir.
	if err != nil {
		return "", false
	}
	capability, err := decodeCap(raw)
	if err != nil {
		_ = os.Remove(path)
		return "", false
	}
	return capability, true
}

// saveCap persists the capability for a target key in a 0600 file.
func saveCap(key, capability string) error {
	dir, err := capsDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create bridge caps dir: %w", err)
	}
	path, err := capFile(key)
	if err != nil {
		return err
	}
	data, err := json.Marshal(capState{ProtocolVersion: cookie.ProtocolVersion, Capability: capability})
	if err != nil {
		return fmt.Errorf("encode bridge capability: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("save bridge capability: %w", err)
	}
	return nil
}

// removeCap deletes the saved capability for a target key.
func removeCap(key string) error {
	path, err := capFile(key)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove bridge capability: %w", err)
	}
	return nil
}

// listCaps returns every saved capability file and its contents.
func listCaps() ([]capEntry, error) {
	dir, err := capsDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list bridge capabilities: %w", err)
	}
	caps := make([]capEntry, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path) //nolint:gosec // G304: path is a sha256 name under our own 0700 config dir.
		if err != nil {
			continue
		}
		capability, err := decodeCap(raw)
		if err != nil {
			_ = os.Remove(path)
			continue
		}
		caps = append(caps, capEntry{path: path, capability: capability})
	}
	return caps, nil
}

func decodeCap(raw []byte) (string, error) {
	var state capState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return "", err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return "", errors.New("bridge capability carries trailing JSON")
	}
	if state.ProtocolVersion != cookie.ProtocolVersion || strings.TrimSpace(state.Capability) == "" {
		return "", fmt.Errorf("bridge capability protocol version %d, want %d",
			state.ProtocolVersion, cookie.ProtocolVersion)
	}
	return state.Capability, nil
}
