package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/rpc"
)

// bridgeDefaultProfile is the profile a bridge target assumes when none is
// given, matching the daemon default.
const bridgeDefaultProfile = "Default"

// bridgeOpenResult is the frozen bridge_open reply.
type bridgeOpenResult struct {
	URL        string  `json:"url"`
	Endpoint   string  `json:"endpoint"`
	Browser    string  `json:"browser"`
	Profile    string  `json:"profile"`
	Capability string  `json:"capability"`
	ExpiresIn  float64 `json:"expires_in"`
}

// bridgeStatusResult is the frozen bridge_status reply; empty when the session
// is gone.
type bridgeStatusResult struct {
	Endpoint  string  `json:"endpoint"`
	Browser   string  `json:"browser"`
	Profile   string  `json:"profile"`
	ExpiresIn float64 `json:"expires_in"`
	PID       int     `json:"pid"`
}

// newBridgeCmd builds the bridge command tree: open a live, cookie-seeded Chrome
// DevTools bridge, list running sessions, and stop one.
func newBridgeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bridge",
		Short: "Open a live, cookie-seeded Chrome DevTools bridge for agent-browser.",
	}
	cmd.AddCommand(newBridgeOpenCmd(), newBridgeLsCmd(), newBridgeStopCmd())
	return cmd
}

func newBridgeOpenCmd() *cobra.Command {
	var headed, headless bool
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
			key := bridgeCapKey(host, br, prof)
			params := map[string]any{
				"browser": br,
				"profile": prof,
				"host":    host,
				"headed":  headed && !headless,
			}
			if r, ok := resolveRequestor(); ok {
				params["requestor"] = r
			}
			if capability, ok := loadCap(key); ok {
				params["capability"] = capability
			}
			var resp bridgeOpenResult
			if err := rpc.CallJSON(cmd.Context(), "bridge_open", params, &resp); err != nil {
				return err
			}
			if err := saveCap(key, resp.Capability); err != nil {
				// The saved capability is the only handle to stop the session;
				// unsaved, tear the just-opened browser down rather than orphan a
				// live, logged-in session until its lease expires.
				var closed struct {
					Closed bool `json:"closed"`
				}
				_ = rpc.CallJSON(cmd.Context(), "bridge_close", map[string]any{"capability": resp.Capability}, &closed)
				return err
			}
			printBridgeReady(cmd, resp)
			return nil
		},
	}
	cmd.Flags().BoolVar(&headed, "headed", true, "Run Chrome headed (default) for fidelity.")
	cmd.Flags().BoolVar(&headless, "headless", false, "Run Chrome headless (--headless=new).")
	cmd.Flags().StringVar(&browser, "browser", "", "The browser to seed the bridge from.")
	cmd.Flags().StringVar(&profile, "profile", "", "The profile to seed the bridge from.")
	return cmd
}

func newBridgeLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List live bridge sessions.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			caps, err := listCaps()
			if err != nil {
				return err
			}
			for _, entry := range caps {
				var st bridgeStatusResult
				if err := rpc.CallJSON(cmd.Context(), "bridge_status", map[string]any{"capability": entry.capability}, &st); err != nil {
					return err
				}
				if st.Endpoint == "" {
					_ = os.Remove(entry.path)
					continue
				}
				cmd.Printf("%s · expires in %s · pid %d\n", st.Endpoint, formatTTL(st.ExpiresIn), st.PID)
			}
			return nil
		},
	}
}

func newBridgeStopCmd() *cobra.Command {
	var browser, profile string
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
			capability, ok := loadCap(key)
			if !ok {
				return fmt.Errorf("no saved bridge for %s", key)
			}
			var resp struct {
				Closed bool `json:"closed"`
			}
			if err := rpc.CallJSON(cmd.Context(), "bridge_close", map[string]any{"capability": capability}, &resp); err != nil {
				return err
			}
			if err := removeCap(key); err != nil {
				return err
			}
			cmd.Printf("bridge closed · %s\n", key)
			return nil
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "", "The browser whose bridge to stop.")
	cmd.Flags().StringVar(&profile, "profile", "", "The profile whose bridge to stop.")
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
	cmd.Printf("bridge ready · %s/%s   (expires in %s)\n", r.Browser, r.Profile, formatTTL(r.ExpiresIn))
	cmd.Printf("  agent-browser connect '%s'\n", r.URL)
	cmd.Printf("  # or:  export AGENT_BROWSER_CDP='%s'\n", r.URL)
	cmd.Printf("  # raw Playwright:  chromium.connectOverCDP('%s')\n", r.URL)
	cmd.Printf("  # drive the existing page — a fresh default-context page won't see your cookies\n")
}

func formatTTL(seconds float64) string {
	return time.Duration(seconds * float64(time.Second)).Round(time.Second).String()
}

// capEntry is one saved capability file and its contents, for ls.
type capEntry struct {
	path       string
	capability string
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
	capability := strings.TrimSpace(string(raw))
	if capability == "" {
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
	if err := os.WriteFile(path, []byte(capability), 0o600); err != nil {
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
		capability := strings.TrimSpace(string(raw))
		if capability == "" {
			continue
		}
		caps = append(caps, capEntry{path: path, capability: capability})
	}
	return caps, nil
}
