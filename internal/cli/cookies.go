package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/rpc"
	"github.com/yasyf/cookiesync/internal/state"
)

func newAuthCmd() *cobra.Command {
	var browser, profile, reason, ttl string
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Release the Safe Storage key behind one Touch ID tap and cache it for a short window.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuth(cmd, browser, profile, reason, ttl)
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "chrome", "The browser to authenticate.")
	cmd.Flags().StringVar(&profile, "profile", "Default", "The profile to authenticate.")
	cmd.Flags().StringVar(&reason, "reason", "", "What the Touch ID prompt should say you're unlocking the cookies to do.")
	cmd.Flags().StringVar(&ttl, "ttl", "", "Override the cache TTL (Go-style duration, e.g. 15m).")
	return cmd
}

// runAuth optionally overrides the cache TTL, then primes the cached key via the daemon
// and reports the authenticated endpoint, matching the Python run_auth.
func runAuth(cmd *cobra.Command, browser, profile, reason, ttl string) error {
	if ttl != "" {
		d, err := state.ParseDuration(ttl)
		if err != nil {
			return err
		}
		if err := state.New(paths.Config).SetAuthTTL(cmd.Context(), d); err != nil {
			return err
		}
	}
	params := map[string]any{"browser": browser, "profile": profile}
	if reason != "" {
		params["reason"] = reason
	}
	var result struct {
		Endpoint string `json:"endpoint"`
	}
	if err := rpc.CallJSON(cmd.Context(), "prime_auth", params, &result); err != nil {
		return err
	}
	cmd.Printf("Authenticated %s.\n", result.Endpoint)
	return nil
}

func newCookiesCmd() *cobra.Command {
	var browser, profile, format string
	cmd := &cobra.Command{
		Use:   "cookies <url>...",
		Short: "Stream the cookies for one or more URLS in the chosen format, merged into one document.",
		Long: "Stream the cookies for one or more URLS in the chosen format, merged into one " +
			"document.\n\nPass several hosts (e.g. an app and the API host it calls) to get a single " +
			"storageState spanning them all — one cached-key decrypt, no extra Touch ID prompt.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCookies(cmd, args, browser, profile, format)
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "chrome", "The browser to read cookies from.")
	cmd.Flags().StringVar(&profile, "profile", "Default", "The profile to read cookies from.")
	cmd.Flags().StringVar(&format, "format", "playwright", "The output wire format (playwright|netscape|header|json).")
	return cmd
}

// runCookies fetches the merged cookies for every url in one daemon call and renders
// them in the chosen format. It sends the dual url/urls wire so an older resident
// daemon still serves the first host. Mirrors the Python run_cookies.
func runCookies(cmd *cobra.Command, urls []string, browser, profile, format string) error {
	switch cookie.OutputFormat(format) {
	case cookie.FormatPlaywright, cookie.FormatNetscape, cookie.FormatHeader, cookie.FormatJSON:
	default:
		return fmt.Errorf("unknown format %q: want playwright, netscape, header, or json", format)
	}
	params := map[string]any{
		"url":     urls[0],
		"urls":    asAnySlice(urls),
		"browser": browser,
		"profile": profile,
	}
	var result struct {
		Cookies []cookie.WireCookie `json:"cookies"`
	}
	if err := rpc.CallJSON(cmd.Context(), "get_cookies", params, &result); err != nil {
		return err
	}
	storage := cookie.StorageState{Cookies: fromWireCookies(result.Cookies)}
	for _, line := range cookie.Render(storage, cookie.OutputFormat(format)) {
		cmd.Println(line)
	}
	return nil
}

func asAnySlice(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

func fromWireCookies(in []cookie.WireCookie) []cookie.Cookie {
	out := make([]cookie.Cookie, len(in))
	for i, w := range in {
		out[i] = cookie.FromWire(w)
	}
	return out
}
