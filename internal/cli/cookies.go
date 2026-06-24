package cli

import (
	"github.com/spf13/cobra"
)

func newAuthCmd() *cobra.Command {
	var browser, profile, reason, ttl string
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Release the Safe Storage key behind one Touch ID tap and cache it for a short window.",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "chrome", "The browser to authenticate.")
	cmd.Flags().StringVar(&profile, "profile", "Default", "The profile to authenticate.")
	cmd.Flags().StringVar(&reason, "reason", "", "What the Touch ID prompt should say you're unlocking the cookies to do.")
	cmd.Flags().StringVar(&ttl, "ttl", "", "Override the cache TTL (Go-style duration, e.g. 15m).")
	return cmd
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
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "chrome", "The browser to read cookies from.")
	cmd.Flags().StringVar(&profile, "profile", "Default", "The profile to read cookies from.")
	cmd.Flags().StringVar(&format, "format", "playwright", "The output wire format (playwright|netscape|header|json).")
	return cmd
}
