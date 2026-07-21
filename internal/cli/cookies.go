package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/mesh"
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
	cmd.Flags().StringVar(&browser, "browser", "", "The browser to authenticate; omitted authenticates every registered local browser behind one tap, and a cold session routes the prompt per browser to a live peer.")
	cmd.Flags().StringVar(&profile, "profile", "Default", "The profile to authenticate (requires --browser).")
	cmd.Flags().StringVar(&reason, "reason", "", "What the Touch ID prompt should say you're unlocking the cookies to do.")
	cmd.Flags().StringVar(&ttl, "ttl", "", "Override the cache TTL (Go-style duration, e.g. 15m).")
	return cmd
}

// runAuth optionally overrides the cache TTL, then primes the cached key(s) via the
// daemon. With an explicit --browser it primes that one endpoint and reports it (the
// Python run_auth path); with --browser omitted it auto-registers this host's installed
// browsers when the registry has none, primes every registered local browser behind one
// tap, and reports each warmed endpoint on stdout with per-browser skips on stderr.
func runAuth(cmd *cobra.Command, browser, profile, reason, ttl string) error {
	if cmd.Flags().Changed("profile") && browser == "" {
		return errors.New("--profile requires --browser")
	}
	if ttl != "" {
		d, err := state.ParseDuration(ttl)
		if err != nil {
			return err
		}
		if err := state.New(paths.Config).SetAuthTTL(cmd.Context(), d); err != nil {
			return err
		}
	}
	if browser == "" {
		return runAuthAll(cmd, reason)
	}
	params := map[string]any{"browser": browser, "profile": profile}
	if reason != "" {
		params["reason"] = reason
	}
	if r, ok := resolveRequestor(); ok {
		params["requestor"] = r
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

// runAuthAll auto-registers this host's installed browsers when the registry has no
// local endpoint, then primes every registered local browser in one daemon call. It
// prints each warmed endpoint id on stdout and each per-browser skip on stderr.
func runAuthAll(cmd *cobra.Command, reason string) error {
	if err := ensureLocalEndpoints(cmd.Context()); err != nil {
		return err
	}
	params := map[string]any{}
	if reason != "" {
		params["reason"] = reason
	}
	if r, ok := resolveRequestor(); ok {
		params["requestor"] = r
	}
	var result struct {
		Endpoints []string `json:"endpoints"`
		Warnings  []string `json:"warnings"`
	}
	if err := rpc.CallJSON(cmd.Context(), "prime_auth", params, &result); err != nil {
		return err
	}
	cmd.Printf("Authenticated %d endpoint(s):\n", len(result.Endpoints))
	for _, id := range result.Endpoints {
		cmd.Println(id)
	}
	for _, warning := range result.Warnings {
		cmd.PrintErrln(warning)
	}
	return nil
}

// ensureLocalEndpoints registers this host's installed browsers when the convergent
// registry holds no local endpoint for self: one primary profile per browser — "Default"
// when its Cookies store exists, else the most-recently-modified profile among
// Profiles() (which already drops Arc's system profile). A browser with no cookie store
// is skipped, and when nothing registers it errors, since there is nothing to
// authenticate.
func ensureLocalEndpoints(ctx context.Context) error {
	self, _, err := mesh.Resolve(ctx)
	if err != nil {
		return err
	}
	store := state.New(paths.Config)
	st, err := store.Load(ctx)
	if err != nil {
		return err
	}
	for _, ep := range st.Endpoints() {
		if ep.Host == self {
			return nil
		}
	}
	registry, err := cookie.Registry()
	if err != nil {
		return err
	}
	names := make([]cookie.BrowserName, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	registered := false
	for _, name := range names {
		profile, err := primaryProfile(registry[name])
		if err != nil {
			return err
		}
		if profile == "" {
			continue
		}
		endpoint := state.Endpoint{Host: self, Browser: string(name), Profile: profile}
		if err := store.AddBrowser(ctx, self, endpoint); err != nil {
			return err
		}
		registered = true
	}
	if !registered {
		return errors.New("no installed browsers detected; run cookiesync browser add")
	}
	return nil
}

// primaryProfile picks the profile ensureLocalEndpoints tracks for a browser: "Default"
// when its Cookies store exists, else the profile whose Cookies store has the newest
// mtime among the browser's profiles. It returns "" when the browser has no store on
// this host.
func primaryProfile(browser cookie.Browser) (string, error) {
	if _, err := os.Stat(browser.CookiesDB("Default")); err == nil {
		return "Default", nil
	}
	profiles, err := browser.Profiles()
	if err != nil {
		return "", err
	}
	newest := ""
	var newestMod time.Time
	for _, p := range profiles {
		info, err := os.Stat(browser.CookiesDB(p.Dir))
		if err != nil {
			return "", err
		}
		if newest == "" || info.ModTime().After(newestMod) {
			newest = p.Dir
			newestMod = info.ModTime()
		}
	}
	return newest, nil
}

func newCookiesCmd() *cobra.Command {
	var browser, profile, format string
	cmd := &cobra.Command{
		Use:   "cookies <url>...",
		Short: "Stream the cookies for one or more URLs in the chosen format, merged into one document; omit --browser to union every registered browser and host.",
		Long: "Stream the cookies for one or more URLs in the chosen format, merged into one " +
			"document.\n\nPass several hosts (e.g. an app and the API host it calls) to get a single " +
			"storageState spanning them all — one cached-key decrypt, no extra Touch ID prompt.\n\n" +
			"With --browser omitted the result is a best-effort union across every registered browser " +
			"and host — local stores and remote peers over ssh — skipping any that fail with a stderr " +
			"warning; --browser is the single-browser escape hatch.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCookies(cmd, args, browser, profile, format)
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "", "The browser to read cookies from; omitted unions every registered browser and host, skipping any that fail.")
	cmd.Flags().StringVar(&profile, "profile", "Default", "The profile to read cookies from (requires --browser).")
	cmd.Flags().StringVar(&format, "format", "playwright", "The output wire format (playwright|netscape|header|json|webstorage).")
	return cmd
}

// runCookies renders the merged cookies for every url in the chosen format. With an
// explicit --browser it fetches that one browser in a single daemon call. With --browser
// omitted it auto-registers this host's installed browsers when the registry has none,
// then unions every registered endpoint — local and remote — rendering the merged set
// on stdout with per-endpoint skips on stderr.
func runCookies(cmd *cobra.Command, urls []string, browser, profile, format string) error {
	switch cookie.OutputFormat(format) {
	case cookie.FormatPlaywright, cookie.FormatNetscape, cookie.FormatHeader, cookie.FormatJSON, cookie.FormatWebStorage:
	default:
		return fmt.Errorf("unknown format %q: want playwright, netscape, header, json, or webstorage", format)
	}
	if cmd.Flags().Changed("profile") && browser == "" {
		return errors.New("--profile requires --browser")
	}
	if browser == "" {
		return runCookiesAll(cmd, urls, format)
	}
	params := map[string]any{
		"urls":    asAnySlice(urls),
		"browser": browser,
		"profile": profile,
	}
	if r, ok := resolveRequestor(); ok {
		params["requestor"] = r
	}
	var result struct {
		ProtocolVersion uint64              `json:"protocol_version"`
		Cookies         []cookie.WireCookie `json:"cookies"`
	}
	if err := rpc.CallJSON(cmd.Context(), "get_cookies", params, &result); err != nil {
		return err
	}
	if result.ProtocolVersion != cookie.ProtocolVersion {
		return fmt.Errorf("cookie protocol version %d, want %d", result.ProtocolVersion, cookie.ProtocolVersion)
	}
	origins, err := fetchOrigins(cmd, urls, browser, profile, format)
	if err != nil {
		return err
	}
	renderCookies(cmd, result.Cookies, origins, format)
	return nil
}

// runCookiesAll auto-registers this host's installed browsers when the registry has no
// local endpoint, then unions the cookies for every url across every registered endpoint
// in one daemon call, renders the merged set on stdout, and writes each per-endpoint
// skip on stderr.
func runCookiesAll(cmd *cobra.Command, urls []string, format string) error {
	if err := ensureLocalEndpoints(cmd.Context()); err != nil {
		return err
	}
	params := map[string]any{"urls": asAnySlice(urls)}
	if r, ok := resolveRequestor(); ok {
		params["requestor"] = r
	}
	var result struct {
		ProtocolVersion uint64              `json:"protocol_version"`
		Cookies         []cookie.WireCookie `json:"cookies"`
		Warnings        []string            `json:"warnings"`
	}
	if err := rpc.CallJSON(cmd.Context(), "get_cookies", params, &result); err != nil {
		return err
	}
	if result.ProtocolVersion != cookie.ProtocolVersion {
		return fmt.Errorf("cookie protocol version %d, want %d", result.ProtocolVersion, cookie.ProtocolVersion)
	}
	origins, err := fetchOrigins(cmd, urls, "", "", format)
	if err != nil {
		return err
	}
	renderCookies(cmd, result.Cookies, origins, format)
	for _, warning := range result.Warnings {
		cmd.PrintErrln(warning)
	}
	return nil
}

// fetchOrigins pulls this host's localStorage + sessionStorage for every url from the
// daemon, but only for the formats that carry origins (playwright and webstorage). It
// scopes to the same browser/profile as the cookies call — an explicit --browser reads
// only that browser's web storage, so the origins pair with the cookies from that same
// browser rather than mixing another browser's token — and reuses the cookies call's
// requestor so the get_web_storage prime rides that warm grant with no extra Touch ID
// tap. Any per-endpoint skip is written to stderr.
func fetchOrigins(cmd *cobra.Command, urls []string, browser, profile, format string) ([]cookie.WireOrigin, error) {
	switch cookie.OutputFormat(format) {
	case cookie.FormatPlaywright, cookie.FormatWebStorage:
	default:
		return nil, nil
	}
	params := map[string]any{"urls": asAnySlice(urls)}
	if browser != "" {
		params["browser"] = browser
		params["profile"] = profile
	}
	if r, ok := resolveRequestor(); ok {
		params["requestor"] = r
	}
	var result struct {
		ProtocolVersion uint64              `json:"protocol_version"`
		Origins         []cookie.WireOrigin `json:"origins"`
		Warnings        []string            `json:"warnings"`
	}
	if err := rpc.CallJSON(cmd.Context(), "get_web_storage", params, &result); err != nil {
		return nil, err
	}
	if result.ProtocolVersion != cookie.ProtocolVersion {
		return nil, fmt.Errorf("origin protocol version %d, want %d", result.ProtocolVersion, cookie.ProtocolVersion)
	}
	for _, warning := range result.Warnings {
		cmd.PrintErrln(warning)
	}
	return result.Origins, nil
}

// renderCookies writes the wire cookies and origins to stdout in the chosen format, one
// document line per Println.
func renderCookies(cmd *cobra.Command, wire []cookie.WireCookie, origins []cookie.WireOrigin, format string) {
	storage := cookie.StorageState{Cookies: fromWireCookies(wire), Origins: fromWireOrigins(origins)}
	for _, line := range cookie.Render(storage, cookie.OutputFormat(format)) {
		cmd.Println(line)
	}
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

func fromWireOrigins(in []cookie.WireOrigin) []cookie.OriginStorage {
	out := make([]cookie.OriginStorage, len(in))
	for i, w := range in {
		out[i] = cookie.OriginFromWire(w)
	}
	return out
}
