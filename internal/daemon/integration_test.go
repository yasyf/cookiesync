package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite" // register the sqlite driver for the test store

	"github.com/yasyf/cookiesync/internal/cache"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
)

// v24Schema is a Chrome v24 cookie store schema, enough for a real extract/apply/
// get_cookies round-trip against an ephemeral SQLite file.
const v24Schema = `
CREATE TABLE cookies (
    creation_utc INTEGER NOT NULL,
    host_key TEXT NOT NULL,
    top_frame_site_key TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    encrypted_value BLOB NOT NULL,
    path TEXT NOT NULL,
    expires_utc INTEGER NOT NULL,
    is_secure INTEGER NOT NULL,
    is_httponly INTEGER NOT NULL,
    last_access_utc INTEGER NOT NULL,
    has_expires INTEGER NOT NULL,
    is_persistent INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    samesite INTEGER NOT NULL,
    source_scheme INTEGER NOT NULL,
    source_port INTEGER NOT NULL,
    last_update_utc INTEGER NOT NULL,
    source_type INTEGER NOT NULL,
    has_cross_site_ancestor INTEGER NOT NULL
);
CREATE UNIQUE INDEX cookies_unique_index ON cookies(
    host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port
);
`

// chromeStoreUnderHome points HOME at a temp dir and creates an empty Chrome v24
// cookie store for the Default profile there, so cookie.Lookup("chrome") resolves to
// it. It returns the chrome Browser the handlers will resolve.
func chromeStoreUnderHome(t *testing.T) cookie.Browser {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	browser, err := cookie.Lookup("chrome")
	if err != nil {
		t.Fatalf("lookup chrome: %v", err)
	}
	addChromeProfileStore(t, browser, "Default")
	return browser
}

// addChromeProfileStore creates an empty Chrome v24 cookie store for profile under
// the browser's (already HOME-redirected) profile root.
func addChromeProfileStore(t *testing.T, browser cookie.Browser, profile string) {
	t.Helper()
	if err := os.MkdirAll(browser.ProfileDir(profile), 0o700); err != nil {
		t.Fatalf("mkdir profile: %v", err)
	}
	db, err := sql.Open("sqlite", browser.CookiesDB(profile))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(v24Schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
}

// TestGetCookiesMergesURLsFromCachedKey proves get_cookies, against a real store and a
// warm cache, decrypts and host-filters each url, unions the result, and emits the
// frozen {"cookies": [...]} wire shape — one cached-key decrypt, no prompt, no extra
// ssh. Two distinct hosts are seeded; a two-url call returns both.
func TestGetCookiesMergesURLsFromCachedKey(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))

	// Seed the store with two cookies on two hosts via the real apply path.
	seed := []cookie.Cookie{
		{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, IsSecure: true, SourceScheme: 2, SourcePort: 443},
		{HostKey: "api.example.com", Name: "tok", Value: "xyz", Path: "/", LastUpdateUTC: 13_350_000_000_000_001, SameSite: 1, IsSecure: true, SourceScheme: 2, SourcePort: 443},
	}
	if _, err := cookie.Apply(ctx, seed, browser, "Default", key); err != nil {
		t.Fatalf("seed apply: %v", err)
	}

	cache := newFakeCache()
	st := stateWith("me@laptop", "")
	fakeMesh(t, "me@laptop")
	d := New(&fakeConsent{}, cache, nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Default"), []byte(key), 0)
	d.grant("local", []cookie.BrowserName{"chrome"}, time.Hour)

	got, err := d.handleGetCookies(ctx, map[string]any{
		"browser": "chrome",
		"urls":    []any{"https://x.com/", "https://api.example.com/"},
	})
	if err != nil {
		t.Fatalf("handleGetCookies: %v", err)
	}
	cookies := wireCookieNames(t, got)
	if len(cookies) != 2 || cookies["sid"].Value != "abc" || cookies["tok"].Value != "xyz" {
		t.Fatalf("get_cookies merged set = %+v, want sid=abc tok=xyz", cookies)
	}
	if cookies["sid"].HostKey != "x.com" || cookies["tok"].HostKey != "api.example.com" {
		t.Fatalf("host keys not preserved: %+v", cookies)
	}
}

// TestGetCookiesHostFilters proves get_cookies returns only the cookies the browser
// would send to the requested host — a single-url call for one host omits the other.
func TestGetCookiesHostFilters(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	seed := []cookie.Cookie{
		{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 1, IsSecure: true, SourceScheme: 2, SourcePort: 443},
		{HostKey: "other.com", Name: "nope", Value: "no", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 1, IsSecure: true, SourceScheme: 2, SourcePort: 443},
	}
	if _, err := cookie.Apply(ctx, seed, browser, "Default", key); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	cache := newFakeCache()
	fakeMesh(t, "me@laptop")
	d := New(&fakeConsent{}, cache, nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: stateWith("me@laptop", "")}, fixedState{st: stateWith("me@laptop", "")})
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Default"), []byte(key), 0)
	d.grant("local", []cookie.BrowserName{"chrome"}, time.Hour)

	got, err := d.handleGetCookies(ctx, map[string]any{"browser": "chrome", "url": "https://x.com/"})
	if err != nil {
		t.Fatalf("handleGetCookies: %v", err)
	}
	cookies := wireCookieNames(t, got)
	if _, ok := cookies["nope"]; ok {
		t.Fatalf("get_cookies leaked the other host's cookie: %+v", cookies)
	}
	if _, ok := cookies["sid"]; !ok {
		t.Fatalf("get_cookies dropped the requested host's cookie: %+v", cookies)
	}
}

// TestGetCookiesUnionLocalAndRemote proves a browser-less get_cookies unions a warm
// local endpoint with a remote one — the remote leg driving the peer's single-browser
// get_cookies over ssh — into one merged set. The recorded ssh command carries the
// recursion guard (--browser) and the origin tag, so the peer takes the single path and
// never re-fans-out.
func TestGetCookiesUnionLocalAndRemote(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	local := []cookie.Cookie{{HostKey: "x.com", Name: "loc", Value: "here", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, IsSecure: true, SourceScheme: 2, SourcePort: 443}}
	if _, err := cookie.Apply(ctx, local, browser, "Default", key); err != nil {
		t.Fatalf("seed apply: %v", err)
	}

	self := "me@laptop"
	fakeMesh(t, self, "you@desktop")
	st := stateWith(self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint("you@desktop", "chrome", "Default"),
	)
	runner := &recordingRunner{byMethod: map[string]string{
		"rpc get_cookies": peerExtractReply(t, cookie.Cookie{HostKey: "x.com", Name: "rem", Value: "there", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, IsSecure: true, SourceScheme: 2, SourcePort: 443}),
	}}
	cache := newFakeCache()
	consent := &fakeConsent{key: key}
	d := New(consent, cache, nil, staticProbe(SessionSnapshot{}), runner, fixedState{st: st}, fixedState{st: st})
	_ = cache.Put(ctx, endpointID(self, "chrome", "Default"), []byte(key), 0)
	d.grant("local", []cookie.BrowserName{"chrome"}, time.Hour)

	got, err := d.handleGetCookies(ctx, map[string]any{"url": "https://x.com/"})
	if err != nil {
		t.Fatalf("handleGetCookies union: %v", err)
	}
	cookies := wireCookieNames(t, got)
	if len(cookies) != 2 || cookies["loc"].Value != "here" || cookies["rem"].Value != "there" {
		t.Fatalf("union = %+v, want loc=here rem=there", cookies)
	}
	if len(consent.promptedReasons) != 0 {
		t.Fatalf("a warm+granted local endpoint must not prompt, got %v", consent.promptedReasons)
	}
	remoteCmd := ""
	for _, call := range runner.calls {
		if strings.Contains(call.cmd, "rpc get_cookies") {
			remoteCmd = call.cmd
		}
	}
	if remoteCmd == "" {
		t.Fatalf("the remote leg never drove rpc get_cookies; calls = %+v", runner.calls)
	}
	if !strings.Contains(remoteCmd, "rpc get_cookies --browser") || !strings.Contains(remoteCmd, "--origin") {
		t.Fatalf("remote cmd = %q, want the single-path recursion guard (--browser) and --origin", remoteCmd)
	}
}

// TestGetCookiesUnionLocalWinsTie proves the conflict rule: when a local and a remote
// endpoint carry the same logical cookie with an equal last_update_utc but a different
// value, MergeRanked keeps the LOCAL machine's value.
func TestGetCookiesUnionLocalWinsTie(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	const stamp = 13_350_000_000_000_000
	local := []cookie.Cookie{{HostKey: "x.com", Name: "sid", Value: "localwins", Path: "/", LastUpdateUTC: stamp, SameSite: 2, IsSecure: true, SourceScheme: 2, SourcePort: 443}}
	if _, err := cookie.Apply(ctx, local, browser, "Default", key); err != nil {
		t.Fatalf("seed apply: %v", err)
	}

	self := "me@laptop"
	fakeMesh(t, self, "you@desktop")
	st := stateWith(self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint("you@desktop", "chrome", "Default"),
	)
	runner := &recordingRunner{byMethod: map[string]string{
		"rpc get_cookies": peerExtractReply(t, cookie.Cookie{HostKey: "x.com", Name: "sid", Value: "remotewins", Path: "/", LastUpdateUTC: stamp, SameSite: 2, IsSecure: true, SourceScheme: 2, SourcePort: 443}),
	}}
	cache := newFakeCache()
	d := New(&fakeConsent{key: key}, cache, nil, staticProbe(SessionSnapshot{}), runner, fixedState{st: st}, fixedState{st: st})
	_ = cache.Put(ctx, endpointID(self, "chrome", "Default"), []byte(key), 0)
	d.grant("local", []cookie.BrowserName{"chrome"}, time.Hour)

	got, err := d.handleGetCookies(ctx, map[string]any{"url": "https://x.com/"})
	if err != nil {
		t.Fatalf("handleGetCookies union: %v", err)
	}
	cookies := wireCookieNames(t, got)
	if len(cookies) != 1 || cookies["sid"].Value != "localwins" {
		t.Fatalf("tie union = %+v, want the local value 'localwins'", cookies)
	}
}

// TestGetCookiesUnionColdLocalSkippedRemoteContributes proves the never-route rule: a
// cold local endpoint on an unattended host is skipped with a warning (cookies never
// routes consent — that is auth's job), the remote endpoint still contributes, and no
// consent is ever evaluated.
func TestGetCookiesUnionColdLocalSkippedRemoteContributes(t *testing.T) {
	ctx := context.Background()
	chromeStoreUnderHome(t)
	self := "me@laptop"
	fakeMesh(t, self, "you@desktop")
	st := stateWith(self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint("you@desktop", "chrome", "Default"),
	)
	runner := &recordingRunner{byMethod: map[string]string{
		"rpc get_cookies": peerExtractReply(t, cookie.Cookie{HostKey: "x.com", Name: "rem", Value: "there", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, IsSecure: true, SourceScheme: 2, SourcePort: 443}),
	}}
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(SessionSnapshot{}), runner, fixedState{st: st}, fixedState{st: st})

	got, err := d.handleGetCookies(ctx, map[string]any{"url": "https://x.com/"})
	if err != nil {
		t.Fatalf("handleGetCookies union: %v", err)
	}
	cookies := wireCookieNames(t, got)
	if len(cookies) != 1 || cookies["rem"].Value != "there" {
		t.Fatalf("union = %+v, want only the remote rem=there", cookies)
	}
	if len(consent.promptedReasons) != 0 || len(consent.batchCalls) != 0 {
		t.Fatalf("cookies must never prompt or route a cold local endpoint, got prompts %v batches %v", consent.promptedReasons, consent.batchCalls)
	}
	warnings := decodeWarnings(t, got)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "skip cold") || !strings.Contains(warnings[0], endpointID(self, "chrome", "Default")) {
		t.Fatalf("warnings = %v, want one 'skip cold' naming the local endpoint", warnings)
	}
}

// TestGetCookiesUnionBrokenLocalStoreSkipped proves best-effort per endpoint: a
// warm+granted local endpoint whose store cannot be read is skipped with a warning
// instead of failing the whole union, and the remote endpoint still contributes.
func TestGetCookiesUnionBrokenLocalStoreSkipped(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	garbage := browser.CookiesDB("Ghost")
	if err := os.MkdirAll(filepath.Dir(garbage), 0o750); err != nil {
		t.Fatalf("mkdir ghost profile: %v", err)
	}
	if err := os.WriteFile(garbage, []byte("not a sqlite database"), 0o600); err != nil {
		t.Fatalf("write ghost store: %v", err)
	}

	self := "me@laptop"
	fakeMesh(t, self, "you@desktop")
	st := stateWith(self, "",
		stateEndpoint(self, "chrome", "Ghost"),
		stateEndpoint("you@desktop", "chrome", "Default"),
	)
	runner := &recordingRunner{byMethod: map[string]string{
		"rpc get_cookies": peerExtractReply(t, cookie.Cookie{HostKey: "x.com", Name: "rem", Value: "there", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, IsSecure: true, SourceScheme: 2, SourcePort: 443}),
	}}
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	cache := newFakeCache()
	d := New(&fakeConsent{key: key}, cache, nil, staticProbe(SessionSnapshot{}), runner, fixedState{st: st}, fixedState{st: st})
	_ = cache.Put(ctx, endpointID(self, "chrome", "Ghost"), []byte(key), 0)
	d.grant("local", []cookie.BrowserName{"chrome"}, time.Hour)

	got, err := d.handleGetCookies(ctx, map[string]any{"url": "https://x.com/"})
	if err != nil {
		t.Fatalf("handleGetCookies union: %v", err)
	}
	cookies := wireCookieNames(t, got)
	if len(cookies) != 1 || cookies["rem"].Value != "there" {
		t.Fatalf("union = %+v, want only the remote rem=there", cookies)
	}
	warnings := decodeWarnings(t, got)
	if len(warnings) != 1 || !strings.Contains(warnings[0], endpointID(self, "chrome", "Ghost")) {
		t.Fatalf("warnings = %v, want one skip naming the broken local endpoint", warnings)
	}
}

// TestGetCookiesUnionLiveLocalOneEvaluation proves decision 8: a browser-less get_cookies
// over a live local session with nothing granted costs exactly ONE consent evaluation for
// the whole call, then extraction proceeds with the released key.
func TestGetCookiesUnionLiveLocalOneEvaluation(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	seed := []cookie.Cookie{{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, IsSecure: true, SourceScheme: 2, SourcePort: 443}}
	if _, err := cookie.Apply(ctx, seed, browser, "Default", key); err != nil {
		t.Fatalf("seed apply: %v", err)
	}

	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "", stateEndpoint(self, "chrome", "Default"))
	consent := &countingConsent{key: key}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handleGetCookies(ctx, map[string]any{"url": "https://x.com/"})
	if err != nil {
		t.Fatalf("handleGetCookies union: %v", err)
	}
	if n := consent.calls.Load(); n != 1 {
		t.Fatalf("consent evaluations = %d, want 1 (a live local union costs one tap)", n)
	}
	cookies := wireCookieNames(t, got)
	if cookies["sid"].Value != "abc" {
		t.Fatalf("union after the one tap = %+v, want sid=abc", cookies)
	}
}

// TestGetCookiesUnionZeroContributorsErrors proves a total shutout — cold local skipped,
// remote ssh down — fails with an error that suggests cookiesync auth, rather than
// serving an empty document.
func TestGetCookiesUnionZeroContributorsErrors(t *testing.T) {
	ctx := context.Background()
	chromeStoreUnderHome(t)
	self := "me@laptop"
	fakeMesh(t, self, "you@desktop")
	st := stateWith(self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint("you@desktop", "chrome", "Default"),
	)
	runner := &recordingRunner{err: errors.New("ssh down")}
	d := New(&fakeConsent{}, newFakeCache(), nil, staticProbe(SessionSnapshot{}), runner, fixedState{st: st}, fixedState{st: st})

	_, err := d.handleGetCookies(ctx, map[string]any{"url": "https://x.com/"})
	if err == nil || !strings.Contains(err.Error(), "cookiesync auth") {
		t.Fatalf("union with no contributors = %v, want an error suggesting cookiesync auth", err)
	}
}

// TestGetCookiesSinglePeerDrivenGrantKeysOrigin proves the frozen single path is
// peer-driven: a get_cookies with an explicit browser and an origin resolves the grant
// via peerRequestor ("host:"+origin), so a warm cache is served silently to the peer's
// origin grant on a cold, unattended host where a fresh release would fail closed.
func TestGetCookiesSinglePeerDrivenGrantKeysOrigin(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	seed := []cookie.Cookie{{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, IsSecure: true, SourceScheme: 2, SourcePort: 443}}
	if _, err := cookie.Apply(ctx, seed, browser, "Default", key); err != nil {
		t.Fatalf("seed apply: %v", err)
	}

	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "", stateEndpoint(self, "chrome", "Default"))
	consent := &fakeConsent{key: key}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	_ = cache.Put(ctx, endpointID(self, "chrome", "Default"), []byte(key), 0)
	d.grant("host:you@desktop", []cookie.BrowserName{"chrome"}, time.Hour)

	got, err := d.handleGetCookies(ctx, map[string]any{"browser": "chrome", "url": "https://x.com/", "origin": "you@desktop"})
	if err != nil {
		t.Fatalf("peer-driven single get_cookies: %v", err)
	}
	cookies := wireCookieNames(t, got)
	if cookies["sid"].Value != "abc" {
		t.Fatalf("peer-driven read = %+v, want sid=abc", cookies)
	}
	if len(consent.promptedReasons) != 0 {
		t.Fatalf("the origin-keyed grant must serve the warm key silently, got prompts %v", consent.promptedReasons)
	}
}

// decodeWarnings renders a handler result through the wire transport and returns its
// "warnings" list, asserting the envelope decodes.
func decodeWarnings(t *testing.T, result any) []string {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var envelope struct {
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("decode warnings: %v (%s)", err, data)
	}
	return envelope.Warnings
}

// TestExtractApplyRoundTripWireContract proves the peer-facing extract/apply pair: a
// warm cache extract emits {"cookies": [...]} for the WHOLE profile (not host-filtered),
// and an apply of a wire array writes the rows back and reports {"applied": n}. extract
// uses a real engine over the same store so the digest is recorded.
func TestExtractApplyRoundTripWireContract(t *testing.T) {
	ctx := context.Background()
	chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	cache := newFakeCache()
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Default"), []byte(key), 0)
	st := stateWith("me@laptop", "")
	fakeMesh(t, "me@laptop")
	d := New(&fakeConsent{key: key}, cache, newRealEngine(t, cache), staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	d.grant("local", []cookie.BrowserName{"chrome"}, time.Hour)

	// Apply two cookies via the frozen wire array.
	in := []cookie.WireCookie{
		cookie.ToWire(cookie.Cookie{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, SourceScheme: 2, SourcePort: 443}),
		cookie.ToWire(cookie.Cookie{HostKey: "y.com", Name: "tok", Value: "xyz", Path: "/", LastUpdateUTC: 13_350_000_000_000_001, SameSite: 1, SourceScheme: 2, SourcePort: 443}),
	}
	applyRes, err := d.handleApply(ctx, map[string]any{"browser": "chrome", "cookies": wireArrayToAny(t, in)})
	if err != nil {
		t.Fatalf("handleApply: %v", err)
	}
	if got := marshalResult(t, applyRes); got != `{"applied":2}` {
		t.Fatalf("apply = %s, want {\"applied\":2}", got)
	}

	// Extract returns the whole profile (both hosts), undecorated by a url filter.
	extractRes, err := d.handleExtract(ctx, map[string]any{"browser": "chrome"})
	if err != nil {
		t.Fatalf("handleExtract: %v", err)
	}
	cookies := wireCookieNames(t, extractRes)
	if len(cookies) != 2 || cookies["sid"].Value != "abc" || cookies["tok"].Value != "xyz" {
		t.Fatalf("extract = %+v, want sid=abc tok=xyz", cookies)
	}
}

// TestApplySerializesPerEndpoint proves concurrent applies to the SAME endpoint queue
// behind its apply lock — the anti-echo digest record and store write never
// interleave, so the recorded digest always matches the store's final content.
func TestApplySerializesPerEndpoint(t *testing.T) {
	ctx := context.Background()
	chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	fakeMesh(t, "me@laptop")
	cache := newFakeCache()
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Default"), []byte(key), 0)
	st := stateWith("me@laptop", "")
	recorder := &countingRecorder{inner: engine.NewDigestRecorder(), hold: 20 * time.Millisecond}
	d := New(&fakeConsent{}, cache, engine.New(nil, cache, nil, recorder), staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	payload := wireArrayToAny(t, []cookie.WireCookie{
		cookie.ToWire(cookie.Cookie{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, SourceScheme: 2, SourcePort: 443}),
	})
	const n = 4
	type outcome struct {
		res any
		err error
	}
	done := make(chan outcome, n)
	for range n {
		go func() {
			res, err := d.handleApply(ctx, map[string]any{"browser": "chrome", "cookies": payload})
			done <- outcome{res: res, err: err}
		}()
	}
	for range n {
		out := <-done
		if out.err != nil {
			t.Errorf("apply: %v", out.err)
			continue
		}
		if got := marshalResult(t, out.res); got != `{"applied":1}` {
			t.Errorf("apply = %s, want {\"applied\":1}", got)
		}
	}
	if got := recorder.peak.Load(); got != 1 {
		t.Errorf("peak concurrent same-endpoint applies = %d, want 1 (apply must serialize per endpoint)", got)
	}
}

// TestApplyDistinctEndpointsOverlap proves the apply lock is per endpoint: applies to
// two different profiles are mid-write at the same moment, so one busy store never
// queues the rest of the fleet.
func TestApplyDistinctEndpointsOverlap(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	addChromeProfileStore(t, browser, "Work")
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	fakeMesh(t, "me@laptop")
	cache := newFakeCache()
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Default"), []byte(key), 0)
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Work"), []byte(key), 0)
	st := stateWith("me@laptop", "")
	arrived := make(chan string, 2)
	release := make(chan struct{})
	recorder := &meetRecorder{inner: engine.NewDigestRecorder(), arrived: arrived, release: release}
	d := New(&fakeConsent{}, cache, engine.New(nil, cache, nil, recorder), staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	payload := wireArrayToAny(t, []cookie.WireCookie{
		cookie.ToWire(cookie.Cookie{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, SourceScheme: 2, SourcePort: 443}),
	})
	done := make(chan error, 2)
	for _, profile := range []string{"Default", "Work"} {
		go func() {
			_, err := d.handleApply(ctx, map[string]any{"browser": "chrome", "profile": profile, "cookies": payload})
			done <- err
		}()
	}
	for i := range 2 {
		select {
		case <-arrived:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of 2 distinct-endpoint applies were mid-write concurrently", i)
		}
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Errorf("apply: %v", err)
		}
	}
}

// convergeFixture wires a daemon whose engine converges one warm local endpoint
// (me@laptop:chrome:Default) against one canned remote peer, parking every
// RecordApplied at a rendezvous — so a test can hold the converge pass mid-critical-
// section, inside the endpoint's apply lock, and probe what a concurrent apply does.
type convergeFixture struct {
	d       *Daemon
	cache   *fakeCache
	key     cookie.AesKey
	arrived chan string
	release chan struct{}
	localID string
}

func newConvergeFixture(t *testing.T) *convergeFixture {
	t.Helper()
	ctx := context.Background()
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	fakeMesh(t, "me@laptop")
	cache := newFakeCache()
	localEP := state.Endpoint{Host: "me@laptop", Browser: "chrome", Profile: "Default"}
	peerEP := state.Endpoint{Host: "you@desktop", Browser: "chrome", Profile: "Default"}
	localID := string(localEP.ID())
	_ = cache.Put(ctx, localID, []byte(key), 0)
	store := &fakeStore{
		withLock: func(_ context.Context, fn func() error) error { return fn() },
		registry: newRegistry(localEP, peerEP),
	}
	runner := &recordingRunner{byMethod: map[string]string{
		"rpc extract": peerExtractReply(t, cookie.Cookie{HostKey: "x.com", Name: "sid", Value: "peer", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, SourceScheme: 2, SourcePort: 443}),
		"rpc apply":   `{"applied":1}`,
	}}
	arrived := make(chan string, 4)
	release := make(chan struct{})
	recorder := &meetRecorder{inner: engine.NewDigestRecorder(), arrived: arrived, release: release}
	st := stateWith("me@laptop", "")
	eng := engine.New(store, cache, runner, recorder)
	d := New(&fakeConsent{}, cache, eng, staticProbe(SessionSnapshot{}), runner, fixedState{st: st}, fixedState{st: st})
	return &convergeFixture{d: d, cache: cache, key: key, arrived: arrived, release: release, localID: localID}
}

// holdConvergeMidLocalWrite starts a sync pass and blocks until the converge is parked
// inside the local endpoint's apply lock, mid-RecordApplied. The returned channel
// carries the pass's error once fx.release is closed.
func (fx *convergeFixture) holdConvergeMidLocalWrite(ctx context.Context, t *testing.T) chan error {
	t.Helper()
	syncDone := make(chan error, 1)
	go func() {
		_, err := fx.d.handleSync(ctx, map[string]any{})
		syncDone <- err
	}()
	select {
	case ep := <-fx.arrived:
		if ep != fx.localID {
			t.Fatalf("converge first recorded %s, want the local endpoint %s", ep, fx.localID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("converge pass never reached its local write")
	}
	return syncDone
}

// TestConvergeLocalWriteSerializesWithApply proves a converge pass's local store write
// and a peer-driven apply for the SAME endpoint hold one mutex: while the converge is
// parked inside the endpoint's critical section, a concurrent apply queues outside it
// instead of interleaving its digest record with the in-flight write.
func TestConvergeLocalWriteSerializesWithApply(t *testing.T) {
	ctx := context.Background()
	chromeStoreUnderHome(t)
	fx := newConvergeFixture(t)
	syncDone := fx.holdConvergeMidLocalWrite(ctx, t)

	payload := wireArrayToAny(t, []cookie.WireCookie{
		cookie.ToWire(cookie.Cookie{HostKey: "y.com", Name: "tok", Value: "xyz", Path: "/", LastUpdateUTC: 13_350_000_000_000_001, SameSite: 1, SourceScheme: 2, SourcePort: 443}),
	})
	applyDone := make(chan error, 1)
	go func() {
		_, err := fx.d.handleApply(ctx, map[string]any{"browser": "chrome", "cookies": payload})
		applyDone <- err
	}()

	select {
	case ep := <-fx.arrived:
		t.Fatalf("apply for %s entered its critical section while the converge pass held the same endpoint's lock", ep)
	case <-time.After(300 * time.Millisecond):
	}

	close(fx.release)
	if err := <-syncDone; err != nil {
		t.Errorf("sync: %v", err)
	}
	if err := <-applyDone; err != nil {
		t.Errorf("apply: %v", err)
	}
}

// TestConvergeLocalWriteOverlapsDistinctApply proves the converge/apply lock is per
// endpoint: while a converge pass holds one endpoint's lock mid-write, an apply for a
// DIFFERENT endpoint enters its own critical section immediately, so one busy store
// never queues the rest of the fleet.
func TestConvergeLocalWriteOverlapsDistinctApply(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	addChromeProfileStore(t, browser, "Work")
	fx := newConvergeFixture(t)
	workID := endpointID("me@laptop", "chrome", "Work")
	_ = fx.cache.Put(ctx, workID, []byte(fx.key), 0)
	syncDone := fx.holdConvergeMidLocalWrite(ctx, t)

	payload := wireArrayToAny(t, []cookie.WireCookie{
		cookie.ToWire(cookie.Cookie{HostKey: "y.com", Name: "tok", Value: "xyz", Path: "/", LastUpdateUTC: 13_350_000_000_000_001, SameSite: 1, SourceScheme: 2, SourcePort: 443}),
	})
	applyDone := make(chan error, 1)
	go func() {
		_, err := fx.d.handleApply(ctx, map[string]any{"browser": "chrome", "profile": "Work", "cookies": payload})
		applyDone <- err
	}()

	select {
	case ep := <-fx.arrived:
		if ep != workID {
			t.Fatalf("second critical-section entry was %s, want %s", ep, workID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("distinct-endpoint apply queued behind the converge pass's lock; want overlap")
	}

	close(fx.release)
	if err := <-syncDone; err != nil {
		t.Errorf("sync: %v", err)
	}
	if err := <-applyDone; err != nil {
		t.Errorf("apply: %v", err)
	}
}

// TestColdExtractsSingleFlightOneConsent proves N concurrent extracts against a cold
// cache collapse into one primeAuth flight: the leader holds the consent prompt while
// the rest join its flight, so exactly one prompt fires and one Put seeds the cache —
// every caller extracts with the shared key.
func TestColdExtractsSingleFlightOneConsent(t *testing.T) {
	ctx := context.Background()
	chromeStoreUnderHome(t)
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	const n = 4
	consent := &gateConsent{
		key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts")),
		// entered holds one slot per caller so a regression that prompts more than
		// once fails on the calls counter instead of deadlocking the extra prompts.
		entered: make(chan struct{}, n),
		release: make(chan struct{}),
	}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	done := make(chan error, n)
	for range n {
		go func() {
			_, err := d.handleExtract(ctx, map[string]any{"browser": "chrome"})
			done <- err
		}()
	}

	<-consent.entered
	// Every caller has probed the cold cache once gets reaches n; the leader is held
	// mid-prompt. A straggler that misses the flight starts a fresh one, whose cache
	// re-probe returns the leader's key without a second prompt or Put — no settle
	// sleep needed.
	waitFor(t, func() bool { return cache.getCalls() >= n })
	close(consent.release)

	for range n {
		if err := <-done; err != nil {
			t.Errorf("extract: %v", err)
		}
	}
	if got := consent.calls.Load(); got != 1 {
		t.Errorf("consent prompts = %d, want 1 (concurrent cold extracts must share one flight)", got)
	}
	if got := cache.putCalls(); got != 1 {
		t.Errorf("cache puts = %d, want 1 (waiters must reuse the leader's key)", got)
	}
}

// TestPrimeAuthStragglerAfterWarmCacheDoesNotReprompt proves a fresh flight over an
// already-warm cache returns the cached key without prompting or re-putting — the
// cache re-probe that closes the double-prompt window a straggler opens by starting
// its flight just after the previous one completed. The straggler is served silently
// only because its requestor holds a live grant; warmth alone never suffices.
func TestPrimeAuthStragglerAfterWarmCacheDoesNotReprompt(t *testing.T) {
	ctx := context.Background()
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Default"), []byte(consent.key), 0)
	d.grant("local", []cookie.BrowserName{"chrome"}, time.Hour)

	key, err := d.primeAuth(ctx, "local", "chrome", "Default", consentReason, releaseLocal)
	if err != nil {
		t.Fatalf("primeAuth: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("primeAuth returned the wrong key")
	}
	if len(consent.promptedReasons) != 0 {
		t.Fatalf("a flight over a warm cache must not prompt, got %v", consent.promptedReasons)
	}
	if got := cache.putCalls(); got != 1 {
		t.Fatalf("cache puts = %d, want 1 (the seed only; the re-probe must not re-put)", got)
	}
}

// TestPrimeAuthFlightSurvivesLeaderCancel proves the flight runs detached from the
// leader's ctx: a leader whose caller disconnects mid-consent returns its own
// ctx.Err() while the prompt keeps running, and a surviving waiter still gets the key
// from that same flight — one prompt, one Put.
func TestPrimeAuthFlightSurvivesLeaderCancel(t *testing.T) {
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	consent := &gateConsent{
		key:     cookie.DeriveKey(cookie.SafeStorageKey("peanuts")),
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := d.primeAuth(leaderCtx, "local", "chrome", "Default", consentReason, releaseLocal)
		leaderDone <- err
	}()
	<-consent.entered

	waiterDone := make(chan error, 1)
	go func() {
		key, err := d.primeAuth(context.Background(), "local", "chrome", "Default", consentReason, releaseLocal)
		if err == nil && string(key) != string(consent.key) {
			err = errors.New("waiter got the wrong key")
		}
		waiterDone <- err
	}()

	cancelLeader()
	select {
	case err := <-leaderDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled leader = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled leader stayed parked behind its own flight")
	}

	close(consent.release)
	if err := <-waiterDone; err != nil {
		t.Fatalf("waiter after leader cancel: %v", err)
	}
	if got := consent.calls.Load(); got != 1 {
		t.Errorf("consent prompts = %d, want 1 (the flight must survive the leader)", got)
	}
	if got := cache.putCalls(); got != 1 {
		t.Errorf("cache puts = %d, want 1 (the surviving flight must seed the cache)", got)
	}
}

// TestPrimeAuthCanceledWaiterReturnsWhileFlightContinues proves a waiter whose own
// conn dies is not parked behind the leader's prompt: it returns its ctx.Err()
// immediately while the flight runs on and still primes the cache for the survivors.
func TestPrimeAuthCanceledWaiterReturnsWhileFlightContinues(t *testing.T) {
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	consent := &gateConsent{
		key:     cookie.DeriveKey(cookie.SafeStorageKey("peanuts")),
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	leaderDone := make(chan error, 1)
	go func() {
		_, err := d.primeAuth(context.Background(), "local", "chrome", "Default", consentReason, releaseLocal)
		leaderDone <- err
	}()
	<-consent.entered

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	cancelWaiter()
	waiterDone := make(chan error, 1)
	go func() {
		_, err := d.primeAuth(waiterCtx, "local", "chrome", "Default", consentReason, releaseLocal)
		waiterDone <- err
	}()
	select {
	case err := <-waiterDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled waiter = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled waiter stayed parked behind the in-flight prime")
	}

	close(consent.release)
	if err := <-leaderDone; err != nil {
		t.Fatalf("leader: %v", err)
	}
	if got := consent.calls.Load(); got != 1 {
		t.Errorf("consent prompts = %d, want 1 (the canceled waiter must not re-prompt)", got)
	}
	if _, ok, _ := cache.Get(context.Background(), endpointID("me@laptop", "chrome", "Default")); !ok {
		t.Errorf("the flight must still prime the cache after a waiter cancel")
	}
}

// TestColdPrimeWarmsAllLocalEndpointsInOneEvaluation proves the batch prime: one cold
// prime for one endpoint runs ONE consent evaluation covering every tracked local
// browser — the requested browser leading — and caches the released keys under every
// tracked local endpoint id (each profile of a browser shares its Safe Storage key),
// with the requested endpoint id put LAST. Peer endpoints never join the batch.
func TestColdPrimeWarmsAllLocalEndpointsInOneEvaluation(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "chrome", "Work"),
		stateEndpoint(self, "arc", "Default"),
		stateEndpoint("you@desktop", "chrome", "Default"),
	)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handlePrimeAuth(ctx, map[string]any{"browser": "chrome"})
	if err != nil {
		t.Fatalf("handlePrimeAuth: %v", err)
	}
	if marshalResult(t, got) != `{"endpoint":"me@laptop:chrome:Default","primed":true}` {
		t.Fatalf("prime_auth = %s", marshalResult(t, got))
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("consent evaluations = %d, want 1 batch for the whole local set", len(consent.batchCalls))
	}
	call := consent.batchCalls[0]
	if call.reason != consentReason {
		t.Fatalf("batch reason = %q, want %q", call.reason, consentReason)
	}
	if len(call.browsers) != 2 || call.browsers[0] != "chrome" || call.browsers[1] != "arc" {
		t.Fatalf("batch browsers = %v, want the requested chrome leading arc", call.browsers)
	}
	requested := endpointID(self, "chrome", "Default")
	for _, id := range []string{requested, endpointID(self, "chrome", "Work"), endpointID(self, "arc", "Default")} {
		if _, ok, _ := cache.Get(ctx, id); !ok {
			t.Errorf("local endpoint %s not warmed by the batch prime", id)
		}
	}
	if _, ok, _ := cache.Get(ctx, endpointID("you@desktop", "chrome", "Default")); ok {
		t.Errorf("a peer endpoint must never be cached by a local prime")
	}
	if len(cache.puts) != 3 || cache.puts[2] != requested {
		t.Fatalf("cache puts = %v, want 3 with the requested endpoint %s last", cache.puts, requested)
	}
}

// TestConcurrentDistinctEndpointPrimesCollapseToOneEvaluation proves batchFlight:
// two concurrent cold primes for DISTINCT endpoints cost ONE Touch ID evaluation —
// the second either joins the in-flight batch or finds its endpoint already warmed
// by it — where the old per-endpoint flights prompted once each.
func TestConcurrentDistinctEndpointPrimesCollapseToOneEvaluation(t *testing.T) {
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "chrome", "Work"),
	)
	consent := &gateConsent{
		key:     cookie.DeriveKey(cookie.SafeStorageKey("peanuts")),
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	leaderDone := make(chan error, 1)
	go func() {
		_, err := d.primeAuth(context.Background(), "local", "chrome", "Default", consentReason, releaseLocal)
		leaderDone <- err
	}()
	<-consent.entered

	waiterDone := make(chan error, 1)
	go func() {
		_, err := d.primeAuth(context.Background(), "local", "chrome", "Work", consentReason, releaseLocal)
		waiterDone <- err
	}()

	close(consent.release)
	if err := <-leaderDone; err != nil {
		t.Fatalf("leader prime: %v", err)
	}
	if err := <-waiterDone; err != nil {
		t.Fatalf("waiter prime: %v", err)
	}
	if got := consent.calls.Load(); got != 1 {
		t.Errorf("consent evaluations = %d, want 1 (distinct-endpoint primes must collapse into one batch)", got)
	}
	for _, id := range []string{endpointID(self, "chrome", "Default"), endpointID(self, "chrome", "Work")} {
		if _, ok, _ := cache.Get(context.Background(), id); !ok {
			t.Errorf("endpoint %s not warmed by the collapsed prime", id)
		}
	}
	if got := cache.putCalls(); got != 2 {
		t.Errorf("cache puts = %d, want 2 (one per tracked local endpoint, no re-seeding)", got)
	}
}

// TestPrimeAuthPartialBatchServesWaiterWhileLeaderBrowserDenied proves the F5 waiter
// path: one requestor primes two DISTINCT browsers concurrently — the leader's browser
// is denied (Missing) while the waiter's releases OK — and they share ONE consent
// evaluation. The leader fails with its own browser's ConsentError; the waiter still
// gets its key. The distinct-PROFILE collapse test never reaches this, since there
// every browser in the batch resolves to one shared outcome.
func TestPrimeAuthPartialBatchServesWaiterWhileLeaderBrowserDenied(t *testing.T) {
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "arc", "Default"),
	)
	consent := &partialGateConsent{
		key:     cookie.DeriveKey(cookie.SafeStorageKey("peanuts")),
		failFor: "chrome",
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	leaderDone := make(chan error, 1)
	go func() {
		_, err := d.primeAuth(context.Background(), "sid:1", "chrome", "Default", consentReason, releaseLocal)
		leaderDone <- err
	}()
	<-consent.entered

	waiterDone := make(chan error, 1)
	go func() {
		key, err := d.primeAuth(context.Background(), "sid:1", "arc", "Default", consentReason, releaseLocal)
		if err == nil && string(key) != string(consent.key) {
			err = errors.New("waiter got the wrong key")
		}
		waiterDone <- err
	}()

	close(consent.release)

	var declined *cookie.ConsentError
	if leaderErr := <-leaderDone; !errors.As(leaderErr, &declined) {
		t.Fatalf("leader prime for the denied browser = %v, want *cookie.ConsentError", leaderErr)
	}
	if err := <-waiterDone; err != nil {
		t.Fatalf("waiter prime for the released browser: %v", err)
	}
	if got := consent.batches.Load(); got != 1 {
		t.Errorf("consent evaluations = %d, want 1 (the waiter must ride the leader's batch, not re-lead)", got)
	}
	if _, ok, _ := cache.Get(context.Background(), endpointID(self, "arc", "Default")); !ok {
		t.Errorf("the waiter's browser must be warmed by the shared batch")
	}
	if _, ok, _ := cache.Get(context.Background(), endpointID(self, "chrome", "Default")); ok {
		t.Errorf("the denied browser must not be cached")
	}
}

// TestLocalPrimeAndInboundConsentSerializeThePrompt proves promptGate across flights:
// a local prime and an inbound request_consent each evaluate consent once, but at
// most one Touch ID sheet is in flight at a time.
func TestLocalPrimeAndInboundConsentSerializeThePrompt(t *testing.T) {
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "")
	consent := &countingConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts")), hold: 20 * time.Millisecond}
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	done := make(chan error, 2)
	go func() {
		_, err := d.primeAuth(context.Background(), "local", "chrome", "Default", consentReason, releaseLocal)
		done <- err
	}()
	go func() {
		got, err := d.handleRequestConsent(context.Background(), map[string]any{
			"browser": "chrome", "profile": "Work", "nonce": "n", "endpoint": "them@host:chrome:Work",
		})
		if err == nil && marshalResult(t, got) != `{"endpoint":"them@host:chrome:Work","nonce":"n","status":"approved"}` {
			err = errors.New("inbound consent did not approve: " + marshalResult(t, got))
		}
		done <- err
	}()
	for range 2 {
		if err := <-done; err != nil {
			t.Errorf("prime/consent: %v", err)
		}
	}
	if got := consent.calls.Load(); got != 2 {
		t.Errorf("consent prompts = %d, want 2 (one per flight mode)", got)
	}
	if got := consent.peak.Load(); got != 1 {
		t.Errorf("peak concurrent prompts = %d, want 1 (flights must serialize the sheet)", got)
	}
}

// TestRequestedEndpointRePutSurvivesEvictAllRace proves the verify-and-re-Put tail of
// releaseAllLocal: when an EvictAll races in right after the requested endpoint's Put
// (a concurrent Put healing the degraded wrapper mid-batch), the requested endpoint
// is re-Put and ends warm — the one endpoint the prime was for never comes out cold.
func TestRequestedEndpointRePutSurvivesEvictAllRace(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	requested := endpointID(self, "chrome", "Default")
	st := stateWith(self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "chrome", "Work"),
	)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	cache := &raceEvictCache{fakeCache: newFakeCache(), evictOn: requested}
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	key, err := d.primeAuth(ctx, "local", "chrome", "Default", consentReason, releaseLocal)
	if err != nil {
		t.Fatalf("primeAuth: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("primeAuth returned the wrong key")
	}
	work := endpointID(self, "chrome", "Work")
	wantPuts := []string{work, requested, requested}
	if len(cache.puts) != len(wantPuts) {
		t.Fatalf("cache puts = %v, want %v (bulk, requested last, re-Put after the evict)", cache.puts, wantPuts)
	}
	for i, want := range wantPuts {
		if cache.puts[i] != want {
			t.Fatalf("cache puts = %v, want %v (bulk, requested last, re-Put after the evict)", cache.puts, wantPuts)
		}
	}
	if _, ok, _ := cache.Get(ctx, requested); !ok {
		t.Fatalf("the requested endpoint must be re-Put after the racing EvictAll")
	}
}

// TestRequestedEndpointLastSurvivesRealCacheHeal pins the requested-last Put ordering
// against the REAL key cache: a KeyCache opened degraded (keybag locked) heals on the
// requested endpoint's Put — the last of the batch — whose swap runs EvictAll. The
// bulk Puts before it are dropped by the heal, but the requested endpoint, being
// last, survives Enclave-wrapped; were it put any earlier, the prime's own endpoint
// would come out cold.
func TestRequestedEndpointLastSurvivesRealCacheHeal(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	// One open probe + two bulk Puts stay degraded; the fourth probe — the requested
	// endpoint's Put — heals.
	binary := writeHealingCacheHelper(t, 4)
	restore := paths.SetHelperBinaryForTest(binary)
	t.Cleanup(restore)

	wrapper, err := cache.OpenWrapper(ctx, helper.Bridge{})
	if !errors.Is(err, cache.ErrSEPresenceUnavailable) {
		t.Fatalf("OpenWrapper = %v, want ErrSEPresenceUnavailable", err)
	}
	keyCache := cache.NewKeyCache(wrapper)
	t.Cleanup(func() { _ = wrapper.Close(context.Background()) })

	st := stateWith(self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "chrome", "Work"),
		stateEndpoint(self, "arc", "Default"),
	)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	d := New(consent, keyCache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	requested := endpointID(self, "chrome", "Default")
	key, err := d.primeAuth(ctx, "local", "chrome", "Default", consentReason, releaseLocal)
	if err != nil {
		t.Fatalf("primeAuth: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("primeAuth returned the wrong key")
	}
	if keyCache.Degraded() {
		t.Fatalf("the cache must have healed on the requested endpoint's Put")
	}
	got, ok, err := keyCache.Get(ctx, requested)
	if err != nil || !ok {
		t.Fatalf("requested endpoint after the heal = %q, %v, %v, want the warm key", got, ok, err)
	}
	if string(got) != string(consent.key) {
		t.Fatalf("requested endpoint key = %q, want %q", got, consent.key)
	}
	for _, dropped := range []string{endpointID(self, "chrome", "Work"), endpointID(self, "arc", "Default")} {
		if _, ok, _ := keyCache.Get(ctx, dropped); ok {
			t.Errorf("bulk endpoint %s survived the heal EvictAll — the requested endpoint was not put last", dropped)
		}
	}
}

// writeHealingCacheHelper writes a fake cookiesync-keyhelper whose cache-newkey
// refuses with the presence code (exit 3) until its healAt'th invocation, then
// succeeds — so a KeyCache opened degraded heals on the Put that makes the healAt'th
// probe. cache-wrap/cache-unwrap XOR stdin to stdout; cache-dropkey is a no-op.
func writeHealingCacheHelper(t *testing.T, healAt int) string {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "cookiesync-keyhelper")
	countPath := filepath.Join(dir, "newkey.count")
	body := fmt.Sprintf(`#!/bin/sh
case "$1" in
cache-newkey)
  echo x >> %q
  if [ "$(grep -c x %q)" -lt %d ]; then exit 3; fi
  exit 0
  ;;
cache-dropkey)
  exit 0
  ;;
cache-wrap|cache-unwrap)
  exec /usr/bin/perl -0777 -pe 's/(.)/chr(ord($1)^0x5A)/ges'
  ;;
*)
  echo "unexpected verb $1" >&2
  exit 99
  ;;
esac
`, countPath, countPath, healAt)
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write healing cache helper: %v", err)
	}
	return binary
}

// TestRequestConsentAnswersWhileRoutedReleaseInFlight is the same-host routed-consent
// cycle regression for promptGate: while this host's own outbound routed release is
// mid-ssh (a hard route from an attended host), an inbound request_consent must still
// reach the Touch ID prompt — the gate is never held across routedRelease.
func TestRequestConsentAnswersWhileRoutedReleaseInFlight(t *testing.T) {
	me := currentUser(t)
	self := "me@laptop"
	peer := "you@desktop"
	endpoint := endpointID(self, "chrome", "Default")
	nonce := "gate-nonce"

	fakeMesh(t, self, peer)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	inner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_consent": approvedReply(t, nonce, endpoint)},
	}
	runner := &gatedRunner{inner: inner, match: "request_consent", arrived: make(chan struct{}, 1), release: make(chan struct{})}
	st := stateWith(self, peer, stateEndpoint(peer, "chrome", "Default"))
	st.ConsentRouteHard = true
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(me)), runner, fixedState{st: st}, fixedState{st: st})
	pinnedNonce(d, nonce)

	primeDone := make(chan error, 1)
	go func() {
		_, err := d.primeAuth(context.Background(), "local", "chrome", "Default", consentReason, releaseLocal)
		primeDone <- err
	}()
	<-runner.arrived

	inboundDone := make(chan error, 1)
	go func() {
		got, err := d.handleRequestConsent(context.Background(), map[string]any{
			"browser": "chrome", "nonce": "n2", "endpoint": "them@host:chrome:Work",
		})
		if err == nil && marshalResult(t, got) != `{"endpoint":"them@host:chrome:Work","nonce":"n2","status":"approved"}` {
			err = errors.New("inbound consent did not approve: " + marshalResult(t, got))
		}
		inboundDone <- err
	}()
	select {
	case err := <-inboundDone:
		if err != nil {
			t.Fatalf("inbound request_consent mid-routed-release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("inbound request_consent blocked behind the outbound routed release — promptGate is held across ssh")
	}

	close(runner.release)
	if err := <-primeDone; err != nil {
		t.Fatalf("routed prime: %v", err)
	}
}

// gatedRunner parks any Run whose command contains match — send on arrived, wait for
// release — so a test holds an outbound ssh mid-flight; everything else passes through
// to inner.
type gatedRunner struct {
	inner   *recordingRunner
	match   string
	arrived chan struct{}
	release chan struct{}
}

func (r *gatedRunner) Run(ctx context.Context, target, cmd string, stdin []byte) (string, error) {
	if strings.Contains(cmd, r.match) {
		r.arrived <- struct{}{}
		<-r.release
	}
	return r.inner.Run(ctx, target, cmd, stdin)
}

// waitFor polls cond every 5ms, failing the test when it does not hold within 2s.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not reached within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// wireCookieNames decodes a {"cookies": [...]} handler result into a by-name map of
// wire cookies, asserting the envelope shape.
func wireCookieNames(t *testing.T, result any) map[string]cookie.WireCookie {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var envelope struct {
		Cookies []cookie.WireCookie `json:"cookies"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("decode cookies envelope: %v (%s)", err, data)
	}
	out := map[string]cookie.WireCookie{}
	for _, c := range envelope.Cookies {
		out[c.Name] = c
	}
	return out
}

// peerExtractReply renders the frozen {"cookies": [...]} reply a peer's rpc extract
// streams back, carrying the given cookies as wire records.
func peerExtractReply(t *testing.T, cookies ...cookie.Cookie) string {
	t.Helper()
	wire := make([]cookie.WireCookie, len(cookies))
	for i, c := range cookies {
		wire[i] = cookie.ToWire(c)
	}
	data, err := json.Marshal(map[string]any{"cookies": wire})
	if err != nil {
		t.Fatalf("marshal extract reply: %v", err)
	}
	return string(data)
}

// wireArrayToAny renders a wire-cookie slice into the []any map-tree a JSON request
// param carries, so a handler param matches what the transport delivers.
func wireArrayToAny(t *testing.T, in []cookie.WireCookie) []any {
	t.Helper()
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal wire array: %v", err)
	}
	var out []any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode wire array: %v", err)
	}
	return out
}

// newRealEngine builds an engine whose only role in these handler tests is to carry the
// shared anti-echo recorder (handleApply records through engine.Recorder()). extract/
// apply do not call Sync/Reconcile, so the store and ssh runner are unused.
func newRealEngine(t *testing.T, cache *fakeCache) *engine.Engine {
	t.Helper()
	return engine.New(nil, cache, nil, engine.NewDigestRecorder())
}
