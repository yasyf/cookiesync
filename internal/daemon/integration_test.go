package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"

	_ "modernc.org/sqlite" // register the sqlite driver for the test store

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
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
	if err := os.MkdirAll(browser.ProfileDir("Default"), 0o700); err != nil {
		t.Fatalf("mkdir profile: %v", err)
	}
	db, err := sql.Open("sqlite", browser.CookiesDB("Default"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(v24Schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return browser
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
	d := New(&fakeConsent{}, cache, nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: st})
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Default"), []byte(key), 0)

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
	d := New(&fakeConsent{}, cache, nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: stateWith("me@laptop", "")})
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Default"), []byte(key), 0)

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
	d := New(&fakeConsent{key: key}, cache, newRealEngine(t, cache), staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st})

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
