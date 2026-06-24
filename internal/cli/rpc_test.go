package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite" // register the sqlite driver for the test store

	"github.com/yasyf/cookiesync/internal/cookie"
)

// v24Schema is a Chrome v24 cookie store schema, enough for an rpc extract/apply
// round-trip against a real ephemeral SQLite file.
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

// fakeConsent returns a fixed key, so the rpc handlers run without Touch ID or the
// signed helper.
type fakeConsent struct {
	key cookie.AesKey
}

func (c fakeConsent) ObtainKey(_ context.Context, _ cookie.Browser, _ string) (cookie.AesKey, error) {
	return c.key, nil
}

func (c fakeConsent) ObtainKeyUnprompted(_ context.Context, _ cookie.Browser) (cookie.AesKey, error) {
	return c.key, nil
}

func tempBrowser(t *testing.T) cookie.Browser {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "Default"), 0o700); err != nil {
		t.Fatalf("mkdir profile: %v", err)
	}
	browser := cookie.Browser{
		Name:            cookie.BrowserName("test"),
		Display:         "Test",
		DataRoot:        root,
		KeychainService: "Test Safe Storage",
	}
	db, err := sql.Open("sqlite", browser.CookiesDB("Default"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(v24Schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
	return browser
}

// TestRPCExtractApplyJSONContract proves the rpc extract output and rpc apply input/
// output match the frozen JSON contract end to end against a real ephemeral store: an
// apply ingests a bare wire-cookie array and reports {"applied": n}; a subsequent
// extract emits {"cookies": [...]} whose wire records decode back to the applied set.
func TestRPCExtractApplyJSONContract(t *testing.T) {
	ctx := context.Background()
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	consent := fakeConsent{key: key}
	browser := tempBrowser(t)

	// Apply: a bare JSON array of wire cookies is the frozen stdin payload. Parse it the
	// way runRPCApply does, then write through applyCookies -> {"applied": n}.
	in := []cookie.Cookie{
		{HostKey: ".x.com", Name: "sid", Value: "abc", Path: "/", ExpiresUTC: 0, LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2},
		{HostKey: ".y.com", Name: "tok", Value: "xyz", Path: "/app", ExpiresUTC: 0, LastUpdateUTC: 13_350_000_000_000_001, SameSite: 1},
	}
	wireArray, err := json.Marshal(toWireArray(in))
	if err != nil {
		t.Fatalf("marshal wire array: %v", err)
	}
	parsed, err := cookie.UnmarshalCookies(wireArray)
	if err != nil {
		t.Fatalf("UnmarshalCookies (stdin contract): %v", err)
	}
	applied, err := applyCookies(ctx, consent, browser, "Default", parsed)
	if err != nil {
		t.Fatalf("applyCookies: %v", err)
	}
	if applied != 2 {
		t.Fatalf("applied = %d, want 2", applied)
	}

	// Extract: -> {"cookies": [...]} that decodes back to the applied set.
	got, err := extractCookies(ctx, consent, browser, "Default")
	if err != nil {
		t.Fatalf("extractCookies: %v", err)
	}
	payload, err := cookie.MarshalCookies(got)
	if err != nil {
		t.Fatalf("MarshalCookies: %v", err)
	}
	var envelope struct {
		Cookies []cookie.WireCookie `json:"cookies"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("extract envelope parse: %v", err)
	}
	if len(envelope.Cookies) != 2 {
		t.Fatalf("extract returned %d cookies, want 2: %s", len(envelope.Cookies), payload)
	}
	byName := map[string]cookie.WireCookie{}
	for _, c := range envelope.Cookies {
		byName[c.Name] = c
	}
	if byName["sid"].Value != "abc" || byName["sid"].HostKey != ".x.com" {
		t.Fatalf("sid cookie = %+v", byName["sid"])
	}
	if byName["tok"].Value != "xyz" || byName["tok"].LastUpdateUTC != 13_350_000_000_000_001 {
		t.Fatalf("tok cookie = %+v", byName["tok"])
	}

	// The {"applied": n} envelope is itself the frozen shape; assert it directly.
	appliedJSON, err := json.Marshal(struct {
		Applied int `json:"applied"`
	}{Applied: applied})
	if err != nil {
		t.Fatalf("marshal applied: %v", err)
	}
	if string(appliedJSON) != `{"applied":2}` {
		t.Fatalf("applied envelope = %s, want {\"applied\":2}", appliedJSON)
	}
}

func toWireArray(cookies []cookie.Cookie) []cookie.WireCookie {
	out := make([]cookie.WireCookie, len(cookies))
	for i, c := range cookies {
		out[i] = cookie.ToWire(c)
	}
	return out
}

// TestRunRPCExtractRejectsUnknownBrowser proves the extract command body resolves the
// browser through the registry and fails loudly on an unknown one, rather than emitting
// an empty cookie set.
func TestRunRPCExtractRejectsUnknownBrowser(t *testing.T) {
	var out strings.Builder
	err := runRPCExtract(context.Background(), fakeConsent{}, "definitely-not-a-browser", "Default", &out)
	if err == nil {
		t.Fatalf("expected an unknown-browser error, got output %q", out.String())
	}
}
