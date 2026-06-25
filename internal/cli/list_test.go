package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"

	_ "modernc.org/sqlite" // register the sqlite driver for the test store

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/manifest"
)

// v24Schema is a Chrome v24 cookie store schema, enough to seed a real store for the
// list fingerprint.
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

// chromeStore points HOME at a temp dir and creates a Chrome v24 cookie store for the
// given profile, seeded with the given cookies via the real apply path. It returns the
// chrome Browser the list command will resolve.
func chromeStore(t *testing.T, profile string, key cookie.AesKey, cookies ...cookie.Cookie) cookie.Browser {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	browser, err := cookie.Lookup("chrome")
	if err != nil {
		t.Fatalf("lookup chrome: %v", err)
	}
	if err := os.MkdirAll(browser.ProfileDir(profile), 0o700); err != nil {
		t.Fatalf("mkdir profile: %v", err)
	}
	db, err := sql.Open("sqlite", browser.CookiesDB(profile))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := db.Exec(v24Schema); err != nil {
		_ = db.Close()
		t.Fatalf("schema: %v", err)
	}
	_ = db.Close()
	if len(cookies) > 0 {
		if _, err := cookie.Apply(context.Background(), cookies, browser, profile, key); err != nil {
			t.Fatalf("seed apply: %v", err)
		}
	}
	return browser
}

func sample(host, name, value string) cookie.Cookie {
	return cookie.Cookie{
		HostKey: cookie.HostKey(host), Name: name, Value: value, Path: "/",
		LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, IsSecure: true,
		SourceScheme: 2, SourcePort: 443,
	}
}

// TestListEmitsLocalWatchItemsWithApplyStableFingerprint proves `list --json` emits one
// WatchItem per present LOCAL endpoint with a profile dir, the watch_dirs pointing at the
// profile dir, and the fingerprint equal to the store's LogicalDigest — and that the
// fingerprint is apply-stable (re-listing after a self-induced apply is unchanged). A
// remote endpoint and a local endpoint with no profile dir are both skipped.
func TestListEmitsLocalWatchItemsWithApplyStableFingerprint(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	browser := chromeStore(t, "Default", key, sample(".x.com", "sid", "abc"), sample(".y.com", "tok", "xyz"))

	// HOME is now set; seed the mesh and the cookiesync registry under a temp XDG.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	seedRegistry(t, self, "you@desktop")
	store := state.New(paths.Config)
	local := state.Endpoint{Host: self, Browser: "chrome", Profile: "Default"}
	remote := state.Endpoint{Host: "you@desktop", Browser: "chrome", Profile: "Default"}
	absent := state.Endpoint{Host: self, Browser: "chrome", Profile: "NoSuchProfile"}
	for _, ep := range []state.Endpoint{local, remote, absent} {
		if err := store.AddBrowser(ctx, self, ep); err != nil {
			t.Fatalf("add %s: %v", ep.ID(), err)
		}
	}

	items := runListJSON(t)
	if len(items) != 1 {
		t.Fatalf("list emitted %d items, want 1 (local present; remote and absent-dir skipped): %+v", len(items), items)
	}
	item := items[0]
	if item.ID != string(local.ID()) {
		t.Fatalf("item id = %q, want %q", item.ID, local.ID())
	}
	if len(item.WatchDirs) != 1 || item.WatchDirs[0] != browser.ProfileDir("Default") {
		t.Fatalf("watch_dirs = %v, want [%s]", item.WatchDirs, browser.ProfileDir("Default"))
	}

	// The fingerprint equals the store's logical digest.
	rows, err := cookie.Read(ctx, browser, "Default")
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	want := string(cookie.LogicalDigest(rows))
	if item.Fingerprint != want {
		t.Fatalf("fingerprint = %q, want %q (LogicalDigest)", item.Fingerprint, want)
	}

	// Apply-stable: a self-induced re-apply of the same set leaves the listed fingerprint
	// unchanged — the property synckitd dedups cookiesync's own write on.
	reapply := make([]cookie.Cookie, 0, len(rows))
	for _, row := range rows {
		c, ok := cookie.DecryptRow(row, key)
		if !ok {
			t.Fatalf("decrypt row %s/%s failed", row.HostKey, row.Name)
		}
		reapply = append(reapply, c)
	}
	if _, err := cookie.Apply(ctx, reapply, browser, "Default", key); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	after := runListJSON(t)
	if len(after) != 1 || after[0].Fingerprint != want {
		t.Fatalf("fingerprint changed across a self-induced apply: %+v, want stable %q", after, want)
	}
}

// runListJSON runs `list --json` on a fresh root and decodes the watch items.
func runListJSON(t *testing.T) []manifest.WatchItem {
	t.Helper()
	var out bytes.Buffer
	root := newRoot("test")
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"list", "--json"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("list --json: %v\n%s", err, out.String())
	}
	var items []manifest.WatchItem
	if err := json.Unmarshal(out.Bytes(), &items); err != nil {
		t.Fatalf("list --json is not valid JSON: %v\n%s", err, out.String())
	}
	return items
}
