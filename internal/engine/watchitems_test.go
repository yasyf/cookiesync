package engine

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "modernc.org/sqlite" // register the sqlite driver for the fixture cookie store

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
)

// v24Schema is a Chrome v24 cookie store schema, enough for cookie.Read to open the
// fixture store and return zero rows.
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
`

// addChromeStore creates an empty Chrome v24 cookie store for profile under the browser's
// (already HOME-redirected) profile root, so cookie.Read resolves a real, readable DB.
func addChromeStore(t *testing.T, browser cookie.Browser, profile string) {
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

// TestWatchItemDeclaresCookiesDBFile pins watchItem to declare the endpoint's Cookies DB
// file in WatchDirs (not its profile directory, whose recursive watch cost ~63k fds), and
// to skip an endpoint whose profile directory is absent.
func TestWatchItemDeclaresCookiesDBFile(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		present bool
		wantOK  bool
	}{
		{"present store declares the Cookies DB file", "Default", true, true},
		{"absent profile dir yields ok=false", "Ghost", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			browser, err := cookie.Lookup("chrome")
			if err != nil {
				t.Fatalf("lookup chrome: %v", err)
			}
			if tt.present {
				addChromeStore(t, browser, tt.profile)
			}
			ep := state.Endpoint{Host: "me@laptop", Browser: "chrome", Profile: tt.profile}
			item, ok, err := watchItem(context.Background(), ep)
			if err != nil {
				t.Fatalf("watchItem: %v", err)
			}
			if ok != tt.wantOK {
				t.Fatalf("watchItem ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			want := browser.CookiesDB(tt.profile)
			if len(item.WatchDirs) != 1 || item.WatchDirs[0] != want {
				t.Fatalf("watchItem WatchDirs = %v, want [%s]", item.WatchDirs, want)
			}
			if item.ID != string(ep.ID()) {
				t.Fatalf("watchItem ID = %q, want %q", item.ID, ep.ID())
			}
		})
	}
}
