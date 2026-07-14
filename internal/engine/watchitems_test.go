package engine

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// singletonLock plants the SingletonLock symlink Chromium keeps at the data root,
// targeting "<hostname>-<pid>".
func singletonLock(t *testing.T, browser cookie.Browser, pid int) {
	t.Helper()
	if err := os.Symlink(fmt.Sprintf("laptop.local-%d", pid), filepath.Join(browser.DataRoot, "SingletonLock")); err != nil {
		t.Fatalf("plant SingletonLock: %v", err)
	}
}

// TestWatchItemBusyWhenBrowserMidWrite pins the busy signal: an item reports Busy only
// when the owning browser is running (a live pid behind SingletonLock) AND the store
// or a -journal/-wal sidecar was written within busyWriteWindow — either alone is not
// enough, and a stale post-crash lock never counts as running.
func TestWatchItemBusyWhenBrowserMidWrite(t *testing.T) {
	const deadPID = 99999999
	tests := []struct {
		name       string
		pid        int
		staleStore bool
		sidecar    string
		wantBusy   bool
	}{
		{"running browser and fresh store is busy", os.Getpid(), false, "", true},
		{"running browser and fresh journal sidecar is busy", os.Getpid(), true, "Cookies-journal", true},
		{"running browser and fresh wal sidecar is busy", os.Getpid(), true, "Cookies-wal", true},
		{"running browser but idle store is not busy", os.Getpid(), true, "", false},
		{"fresh store without the browser is not busy", 0, false, "", false},
		{"fresh store behind a stale crash lock is not busy", deadPID, false, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			browser, err := cookie.Lookup("chrome")
			if err != nil {
				t.Fatalf("lookup chrome: %v", err)
			}
			addChromeStore(t, browser, "Default")
			if tt.pid != 0 {
				singletonLock(t, browser, tt.pid)
			}
			if tt.staleStore {
				old := time.Now().Add(-time.Minute)
				if err := os.Chtimes(browser.CookiesDB("Default"), old, old); err != nil {
					t.Fatalf("age store: %v", err)
				}
			}
			if tt.sidecar != "" {
				path := filepath.Join(browser.ProfileDir("Default"), tt.sidecar)
				if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
					t.Fatalf("plant sidecar: %v", err)
				}
			}

			ep := state.Endpoint{Host: "me@laptop", Browser: "chrome", Profile: "Default"}
			item, ok, err := watchItem(context.Background(), ep)
			if err != nil || !ok {
				t.Fatalf("watchItem ok=%v err=%v, want present item", ok, err)
			}
			if item.Busy != tt.wantBusy {
				t.Fatalf("Busy = %v (reason %q), want %v", item.Busy, item.BusyReason, tt.wantBusy)
			}
			if tt.wantBusy && !strings.Contains(item.BusyReason, "Chrome") {
				t.Fatalf("BusyReason = %q, want it to name the browser", item.BusyReason)
			}
			if tt.wantBusy && item.Fingerprint != "" {
				t.Fatalf("busy item carries fingerprint %q, want empty (no torn read)", item.Fingerprint)
			}
			if !tt.wantBusy && item.BusyReason != "" {
				t.Fatalf("idle item carries BusyReason %q", item.BusyReason)
			}
		})
	}
}
