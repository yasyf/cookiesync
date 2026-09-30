//go:build linux

package daemon

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/bridge"
	"github.com/yasyf/cookiesync/internal/cookie"
)

func importOnlyBridgeDaemon(t *testing.T) (*Daemon, *fakeConsent) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	fakeMesh(t, importTestSelf)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	st := stateWith(importTestSelf, "")
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	d.processes = testBridgeProcesses(t)
	t.Cleanup(func() { d.closeAllBridges(context.Background()) })
	d.seedSource = func(context.Context, cookie.Browser, string, cookie.AesKey) (cookie.StorageState, cookie.SeedCounts, error) {
		t.Errorf("seedSource called: an open over a live import must never read the profile")
		return cookie.StorageState{}, cookie.SeedCounts{}, errors.New("profile read forbidden")
	}
	return d, consent
}

func bridgeProbeRecord(expiresAt time.Time) importRecord {
	return importTestRecord([]string{"example.com"},
		[]cookie.Cookie{{HostKey: "example.com", Name: "bridge_probe", Value: "ok", Path: "/", IsSecure: true, SameSite: 2}},
		nil, expiresAt)
}

func assertNoNativeDataRoot(t *testing.T) {
	t.Helper()
	chrome, err := cookie.Lookup(cookie.BrowserName("chrome"))
	if err != nil {
		t.Fatalf("lookup chrome: %v", err)
	}
	if _, err := os.Stat(chrome.DataRoot); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("native data root %s exists (stat: %v), want none created by an import-backed open", chrome.DataRoot, err)
	}
}

// TestBridgeOpenResolvesAnImportedTargetWithoutLocalProfile runs bridge_open against
// an empty data root with the launcher stubbed: a live import passes validation with
// no tap and no profile read; no import, or an advertised open, is refused as unknown.
func TestBridgeOpenResolvesAnImportedTargetWithoutLocalProfile(t *testing.T) {
	tests := []struct {
		name      string
		record    bool
		advertise string
		wantErr   string
	}{
		{"a live import stands in for the missing profile", true, "", "resolve chrome: launcher stubbed"},
		{"no import refuses the missing profile before launch", false, "", `unknown profile "Default" for browser chrome`},
		{"an advertised open ignores the import", true, "host:1", `unknown profile "Default" for browser chrome`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, consent := importOnlyBridgeDaemon(t)
			d.hostBinary = func() (string, error) { return "", errors.New("launcher stubbed") }
			if tt.record {
				d.imports.put(importKey{browser: "chrome", profile: "Default"}, bridgeProbeRecord(time.Now().Add(time.Minute)))
			}
			params := map[string]any{"browser": "chrome", "profile": "Default", "headed": false}
			if tt.advertise != "" {
				params["advertise"] = tt.advertise
			}

			_, err := dispatchSelf(t, d, "bridge_open", params)
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("bridge_open error = %v, want %q", err, tt.wantErr)
			}
			if got := consent.biometricCalls.Load(); got != 0 {
				t.Fatalf("ObtainKeyBiometric calls = %d, want 0", got)
			}
			if got := bridgeCount(d); got != 0 {
				t.Fatalf("sessions after the refused open = %d, want 0", got)
			}
			assertNoNativeDataRoot(t)
		})
	}
}

// TestBridgeOpenSeedsFromAnImportWithoutLocalProfile is the fresh-VM proof over a
// real Chrome: with no native profile at all, a live import opens a seeded bridge
// with no tap, no profile read, and no native data root created.
func TestBridgeOpenSeedsFromAnImportWithoutLocalProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: launches a real Chrome")
	}
	if _, err := bridge.ResolveHostBinary(); err != nil {
		t.Skipf("skipping: Chrome not installed: %v", err)
	}
	d, consent := importOnlyBridgeDaemon(t)
	d.imports.put(importKey{browser: "chrome", profile: "Default"}, bridgeProbeRecord(time.Now().Add(time.Minute)))

	ctx := context.Background()
	res, err := dispatchSelf(t, d, "bridge_open", map[string]any{"browser": "chrome", "profile": "Default", "headed": false})
	if err != nil {
		t.Fatalf("bridge_open over an import with no local profile: %v", err)
	}
	open := resultMap(t, res)
	url, _ := open["url"].(string)
	if url == "" {
		t.Fatalf("bridge_open missing url: %+v", open)
	}
	if got := consent.biometricCalls.Load(); got != 0 {
		t.Fatalf("ObtainKeyBiometric calls = %d, want 0 (the import replaces the tap)", got)
	}
	client := dialBridge(ctx, t, url)
	if names := relayCookieNames(ctx, t, client); !contains(names, "bridge_probe") {
		t.Fatalf("relay cookies = %v, want the imported bridge_probe", names)
	}
	assertNoNativeDataRoot(t)
}
