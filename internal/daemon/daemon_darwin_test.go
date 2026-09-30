//go:build darwin

package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/auth"
	"github.com/yasyf/cookiesync/internal/cache"
	"github.com/yasyf/cookiesync/internal/helper"
)

// TestHandleAuthStatusLockedUnwrapRefusalReportsLocked reproduces the live incident over
// the real cache: a wrapped key cached while unlocked, then the screen locks and
// cache-unwrap refuses the per-boot key (exit 3). The refusal demotes the cache — the
// two-way degrade — so auth_status reports authenticated:false, degraded:true,
// locked:true instead of a raw RPC error.
func TestHandleAuthStatusLockedUnwrapRefusalReportsLocked(t *testing.T) {
	fakeMesh(t, "me@laptop")
	binary := writeUnwrapRefusingHelper(t, 3, "keyhelper: SecKeyCreateDecryptedData failed: interaction not allowed (OSStatus -25308)")
	ctx := context.Background()

	keyCache, err := cache.Open(ctx, helper.Bridge{Binary: binary})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	st := stateWith("me@laptop", "")
	d := New(&fakeConsent{}, keyCache, nil, staticProbe(SessionSnapshot{OnConsole: true, Locked: true}), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	id := endpointID("me@laptop", "chrome", "Default")
	if _, err := keyCache.Put(ctx, id, []byte("safe-storage-key"), 5*time.Minute); err != nil {
		t.Fatalf("Put a wrapped key while unlocked: %v", err)
	}

	got, err := d.handleAuthStatus(ctx, map[string]any{"browser": "chrome"})
	if err != nil {
		t.Fatalf("handleAuthStatus must swallow the locked-keybag refusal, got %v", err)
	}
	if marshalResult(t, got) != `{"authenticated":false,"degraded":true,"endpoint":"me@laptop:chrome:Default","keybag_locked":true}` {
		t.Fatalf("auth_status = %s, want the locked reply with the demoted cache degraded", marshalResult(t, got))
	}
}

// writeUnwrapRefusingHelper writes a fake cookiesync-keyhelper that opens and wraps
// cleanly — cache-newkey and cache-wrap succeed — but whose cache-unwrap prints
// diagnostic to stderr and exits with code, the "keybag locked after open" surface.
func writeUnwrapRefusingHelper(t *testing.T, code int, diagnostic string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "cookiesync-keyhelper")
	body := `#!/bin/sh
case "$1" in
cache-newkey|cache-dropkey)
  exit 0
  ;;
cache-wrap)
  exec /usr/bin/perl -0777 -pe 's/(.)/chr(ord($1)^0x5A)/ges'
  ;;
cache-unwrap)
  printf '%s\n' "` + diagnostic + `" >&2
  exit ` + fmt.Sprintf("%d", code) + `
  ;;
*)
  echo "unexpected verb $1" >&2
  exit 99
  ;;
esac
`
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write unwrap-refusing helper: %v", err)
	}
	return binary
}

// TestHandleAuthStatusBoundsWedgedUnwrapReportsLockedNote proves the cache read is bounded
// too: the Enclave opened healthy and cached a key, then the screen locked and cache-unwrap
// hangs (a helper round-trip with no deadline of its own). auth.StatusTimeout kills the
// unwrap and the locked keybag is reported as the OK-with-note reply, not a FAIL.
func TestHandleAuthStatusBoundsWedgedUnwrapReportsLockedNote(t *testing.T) {
	fakeMesh(t, "me@laptop")
	restore := auth.StatusTimeout
	auth.StatusTimeout = 50 * time.Millisecond
	t.Cleanup(func() { auth.StatusTimeout = restore })

	ctx := context.Background()
	keyCache, err := cache.Open(ctx, helper.Bridge{Binary: writeHangingUnwrapHelper(t)})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	st := stateWith("me@laptop", "")
	d := New(&fakeConsent{}, keyCache, nil, staticProbe(SessionSnapshot{OnConsole: true, Locked: true}), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	id := endpointID("me@laptop", "chrome", "Default")
	if _, err := keyCache.Put(ctx, id, []byte("safe-storage-key"), 5*time.Minute); err != nil {
		t.Fatalf("Put a wrapped key while unlocked: %v", err)
	}

	done := make(chan any, 1)
	start := time.Now()
	go func() {
		got, err := d.handleAuthStatus(ctx, map[string]any{"browser": "chrome"})
		if err != nil {
			t.Errorf("handleAuthStatus must swallow the bounded-out unwrap, got %v", err)
		}
		done <- got
	}()

	select {
	case got := <-done:
		if marshalResult(t, got) != `{"authenticated":false,"degraded":false,"endpoint":"me@laptop:chrome:Default","keybag_locked":true}` {
			t.Fatalf("auth_status = %s, want the locked note reply", marshalResult(t, got))
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("handleAuthStatus took %v; auth.StatusTimeout must bound the unwrap", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handleAuthStatus hung on a wedged cache-unwrap; auth.StatusTimeout did not bound it")
	}
}

// writeHangingUnwrapHelper writes a fake cookiesync-keyhelper that opens and wraps cleanly
// — cache-newkey and cache-wrap succeed — but whose cache-unwrap hangs, the "keybag locked,
// unwrap wedged after open" surface. It execs sleep so the bound's kill leaves no orphan.
func writeHangingUnwrapHelper(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "cookiesync-keyhelper")
	body := `#!/bin/sh
case "$1" in
cache-newkey|cache-dropkey)
  exit 0
  ;;
cache-wrap)
  exec cat
  ;;
cache-unwrap)
  exec sleep 30
  ;;
*)
  echo "unexpected verb $1" >&2
  exit 99
  ;;
esac
`
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write hanging-unwrap helper: %v", err)
	}
	return binary
}

// writeBlockingHealHelper writes a fake cookiesync-keyhelper whose first cache-newkey
// (the Open probe) exits 3 to degrade, and whose next cache-newkey (a KeyCache heal)
// appends to tallyPath then parks until releasePath exists — a heal wedged in its
// presence prompt, so a test can drive auth_status against a cache mid-heal.
func writeBlockingHealHelper(t *testing.T) (binary, tallyPath, releasePath string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "cookiesync-keyhelper")
	countPath := filepath.Join(dir, "newkey.count")
	tallyPath = filepath.Join(dir, "heal.tally")
	releasePath = filepath.Join(dir, "release")
	body := `#!/bin/sh
case "$1" in
cache-newkey)
  n=$(cat "` + countPath + `" 2>/dev/null || echo 0); n=$((n+1)); printf '%s' "$n" > "` + countPath + `"
  if [ "$n" -gt 1 ]; then
    printf 'x\n' >> "` + tallyPath + `"
    while [ ! -f "` + releasePath + `" ]; do sleep 0.01; done
  fi
  exit 3
  ;;
*)
  echo "unexpected verb $1" >&2
  exit 99
  ;;
esac
`
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write blocking heal helper: %v", err)
	}
	return binary, tallyPath, releasePath
}

// TestHandleAuthStatusReturnsWhileAHealIsMidFlight proves the A1 lock split at the daemon
// boundary: with a Put's heal parked in cache-newkey (its presence prompt), a status read
// still returns within auth.StatusTimeout because the heal no longer holds the wrapper lock
// the read's Degraded check takes.
func TestHandleAuthStatusReturnsWhileAHealIsMidFlight(t *testing.T) {
	fakeMesh(t, "me@laptop")
	binary, tallyPath, releasePath := writeBlockingHealHelper(t)
	keyCache, err := cache.Open(context.Background(), helper.Bridge{Binary: binary})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !keyCache.Degraded() {
		t.Fatalf("Open over a presence-refusing helper must degrade")
	}
	st := stateWith("me@laptop", "")
	d := New(&fakeConsent{}, keyCache, nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	d.broker.KeybagProbe = staticProbe(liveSession(currentUser(t)))

	id := endpointID("me@laptop", "chrome", "Default")
	putDone := make(chan error, 1)
	go func() {
		_, err := keyCache.Put(context.Background(), id, []byte("k"), 5*time.Minute)
		putDone <- err
	}()
	t.Cleanup(func() {
		_ = os.WriteFile(releasePath, nil, 0o600)
		<-putDone
	})
	// Wait until the heal is parked in cache-newkey.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if data, _ := os.ReadFile(tallyPath); len(data) > 0 { //nolint:gosec // test-controlled temp file.
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("heal never parked in cache-newkey")
		}
		time.Sleep(2 * time.Millisecond)
	}

	done := make(chan any, 1)
	start := time.Now()
	go func() {
		got, err := d.handleAuthStatus(context.Background(), map[string]any{"browser": "chrome"})
		if err != nil {
			t.Errorf("handleAuthStatus: %v", err)
		}
		done <- got
	}()
	select {
	case <-done:
		if elapsed := time.Since(start); elapsed > auth.StatusTimeout {
			t.Fatalf("handleAuthStatus took %v with a heal mid-flight; the read must stay off the heal lock (bound %v)", elapsed, auth.StatusTimeout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handleAuthStatus hung with a heal mid-flight")
	}
}
