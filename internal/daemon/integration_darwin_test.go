//go:build darwin

package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite" // register the sqlite driver for the test store

	"github.com/yasyf/cookiesync/internal/cache"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/synckit/authkit"
)

// TestRequestedEndpointLastSurvivesRealCacheHeal pins the requested-last Put ordering
// in releaseAllLocal against the REAL key cache: a KeyCache opened degraded (keybag
// locked) heals on the requested endpoint's Put — the last of the batch — whose epoch
// swap evicts every pre-heal entry. The bulk Puts before it are dropped by the heal,
// but the requested endpoint, being last, survives Enclave-wrapped; were it put any
// earlier, the prime's own endpoint would come out cold.
func TestRequestedEndpointLastSurvivesRealCacheHeal(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	// One open probe + two bulk Puts' probes stay refused; the fourth probe — the
	// requested endpoint's Put — heals.
	binary := writeHealingCacheHelper(t, 4)
	t.Setenv(authkit.HelperEnvVar, binary)

	keyCache, err := cache.Open(ctx, helper.Bridge{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !keyCache.Degraded() {
		t.Fatalf("the cache must open degraded under the locked keybag")
	}
	t.Cleanup(func() {
		if err := keyCache.Close(context.Background()); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	st := stateWith(self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "chrome", "Work"),
		stateEndpoint(self, "arc", "Default"),
	)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	d := New(consent, keyCache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	requested := endpointID(self, "chrome", "Default")
	key, _, err := d.primeAuth(ctx, "local", "chrome", "Default", consentReason, releaseLocal)
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
			t.Errorf("bulk endpoint %s survived the heal eviction — the requested endpoint was not put last", dropped)
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
