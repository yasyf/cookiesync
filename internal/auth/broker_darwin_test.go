//go:build darwin

package auth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cache"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/helper"
)

// writeScriptedHelper writes a fake cookiesync-keyhelper whose cache-newkey
// succeeds for the first newkeyOKUntil invocations then exits 3, and whose
// cache-unwrap exits 3 for the first unwrapRefusals calls then XORs like
// cache-wrap. Counts persist in the script's temp dir.
func writeScriptedHelper(t *testing.T, newkeyOKUntil, unwrapRefusals int) string {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "cookiesync-keyhelper")
	newkeyCount := filepath.Join(dir, "newkey.count")
	unwrapCount := filepath.Join(dir, "unwrap.count")
	body := fmt.Sprintf(`#!/bin/sh
case "$1" in
cache-newkey)
  echo x >> %q
  if [ "$(grep -c x %q)" -le %d ]; then exit 0; fi
  echo "keyhelper: cache-newkey failed: interaction not allowed (OSStatus -25308)" >&2
  exit 3
  ;;
cache-dropkey)
  exit 0
  ;;
cache-wrap)
  exec /usr/bin/perl -0777 -pe 's/(.)/chr(ord($1)^0x5A)/ges'
  ;;
cache-unwrap)
  echo x >> %q
  if [ "$(grep -c x %q)" -le %d ]; then
    echo "keyhelper: SecKeyCreateDecryptedData failed: interaction not allowed (OSStatus -25308)" >&2
    exit 3
  fi
  exec /usr/bin/perl -0777 -pe 's/(.)/chr(ord($1)^0x5A)/ges'
  ;;
*)
  echo "unexpected verb $1" >&2
  exit 99
  ;;
esac
`, newkeyCount, newkeyCount, newkeyOKUntil, unwrapCount, unwrapCount, unwrapRefusals)
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write scripted helper: %v", err)
	}
	return binary
}

// TestPrimeAuthDegradesToFreshReleaseOnLockedCacheGet is the live-incident
// regression: the cache healed to ENCLAVE holds a key whose unwrap the keybag
// now refuses (helper exit 3). A Key call under a live session must treat the
// refusal as a miss — the cache demotes itself — and succeed via ONE fresh
// prompt flight whose NEW key both returns and lands warm, never a raw error.
func TestPrimeAuthDegradesToFreshReleaseOnLockedCacheGet(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	// One newkey success (the ENCLAVE open); every later probe (the heal) refuses,
	// and every unwrap refuses — the locked-keybag surface.
	binary := writeScriptedHelper(t, 1, 1_000_000)
	keyCache, err := cache.Open(ctx, helper.Bridge{Binary: binary})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = keyCache.Close(context.Background()) })
	if keyCache.Degraded() {
		t.Fatalf("the cache must open ENCLAVE-wrapped")
	}

	id := endpointID(self, "chrome", "Default")
	if _, err := keyCache.Put(ctx, id, []byte("stale-safe-storage-key"), degradedAuthTTL); err != nil {
		t.Fatalf("seed Put: %v", err)
	}

	st := stateWith(self, "")
	newKey := cookie.DeriveKey(cookie.SafeStorageKey("fresh-peanuts"))
	consent := &fakeConsent{key: newKey}
	b := newTestBroker(consent, keyCache, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, st)

	key, surface, err := b.Key(ctx, Req{Requestor: "local", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal})
	if err != nil {
		t.Fatalf("Key over a presence-refused warm entry must degrade to a fresh release, got %v", err)
	}
	if string(key) != string(newKey) {
		t.Fatalf("Key = %q, want the NEW key from the fresh flight", key)
	}
	if surface != SurfaceLocal {
		t.Fatalf("surface = %v, want SurfaceLocal (one fresh sheet)", surface)
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("consent evaluations = %d, want exactly 1 fresh flight", len(consent.batchCalls))
	}
	if !keyCache.Degraded() {
		t.Fatalf("the presence refusal must demote the cache to memory")
	}
	got, ok, err := keyCache.Get(ctx, id)
	if err != nil || !ok {
		t.Fatalf("post-release Get = %v, %v, %v, want the fresh key warm", got, ok, err)
	}
	if string(got) != string(newKey) {
		t.Fatalf("cached key = %q, want the NEW key", got)
	}
}

// writeWrapRefusingHelper writes a fake cookiesync-keyhelper whose first
// cache-newkey succeeds (an ENCLAVE open) and every later one exits 3, and
// whose cache-wrap always exits 3 — every Put demotes mid-call and publishes in
// memory.
func writeWrapRefusingHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "cookiesync-keyhelper")
	newkeyCount := filepath.Join(dir, "newkey.count")
	body := fmt.Sprintf(`#!/bin/sh
case "$1" in
cache-newkey)
  echo x >> %q
  if [ "$(grep -c x %q)" -le 1 ]; then exit 0; fi
  echo "keyhelper: cache-newkey failed: interaction not allowed (OSStatus -25308)" >&2
  exit 3
  ;;
cache-dropkey)
  exit 0
  ;;
cache-wrap)
  echo "keyhelper: SecKeyCreateEncryptedData failed: interaction not allowed (OSStatus -25308)" >&2
  exit 3
  ;;
*)
  echo "unexpected verb $1" >&2
  exit 99
  ;;
esac
`, newkeyCount, newkeyCount)
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write wrap-refusing helper: %v", err)
	}
	return binary
}

// TestReleaseGrantCappedWhenPutDemotesMidCall drives a release over the REAL
// cache whose wrap refuses mid-Put: the key still publishes (in memory) and the
// grant window is capped at degradedAuthTTL because the Put reported the
// degraded publish — the epoch was ENCLAVE when the flight started, so a
// pre-Put probe would have granted the full hour.
func TestReleaseGrantCappedWhenPutDemotesMidCall(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	keyCache, err := cache.Open(ctx, helper.Bridge{Binary: writeWrapRefusingHelper(t)})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = keyCache.Close(context.Background()) })
	if keyCache.Degraded() {
		t.Fatalf("the cache must open ENCLAVE-wrapped")
	}

	st := stateWith(self, "")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	b := newTestBroker(consent, keyCache, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, st)

	before := time.Now()
	key, _, err := b.Key(ctx, Req{Requestor: "local", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal})
	if err != nil {
		t.Fatalf("Key over a wrap-refusing helper must publish in memory, got %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("Key returned the wrong key")
	}
	if !keyCache.Degraded() {
		t.Fatalf("the refused wrap must demote the cache mid-Put")
	}
	got, ok, err := keyCache.Get(ctx, endpointID(self, "chrome", "Default"))
	if err != nil || !ok || string(got) != string(consent.key) {
		t.Fatalf("post-release Get = %q, %v, %v, want the key warm in memory", got, ok, err)
	}
	expiry, granted := b.grants.Granted("local", "chrome")
	if !granted {
		t.Fatalf("the release must grant local:chrome")
	}
	if window := expiry.Sub(before); window > degradedAuthTTL+time.Minute {
		t.Fatalf("grant window = %v, want the degraded cap ~%v (never the configured hour)", window, degradedAuthTTL)
	}
}

// TestKeyRePublishesWhenEpochRetiresRightAfterFlightPut pins the load-bearing
// post-flight re-Put: the epoch retires right after the flight's successful Put
// returns (the waiter's own Get hits the one unwrap refusal, demoting and
// evicting the entry), and Key must re-publish under the current epoch so the
// key it reports primed is still warm afterward. A re-publish whose heal is
// refused lands degraded and must re-cap the flight's full-window grant at
// degradedAuthTTL alongside the entry — never leave the requestor riding an
// hour-long grant over a five-minute RAM entry.
func TestKeyRePublishesWhenEpochRetiresRightAfterFlightPut(t *testing.T) {
	tests := []struct {
		name string
		// newkey successes: 1 covers only the open (the re-Put's heal is
		// refused, landing MEMORY); a large count lets the re-Put heal back
		// to ENCLAVE.
		newkeyOKUntil int
		wantDegraded  bool
	}{
		{name: "heal succeeds: full grant window stands", newkeyOKUntil: 1_000_000, wantDegraded: false},
		{name: "heal refused: grant re-capped at degradedAuthTTL", newkeyOKUntil: 1, wantDegraded: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			self := "me@laptop"
			fakeMesh(t, self)
			// Exactly ONE unwrap refusal — the post-flight Get.
			binary := writeScriptedHelper(t, tc.newkeyOKUntil, 1)
			keyCache, err := cache.Open(ctx, helper.Bridge{Binary: binary})
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			t.Cleanup(func() { _ = keyCache.Close(context.Background()) })

			st := stateWith(self, "")
			consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
			b := newTestBroker(consent, keyCache, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, st)

			id := endpointID(self, "chrome", "Default")
			before := time.Now()
			key, _, err := b.Key(ctx, Req{Requestor: "local", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal})
			if err != nil {
				t.Fatalf("Key: %v", err)
			}
			if string(key) != string(consent.key) {
				t.Fatalf("Key returned the wrong key")
			}
			got, ok, err := keyCache.Get(ctx, id)
			if err != nil || !ok {
				t.Fatalf("Get after the post-flight epoch retire = %v, %v, %v, want warm (the re-Put must re-publish)", got, ok, err)
			}
			if string(got) != string(consent.key) {
				t.Fatalf("cached key = %q, want the released key", got)
			}
			if keyCache.Degraded() != tc.wantDegraded {
				t.Fatalf("Degraded = %v, want %v", keyCache.Degraded(), tc.wantDegraded)
			}
			expiry, granted := b.grants.Granted("local", "chrome")
			if !granted {
				t.Fatalf("the release must grant local:chrome")
			}
			window := expiry.Sub(before)
			if tc.wantDegraded && window > degradedAuthTTL+time.Minute {
				t.Fatalf("grant window = %v, want re-capped at ~%v after the degraded re-publish", window, degradedAuthTTL)
			}
			if !tc.wantDegraded && window < degradedAuthTTL+time.Minute {
				t.Fatalf("grant window = %v, want the configured full window (~%v), never a spurious cap", window, st.Settings.AuthTTL)
			}
		})
	}
}
