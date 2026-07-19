package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cache"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/helper"
	consentkit "github.com/yasyf/synckit/consent"
	"github.com/yasyf/synckit/hostregistry"
	"github.com/yasyf/synckit/presence"
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

// TestDegradedRePutNeverExtendsNearExpiryGrant pins the cap-only re-Put
// regression: a requestor rides releaseAndCacheKey's already-granted warm-key
// fast path (batch ttl = the full configured hour) into a post-flight degraded
// re-Put, and its near-expiry grant must stay near expiry — never silently
// extended to the degraded window with zero fresh consent.
func TestDegradedRePutNeverExtendsNearExpiryGrant(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	keyCache := newFakeCache()
	keyCache.degraded = true
	id := endpointID(self, "chrome", "Default")
	if _, err := keyCache.Put(ctx, id, []byte(consent.key), time.Minute); err != nil {
		t.Fatalf("seed Put: %v", err)
	}
	// Key's probe misses (flight leads), the flight's re-probe hits (warm fast
	// path), the post-flight probe misses (degraded re-Put).
	keyCache.missGets = map[int]bool{1: true, 3: true}
	b := newTestBroker(consent, keyCache, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, st)

	before := time.Now()
	b.Grant("local", []cookie.BrowserName{"chrome"}, time.Minute)
	key, _, err := b.Key(ctx, Req{Requestor: "local", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal})
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("Key returned the wrong key")
	}
	if len(consent.promptedReasons) != 0 {
		t.Fatalf("the warm-key fast path must not prompt, got %v", consent.promptedReasons)
	}
	if puts := keyCache.putOrder(); len(puts) != 2 || puts[1] != id {
		t.Fatalf("puts = %v, want the seed then the re-Put of %s", puts, id)
	}
	expiry, granted := b.grants.Granted("local", "chrome")
	if !granted {
		t.Fatalf("the near-expiry grant must survive the re-Put")
	}
	if window := expiry.Sub(before); window > time.Minute+time.Second {
		t.Fatalf("grant window = %v, want the pre-existing ~1m — a degraded re-Put must never extend a grant", window)
	}
}

// TestLocalKeysOneFlightBudget proves the data-read budget: two cold browsers on
// a cold host spend the ONE flight on the first (a routed release), and the
// second is a budget-exhausted skip — never a second flight, whatever surface
// the first used.
func TestLocalKeysOneFlightBudget(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peer := "you@desktop"
	nonce := "one-flight-nonce"
	fakeMesh(t, self, peer)
	st := stateWith(self, "",
		stateEndpoint(self, "arc", "Default"),
		stateEndpoint(self, "chrome", "Default"),
	)
	arcEndpoint := endpointID(self, "arc", "Default")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_consent": approvedReply(t, nonce, arcEndpoint)},
	}
	cache := newFakeCache()
	b := newTestBroker(consent, cache, staticProbe(presence.SessionSnapshot{}), runner, st)
	pinnedNonce(b, nonce)

	outcomes, err := b.LocalKeys(ctx, "local", testConsentReason, OneFlight)
	if err != nil {
		t.Fatalf("LocalKeys(OneFlight): %v", err)
	}
	if len(outcomes) != 2 {
		t.Fatalf("outcomes = %d, want one per tracked endpoint", len(outcomes))
	}
	if outcomes[0].Endpoint != arcEndpoint || outcomes[0].Err != nil || outcomes[0].Skipped || string(outcomes[0].Key) != string(consent.key) {
		t.Fatalf("first outcome = %+v, want arc released via the one routed flight", outcomes[0])
	}
	if !outcomes[1].Skipped || outcomes[1].Key != nil || outcomes[1].Err != nil {
		t.Fatalf("second outcome = %+v, want a budget-exhausted skip", outcomes[1])
	}
	if got := runner.consentCalls(); got != 1 {
		t.Fatalf("routed request_consent calls = %d, want 1 (the budget is one flight)", got)
	}
	if consent.unpromptedCalled != 1 {
		t.Fatalf("unprompted releases = %d, want 1", consent.unpromptedCalled)
	}
}

// TestLocalKeysPrimeAllRoutesEachColdBrowser proves the auth budget: a routed
// release gates one browser, so on a cold host every distinct cold browser
// leads its own routed flight — one request_consent each — and each browser's
// endpoints verify warm.
func TestLocalKeysPrimeAllRoutesEachColdBrowser(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peer := "you@desktop"
	nonce := "prime-all-nonce"
	fakeMesh(t, self, peer)
	st := stateWith(self, "",
		stateEndpoint(self, "arc", "Default"),
		stateEndpoint(self, "chrome", "Default"),
	)
	arcEndpoint := endpointID(self, "arc", "Default")
	chromeEndpoint := endpointID(self, "chrome", "Default")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies: map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{
			arcEndpoint:    approvedReply(t, nonce, arcEndpoint),
			chromeEndpoint: approvedReply(t, nonce, chromeEndpoint),
		},
	}
	cache := newFakeCache()
	b := newTestBroker(consent, cache, staticProbe(presence.SessionSnapshot{}), runner, st)
	pinnedNonce(b, nonce)

	outcomes, err := b.LocalKeys(ctx, "local", testConsentReason, PrimeAll)
	if err != nil {
		t.Fatalf("LocalKeys(PrimeAll): %v", err)
	}
	if got := runner.consentCalls(); got != 2 {
		t.Fatalf("routed request_consent calls = %d, want 2 (one per distinct cold browser)", got)
	}
	if consent.unpromptedCalled != 2 {
		t.Fatalf("unprompted releases = %d, want 2", consent.unpromptedCalled)
	}
	if len(outcomes) != 2 {
		t.Fatalf("outcomes = %d, want one per distinct browser", len(outcomes))
	}
	for _, oc := range outcomes {
		if oc.Err != nil || oc.Skipped {
			t.Fatalf("outcome %+v, want every browser released", oc)
		}
		if len(oc.Warm) != 1 || oc.Warm[0] != oc.Endpoint {
			t.Fatalf("outcome %s Warm = %v, want its endpoint verified warm", oc.Browser, oc.Warm)
		}
	}
}

// TestConcurrentDistinctBrowserKeysNeverShareAFlight is the per-browser
// singleflight regression: one requestor's concurrent Key calls for TWO
// browsers, where browser A's routed release fails (its approver answers
// unavailable and no other candidate exists) while browser B's approver
// approves — B must get its own key, never A's routed error.
func TestConcurrentDistinctBrowserKeysNeverShareAFlight(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peer := "you@desktop"
	nonce := "distinct-browser-nonce"
	fakeMesh(t, self, peer)
	st := stateWith(self, "",
		stateEndpoint(self, "arc", "Default"),
		stateEndpoint(self, "chrome", "Default"),
	)
	arcEndpoint := endpointID(self, "arc", "Default")
	chromeEndpoint := endpointID(self, "chrome", "Default")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies: map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{
			arcEndpoint:    `{"status":"unavailable"}`,
			chromeEndpoint: approvedReply(t, nonce, chromeEndpoint),
		},
	}
	b := newTestBroker(consent, newFakeCache(), staticProbe(presence.SessionSnapshot{}), runner, st)
	pinnedNonce(b, nonce)

	type result struct {
		key cookie.AesKey
		err error
	}
	arcDone := make(chan result, 1)
	chromeDone := make(chan result, 1)
	go func() {
		key, _, err := b.Key(ctx, Req{Requestor: "local", Browser: "arc", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal})
		arcDone <- result{key, err}
	}()
	go func() {
		key, _, err := b.Key(ctx, Req{Requestor: "local", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal})
		chromeDone <- result{key, err}
	}()

	arc := <-arcDone
	chrome := <-chromeDone
	var authErr *consentkit.AuthRequired
	if !errors.As(arc.err, &authErr) {
		t.Fatalf("arc (unavailable approver, no fallback) = %v, want *consentkit.AuthRequired", arc.err)
	}
	if chrome.err != nil {
		t.Fatalf("chrome must not receive arc's routed failure, got %v", chrome.err)
	}
	if string(chrome.key) != string(consent.key) {
		t.Fatalf("chrome key = %q, want the released key", chrome.key)
	}
}

// TestRoutedBatchBulkCachesSiblingProfiles proves a routed approval bulk-warms
// the browser's sibling profiles exactly like a local release does — every
// profile shares one Safe Storage key — with the requested endpoint put LAST so
// it survives any heal a sibling Put triggers, while another browser's endpoint
// stays cold (a routed approval gates one browser).
func TestRoutedBatchBulkCachesSiblingProfiles(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peer := "you@desktop"
	nonce := "bulk-route-nonce"
	fakeMesh(t, self, peer)
	st := stateWith(self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "chrome", "Work"),
		stateEndpoint(self, "arc", "Default"),
	)
	requested := endpointID(self, "chrome", "Default")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_consent": approvedReply(t, nonce, requested)},
	}
	cache := newFakeCache()
	b := newTestBroker(consent, cache, staticProbe(presence.SessionSnapshot{}), runner, st)
	pinnedNonce(b, nonce)

	key, surface, err := b.Key(ctx, Req{Requestor: "local", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal})
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if surface != SurfaceRouted {
		t.Fatalf("surface = %v, want SurfaceRouted", surface)
	}
	for _, id := range []string{requested, endpointID(self, "chrome", "Work")} {
		got, ok, _ := cache.Get(ctx, id)
		if !ok || string(got) != string(key) {
			t.Errorf("endpoint %s not bulk-warmed by the routed release", id)
		}
	}
	if _, ok, _ := cache.Get(ctx, endpointID(self, "arc", "Default")); ok {
		t.Errorf("a routed approval gates one browser; arc must stay cold")
	}
	puts := cache.putOrder()
	if len(puts) == 0 || puts[len(puts)-1] != requested {
		t.Fatalf("cache puts = %v, want the requested endpoint %s put last", puts, requested)
	}
}

// TestKeyApproverProbeErrorClassifiesUnavailable proves an approver-mode probe
// failure classifies Unavailable — the flake fails over instead of killing the
// requesting host's routed release.
func TestKeyApproverProbeErrorClassifiesUnavailable(t *testing.T) {
	probeErr := errors.New("ioreg: signal: killed")
	probe := func(context.Context) (presence.SessionSnapshot, error) {
		return presence.SessionSnapshot{}, probeErr
	}
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	b := newTestBroker(consent, newFakeCache(), probe, &recordingRunner{}, stateWith("me@laptop", ""))

	_, _, err := b.Key(context.Background(), Req{Requestor: "host:them", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeApprover})
	if !errors.Is(err, probeErr) {
		t.Fatalf("Key over a failed probe = %v, want it to wrap %v", err, probeErr)
	}
	if got := Classify(err); got != consentkit.VerdictUnavailable {
		t.Fatalf("Classify(probe error) = %v, want VerdictUnavailable", got)
	}
	if len(consent.promptedReasons) != 0 {
		t.Fatalf("a failed probe must not prompt, got %v", consent.promptedReasons)
	}
}

// TestKeyLocalProbeErrorDegradesToLocalGate proves a ModeLocal release whose
// presence probe fails to run (a starved ioreg) attempts the local Touch ID
// gate instead of dying: one prompt, key released and cached, no error.
func TestKeyLocalProbeErrorDegradesToLocalGate(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	probeErr := errors.New("ioreg: signal: killed")
	probe := func(context.Context) (presence.SessionSnapshot, error) {
		return presence.SessionSnapshot{}, probeErr
	}
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	cache := newFakeCache()
	b := newTestBroker(consent, cache, probe, &recordingRunner{}, stateWith(self, ""))

	key, surface, err := b.Key(ctx, Req{Requestor: "local", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal})
	if err != nil {
		t.Fatalf("Key over a failed probe must attempt the local gate, got %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("Key = %q, want the released key %q", key, consent.key)
	}
	if surface != SurfaceLocal {
		t.Fatalf("surface = %v, want SurfaceLocal", surface)
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("consent evaluations = %d, want exactly 1 local prompt", len(consent.batchCalls))
	}
	got, ok, err := cache.Get(ctx, endpointID(self, "chrome", "Default"))
	if err != nil || !ok || string(got) != string(key) {
		t.Fatalf("post-release Get = %q, %v, %v, want the key cached warm", got, ok, err)
	}
}

// localReleaseOutcome is every observable a hard-route ModeLocal release
// leaves behind, comparable across runner scenarios.
type localReleaseOutcome struct {
	key        string
	surface    Surface
	errText    string
	prompts    []string
	unprompted int
	cachedKey  string
	warm       bool
}

// hardRouteLocalRelease runs one ModeLocal Key release for chrome with a hard
// consent route to you@desktop and an attended local session, over the given
// runner.
func hardRouteLocalRelease(t *testing.T, runner SSHRunner) localReleaseOutcome {
	t.Helper()
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self, "you@desktop")
	st := stateWith(self, "you@desktop", stateEndpoint(self, "chrome", "Default"))
	st.ConsentRouteHard = true
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	c := newFakeCache()
	b := newTestBroker(consent, c, staticProbe(liveSession(currentUser(t))), runner, st)

	key, surface, err := b.Key(ctx, Req{Requestor: "local", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal})
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	cached, warm, cerr := c.Get(ctx, endpointID(self, "chrome", "Default"))
	if cerr != nil {
		t.Fatalf("cache get: %v", cerr)
	}
	return localReleaseOutcome{
		key:        string(key),
		surface:    surface,
		errText:    errText,
		prompts:    append([]string(nil), consent.promptedReasons...),
		unprompted: consent.unpromptedCalled,
		cachedKey:  string(cached),
		warm:       warm,
	}
}

// TestKeyHardRouteWhoamiSSHErrorMatchesNotLivePeer proves a hard consent route
// whose whoami probe fails with an SSHError — even a non-255 remote exit, the
// shape a transport flake produces — counts as peer-not-live: the local
// release proceeds through Touch ID exactly as it does when the peer answers a
// locked whoami, instead of bricking every local release on this host.
func TestKeyHardRouteWhoamiSSHErrorMatchesNotLivePeer(t *testing.T) {
	exit1 := exec.Command("/bin/sh", "-c", "exit 1").Run()
	var exitErr *exec.ExitError
	if !errors.As(exit1, &exitErr) {
		t.Fatalf("fabricate exit-1: %v", exit1)
	}
	notLive := &approverMesh{}
	flaky := &whoamiErrMesh{
		approverMesh: &approverMesh{},
		target:       "you@desktop",
		err:          &hostregistry.SSHError{Addr: "you@desktop", Stderr: "whoami failed remotely", Err: exit1},
	}

	baseline := hardRouteLocalRelease(t, notLive)
	if baseline.errText != "" || baseline.surface != SurfaceLocal || len(baseline.prompts) != 1 {
		t.Fatalf("peer-not-live baseline must release locally, got %+v", baseline)
	}
	flaked := hardRouteLocalRelease(t, flaky)
	if !reflect.DeepEqual(flaked, baseline) {
		t.Fatalf("whoami ssh-error outcome = %+v, want the peer-not-live outcome %+v", flaked, baseline)
	}
	if asked := flaky.consentTargets(); len(asked) != 0 {
		t.Fatalf("request_consent dials = %v, want none", asked)
	}
}

// TestKeyHardRouteMalformedWhoamiIsFatal proves the probe-shaped carve-out
// stays narrow: a hard-routed peer whose whoami reply does not parse fails the
// release outright — no Touch ID prompt, no cached key.
func TestKeyHardRouteMalformedWhoamiIsFatal(t *testing.T) {
	runner := &approverMesh{whoami: map[string]string{"you@desktop": "not json"}}

	got := hardRouteLocalRelease(t, runner)
	if got.errText == "" || !strings.Contains(got.errText, "parse presence from you@desktop") {
		t.Fatalf("malformed whoami err = %q, want a fatal parse failure", got.errText)
	}
	if len(got.prompts) != 0 || got.unprompted != 0 {
		t.Fatalf("a fatal probe failure must not prompt, got %+v", got)
	}
	if got.warm {
		t.Fatalf("a fatal probe failure must not cache a key")
	}
}
