package cache

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/cookiesync/internal/paths"
)

// Parity oracles ported from the original Python tests/test_cache.py. The
// wrap/unwrap boundary is the only macOS-specific surface, so it is doubled by a
// reversible XOR fake (a real shell-out for the wrapper round-trip, and an
// in-process fakeWrapper for the cache logic) and the clock is injected.

const (
	endpoint = "yasyf-home:chrome:Default"
	other    = "yasyf-work:arc:Profile 1"
	xorMask  = 0x5A
)

func testKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// fakeWrapper is a reversible XOR stand-in for the Secure-Enclave ECIES blob.
type fakeWrapper struct{}

func (fakeWrapper) Wrap(_ context.Context, plaintext []byte) ([]byte, error) {
	return xor(plaintext), nil
}

func (fakeWrapper) Unwrap(_ context.Context, blob []byte) ([]byte, error) {
	return xor(blob), nil
}

func xor(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ xorMask
	}
	return out
}

// writeFakeCacheHelper writes an executable fake cookiesync-keyhelper emulating the
// cache-* contract: cache-newkey / cache-dropkey are logged no-op exit-0s, and
// cache-wrap / cache-unwrap XOR stdin to stdout (binary-safe via /usr/bin/perl). It
// returns the helper binary path and the log path; paths.SetHelperBinaryForTest
// points the bridge's zero value at it.
func writeFakeCacheHelper(t *testing.T) (binary, logPath string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "cookiesync-keyhelper")
	logPath = filepath.Join(dir, "helper.log")
	body := `#!/bin/sh
verb="$1"
label="$2"
case "$verb" in
cache-newkey|cache-dropkey)
  printf '%s %s\n' "$verb" "$label" >> "` + logPath + `"
  exit 0
  ;;
cache-wrap|cache-unwrap)
  exec /usr/bin/perl -0777 -pe 's/(.)/chr(ord($1)^` + "0x5A" + `)/ges'
  ;;
*)
  echo "unexpected verb $verb" >&2
  exit 99
  ;;
esac
`
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write fake cache helper: %v", err)
	}
	return binary, logPath
}

func TestSecureEnclaveWrapperRoundTripsViaTheSignedHelper(t *testing.T) {
	binary, logPath := writeFakeCacheHelper(t)
	restore := paths.SetHelperBinaryForTest(binary)
	t.Cleanup(restore)
	ctx := context.Background()

	opened, err := OpenWrapper(ctx, helper.Bridge{})
	if err != nil {
		t.Fatalf("OpenWrapper: %v", err)
	}
	wrapper, ok := opened.(*SecureEnclaveWrapper)
	if !ok {
		t.Fatalf("wrapper = %T, want *SecureEnclaveWrapper", opened)
	}
	key := testKey()
	blob, err := wrapper.Wrap(ctx, key)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if bytes.Equal(blob, key) {
		t.Fatalf("blob equals plaintext key; wrap did nothing")
	}
	got, err := wrapper.Unwrap(ctx, blob)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("round-trip = %x, want %x", got, key)
	}
	if err := wrapper.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	lines := strings.Split(strings.TrimRight(readFile(t, logPath), "\n"), "\n")
	if want := "cache-newkey " + wrapper.Label(); lines[0] != want {
		t.Fatalf("log[0] = %q, want %q", lines[0], want)
	}
	if want := "cache-dropkey " + wrapper.Label(); lines[len(lines)-1] != want {
		t.Fatalf("log[-1] = %q, want %q", lines[len(lines)-1], want)
	}
}

func TestSecureEnclaveWrapperFailsClosedWhenHelperMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent", "cookiesync-keyhelper")
	restore := paths.SetHelperBinaryForTest(missing)
	t.Cleanup(restore)

	_, err := OpenWrapper(context.Background(), helper.Bridge{})
	var helperErr *paths.HelperError
	if !errors.As(err, &helperErr) {
		t.Fatalf("err = %v, want *paths.HelperError", err)
	}
}

// writeFailingNewkeyHelper writes a fake cookiesync-keyhelper whose cache-newkey
// prints diagnostic to stderr and exits with code; any other verb exits 99.
func writeFailingNewkeyHelper(t *testing.T, code int, diagnostic string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "cookiesync-keyhelper")
	body := `#!/bin/sh
case "$1" in
cache-newkey)
  printf '%s\n' "` + diagnostic + `" >&2
  exit ` + strconv.Itoa(code) + `
  ;;
*)
  echo "unexpected verb $1" >&2
  exit 99
  ;;
esac
`
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write failing newkey helper: %v", err)
	}
	return binary
}

func TestOpenWrapperDegradesToMemoryWhenPresenceUnavailable(t *testing.T) {
	const diagnostic = "keyhelper: SecKeyCreateRandomKey failed: interaction not allowed (OSStatus -25308)"
	script := writeFailingNewkeyHelper(t, 3, diagnostic)
	ctx := context.Background()

	wrapper, err := OpenWrapper(ctx, helper.Bridge{Binary: script})
	if !errors.Is(err, ErrSEPresenceUnavailable) {
		t.Fatalf("err = %v, want ErrSEPresenceUnavailable", err)
	}
	if !strings.Contains(err.Error(), diagnostic) {
		t.Fatalf("err = %q, want it to carry the helper stderr %q", err, diagnostic)
	}
	hw, ok := wrapper.(*healingWrapper)
	if !ok {
		t.Fatalf("wrapper = %T, want *healingWrapper", wrapper)
	}
	if !hw.degraded() {
		t.Fatalf("healingWrapper not degraded at open")
	}
	key := testKey()
	blob, err := wrapper.Wrap(ctx, key)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := wrapper.Unwrap(ctx, blob)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("round-trip = %x, want %x", got, key)
	}
	if err := wrapper.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestOpenWrapperFailsLoudOnExitTwoWithHelperStderr(t *testing.T) {
	const diagnostic = "keyhelper: SecKeyCreateRandomKey failed: no Secure Enclave (OSStatus -4)"
	script := writeFailingNewkeyHelper(t, 2, diagnostic)

	wrapper, err := OpenWrapper(context.Background(), helper.Bridge{Binary: script})
	if wrapper != nil {
		t.Fatalf("wrapper = %T, want nil", wrapper)
	}
	if err == nil || errors.Is(err, ErrSEPresenceUnavailable) {
		t.Fatalf("err = %v, want a non-degraded failure", err)
	}
	for _, want := range []string{"cache-newkey exited 2", diagnostic} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %q, want it to contain %q", err, want)
		}
	}
}

// writeUnwrapRefusingHelper writes a fake cookiesync-keyhelper that opens and wraps
// cleanly — cache-newkey and cache-wrap succeed, so the cache opens Enclave-backed and a
// Put stores a wrapped blob — but whose cache-unwrap prints diagnostic to stderr and
// exits with code: the live "keybag locked after open" surface a warm key hits on Get.
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
  exit ` + strconv.Itoa(code) + `
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

// TestSecureEnclaveWrapperUnwrapTagsLockedKeybag proves a live cache-unwrap refusal tags
// the presence sentinel only on exit 3 (keybag locked): the Get error errors.Is
// ErrSEPresenceUnavailable there and carries the helper stderr, while a sibling exit 1
// (key missing / decrypt failed) stays an untagged loud failure.
func TestSecureEnclaveWrapperUnwrapTagsLockedKeybag(t *testing.T) {
	tests := []struct {
		name         string
		code         int
		diagnostic   string
		wantSentinel bool
	}{
		{
			name:         "exit 3 locked keybag is the sentinel",
			code:         3,
			diagnostic:   "keyhelper: SecKeyCreateDecryptedData failed: interaction not allowed (OSStatus -25308)",
			wantSentinel: true,
		},
		{
			name:         "exit 1 decrypt failure is not the sentinel",
			code:         1,
			diagnostic:   "keyhelper: SecKeyCreateDecryptedData failed: key missing or decrypt failed (OSStatus -50)",
			wantSentinel: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			wrapper, err := OpenWrapper(ctx, helper.Bridge{Binary: writeUnwrapRefusingHelper(t, tc.code, tc.diagnostic)})
			if err != nil {
				t.Fatalf("OpenWrapper: %v", err)
			}
			c := NewKeyCache(wrapper)
			if err := c.Put(ctx, endpoint, testKey(), 30*time.Second); err != nil {
				t.Fatalf("Put: %v", err)
			}
			if _, _, err = c.Get(ctx, endpoint); err == nil {
				t.Fatalf("Get succeeded, want the cache-unwrap refusal")
			}
			if got := errors.Is(err, ErrSEPresenceUnavailable); got != tc.wantSentinel {
				t.Fatalf("errors.Is(err, ErrSEPresenceUnavailable) = %v, want %v (err = %v)", got, tc.wantSentinel, err)
			}
			if !strings.Contains(err.Error(), tc.diagnostic) {
				t.Fatalf("err = %q, want it to carry the helper stderr %q", err, tc.diagnostic)
			}
		})
	}
}

// writeHealingHelper writes a fake cookiesync-keyhelper whose cache-newkey exits 3
// (presence unavailable) for its first exit3 invocations — counted in a sidecar
// file — and thenCode afterwards (0 heals, anything else refuses). Every verb is
// logged; cache-wrap / cache-unwrap XOR stdin to stdout and cache-dropkey no-ops.
func writeHealingHelper(t *testing.T, exit3, thenCode int) (binary, logPath string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "cookiesync-keyhelper")
	logPath = filepath.Join(dir, "helper.log")
	countPath := filepath.Join(dir, "newkey.count")
	body := `#!/bin/sh
verb="$1"
label="$2"
printf '%s %s\n' "$verb" "$label" >> "` + logPath + `"
case "$verb" in
cache-newkey)
  n=$(cat "` + countPath + `" 2>/dev/null || echo 0)
  n=$((n+1))
  printf '%s' "$n" > "` + countPath + `"
  if [ "$n" -le ` + strconv.Itoa(exit3) + ` ]; then
    echo "keyhelper: SecKeyCreateRandomKey failed: interaction not allowed (OSStatus -25308)" >&2
    exit 3
  fi
  if [ ` + strconv.Itoa(thenCode) + ` -ne 0 ]; then
    echo "keyhelper: SecKeyCreateRandomKey failed: no Secure Enclave (OSStatus -4)" >&2
    exit ` + strconv.Itoa(thenCode) + `
  fi
  exit 0
  ;;
cache-dropkey)
  exit 0
  ;;
cache-wrap|cache-unwrap)
  exec /usr/bin/perl -0777 -pe 's/(.)/chr(ord($1)^0x5A)/ges'
  ;;
*)
  echo "unexpected verb $verb" >&2
  exit 99
  ;;
esac
`
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write healing helper: %v", err)
	}
	return binary, logPath
}

func TestKeyCachePutHealsTheDegradedWrapper(t *testing.T) {
	binary, logPath := writeHealingHelper(t, 3, 0)
	ctx := context.Background()

	wrapper, err := OpenWrapper(ctx, helper.Bridge{Binary: binary})
	if !errors.Is(err, ErrSEPresenceUnavailable) {
		t.Fatalf("OpenWrapper err = %v, want ErrSEPresenceUnavailable", err)
	}
	c := NewKeyCache(wrapper)
	if !c.Degraded() {
		t.Fatalf("Degraded() = false at open")
	}

	key := testKey()
	for _, id := range []string{endpoint, other} {
		if err := c.Put(ctx, id, key, 30*time.Second); err != nil {
			t.Fatalf("degraded Put %s: %v", id, err)
		}
		if !bytes.Equal(c.entries[id].blob, key) {
			t.Fatalf("degraded blob for %s = %x, want the identity RAM copy %x", id, c.entries[id].blob, key)
		}
		got, ok, err := c.Get(ctx, id)
		if err != nil || !ok || !bytes.Equal(got, key) {
			t.Fatalf("degraded Get %s = %x ok=%v err=%v", id, got, ok, err)
		}
	}
	if !c.Degraded() {
		t.Fatalf("Degraded() = false while re-probes still exit 3")
	}
	if log := readFile(t, logPath); strings.Contains(log, "cache-wrap") || strings.Contains(log, "cache-unwrap") {
		t.Fatalf("degraded Put/Get must stay in process memory, not shell the helper:\n%s", log)
	}

	const healed = "yasyf-home:arc:Default"
	if err := c.Put(ctx, healed, key, 30*time.Second); err != nil {
		t.Fatalf("healing Put: %v", err)
	}
	if c.Degraded() {
		t.Fatalf("Degraded() = true after the healing Put")
	}
	if len(c.entries) != 1 {
		t.Fatalf("entries after heal = %d, want 1 (every identity blob evicted)", len(c.entries))
	}
	if blob := c.entries[healed].blob; !bytes.Equal(blob, xor(key)) {
		t.Fatalf("healed blob = %x, want the Enclave-wrapped %x", blob, xor(key))
	}
	for _, id := range []string{endpoint, other} {
		if _, ok, _ := c.Get(ctx, id); ok {
			t.Fatalf("identity entry %s still served after the heal swap", id)
		}
	}
	got, ok, err := c.Get(ctx, healed)
	if err != nil || !ok || !bytes.Equal(got, key) {
		t.Fatalf("Get after heal = %x ok=%v err=%v", got, ok, err)
	}

	if err := c.Put(ctx, endpoint, key, 30*time.Second); err != nil {
		t.Fatalf("post-heal Put: %v", err)
	}
	if got := strings.Count(readFile(t, logPath), "cache-newkey"); got != 4 {
		t.Fatalf("cache-newkey ran %d times, want 4 (open + one re-probe per degraded Put, none after heal)", got)
	}
	if err := wrapper.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !strings.Contains(readFile(t, logPath), "cache-dropkey") {
		t.Fatalf("Close after heal must drop the Enclave key")
	}
}

func TestKeyCachePutFailsLoudWhenReprobeRefuses(t *testing.T) {
	binary, _ := writeHealingHelper(t, 1, 2)
	ctx := context.Background()

	wrapper, err := OpenWrapper(ctx, helper.Bridge{Binary: binary})
	if !errors.Is(err, ErrSEPresenceUnavailable) {
		t.Fatalf("OpenWrapper err = %v, want ErrSEPresenceUnavailable", err)
	}
	c := NewKeyCache(wrapper)

	err = c.Put(ctx, endpoint, testKey(), 30*time.Second)
	if err == nil {
		t.Fatalf("Put succeeded, want the exit-2 re-probe failure")
	}
	for _, want := range []string{"cache-newkey re-probe exited 2", "no Secure Enclave (OSStatus -4)"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err = %q, want it to contain %q", err, want)
		}
	}
	if !c.Degraded() {
		t.Fatalf("Degraded() = false after a refused re-probe")
	}
	if len(c.entries) != 0 {
		t.Fatalf("failed Put stored an entry")
	}
}

func TestPutRewrapsWhenAHealSwapsMidPut(t *testing.T) {
	binary, logPath := writeHealingHelper(t, 2, 0)
	ctx := context.Background()

	wrapper, err := OpenWrapper(ctx, helper.Bridge{Binary: binary})
	if !errors.Is(err, ErrSEPresenceUnavailable) {
		t.Fatalf("OpenWrapper err = %v, want ErrSEPresenceUnavailable", err)
	}
	hw := wrapper.(*healingWrapper)
	c := NewKeyCache(hw)
	key := testKey()

	// Park the stale Put on c.mu after its re-probe stayed degraded (identity blob in
	// hand), swap the wrapper to the Enclave underneath it, then release: the stale Put
	// must notice the swap and re-wrap through the Enclave instead of inserting. The swap
	// is applied directly, not via a second Put, to drive exactly one flight: a second Put
	// would join the parked re-probe, then re-probe again once it stayed degraded, muddying
	// the cache-newkey count.
	c.mu.Lock()
	stale := make(chan error, 1)
	go func() { stale <- c.Put(ctx, endpoint, key, 30*time.Second) }()
	waitFor(t, func() bool { return strings.Count(readFile(t, logPath), "cache-newkey") == 2 })

	hw.se.Store(&SecureEnclaveWrapper{helper: hw.bridge, label: hw.label})
	c.mu.Unlock()

	if err := <-stale; err != nil {
		t.Fatalf("stale Put: %v", err)
	}
	if got := strings.Count(readFile(t, logPath), "cache-wrap"); got != 1 {
		t.Fatalf("cache-wrap ran %d times, want 1 (the stale Put's re-wrap through the Enclave)", got)
	}
	e, ok := c.entries[endpoint]
	if !ok {
		t.Fatalf("stale Put stored no entry")
	}
	if !bytes.Equal(e.blob, xor(key)) {
		t.Fatalf("entry = %x, want Enclave-wrapped %x (identity blob crossed the heal swap)", e.blob, xor(key))
	}
}

func TestHealEvictionSparesCurrentWrapperEntry(t *testing.T) {
	binary, _ := writeHealingHelper(t, 2, 0)
	ctx := context.Background()

	wrapper, err := OpenWrapper(ctx, helper.Bridge{Binary: binary})
	if !errors.Is(err, ErrSEPresenceUnavailable) {
		t.Fatalf("OpenWrapper err = %v, want ErrSEPresenceUnavailable", err)
	}
	hw := wrapper.(*healingWrapper)
	c := NewKeyCache(hw)
	if !c.Degraded() {
		t.Fatalf("Degraded() = false at open")
	}

	key := testKey()
	// A stale entry laid down while degraded: identity-wrapped in RAM.
	if err := c.Put(ctx, "stale", key, 30*time.Second); err != nil {
		t.Fatalf("degraded Put: %v", err)
	}
	if !c.Degraded() {
		t.Fatalf("Degraded() = false while the re-probe still exits 3")
	}

	// Perform the memory-to-Enclave swap directly, without going through a healing Put.
	inner, healed, err := hw.heal(ctx)
	if err != nil {
		t.Fatalf("heal: %v", err)
	}
	if !healed {
		t.Fatalf("heal healed = false, want the memory-to-Enclave swap")
	}
	if _, ok := inner.(*SecureEnclaveWrapper); !ok {
		t.Fatalf("heal returned %T, want *SecureEnclaveWrapper", inner)
	}

	// A fresh entry laid down after the swap: Enclave-wrapped by the live wrapper.
	if err := c.Put(ctx, "fresh", key, 30*time.Second); err != nil {
		t.Fatalf("post-heal Put: %v", err)
	}
	if blob := c.entries["fresh"].blob; !bytes.Equal(blob, xor(key)) {
		t.Fatalf("fresh blob = %x, want the Enclave-wrapped %x", blob, xor(key))
	}

	// Call the eviction directly to model a concurrent Put's fresh entry landing between the
	// swap and the (synchronous) heal-time eviction. evictStale must spare fresh, drop stale.
	c.evictStale(inner)

	got, ok, err := c.Get(ctx, "fresh")
	if err != nil || !ok || !bytes.Equal(got, key) {
		t.Fatalf("Get(fresh) = %x ok=%v err=%v, want the key still served", got, ok, err)
	}
	if _, ok, _ := c.Get(ctx, "stale"); ok {
		t.Fatalf("stale identity entry still served after evictStale")
	}
	if len(c.entries) != 1 {
		t.Fatalf("entries after evictStale = %d, want 1 (only the fresh Enclave entry)", len(c.entries))
	}
}

// TestEvictStaleUsesInstalledWrapperNotLiveInner proves the heal eviction targets the
// wrapper the swap installed rather than the live c.inner(): a Close that reverts inner to
// the identity wrapper between the swap and the eviction must not spare a stale entry that
// Get would then serve.
func TestEvictStaleUsesInstalledWrapperNotLiveInner(t *testing.T) {
	binary, _ := writeHealingHelper(t, 2, 0)
	ctx := context.Background()

	wrapper, err := OpenWrapper(ctx, helper.Bridge{Binary: binary})
	if !errors.Is(err, ErrSEPresenceUnavailable) {
		t.Fatalf("OpenWrapper err = %v, want ErrSEPresenceUnavailable", err)
	}
	hw := wrapper.(*healingWrapper)
	c := NewKeyCache(hw)

	key := testKey()
	if err := c.Put(ctx, "stale", key, 30*time.Second); err != nil {
		t.Fatalf("degraded Put: %v", err)
	}
	inner, healed, err := hw.heal(ctx)
	if err != nil || !healed {
		t.Fatalf("heal healed=%v err=%v, want the memory-to-Enclave swap", healed, err)
	}
	if err := c.Put(ctx, "fresh", key, 30*time.Second); err != nil {
		t.Fatalf("post-heal Put: %v", err)
	}

	// A concurrent Close drops the Enclave key and reverts the live wrapper to the identity
	// memoryWrapper before the healing Put's eviction runs.
	if err := hw.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !c.Degraded() {
		t.Fatalf("Degraded() = false after Close")
	}

	c.evictStale(inner)
	if _, ok := c.entries["stale"]; ok {
		t.Fatalf("stale identity entry survived evictStale after a racing Close (Get would serve it)")
	}
	if _, ok := c.entries["fresh"]; !ok {
		t.Fatalf("fresh Enclave entry wrongly dropped by evictStale after Close")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not reached within 5s")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestKeyCacheHealSwapUnderConcurrentUse(t *testing.T) {
	ctx := context.Background()
	keyFor := func(id string) []byte {
		k := make([]byte, 32)
		for i := range k {
			k[i] = byte(i) ^ id[len(id)-1]
		}
		return k
	}
	for iter := range 4 {
		binary, _ := writeHealingHelper(t, 3, 0)
		wrapper, err := OpenWrapper(ctx, helper.Bridge{Binary: binary})
		if !errors.Is(err, ErrSEPresenceUnavailable) {
			t.Fatalf("iter %d: OpenWrapper err = %v, want ErrSEPresenceUnavailable", iter, err)
		}
		c := NewKeyCache(wrapper)

		var wg sync.WaitGroup
		failures := make(chan string, 64)
		for g := range 6 {
			id := endpoint + strconv.Itoa(g)
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 3 {
					if err := c.Put(ctx, id, keyFor(id), 30*time.Second); err != nil {
						failures <- "Put " + id + ": " + err.Error()
						return
					}
					got, ok, err := c.Get(ctx, id)
					if err != nil {
						failures <- "Get " + id + ": " + err.Error()
						return
					}
					if ok && !bytes.Equal(got, keyFor(id)) {
						failures <- "Get " + id + " returned wrong bytes"
						return
					}
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 3 {
				c.EvictAll()
			}
		}()
		wg.Wait()
		close(failures)
		for msg := range failures {
			t.Fatalf("iter %d: %s", iter, msg)
		}

		if c.Degraded() {
			t.Fatalf("iter %d: still degraded after every Put completed", iter)
		}
		c.mu.Lock()
		for id, e := range c.entries {
			if !bytes.Equal(e.blob, xor(keyFor(id))) {
				c.mu.Unlock()
				t.Fatalf("iter %d: surviving entry %s is not Enclave-wrapped", iter, id)
			}
		}
		c.mu.Unlock()

		final := endpoint + "0"
		if err := c.Put(ctx, final, keyFor(final), 30*time.Second); err != nil {
			t.Fatalf("iter %d: final Put: %v", iter, err)
		}
		got, ok, err := c.Get(ctx, final)
		if err != nil || !ok || !bytes.Equal(got, keyFor(final)) {
			t.Fatalf("iter %d: final Get = %x ok=%v err=%v", iter, got, ok, err)
		}
	}
}

func TestKeyCacheOverAPlainWrapperIsNotDegraded(t *testing.T) {
	if NewKeyCache(fakeWrapper{}).Degraded() {
		t.Fatalf("Degraded() = true over a plain wrapper")
	}
}

func TestMemoryWrapperRoundTripsKeyByteForByte(t *testing.T) {
	ctx := context.Background()
	w := memoryWrapper{}
	key := []byte{0x00, 0x01, 0xFF, 0x5A, 0x80, 0x0A, 0x00}

	blob, err := w.Wrap(ctx, key)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if !bytes.Equal(blob, key) {
		t.Fatalf("blob = %x, want identity %x", blob, key)
	}
	key[0] = 0xEE
	if blob[0] != 0x00 {
		t.Fatalf("blob aliases the caller's key slice")
	}
	got, err := w.Unwrap(ctx, blob)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatalf("round-trip = %x, want %x", got, blob)
	}
}

func TestKeyCacheOverTheMemoryWrapper(t *testing.T) {
	ctx := context.Background()
	c := NewKeyCache(memoryWrapper{})
	key := testKey()
	if err := c.Put(ctx, endpoint, key, 30*time.Second); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok, err := c.Get(ctx, endpoint)
	if err != nil || !ok || !bytes.Equal(got, key) {
		t.Fatalf("Get = %x ok=%v err=%v", got, ok, err)
	}
	c.EvictAll()
	if _, ok, _ := c.Get(ctx, endpoint); ok {
		t.Fatalf("endpoint present after EvictAll")
	}
}

func TestKeyCacheOverTheSignedHelperWrapper(t *testing.T) {
	binary, _ := writeFakeCacheHelper(t)
	restore := paths.SetHelperBinaryForTest(binary)
	t.Cleanup(restore)
	ctx := context.Background()

	wrapper, err := OpenWrapper(ctx, helper.Bridge{})
	if err != nil {
		t.Fatalf("OpenWrapper: %v", err)
	}
	c := NewKeyCache(wrapper)
	key := testKey()
	if err := c.Put(ctx, endpoint, key, 30*time.Second); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if stored := c.entries[endpoint].blob; bytes.Equal(stored, key) {
		t.Fatalf("stored value is the raw key, not the wrapped blob")
	}
	got, ok, err := c.Get(ctx, endpoint)
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("Get = %x, want %x", got, key)
	}
}

// clock is a manually advanced clock anchored at a fixed base, mirroring the
// Python float clock starting at 0.
type clock struct {
	base time.Time
	d    time.Duration
}

func (c *clock) now() time.Time { return c.base.Add(c.d) }

func (c *clock) set(seconds float64) {
	c.d = time.Duration(seconds * float64(time.Second))
}

func newCache(c *clock) *KeyCache {
	return NewKeyCacheWithClock(fakeWrapper{}, c.now)
}

func TestPutThenGetReturnsTheKey(t *testing.T) {
	ctx := context.Background()
	c := newCache(&clock{base: time.Unix(0, 0)})
	if err := c.Put(ctx, endpoint, testKey(), 30*time.Second); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok, err := c.Get(ctx, endpoint)
	if err != nil || !ok || !bytes.Equal(got, testKey()) {
		t.Fatalf("Get = %x ok=%v err=%v", got, ok, err)
	}
}

func TestGetMissingReturnsNone(t *testing.T) {
	c := newCache(&clock{base: time.Unix(0, 0)})
	_, ok, err := c.Get(context.Background(), endpoint)
	if ok || err != nil {
		t.Fatalf("Get miss: ok=%v err=%v", ok, err)
	}
}

func TestGetAfterTTLReturnsNone(t *testing.T) {
	ctx := context.Background()
	clk := &clock{base: time.Unix(0, 0)}
	c := newCache(clk)
	if err := c.Put(ctx, endpoint, testKey(), 30*time.Second); err != nil {
		t.Fatalf("Put: %v", err)
	}
	clk.set(29.999)
	if _, ok, _ := c.Get(ctx, endpoint); !ok {
		t.Fatalf("Get at 29.999s should hit")
	}
	clk.set(30.0)
	if _, ok, _ := c.Get(ctx, endpoint); ok {
		t.Fatalf("Get at 30.0s should miss")
	}
}

func TestExpiredGetEvictsTheEntry(t *testing.T) {
	ctx := context.Background()
	clk := &clock{base: time.Unix(0, 0)}
	c := newCache(clk)
	if err := c.Put(ctx, endpoint, testKey(), 30*time.Second); err != nil {
		t.Fatalf("Put: %v", err)
	}
	clk.set(30.0)
	if _, ok, _ := c.Get(ctx, endpoint); ok {
		t.Fatalf("Get at 30.0s should miss")
	}
	if _, present := c.entries[endpoint]; present {
		t.Fatalf("expired entry was not evicted")
	}
}

func TestEvictClearsOneEntry(t *testing.T) {
	ctx := context.Background()
	c := newCache(&clock{base: time.Unix(0, 0)})
	mustPut(t, c, endpoint, 30*time.Second)
	mustPut(t, c, other, 30*time.Second)
	c.Evict(endpoint)
	if _, ok, _ := c.Get(ctx, endpoint); ok {
		t.Fatalf("evicted endpoint still present")
	}
	if _, ok, _ := c.Get(ctx, other); !ok {
		t.Fatalf("non-evicted endpoint missing")
	}
}

func TestEvictMissingEndpointIsANoop(t *testing.T) {
	c := newCache(&clock{base: time.Unix(0, 0)})
	c.Evict(endpoint)
	if len(c.entries) != 0 {
		t.Fatalf("entries not empty after no-op evict")
	}
}

func TestEvictAllClearsEveryEntry(t *testing.T) {
	ctx := context.Background()
	c := newCache(&clock{base: time.Unix(0, 0)})
	mustPut(t, c, endpoint, 30*time.Second)
	mustPut(t, c, other, 30*time.Second)
	c.EvictAll()
	if len(c.entries) != 0 {
		t.Fatalf("entries not empty after EvictAll")
	}
	if _, ok, _ := c.Get(ctx, endpoint); ok {
		t.Fatalf("endpoint present after EvictAll")
	}
	if _, ok, _ := c.Get(ctx, other); ok {
		t.Fatalf("other present after EvictAll")
	}
}

func TestStoredValueIsTheWrappedBlobNotTheRawKey(t *testing.T) {
	ctx := context.Background()
	c := newCache(&clock{base: time.Unix(0, 0)})
	if err := c.Put(ctx, endpoint, testKey(), 30*time.Second); err != nil {
		t.Fatalf("Put: %v", err)
	}
	stored := c.entries[endpoint].blob
	if bytes.Equal(stored, testKey()) {
		t.Fatalf("stored value is the raw key")
	}
	if !bytes.Equal(stored, xor(testKey())) {
		t.Fatalf("stored value is not the XOR-wrapped key")
	}
	unwrapped, err := fakeWrapper{}.Unwrap(ctx, stored)
	if err != nil || !bytes.Equal(unwrapped, testKey()) {
		t.Fatalf("unwrap of stored blob = %x err=%v", unwrapped, err)
	}
}

func TestPutOverwritesAnExistingEntry(t *testing.T) {
	ctx := context.Background()
	clk := &clock{base: time.Unix(0, 0)}
	c := newCache(clk)
	if err := c.Put(ctx, endpoint, testKey(), 30*time.Second); err != nil {
		t.Fatalf("Put: %v", err)
	}
	clk.set(40.0)
	newKey := reversed(testKey())
	if err := c.Put(ctx, endpoint, newKey, 10*time.Second); err != nil {
		t.Fatalf("Put overwrite: %v", err)
	}
	got, ok, err := c.Get(ctx, endpoint)
	if err != nil || !ok || !bytes.Equal(got, newKey) {
		t.Fatalf("Get after overwrite = %x ok=%v err=%v", got, ok, err)
	}
	clk.set(50.0)
	if _, ok, _ := c.Get(ctx, endpoint); ok {
		t.Fatalf("Get at 50.0s should miss (overwritten ttl expired)")
	}
}

func mustPut(t *testing.T, c *KeyCache, id string, ttl time.Duration) {
	t.Helper()
	if err := c.Put(context.Background(), id, testKey(), ttl); err != nil {
		t.Fatalf("Put %s: %v", id, err)
	}
}

func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // path is a test-controlled temp file.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// writeBlockingNewkeyHelper writes a fake cookiesync-keyhelper whose cache-newkey appends
// one line to tallyPath — an invocation tally — then blocks until releasePath exists and
// exits 3 (stays degraded). It stands in for a heal's Touch ID presence prompt parked at
// human timescale, so a test can prove reads don't queue behind it.
func writeBlockingNewkeyHelper(t *testing.T) (binary, tallyPath, releasePath string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "cookiesync-keyhelper")
	tallyPath = filepath.Join(dir, "newkey.tally")
	releasePath = filepath.Join(dir, "release")
	body := `#!/bin/sh
case "$1" in
cache-newkey)
  printf 'x\n' >> "` + tallyPath + `"
  while [ ! -f "` + releasePath + `" ]; do sleep 0.01; done
  exit 3
  ;;
*)
  echo "unexpected verb $1" >&2
  exit 99
  ;;
esac
`
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write blocking newkey helper: %v", err)
	}
	return binary, tallyPath, releasePath
}

func tallyCount(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // path is a test-controlled temp file.
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.Count(string(data), "x\n")
}

func TestDegradedReadsDoNotBlockOnAnInFlightHeal(t *testing.T) {
	binary, tallyPath, releasePath := writeBlockingNewkeyHelper(t)
	hw := &healingWrapper{bridge: helper.Bridge{Binary: binary}, label: "test-label"}
	c := NewKeyCache(hw)
	if !c.Degraded() {
		t.Fatalf("Degraded() = false at open over a healingWrapper")
	}

	// A Put whose heal parks in cache-newkey, the human-timescale presence prompt.
	putDone := make(chan error, 1)
	go func() { putDone <- c.Put(context.Background(), endpoint, testKey(), 30*time.Second) }()
	waitFor(t, func() bool { return tallyCount(t, tallyPath) == 1 })

	// While the heal is parked holding w.mu across the subprocess, a concurrent reader
	// must return well under a short bound — reads load the wrapper atomically, never
	// taking w.mu. A reader that instead queued on the heal lock would block until the
	// release below and trip the 2s watchdog.
	readDone := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		_ = c.Degraded()
		if _, _, err := c.Get(context.Background(), endpoint); err != nil {
			t.Errorf("Get during in-flight heal: %v", err)
		}
		readDone <- time.Since(start)
	}()
	select {
	case elapsed := <-readDone:
		if elapsed > 250*time.Millisecond {
			t.Fatalf("reads took %v behind an in-flight heal; the heal must not hold the read lock", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reads blocked behind the in-flight heal")
	}

	if err := os.WriteFile(releasePath, nil, 0o600); err != nil {
		t.Fatalf("release the heal: %v", err)
	}
	if err := <-putDone; err != nil {
		t.Fatalf("Put after release: %v", err)
	}
}

// writeGatedNewkeyHelper writes a helper whose cache-newkey blocks until a release
// file appears and then exits thenCode, so a heal can be parked mid-flight. It tallies
// cache-newkey and cache-dropkey invocations and XORs cache-wrap/cache-unwrap.
func writeGatedNewkeyHelper(t *testing.T, thenCode int) (binary, newkeyTally, dropTally, releasePath string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "cookiesync-keyhelper")
	newkeyTally = filepath.Join(dir, "newkey.tally")
	dropTally = filepath.Join(dir, "drop.tally")
	releasePath = filepath.Join(dir, "release")
	body := `#!/bin/sh
verb="$1"
case "$verb" in
cache-newkey)
  printf 'x\n' >> "` + newkeyTally + `"
  while [ ! -f "` + releasePath + `" ]; do sleep 0.01; done
  exit ` + strconv.Itoa(thenCode) + `
  ;;
cache-wrap|cache-unwrap)
  exec /usr/bin/perl -0777 -pe 's/(.)/chr(ord($1)^0x5A)/ges'
  ;;
cache-dropkey)
  printf 'x\n' >> "` + dropTally + `"
  exit 0
  ;;
*)
  echo "unexpected verb $verb" >&2
  exit 99
  ;;
esac
`
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write gated newkey helper: %v", err)
	}
	return binary, newkeyTally, dropTally, releasePath
}

// writeCtxExpiryNewkeyHelper writes a helper whose first cache-newkey blocks forever
// (until its ctx-killed subprocess dies) and whose second and later calls exit 0, so a
// healer's ctx can expire mid-probe and a live-ctx waiter can re-probe to success.
func writeCtxExpiryNewkeyHelper(t *testing.T) (binary, newkeyTally string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "cookiesync-keyhelper")
	newkeyTally = filepath.Join(dir, "newkey.tally")
	countPath := filepath.Join(dir, "newkey.count")
	body := `#!/bin/sh
verb="$1"
case "$verb" in
cache-newkey)
  n=$(cat "` + countPath + `" 2>/dev/null || echo 0)
  n=$((n+1))
  printf '%s' "$n" > "` + countPath + `"
  printf 'x\n' >> "` + newkeyTally + `"
  if [ "$n" -ge 2 ]; then exit 0; fi
  while true; do sleep 0.01; done
  ;;
cache-wrap|cache-unwrap)
  exec /usr/bin/perl -0777 -pe 's/(.)/chr(ord($1)^0x5A)/ges'
  ;;
cache-dropkey)
  exit 0
  ;;
*)
  echo "unexpected verb $verb" >&2
  exit 99
  ;;
esac
`
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write ctx-expiry newkey helper: %v", err)
	}
	return binary, newkeyTally
}

func TestConcurrentDegradedPutsShareOneSuccessfulHeal(t *testing.T) {
	binary, newkeyTally, dropTally, releasePath := writeGatedNewkeyHelper(t, 0)
	hw := &healingWrapper{bridge: helper.Bridge{Binary: binary}, label: "test-label"}
	c := NewKeyCache(hw)
	if !c.Degraded() {
		t.Fatalf("Degraded() = false at open over a healingWrapper")
	}

	const n = 8
	key := testKey()
	errs := make(chan error, n)
	for range n {
		go func() { errs <- c.Put(context.Background(), endpoint, key, 30*time.Second) }()
	}
	// Every other Put queues on w.mu behind the one heal parked at cache-newkey; no
	// second probe starts while it is in flight.
	waitFor(t, func() bool { return tallyCount(t, newkeyTally) == 1 })
	time.Sleep(100 * time.Millisecond)
	if got := tallyCount(t, newkeyTally); got != 1 {
		t.Fatalf("cache-newkey ran %d times while one heal was in flight, want 1", got)
	}

	if err := os.WriteFile(releasePath, nil, 0o600); err != nil {
		t.Fatalf("release the heal: %v", err)
	}
	for range n {
		if err := <-errs; err != nil {
			t.Fatalf("degraded Put: %v", err)
		}
	}
	// One success installs the Enclave key exactly once; every queued Put sees se
	// installed and never re-probes, so there is no second Touch ID prompt and no
	// key-wiping second cache-newkey.
	if got := tallyCount(t, newkeyTally); got != 1 {
		t.Fatalf("cache-newkey ran %d times for %d Puts sharing one successful heal, want 1", got, n)
	}
	if c.Degraded() {
		t.Fatalf("Degraded() = true after the heal installed the Enclave key")
	}
	c.mu.Lock()
	e, ok := c.entries[endpoint]
	c.mu.Unlock()
	if !ok {
		t.Fatalf("no entry after the healing Puts")
	}
	if !bytes.Equal(e.blob, xor(key)) {
		t.Fatalf("entry = %x, want the Enclave-wrapped %x", e.blob, xor(key))
	}
	if err := hw.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := tallyCount(t, dropTally); got != 1 {
		t.Fatalf("cache-dropkey ran %d times on Close, want 1", got)
	}
}

func TestCloseRacingASuccessfulHealLeavesNoEnclaveKey(t *testing.T) {
	binary, newkeyTally, dropTally, releasePath := writeGatedNewkeyHelper(t, 0)
	hw := &healingWrapper{bridge: helper.Bridge{Binary: binary}, label: "test-label"}
	c := NewKeyCache(hw)

	putDone := make(chan error, 1)
	go func() { putDone <- c.Put(context.Background(), endpoint, testKey(), 30*time.Second) }()
	waitFor(t, func() bool { return tallyCount(t, newkeyTally) == 1 })

	// Close is issued while the probe is parked; it queues on w.mu behind the heal,
	// so the key the exit-0 probe installs is there for Close to drop.
	closeDone := make(chan error, 1)
	go func() { closeDone <- hw.Close(context.Background()) }()
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(releasePath, nil, 0o600); err != nil {
		t.Fatalf("release the heal: %v", err)
	}
	if err := <-putDone; err != nil {
		t.Fatalf("Put racing Close: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}
	// The exit-0 probe created an Enclave key before Close's verdict landed; it must
	// not survive: every created key gets dropped, and nothing Enclave-backed is
	// handed out after Close.
	created, dropped := tallyCount(t, newkeyTally), tallyCount(t, dropTally)
	if created != dropped {
		t.Fatalf("cache-newkey ran %d times but cache-dropkey %d; the key created by the flight racing Close must be dropped", created, dropped)
	}
	if !c.Degraded() {
		t.Fatalf("Degraded() = false after Close; nothing Enclave-backed may be handed out post-Close")
	}
}

func TestCloseWaitsForInFlightHealThenDropsTheKey(t *testing.T) {
	binary, newkeyTally, dropTally, releasePath := writeGatedNewkeyHelper(t, 0)
	hw := &healingWrapper{bridge: helper.Bridge{Binary: binary}, label: "test-label"}
	c := NewKeyCache(hw)

	putDone := make(chan error, 1)
	go func() { putDone <- c.Put(context.Background(), endpoint, testKey(), 30*time.Second) }()
	waitFor(t, func() bool { return tallyCount(t, newkeyTally) == 1 })

	// Close lands while the heal is parked in cache-newkey. It must wait for that heal so
	// the Enclave key the heal installs gets dropped — not return early past a still-nil se.
	closeDone := make(chan error, 1)
	go func() { closeDone <- hw.Close(context.Background()) }()
	time.Sleep(100 * time.Millisecond)
	if got := tallyCount(t, dropTally); got != 0 {
		t.Fatalf("cache-dropkey ran %d times before the heal finished, want 0", got)
	}

	if err := os.WriteFile(releasePath, nil, 0o600); err != nil {
		t.Fatalf("release the heal: %v", err)
	}
	if err := <-putDone; err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := tallyCount(t, newkeyTally); got != 1 {
		t.Fatalf("cache-newkey ran %d times, want 1 (Close must not spawn a second heal)", got)
	}
	if got := tallyCount(t, dropTally); got != 1 {
		t.Fatalf("cache-dropkey ran %d times, want 1 (Close drops the in-flight heal's key exactly once)", got)
	}
}

func TestCloseWithFailedDropLeavesTheKeyRetryable(t *testing.T) {
	binary, _, dropTally, releasePath := writeGatedNewkeyHelper(t, 0)
	hw := &healingWrapper{bridge: helper.Bridge{Binary: binary}, label: "test-label"}
	c := NewKeyCache(hw)

	// Install a real Enclave key first.
	if err := os.WriteFile(releasePath, nil, 0o600); err != nil {
		t.Fatalf("release the heal: %v", err)
	}
	if err := c.Put(context.Background(), endpoint, testKey(), 30*time.Second); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if c.Degraded() {
		t.Fatalf("Degraded() = true, want a healed wrapper before Close")
	}

	// A Close whose cache-dropkey fails (here: an already-canceled ctx kills the drop
	// subprocess) must surface the error and NOT clear se — otherwise the key leaks
	// non-retryably and a later Close falsely reports success against a live key.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := hw.Close(canceled); err == nil {
		t.Fatalf("Close with a canceled ctx: got nil, want the drop error")
	}
	if c.Degraded() {
		t.Fatalf("Degraded() = true after a failed drop: se was cleared, the key leaked non-retryably")
	}
	if got := tallyCount(t, dropTally); got != 0 {
		t.Fatalf("cache-dropkey ran %d times on the canceled drop, want 0", got)
	}

	// A retry with a live ctx must actually drop the still-present key.
	if err := hw.Close(context.Background()); err != nil {
		t.Fatalf("retry Close: %v", err)
	}
	if !c.Degraded() {
		t.Fatalf("Degraded() = false after a successful retry Close")
	}
	if got := tallyCount(t, dropTally); got != 1 {
		t.Fatalf("cache-dropkey ran %d times, want 1 (the retry dropped the key exactly once)", got)
	}
}

// writeDropExitHelper writes a helper whose cache-newkey exits 0 (so a real
// SecureEnclaveWrapper is minted) and whose cache-dropkey exits 1 with stderr
// until the dropOK marker exists, then exits 0 — parameterizing a cleanly failing
// then succeeding key drop without an in-process fake.
func writeDropExitHelper(t *testing.T) (binary, dropOKPath string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "cookiesync-keyhelper")
	dropOKPath = filepath.Join(dir, "drop-ok")
	body := `#!/bin/sh
verb="$1"
case "$verb" in
cache-newkey)
  exit 0
  ;;
cache-wrap|cache-unwrap)
  exec /usr/bin/perl -0777 -pe 's/(.)/chr(ord($1)^0x5A)/ges'
  ;;
cache-dropkey)
  if [ -f "` + dropOKPath + `" ]; then exit 0; fi
  echo "keyhelper: SecItemDelete failed (OSStatus -25300)" >&2
  exit 1
  ;;
*)
  echo "unexpected verb $verb" >&2
  exit 99
  ;;
esac
`
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write drop-exit helper: %v", err)
	}
	return binary, dropOKPath
}

func TestCloseSurfacesNonzeroDropExit(t *testing.T) {
	binary, dropOKPath := writeDropExitHelper(t)
	ctx := context.Background()

	// A bare SecureEnclaveWrapper whose cache-dropkey exits 1 must surface the exit code
	// rather than swallow it — the key is still live.
	opened, err := OpenWrapper(ctx, helper.Bridge{Binary: binary})
	if err != nil {
		t.Fatalf("OpenWrapper: %v", err)
	}
	se := opened.(*SecureEnclaveWrapper)
	if err := se.Close(ctx); err == nil || !strings.Contains(err.Error(), "cache-dropkey exited 1") {
		t.Fatalf("SecureEnclaveWrapper.Close err = %v, want it to mention the nonzero exit code", err)
	}

	// A healed healingWrapper wrapping an se whose drop still exits 1: Close reports the
	// error and keeps se installed, so the still-live key stays retryable.
	hw := &healingWrapper{bridge: helper.Bridge{Binary: binary}, label: "test-label"}
	c := NewKeyCache(hw)
	if err := c.Put(ctx, endpoint, testKey(), 30*time.Second); err != nil {
		t.Fatalf("healing Put: %v", err)
	}
	if c.Degraded() {
		t.Fatalf("Degraded() = true, want a healed wrapper before Close")
	}
	if err := hw.Close(ctx); err == nil {
		t.Fatalf("healingWrapper.Close over a failing drop: got nil, want the exit-code error")
	}
	if c.Degraded() {
		t.Fatalf("Degraded() = true after a failed drop: se was cleared, the live key leaked non-retryably")
	}

	// Once cache-dropkey succeeds, a retry Close drops the key and clears se.
	if err := os.WriteFile(dropOKPath, nil, 0o600); err != nil {
		t.Fatalf("flip drop to exit 0: %v", err)
	}
	if err := hw.Close(ctx); err != nil {
		t.Fatalf("retry Close after drop succeeds: %v", err)
	}
	if !c.Degraded() {
		t.Fatalf("Degraded() = false after a successful retry Close cleared se")
	}
}

func TestHealAfterCloseStaysDegradedWithoutAKey(t *testing.T) {
	binary, newkeyTally, _, _ := writeGatedNewkeyHelper(t, 0)
	hw := &healingWrapper{bridge: helper.Bridge{Binary: binary}, label: "test-label"}
	c := NewKeyCache(hw)

	if err := hw.Close(context.Background()); err != nil {
		t.Fatalf("Close while degraded: %v", err)
	}
	// A Put after Close must not spawn cache-newkey: closed rejects the heal and the wrapper
	// stays in-memory.
	key := testKey()
	if err := c.Put(context.Background(), endpoint, key, 30*time.Second); err != nil {
		t.Fatalf("Put after Close: %v", err)
	}
	if got := tallyCount(t, newkeyTally); got != 0 {
		t.Fatalf("cache-newkey ran %d times after Close, want 0 (closed rejects new heals)", got)
	}
	if !c.Degraded() {
		t.Fatalf("Degraded() = false after Close-while-degraded")
	}
	c.mu.Lock()
	blob := c.entries[endpoint].blob
	c.mu.Unlock()
	if !bytes.Equal(blob, key) {
		t.Fatalf("entry = %x, want the identity RAM copy %x", blob, key)
	}
}

func TestHealerCtxExpiryLetsAWaiterBecomeTheNextHealer(t *testing.T) {
	binary, newkeyTally := writeCtxExpiryNewkeyHelper(t)
	hw := &healingWrapper{bridge: helper.Bridge{Binary: binary}, label: "test-label"}
	c := NewKeyCache(hw)

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leaderErr := make(chan error, 1)
	go func() { leaderErr <- c.Put(leaderCtx, endpoint, testKey(), 30*time.Second) }()
	waitFor(t, func() bool { return tallyCount(t, newkeyTally) == 1 })

	// A second Put with a live ctx queues on w.mu behind the leader's probe.
	waiterErr := make(chan error, 1)
	go func() { waiterErr <- c.Put(context.Background(), other, testKey(), 30*time.Second) }()
	time.Sleep(100 * time.Millisecond)

	// The leader's ctx expires mid-cache-newkey: its subprocess dies, its heal fails, and it
	// releases w.mu. The queued waiter, ctx still live, runs its own probe and heals —
	// a queued Put must not inherit the leader's cancellation.
	cancelLeader()
	if err := <-leaderErr; err == nil {
		t.Fatalf("leader Put succeeded, want the cancelled-ctx failure")
	}
	if err := <-waiterErr; err != nil {
		t.Fatalf("waiter Put after leader ctx expiry: %v", err)
	}
	if c.Degraded() {
		t.Fatalf("Degraded() = true; the waiter's live-ctx re-probe should have healed")
	}
	if got := tallyCount(t, newkeyTally); got != 2 {
		t.Fatalf("cache-newkey ran %d times, want 2 (leader killed, waiter re-probed to success)", got)
	}
}
