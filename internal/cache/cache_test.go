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

	// Park the stale Put on c.mu after its re-probe stayed degraded (identity blob
	// in hand), let a second Put heal and swap, then release: the stale Put must
	// notice the swap and re-wrap through the Enclave instead of inserting.
	c.mu.Lock()
	stale := make(chan error, 1)
	go func() { stale <- c.Put(ctx, endpoint, key, 30*time.Second) }()
	waitFor(t, func() bool { return strings.Count(readFile(t, logPath), "cache-newkey") == 2 })

	healing := make(chan error, 1)
	go func() { healing <- c.Put(ctx, other, key, 30*time.Second) }()
	waitFor(t, func() bool { return !hw.degraded() })
	c.mu.Unlock()

	if err := <-stale; err != nil {
		t.Fatalf("stale Put: %v", err)
	}
	if err := <-healing; err != nil {
		t.Fatalf("healing Put: %v", err)
	}
	if got := strings.Count(readFile(t, logPath), "cache-wrap"); got != 2 {
		t.Fatalf("cache-wrap ran %d times, want 2 (the healing Put plus the stale Put's re-wrap)", got)
	}
	for id, e := range c.entries {
		if !bytes.Equal(e.blob, xor(key)) {
			t.Fatalf("entry %s = %x, want Enclave-wrapped %x (identity blob crossed the heal swap)", id, e.blob, xor(key))
		}
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
