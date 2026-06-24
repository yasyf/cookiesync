package cache

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

	wrapper, err := OpenWrapper(ctx, helper.Bridge{})
	if err != nil {
		t.Fatalf("OpenWrapper: %v", err)
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
