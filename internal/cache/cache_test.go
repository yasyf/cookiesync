package cache

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/synckit/authkit"
)

// The helper-exec seam is doubled by the scripted fakeHelper and the clock is
// injected, so every epoch transition runs deterministically in process.

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

func xor(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ xorMask
	}
	return out
}

// respond is one scripted fakeHelper reply: stdin payload in, helper result out.
type respond func(stdin []byte) helper.Result

// fakeHelper scripts the helper-exec seam: each verb consumes its queued
// responds, then falls back to a healthy default; calls are counted per verb.
type fakeHelper struct {
	mu    sync.Mutex
	queue map[string][]respond
	calls map[string]int
}

func newFakeHelper() *fakeHelper {
	return &fakeHelper{queue: map[string][]respond{}, calls: map[string]int{}}
}

func (h *fakeHelper) push(verb string, rs ...respond) {
	h.mu.Lock()
	h.queue[verb] = append(h.queue[verb], rs...)
	h.mu.Unlock()
}

func (h *fakeHelper) count(verb string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls[verb]
}

func (h *fakeHelper) run(verb string, stdin []byte) (helper.Result, error) {
	h.mu.Lock()
	h.calls[verb]++
	var r respond
	if q := h.queue[verb]; len(q) > 0 {
		r, h.queue[verb] = q[0], q[1:]
	}
	h.mu.Unlock()
	if r == nil {
		if verb == "cache-wrap" || verb == "cache-unwrap" {
			return helper.Result{Code: 0, Stdout: xor(stdin)}, nil
		}
		return helper.Result{Code: 0}, nil
	}
	return r(stdin), nil
}

func (h *fakeHelper) CacheNewkey(_ context.Context, _ string) (helper.Result, error) {
	return h.run("cache-newkey", nil)
}

func (h *fakeHelper) CacheWrap(_ context.Context, _ string, plaintext []byte) (helper.Result, error) {
	return h.run("cache-wrap", plaintext)
}

func (h *fakeHelper) CacheUnwrap(_ context.Context, _ string, blob []byte) (helper.Result, error) {
	return h.run("cache-unwrap", blob)
}

func (h *fakeHelper) CacheDropkey(_ context.Context, _ string) (helper.Result, error) {
	return h.run("cache-dropkey", nil)
}

// refuse is the keybag presence refusal: exit 3 with an OSStatus diagnostic.
func refuse(_ []byte) helper.Result {
	return helper.Result{Code: helper.CodePresenceUnavailable, Stderr: []byte("keyhelper: interaction not allowed (OSStatus -25308)")}
}

func exitWith(code int, stderr string) respond {
	return func(_ []byte) helper.Result {
		return helper.Result{Code: code, Stderr: []byte(stderr)}
	}
}

// parked wraps r so the call signals entered, then blocks until release closes.
func parked(entered chan<- struct{}, release <-chan struct{}, r respond) respond {
	return func(stdin []byte) helper.Result {
		entered <- struct{}{}
		<-release
		return r(stdin)
	}
}

func okWrap(stdin []byte) helper.Result {
	return helper.Result{Code: 0, Stdout: xor(stdin)}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Unix(1_700_000_000, 0)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func mustOpen(t *testing.T, h Helper, now func() time.Time) *KeyCache {
	t.Helper()
	c, err := open(context.Background(), h, now)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return c
}

func mustPut(t *testing.T, c *KeyCache, id string, key []byte) {
	t.Helper()
	if _, err := c.Put(context.Background(), id, key, time.Minute); err != nil {
		t.Fatalf("Put %s: %v", id, err)
	}
}

func mustGet(t *testing.T, c *KeyCache, id string, want []byte) {
	t.Helper()
	key, ok, err := c.Get(context.Background(), id)
	if err != nil || !ok || !bytes.Equal(key, want) {
		t.Fatalf("Get %s = %q, %v, %v, want %q true nil", id, key, ok, err, want)
	}
}

func mustMiss(t *testing.T, c *KeyCache, id string) {
	t.Helper()
	key, ok, err := c.Get(context.Background(), id)
	if err != nil || ok || key != nil {
		t.Fatalf("Get %s = %q, %v, %v, want a clean miss", id, key, ok, err)
	}
}

func entryCount(c *KeyCache) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func TestOpenStates(t *testing.T) {
	tests := []struct {
		name         string
		newkey       respond
		wantErr      string
		wantDegraded bool
	}{
		{name: "keybag unlocked opens Enclave-wrapped"},
		{
			name:         "presence refusal opens degraded",
			newkey:       refuse,
			wantDegraded: true,
		},
		{
			name:    "exit 2 fails loud with the helper stderr",
			newkey:  exitWith(2, "keyhelper: no Secure Enclave (OSStatus -34018)"),
			wantErr: "cache-newkey exited 2 (no Secure Enclave or keygen refused): keyhelper: no Secure Enclave (OSStatus -34018)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newFakeHelper()
			if tc.newkey != nil {
				h.push("cache-newkey", tc.newkey)
			}
			c, err := open(context.Background(), h, newClock().now)
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("open err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if got := c.Degraded(); got != tc.wantDegraded {
				t.Fatalf("Degraded = %v, want %v", got, tc.wantDegraded)
			}
			if got := h.count("cache-newkey"); got != 1 {
				t.Fatalf("cache-newkey calls = %d, want 1", got)
			}
		})
	}
}

func TestOpenFailsClosedWhenHelperMissing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent", "authkit")
	t.Setenv(authkit.HelperEnvVar, missing)

	_, err := Open(context.Background(), helper.Bridge{})
	var helperErr *authkit.HelperError
	if !errors.As(err, &helperErr) {
		t.Fatalf("err = %v, want *authkit.HelperError", err)
	}
}

func TestPutAndGetBasics(t *testing.T) {
	key := testKey()
	tests := []struct {
		name string
		run  func(t *testing.T, c *KeyCache, clk *clock)
	}{
		{
			name: "put then get returns the key",
			run: func(t *testing.T, c *KeyCache, _ *clock) {
				mustPut(t, c, endpoint, key)
				mustGet(t, c, endpoint, key)
			},
		},
		{
			name: "get missing endpoint misses",
			run: func(t *testing.T, c *KeyCache, _ *clock) {
				mustMiss(t, c, endpoint)
			},
		},
		{
			name: "get after ttl misses and evicts",
			run: func(t *testing.T, c *KeyCache, clk *clock) {
				mustPut(t, c, endpoint, key)
				clk.advance(time.Minute)
				mustMiss(t, c, endpoint)
				if got := entryCount(c); got != 0 {
					t.Fatalf("entries = %d after expiry, want 0", got)
				}
			},
		},
		{
			name: "put overwrites an existing entry",
			run: func(t *testing.T, c *KeyCache, _ *clock) {
				mustPut(t, c, endpoint, key)
				next := xor(key)
				mustPut(t, c, endpoint, next)
				mustGet(t, c, endpoint, next)
			},
		},
		{
			name: "stored value is the wrapped blob not the raw key",
			run: func(t *testing.T, c *KeyCache, _ *clock) {
				mustPut(t, c, endpoint, key)
				c.mu.Lock()
				blob := c.entries[endpoint].blob
				c.mu.Unlock()
				if !bytes.Equal(blob, xor(key)) {
					t.Fatalf("stored blob = %q, want the XOR-wrapped key", blob)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clk := newClock()
			c := mustOpen(t, newFakeHelper(), clk.now)
			tc.run(t, c, clk)
		})
	}
}

func TestGetNonPresenceUnwrapFailureIsFatal(t *testing.T) {
	h := newFakeHelper()
	c := mustOpen(t, h, newClock().now)
	mustPut(t, c, endpoint, testKey())
	h.push("cache-unwrap", exitWith(1, "keyhelper: decrypt failed"))

	_, ok, err := c.Get(context.Background(), endpoint)
	want := "cache-unwrap exited 1 (key missing or decrypt failed): keyhelper: decrypt failed"
	if ok || err == nil || err.Error() != want {
		t.Fatalf("Get = %v, %v, want error %q", ok, err, want)
	}
	if c.Degraded() {
		t.Fatalf("a non-presence unwrap failure must not demote the cache")
	}
}

func TestPutReprobeExitTwoFailsLoud(t *testing.T) {
	h := newFakeHelper()
	h.push("cache-newkey", refuse, exitWith(2, "keyhelper: keygen refused"))
	c := mustOpen(t, h, newClock().now)

	_, err := c.Put(context.Background(), endpoint, testKey(), time.Minute)
	want := "cache-newkey re-probe exited 2 (no Secure Enclave or keygen refused): keyhelper: keygen refused"
	if err == nil || err.Error() != want {
		t.Fatalf("Put err = %v, want %q", err, want)
	}
}

// TestGetPresenceRefusalDemotesEvictsAndMisses is the Bug A/B unit regression:
// a refused unwrap reads as a miss, demotes to MEMORY, and evicts the entry.
func TestGetPresenceRefusalDemotesEvictsAndMisses(t *testing.T) {
	h := newFakeHelper()
	c := mustOpen(t, h, newClock().now)
	mustPut(t, c, endpoint, testKey())
	h.push("cache-unwrap", refuse)

	mustMiss(t, c, endpoint)
	if !c.Degraded() {
		t.Fatalf("a refused unwrap must demote the cache to MEMORY")
	}
	if got := entryCount(c); got != 0 {
		t.Fatalf("entries = %d after the refusal, want 0 (dead entry evicted)", got)
	}
	mustMiss(t, c, endpoint)
	if got := h.count("cache-unwrap"); got != 1 {
		t.Fatalf("cache-unwrap calls = %d, want 1 (the evicted entry must not re-exec the helper)", got)
	}
}

// TestPutPresenceRefusalDegradesAndStores proves a refused wrap can never fail
// a Put: it demotes, retries in memory, and converges within two iterations.
func TestPutPresenceRefusalDegradesAndStores(t *testing.T) {
	h := newFakeHelper()
	c := mustOpen(t, h, newClock().now)
	h.push("cache-wrap", refuse)
	h.push("cache-newkey", refuse) // the retry's heal probe: keybag still locked

	key := testKey()
	mustPut(t, c, endpoint, key)
	if !c.Degraded() {
		t.Fatalf("a refused wrap must demote the cache to MEMORY")
	}
	mustGet(t, c, endpoint, key)
	if got := h.count("cache-wrap"); got != 1 {
		t.Fatalf("cache-wrap calls = %d, want 1 (Put must converge within 2 iterations)", got)
	}
	if got := h.count("cache-newkey"); got != 2 {
		t.Fatalf("cache-newkey calls = %d, want 2 (open + one heal probe)", got)
	}
	if got := h.count("cache-unwrap"); got != 0 {
		t.Fatalf("cache-unwrap calls = %d, want 0 (a MEMORY entry reads without the helper)", got)
	}
}

// TestDemoteThenHealRoundTrip drives the two-way cycle: ENCLAVE, demote to
// MEMORY on a refusal, heal back to a fresh ENCLAVE epoch on a later Put.
func TestDemoteThenHealRoundTrip(t *testing.T) {
	h := newFakeHelper()
	c := mustOpen(t, h, newClock().now)
	key := testKey()
	mustPut(t, c, endpoint, key)

	h.push("cache-unwrap", refuse)
	mustMiss(t, c, endpoint)
	if !c.Degraded() {
		t.Fatalf("the refusal must demote the cache")
	}

	mustPut(t, c, other, key) // heal probe succeeds (default newkey exit 0)
	if c.Degraded() {
		t.Fatalf("the Put's re-probe must heal the cache")
	}
	mustGet(t, c, other, key)
	if got := h.count("cache-newkey"); got != 2 {
		t.Fatalf("cache-newkey calls = %d, want 2 (open + the healing probe)", got)
	}
	mustMiss(t, c, endpoint)
	mustPut(t, c, endpoint, key)
	mustGet(t, c, endpoint, key)
}

// TestDemoteCASLosesToNewerHeal drives demote itself with a retired epoch — the
// pointer a slow refusal captured before a demote-and-heal cycle replaced it —
// and proves the newer healed epoch survives: demote must CAS the failing
// epoch and lose, where a raw Store would clobber the heal and re-degrade a
// cache whose keybag just unlocked.
func TestDemoteCASLosesToNewerHeal(t *testing.T) {
	h := newFakeHelper()
	c := mustOpen(t, h, newClock().now)
	key := testKey()
	mustPut(t, c, endpoint, key)
	stale := c.state.Load() // the epoch a slow refusal observed before losing the race

	h.push("cache-unwrap", refuse)
	mustMiss(t, c, endpoint) // demotes the first epoch
	if !c.Degraded() {
		t.Fatalf("the fast refusal must demote the cache")
	}
	const healed = "yasyf-home:arc:Default"
	mustPut(t, c, healed, key) // heals to a fresh ENCLAVE epoch
	if c.Degraded() {
		t.Fatalf("the Put must heal the cache before the slow refusal lands")
	}
	healedEpoch := c.state.Load()
	if healedEpoch == stale {
		t.Fatalf("the heal must install a fresh epoch")
	}

	c.demote(stale) // the slow refusal lands now, carrying its retired epoch
	if got := c.state.Load(); got != healedEpoch {
		t.Fatalf("the slow refusal's demote replaced the healed epoch — it must CAS the failing epoch and lose")
	}
	if c.Degraded() {
		t.Fatalf("a lost demote must leave the cache Enclave-wrapped")
	}
	mustGet(t, c, healed, key)

	c.demote(healedEpoch) // a refusal of the CURRENT epoch still wins
	if !c.Degraded() {
		t.Fatalf("a demote of the current epoch must degrade the cache")
	}
}

// TestCloseIsTerminal proves CLOSED is terminal: entries gone, Put returns
// ErrClosed, and the Enclave key drops exactly once — never when none exists.
func TestCloseIsTerminal(t *testing.T) {
	tests := []struct {
		name         string
		degradedOpen bool
		wantDrops    int
	}{
		{name: "healthy open drops the key once", wantDrops: 1},
		{name: "degraded open never provisioned a key to drop", degradedOpen: true, wantDrops: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			h := newFakeHelper()
			if tc.degradedOpen {
				h.push("cache-newkey", refuse, refuse) // open + the Put's heal probe stay locked
			}
			c := mustOpen(t, h, newClock().now)
			mustPut(t, c, endpoint, testKey())

			if err := c.Close(ctx); err != nil {
				t.Fatalf("Close: %v", err)
			}
			mustMiss(t, c, endpoint)
			if _, err := c.Put(ctx, other, testKey(), time.Minute); !errors.Is(err, ErrClosed) {
				t.Fatalf("Put after Close = %v, want ErrClosed", err)
			}
			if c.Degraded() {
				t.Fatalf("a closed cache is not degraded")
			}
			if err := c.Close(ctx); err != nil {
				t.Fatalf("repeat Close: %v", err)
			}
			if got := h.count("cache-dropkey"); got != tc.wantDrops {
				t.Fatalf("cache-dropkey calls = %d, want %d", got, tc.wantDrops)
			}
		})
	}
}

func TestCloseSurfacesNonzeroDropExit(t *testing.T) {
	h := newFakeHelper()
	c := mustOpen(t, h, newClock().now)
	h.push("cache-dropkey", exitWith(1, "keyhelper: delete failed"))

	err := c.Close(context.Background())
	want := "cache-dropkey exited 1 (key still live): keyhelper: delete failed"
	if err == nil || err.Error() != want {
		t.Fatalf("Close err = %v, want %q", err, want)
	}
	if _, err := c.Put(context.Background(), endpoint, testKey(), time.Minute); !errors.Is(err, ErrClosed) {
		t.Fatalf("Put after a failed drop = %v, want ErrClosed (Close stays terminal)", err)
	}
}

// TestPutRacingCloseNeverPublishes is the b2e6be7 regression: a Put whose wrap
// is in flight when Close lands fails its publish check and returns ErrClosed.
func TestPutRacingCloseNeverPublishes(t *testing.T) {
	ctx := context.Background()
	h := newFakeHelper()
	c := mustOpen(t, h, newClock().now)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h.push("cache-wrap", parked(entered, release, okWrap))

	putDone := make(chan error, 1)
	go func() {
		_, err := c.Put(ctx, endpoint, testKey(), time.Minute)
		putDone <- err
	}()
	<-entered

	if err := c.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	close(release)
	if err := <-putDone; !errors.Is(err, ErrClosed) {
		t.Fatalf("Put racing Close = %v, want ErrClosed", err)
	}
	if got := entryCount(c); got != 0 {
		t.Fatalf("entries = %d after Close, want 0 (the racing Put must not publish)", got)
	}
	mustMiss(t, c, endpoint)
}

// TestPutRetriesAcrossHealAlwaysPublishes parks a Put's wrap, demotes and heals
// underneath it, and proves the Put re-wraps under the healed epoch and lands
// warm — the guarantee that absorbed the caller-side re-Put dance.
func TestPutRetriesAcrossHealAlwaysPublishes(t *testing.T) {
	ctx := context.Background()
	h := newFakeHelper()
	c := mustOpen(t, h, newClock().now)
	key := testKey()
	mustPut(t, c, other, key) // wrap #1

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h.push("cache-wrap", parked(entered, release, okWrap))

	putDone := make(chan error, 1)
	go func() {
		_, err := c.Put(ctx, endpoint, key, time.Minute)
		putDone <- err
	}() // wrap #2 parks
	<-entered

	h.push("cache-unwrap", refuse)
	mustMiss(t, c, other) // demote the first epoch
	const healed = "yasyf-home:arc:Default"
	mustPut(t, c, healed, key) // heal to a fresh ENCLAVE epoch (wrap #3)
	if c.Degraded() {
		t.Fatalf("the healing Put must leave the cache Enclave-wrapped")
	}

	close(release)
	if err := <-putDone; err != nil {
		t.Fatalf("Put racing the heal: %v", err)
	}
	mustGet(t, c, endpoint, key)
	mustGet(t, c, healed, key)
	if got := h.count("cache-wrap"); got != 4 {
		t.Fatalf("cache-wrap calls = %d, want 4 (the racing Put must re-wrap once under the healed epoch)", got)
	}
}

// TestPutRacingDemoteRepublishesUnderMemory demotes the cache while a Put's wrap
// is parked mid-flight: the Put discards the stale wrap, re-resolves the fresh
// MEMORY epoch (its heal probe still refused), and publishes there — the routed
// approval caches, never lost.
func TestPutRacingDemoteRepublishesUnderMemory(t *testing.T) {
	ctx := context.Background()
	h := newFakeHelper()
	c := mustOpen(t, h, newClock().now)
	key := testKey()
	mustPut(t, c, other, key)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h.push("cache-wrap", parked(entered, release, okWrap))

	putDone := make(chan error, 1)
	go func() {
		_, err := c.Put(ctx, endpoint, key, time.Minute)
		putDone <- err
	}()
	<-entered

	h.push("cache-unwrap", refuse)
	mustMiss(t, c, other) // demotes the parked wrap's epoch
	if !c.Degraded() {
		t.Fatalf("the refusal must demote the cache")
	}
	h.push("cache-newkey", refuse) // the racing Put's heal probe: keybag still locked

	close(release)
	if err := <-putDone; err != nil {
		t.Fatalf("Put racing the demote: %v", err)
	}
	if !c.Degraded() {
		t.Fatalf("the cache must stay MEMORY after the re-publish")
	}
	mustGet(t, c, endpoint, key)
	c.mu.Lock()
	ep := c.entries[endpoint].ep
	c.mu.Unlock()
	if ep != c.state.Load() {
		t.Fatalf("the re-published entry must carry the current post-demote MEMORY epoch")
	}
	if got := h.count("cache-unwrap"); got != 1 {
		t.Fatalf("cache-unwrap calls = %d, want 1 (a MEMORY entry reads without the helper)", got)
	}
}

// TestPutHealsOncePerCallUnderPresenceFlapping scripts the flap — every heal
// probe succeeds, every Enclave wrap refuses — and proves one Put heals at most
// once: the post-heal refusal demotes and publishes in memory instead of
// spinning through re-probes.
func TestPutHealsOncePerCallUnderPresenceFlapping(t *testing.T) {
	h := newFakeHelper()
	h.push("cache-newkey", refuse) // degraded open; every later probe succeeds
	c := mustOpen(t, h, newClock().now)
	h.push("cache-wrap", refuse, refuse, refuse)

	key := testKey()
	mustPut(t, c, endpoint, key)
	if !c.Degraded() {
		t.Fatalf("the post-heal refusal must leave the cache in MEMORY")
	}
	mustGet(t, c, endpoint, key)
	if got := h.count("cache-newkey"); got != 2 {
		t.Fatalf("cache-newkey calls = %d, want 2 (open + exactly one heal probe per Put)", got)
	}
	if got := h.count("cache-wrap"); got != 1 {
		t.Fatalf("cache-wrap calls = %d, want 1 (the refused Enclave wrap; the retry publishes in memory)", got)
	}
}

// TestPutReportsPublishEpochAndCapsDegradedTTL pins the C1 contract: Put
// reports the epoch kind it actually published under — mid-call demotes and
// heals included, never a pre-call probe — and a MEMORY publish caps the entry
// TTL at DegradedTTL whatever the caller asked for.
func TestPutReportsPublishEpochAndCapsDegradedTTL(t *testing.T) {
	key := testKey()
	tests := []struct {
		name         string
		setup        func(h *fakeHelper) // queue pushes before open and Put
		preOpen      bool                // push a refusing open probe first
		wantDegraded bool
	}{
		{
			name:         "enclave publish reports enclave and keeps the full TTL",
			setup:        func(*fakeHelper) {},
			wantDegraded: false,
		},
		{
			name: "wrap refusal demotes mid-call and publishes capped in memory",
			setup: func(h *fakeHelper) {
				h.push("cache-wrap", refuse)
				h.push("cache-newkey", refuse) // the retry's heal probe: keybag still locked
			},
			wantDegraded: true,
		},
		{
			name:         "heal mid-call publishes Enclave-wrapped with the full TTL",
			setup:        func(*fakeHelper) {}, // the Put's heal probe succeeds by default
			preOpen:      true,
			wantDegraded: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newFakeHelper()
			if tc.preOpen {
				h.push("cache-newkey", refuse) // degraded open
			}
			clk := newClock()
			c := mustOpen(t, h, clk.now)
			tc.setup(h)

			degraded, err := c.Put(context.Background(), endpoint, key, time.Hour)
			if err != nil {
				t.Fatalf("Put: %v", err)
			}
			if degraded != tc.wantDegraded {
				t.Fatalf("Put degraded = %v, want %v", degraded, tc.wantDegraded)
			}
			clk.advance(DegradedTTL - time.Second)
			mustGet(t, c, endpoint, key) // warm inside the degraded window either way
			clk.advance(2 * time.Second)
			if tc.wantDegraded {
				mustMiss(t, c, endpoint) // the MEMORY entry dies at DegradedTTL, not the asked hour
				return
			}
			mustGet(t, c, endpoint, key) // the ENCLAVE entry keeps the full hour
			clk.advance(time.Hour)
			mustMiss(t, c, endpoint)
		})
	}
}

// TestCloseBoundedWhileHealHoldsLock proves shutdown never hangs behind a heal
// parked in its presence prompt: Close returns the ctx error by its deadline,
// performs no transition, and a later unobstructed Close still succeeds.
func TestCloseBoundedWhileHealHoldsLock(t *testing.T) {
	h := newFakeHelper()
	h.push("cache-newkey", refuse) // degraded open
	c := mustOpen(t, h, newClock().now)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h.push("cache-newkey", parked(entered, release, refuse))
	putDone := make(chan error, 1)
	go func() {
		_, err := c.Put(context.Background(), endpoint, testKey(), time.Minute)
		putDone <- err
	}()
	<-entered // the Put's heal holds healMu, parked in cache-newkey

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := c.Close(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close under a parked heal = %v, want the ctx deadline", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Close took %v; its ctx must bound the healMu wait", elapsed)
	}
	if c.state.Load().kind == stateClosed {
		t.Fatalf("a bounded-out Close must not install the CLOSED epoch")
	}

	close(release)
	if err := <-putDone; err != nil {
		t.Fatalf("Put across the bounded Close: %v", err)
	}
	mustGet(t, c, endpoint, testKey())
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("unobstructed Close: %v", err)
	}
	mustMiss(t, c, endpoint)
}

// TestGetInFlightAcrossCloseNeverReturnsKey parks a Get's unwrap, Closes the
// cache underneath it, then lets the unwrap succeed: the stale success reads as
// a miss — the b2e6be7 window.
func TestGetInFlightAcrossCloseNeverReturnsKey(t *testing.T) {
	ctx := context.Background()
	h := newFakeHelper()
	c := mustOpen(t, h, newClock().now)
	mustPut(t, c, endpoint, testKey())

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h.push("cache-unwrap", parked(entered, release, okWrap))

	type read struct {
		key []byte
		ok  bool
		err error
	}
	done := make(chan read, 1)
	go func() {
		k, ok, err := c.Get(ctx, endpoint)
		done <- read{key: k, ok: ok, err: err}
	}()
	<-entered

	if err := c.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	close(release)
	if g := <-done; g.err != nil || g.ok || g.key != nil {
		t.Fatalf("Get across Close = %q, %v, %v, want a clean miss", g.key, g.ok, g.err)
	}
}

// TestGetInFlightAcrossDemoteMisses parks a Get's unwrap, demotes the cache
// underneath it, then lets the unwrap succeed: the stale success reads as a miss
// and the dead entry is evicted.
func TestGetInFlightAcrossDemoteMisses(t *testing.T) {
	ctx := context.Background()
	h := newFakeHelper()
	c := mustOpen(t, h, newClock().now)
	key := testKey()
	mustPut(t, c, endpoint, key)
	mustPut(t, c, other, key)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h.push("cache-unwrap", parked(entered, release, okWrap))

	type read struct {
		key []byte
		ok  bool
		err error
	}
	done := make(chan read, 1)
	go func() {
		k, ok, err := c.Get(ctx, endpoint)
		done <- read{key: k, ok: ok, err: err}
	}()
	<-entered

	h.push("cache-unwrap", refuse)
	mustMiss(t, c, other) // demotes the parked unwrap's epoch
	if !c.Degraded() {
		t.Fatalf("the refusal must demote the cache")
	}
	close(release)
	if g := <-done; g.err != nil || g.ok || g.key != nil {
		t.Fatalf("Get across the demote = %q, %v, %v, want a clean miss", g.key, g.ok, g.err)
	}
	if got := entryCount(c); got != 0 {
		t.Fatalf("entries = %d, want 0 (both stale-epoch entries evicted)", got)
	}
}

// TestGetStaleErrorNeverPropagates parks an unwrap that will fail, retires its
// epoch underneath it, and proves the stale error surfaces as a miss after a
// demote and as ErrClosed after Close — never raw.
func TestGetStaleErrorNeverPropagates(t *testing.T) {
	tests := []struct {
		name   string
		retire func(t *testing.T, c *KeyCache, h *fakeHelper)
		check  func(t *testing.T, key []byte, ok bool, err error)
	}{
		{
			name: "across a demote reads as a miss",
			retire: func(t *testing.T, c *KeyCache, h *fakeHelper) {
				t.Helper()
				h.push("cache-unwrap", refuse)
				mustMiss(t, c, other)
			},
			check: func(t *testing.T, key []byte, ok bool, err error) {
				t.Helper()
				if err != nil || ok || key != nil {
					t.Fatalf("stale-error Get = %q, %v, %v, want a clean miss", key, ok, err)
				}
			},
		},
		{
			name: "across Close reads as ErrClosed",
			retire: func(t *testing.T, c *KeyCache, _ *fakeHelper) {
				t.Helper()
				if err := c.Close(context.Background()); err != nil {
					t.Fatalf("Close: %v", err)
				}
			},
			check: func(t *testing.T, key []byte, ok bool, err error) {
				t.Helper()
				if !errors.Is(err, ErrClosed) || ok || key != nil {
					t.Fatalf("stale-error Get = %q, %v, %v, want ErrClosed", key, ok, err)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			h := newFakeHelper()
			c := mustOpen(t, h, newClock().now)
			key := testKey()
			mustPut(t, c, endpoint, key)
			mustPut(t, c, other, key)

			entered := make(chan struct{}, 1)
			release := make(chan struct{})
			h.push("cache-unwrap", parked(entered, release, exitWith(1, "keyhelper: decrypt failed")))

			type read struct {
				key []byte
				ok  bool
				err error
			}
			done := make(chan read, 1)
			go func() {
				k, ok, err := c.Get(ctx, endpoint)
				done <- read{key: k, ok: ok, err: err}
			}()
			<-entered

			tc.retire(t, c, h)
			close(release)
			g := <-done
			tc.check(t, g.key, g.ok, g.err)
		})
	}
}

// TestHealEvictionSparesNewEpochPut is the 42a9649 regression over epochs: Puts
// that ride the heal publish under the fresh epoch and survive its eviction,
// while every pre-heal MEMORY entry dies with its epoch.
func TestHealEvictionSparesNewEpochPut(t *testing.T) {
	ctx := context.Background()
	h := newFakeHelper()
	h.push("cache-newkey", refuse, refuse) // degraded open + the first Put's probe
	c := mustOpen(t, h, newClock().now)
	key := testKey()
	mustPut(t, c, endpoint, key) // MEMORY entry, evicted by the heal below

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	h.push("cache-newkey", parked(entered, release, func(_ []byte) helper.Result {
		return helper.Result{Code: 0}
	}))

	const leader, rider = "yasyf-home:arc:Default", "yasyf-home:arc:Work"
	done := make(chan error, 2)
	go func() {
		_, err := c.Put(ctx, leader, key, time.Minute)
		done <- err
	}()
	<-entered // the leader's heal is parked in cache-newkey
	go func() {
		_, err := c.Put(ctx, rider, key, time.Minute)
		done <- err
	}()
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("Put across the heal: %v", err)
		}
	}

	if c.Degraded() {
		t.Fatalf("the heal must leave the cache Enclave-wrapped")
	}
	// Observe the entries map directly, before any Get can lazily evict: the
	// heal itself must have dropped the stale MEMORY entry while sparing the
	// new-epoch Puts.
	cur := c.state.Load()
	c.mu.Lock()
	if _, ok := c.entries[endpoint]; ok {
		t.Errorf("the pre-heal MEMORY entry %s survived the heal-time eviction", endpoint)
	}
	for _, id := range []string{leader, rider} {
		e, ok := c.entries[id]
		if !ok {
			t.Errorf("entry %s missing after the heal it rode", id)
			continue
		}
		if e.ep != cur {
			t.Errorf("entry %s published under a stale epoch", id)
		}
	}
	c.mu.Unlock()
	if got := h.count("cache-newkey"); got != 3 {
		t.Fatalf("cache-newkey calls = %d, want 3 (open + one refused probe + one shared heal)", got)
	}
	mustMiss(t, c, endpoint)
	if got := h.count("cache-unwrap"); got != 0 {
		t.Fatalf("cache-unwrap calls = %d, want 0 (the evicted entry must not re-exec the helper)", got)
	}
	mustGet(t, c, leader, key)
	mustGet(t, c, rider, key)
}

// TestKeyCacheOverTheSignedHelperBridge keeps the seam honest against the real
// helper.Bridge, round-tripping a key through an executable fake keyhelper.
func TestKeyCacheOverTheSignedHelperBridge(t *testing.T) {
	binary := writeFakeCacheHelper(t)
	c, err := Open(context.Background(), helper.Bridge{Binary: binary})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := c.Close(context.Background()); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	key := testKey()
	mustPut(t, c, endpoint, key)
	mustGet(t, c, endpoint, key)
	c.mu.Lock()
	blob := c.entries[endpoint].blob
	c.mu.Unlock()
	if bytes.Equal(blob, key) {
		t.Fatalf("the stored blob must not be the raw key")
	}
}

// writeFakeCacheHelper writes an executable fake keyhelper speaking the cache-*
// contract: newkey/dropkey exit 0, wrap/unwrap XOR stdin to stdout via perl.
func writeFakeCacheHelper(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "cookiesync-keyhelper")
	body := `#!/bin/sh
case "$1" in
cache-newkey|cache-dropkey)
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
`
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write fake cache helper: %v", err)
	}
	return binary
}

func TestNewLabelIsFreshHex(t *testing.T) {
	a, err := newLabel()
	if err != nil {
		t.Fatalf("newLabel: %v", err)
	}
	b, err := newLabel()
	if err != nil {
		t.Fatalf("newLabel: %v", err)
	}
	if len(a) != 16 || strings.Trim(a, "0123456789abcdef") != "" {
		t.Fatalf("label %q is not 16 hex chars", a)
	}
	if a == b {
		t.Fatalf("labels must be random, got %q twice", a)
	}
}
