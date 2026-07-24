package daemon

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/auth"
	"github.com/yasyf/cookiesync/internal/cache"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/helper"
	"github.com/yasyf/synckit/authkit"
	synckit "github.com/yasyf/synckit/rpc"
	"github.com/yasyf/synckit/syncservice"
)

// TestDispatcherRoutesEveryMethod proves the dispatcher binds every method in the
// frozen set to a handler — an unknown method is the only "unknown method" error. Each
// known method is dispatched with a benign params map and asserted NOT to come back as
// unknown; whether the handler itself then succeeds or errors is exercised elsewhere,
// here we only prove routing.
func TestDispatcherRoutesEveryMethod(t *testing.T) {
	me := currentUser(t)
	consent := &fakeConsent{}
	st := stateWith("me@laptop", "")
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(me)), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	dispatcher := d.Dispatcher()

	// Every frozen method must route to a handler. Some reach the nil engine, the
	// store, or the cookie layer and come back as a handler error (or a panic the
	// dispatcher recovers into an error response) — that still proves the method
	// routed. The one thing none may return is "unknown method".
	methods := append([]string{
		"whoami", "auth_status", "request_consent",
		"extract", "apply", "sync", "reconcile", "prime_auth", "get_cookies",
	}, syncservice.AllMethods...)
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			resp := dispatcher.Dispatch(context.Background(), request(method))
			if !resp.OK && strings.Contains(resp.Error, "unknown method") {
				t.Fatalf("method %q did not route: %s", method, resp.Error)
			}
		})
	}

	resp := dispatcher.Dispatch(context.Background(), request("does_not_exist"))
	if resp.OK || !strings.Contains(resp.Error, "unknown method") {
		t.Fatalf("unknown method should be rejected, got ok=%v err=%q", resp.OK, resp.Error)
	}
}

// TestBuildOpensAndDropsTheEnclaveKey proves the daemon's Build opens the per-boot
// Secure-Enclave key at startup (one cache-newkey with a fresh label) and the returned
// closer drops it on shutdown (cache-dropkey with the SAME label), so a leaked wrapped
// blob is unrecoverable off-box. It also proves the cache is emptied on shutdown.
func TestBuildOpensAndDropsTheEnclaveKey(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	binary, logPath := writeFakeCacheHelper(t)
	t.Setenv(authkit.HelperEnvVar, binary)
	fakeMesh(t, "me@laptop")
	ctx := context.Background()

	_, keyCache, err := build(ctx, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// A key cached after startup is gone after shutdown (the closer evicts the cache).
	id := endpointID("me@laptop", "chrome", "Default")
	if _, err := keyCache.Put(ctx, id, []byte("k"), 5_000_000_000); err != nil {
		t.Fatalf("cache Put: %v", err)
	}
	if err := keyCache.Close(ctx); err != nil {
		t.Fatalf("closer: %v", err)
	}
	if _, ok, _ := keyCache.Get(ctx, id); ok {
		t.Fatalf("cache not evicted on shutdown")
	}

	log := readLog(t, logPath)
	newkey, dropkey := "", ""
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		switch {
		case strings.HasPrefix(line, "cache-newkey "):
			newkey = strings.TrimPrefix(line, "cache-newkey ")
		case strings.HasPrefix(line, "cache-dropkey "):
			dropkey = strings.TrimPrefix(line, "cache-dropkey ")
		}
	}
	if newkey == "" {
		t.Fatalf("Build did not open the Enclave key (no cache-newkey); log:\n%s", log)
	}
	if dropkey == "" {
		t.Fatalf("shutdown did not drop the Enclave key (no cache-dropkey); log:\n%s", log)
	}
	if newkey != dropkey {
		t.Fatalf("dropped label %q != opened label %q (per-boot key not cleaned up)", dropkey, newkey)
	}
}

// TestBuildDegradedPresenceStartsWithMemoryCache proves a cache-newkey presence
// refusal (helper exit 3) does not kill the daemon: the open warns exactly once —
// carrying the helper's OSStatus diagnostic — and serves degraded, with cached keys
// round-tripping in process memory and the helper touched only for newkey probes.
func TestBuildDegradedPresenceStartsWithMemoryCache(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	binary, logPath := writeStubHelper(t, 3, "keyhelper: cache-newkey failed: interaction not allowed (OSStatus -25308)")
	t.Setenv(authkit.HelperEnvVar, binary)
	fakeMesh(t, "me@laptop")

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx := context.Background()
	_, keyCache, err := build(ctx, nil)
	if err != nil {
		t.Fatalf("Build with a presence-unavailable helper must degrade, got %v", err)
	}

	const warn = "Secure Enclave presence unavailable — screen locked or no user present; caching keys in process memory until the keybag unlocks"
	if got := strings.Count(logs.String(), warn); got != 1 {
		t.Fatalf("degraded Build must WARN exactly once, got %d in:\n%s", got, logs.String())
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "OSStatus -25308") {
		t.Fatalf("the WARN must log at level WARN with the helper diagnostic, got:\n%s", logs.String())
	}

	id := endpointID("me@laptop", "chrome", "Default")
	if _, err := keyCache.Put(ctx, id, []byte("k"), 5*time.Minute); err != nil {
		t.Fatalf("cache Put on the degraded cache: %v", err)
	}
	if key, ok, err := keyCache.Get(ctx, id); err != nil || !ok || string(key) != "k" {
		t.Fatalf("cache Get = %q, %v, %v, want k true nil", key, ok, err)
	}
	if !keyCache.Degraded() {
		t.Fatalf("the cache must report Degraded while the keybag stays locked")
	}
	if err := keyCache.Close(ctx); err != nil {
		t.Fatalf("closer: %v", err)
	}
	if _, ok, _ := keyCache.Get(ctx, id); ok {
		t.Fatalf("cache not evicted on shutdown")
	}
	// The helper is touched only for newkey probes — the open probe plus the Put's
	// heal re-probe — never wrap/unwrap/dropkey while degraded.
	lines := strings.Split(strings.TrimSpace(readLog(t, logPath)), "\n")
	if len(lines) != 2 {
		t.Fatalf("a degraded open + one Put must probe the helper exactly twice, got:\n%s", readLog(t, logPath))
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "cache-newkey ") {
			t.Fatalf("a degraded session must touch the helper only for newkey probes, got:\n%s", readLog(t, logPath))
		}
	}
	if lines[0] != lines[1] {
		t.Fatalf("the heal re-probe must reuse the open probe's label, got:\n%s", readLog(t, logPath))
	}
}

// TestBuildNoEnclaveStaysFatal proves a genuine cache-newkey refusal (exit 2: no
// Secure Enclave or keygen misconfigured) still fails Build outright, surfacing the
// helper's stderr diagnostic — only the presence refusal degrades.
func TestBuildNoEnclaveStaysFatal(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	binary, _ := writeStubHelper(t, 2, "keyhelper: cache-newkey failed: no Secure Enclave (OSStatus -34018)")
	t.Setenv(authkit.HelperEnvVar, binary)
	fakeMesh(t, "me@laptop")

	d, closer, err := buildDaemon(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "cache-newkey exited 2") || !strings.Contains(err.Error(), "OSStatus -34018") {
		t.Fatalf("Build = %v, want the fatal exit-2 error carrying the helper stderr", err)
	}
	if d != nil || closer != nil {
		t.Fatalf("a fatal Build must return no daemon")
	}
}

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

// TestHandleAuthStatusBoundsWedgedProbeReportsLockedNote pins the fast path on the live
// locked/screen-shared incident: the session probe wedges, but a status read must never
// block the caller past its deadline. auth.StatusTimeout bounds the probe and a bounded-out
// probe reports the host locked — the degraded+locked OK-with-note reply the doctor renders
// healthy — rather than hanging into an i/o-timeout FAIL. Without the bound the handler
// would block on the never-done background context and the watchdog would fire.
func TestHandleAuthStatusBoundsWedgedProbeReportsLockedNote(t *testing.T) {
	fakeMesh(t, "me@laptop")
	restore := auth.StatusTimeout
	auth.StatusTimeout = 20 * time.Millisecond
	t.Cleanup(func() { auth.StatusTimeout = restore })

	// A probe that returns only when its context is cancelled — the wedged ioreg/netstat
	// exec.CommandContext the bound kills and unblocks.
	wedged := func(ctx context.Context) (SessionSnapshot, error) {
		<-ctx.Done()
		return SessionSnapshot{}, ctx.Err()
	}
	c := newFakeCache()
	c.degraded = true
	st := stateWith("me@laptop", "")
	d := New(&fakeConsent{}, c, nil, wedged, &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	type result struct {
		got any
		err error
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		got, err := d.handleAuthStatus(context.Background(), map[string]any{"browser": "chrome"})
		done <- result{got, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("handleAuthStatus must not fail on a wedged probe, got %v", r.err)
		}
		if marshalResult(t, r.got) != `{"authenticated":false,"degraded":true,"endpoint":"me@laptop:chrome:Default","keybag_locked":true}` {
			t.Fatalf("auth_status = %s, want the degraded+locked note reply", marshalResult(t, r.got))
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("handleAuthStatus took %v; auth.StatusTimeout must bound the probe near %v", elapsed, auth.StatusTimeout)
		}
		if c.getCalls() != 0 {
			t.Fatalf("cache Get called %d times after a probe timeout; the fallback must skip the cache read", c.getCalls())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handleAuthStatus hung on a wedged probe; auth.StatusTimeout did not bound it")
	}
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

// TestHandleAuthStatusUsesKeybagProbeNotTheFullProbe proves auth_status reads the
// ioreg-only keybag probe: the full probe (the one carrying the netstat screen-share leg)
// never runs, and a screen-shared-but-unlocked keybag reports keybag_locked:false.
func TestHandleAuthStatusUsesKeybagProbeNotTheFullProbe(t *testing.T) {
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")

	var fullProbeCalls, keybagCalls atomic.Int32
	fullProbe := func(_ context.Context) (SessionSnapshot, error) {
		fullProbeCalls.Add(1)
		// A locked verdict: were this probe wrongly used, keybag_locked would flip true.
		return SessionSnapshot{OnConsole: true, Locked: true}, nil
	}
	keybagProbe := func(_ context.Context) (SessionSnapshot, error) {
		keybagCalls.Add(1)
		snap := liveSession(currentUser(t))
		snap.ScreenShared = true
		return snap, nil
	}
	d := New(&fakeConsent{}, newFakeCache(), nil, fullProbe, &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	d.broker.KeybagProbe = keybagProbe

	got, err := d.handleAuthStatus(context.Background(), map[string]any{"browser": "chrome"})
	if err != nil {
		t.Fatalf("handleAuthStatus: %v", err)
	}
	if fullProbeCalls.Load() != 0 {
		t.Fatalf("auth_status ran the full probe %d times; it must read the keybag probe only (no netstat)", fullProbeCalls.Load())
	}
	if keybagCalls.Load() != 1 {
		t.Fatalf("auth_status ran the keybag probe %d times, want 1", keybagCalls.Load())
	}
	if want := `{"authenticated":false,"degraded":false,"endpoint":"me@laptop:chrome:Default","keybag_locked":false}`; marshalResult(t, got) != want {
		t.Fatalf("auth_status = %s, want %s (screen share must not lock the keybag)", marshalResult(t, got), want)
	}
}

// TestWhoamiReadsScreenShareFromTheFullProbe proves whoami still draws its screen-share
// signal from the full probe — only auth_status was moved to the keybag-only read.
func TestWhoamiReadsScreenShareFromTheFullProbe(t *testing.T) {
	me := currentUser(t)
	st := stateWith("me@laptop", "")
	full := liveSession(me)
	full.ScreenShared = true
	d := New(&fakeConsent{}, newFakeCache(), nil, staticProbe(full), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	// A keybag probe with no screen-share signal; whoami must not read it.
	d.broker.KeybagProbe = staticProbe(liveSession(me))

	got, err := d.handleWhoami(context.Background(), map[string]any{})
	if err != nil {
		t.Fatalf("handleWhoami: %v", err)
	}
	if m := got.(map[string]any); m["screen_shared"] != true {
		t.Fatalf("whoami screen_shared = %v, want true (from the full probe)", m["screen_shared"])
	}
}

// TestHandleAuthStatusMasksBoundedCacheReadAfterUnlockedProbe proves the masking fix: an
// unlocked keybag probe followed by a cache read that outruns auth.StatusTimeout reports
// degraded:true, authenticated:false, and keybag_locked:false — not a forced lock and not
// a raw RPC error.
func TestHandleAuthStatusMasksBoundedCacheReadAfterUnlockedProbe(t *testing.T) {
	fakeMesh(t, "me@laptop")
	restore := auth.StatusTimeout
	auth.StatusTimeout = 30 * time.Millisecond
	t.Cleanup(func() { auth.StatusTimeout = restore })

	st := stateWith("me@laptop", "")
	c := &blockingGetCache{fakeCache: newFakeCache()}
	c.degraded = true
	d := New(&fakeConsent{}, c, nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	d.broker.KeybagProbe = staticProbe(liveSession(currentUser(t)))

	done := make(chan any, 1)
	start := time.Now()
	go func() {
		got, err := d.handleAuthStatus(context.Background(), map[string]any{"browser": "chrome"})
		if err != nil {
			t.Errorf("handleAuthStatus must swallow the bounded-out read, got %v", err)
		}
		done <- got
	}()
	select {
	case got := <-done:
		if want := `{"authenticated":false,"degraded":true,"endpoint":"me@laptop:chrome:Default","keybag_locked":false}`; marshalResult(t, got) != want {
			t.Fatalf("auth_status = %s, want %s", marshalResult(t, got), want)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Fatalf("handleAuthStatus took %v; auth.StatusTimeout must bound the read", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handleAuthStatus hung on a blocking cache read")
	}
}

// TestConvergeMethodsShareOneExclusiveMutex proves every method that runs the
// flock-wrapped converge pass — sync, reconcile, and svc.reconcile — is
// registered exclusive: two passes never hold the store lock at once, whichever
// method drives them.
func TestConvergeMethodsShareOneExclusiveMutex(t *testing.T) {
	fakeMesh(t, "me@laptop")
	var concurrent, peak atomic.Int32
	store := &fakeStore{withLock: func(_ context.Context, fn func() error) error {
		n := concurrent.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		err := fn()
		concurrent.Add(-1)
		return err
	}}
	dispatcher := newConvergeDaemon(t, store, &fakeConsent{}).Dispatcher()

	var wg sync.WaitGroup
	for _, method := range []string{"sync", "reconcile", syncservice.MethodReconcile, "sync"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp := dispatcher.Dispatch(context.Background(), request(method)); !resp.OK {
				t.Errorf("dispatch %s: %s", method, resp.Error)
			}
		}()
	}
	wg.Wait()
	if got := peak.Load(); got != 1 {
		t.Errorf("peak concurrent converge passes = %d, want 1 (sync/reconcile must share the exclusive mutex)", got)
	}
}

// TestRequestConsentAnswersWhileSyncHoldsTheFlock is the same-host routed-consent
// cycle regression: request_consent must stay a concurrent handler, answering while a
// sync pass holds the exclusive mutex. A host mid-pass that could not approve consent
// would deadlock two hosts converging each other.
func TestRequestConsentAnswersWhileSyncHoldsTheFlock(t *testing.T) {
	fakeMesh(t, "me@laptop")
	entered := make(chan struct{})
	release := make(chan struct{})
	store := &fakeStore{withLock: func(_ context.Context, fn func() error) error {
		close(entered)
		<-release
		return fn()
	}}
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	dispatcher := newConvergeDaemon(t, store, consent).Dispatcher()

	syncDone := make(chan *synckit.Response, 1)
	go func() { syncDone <- dispatcher.Dispatch(context.Background(), request("sync")) }()
	<-entered

	consentDone := make(chan *synckit.Response, 1)
	go func() { consentDone <- dispatcher.Dispatch(context.Background(), request("request_consent")) }()
	select {
	case resp := <-consentDone:
		if !resp.OK {
			t.Errorf("request_consent mid-sync: %s", resp.Error)
		}
		if got := marshalResult(t, resp.Result); got != `{"endpoint":"e","nonce":"n","status":"approved"}` {
			t.Errorf("request_consent = %s, want the approved echo", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("request_consent blocked behind a mid-pass sync — the routed-consent cycle regressed")
	}

	close(release)
	if resp := <-syncDone; !resp.OK {
		t.Errorf("sync: %s", resp.Error)
	}
}

// newConvergeDaemon builds a daemon whose engine runs a real converge pass over the
// injected store, for dispatcher-level concurrency tests. The probe reports a live
// session so request_consent can approve locally.
func newConvergeDaemon(t *testing.T, store *fakeStore, consent cookie.Consent) *Daemon {
	t.Helper()
	cache := newFakeCache()
	st := stateWith("me@laptop", "")
	eng := engine.New(store, cache, &recordingRunner{}, engine.NewDigestRecorder())
	return New(consent, cache, eng, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
}

func request(method string) *synckit.Request {
	return &synckit.Request{Method: method, Params: map[string]any{
		"browser": "chrome", "url": "https://x.com", "nonce": "n", "endpoint": "e", "cookies": []any{},
	}}
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // path is a test-controlled temp file.
	if err != nil {
		// No log file means neither newkey nor dropkey ran; surface as empty so the
		// caller's assertions fail with a clear message.
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("read helper log %s: %v", path, err)
	}
	return string(data)
}

// writeFakeCacheHelper writes an executable fake cookiesync-keyhelper emulating the
// cache-* contract: cache-newkey / cache-dropkey are logged no-op exit-0s, and
// cache-wrap / cache-unwrap XOR stdin to stdout (binary-safe via perl). It returns the
// helper binary path and the log path so a test asserts the per-boot key lifecycle.
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
  exec /usr/bin/perl -0777 -pe 's/(.)/chr(ord($1)^0x5A)/ges'
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

// writeStubHelper writes a fake cookiesync-keyhelper that logs every invocation, then
// prints stderrMsg and exits with code — the cache-newkey refusal doubles (presence
// exit 3, no-Enclave exit 2) the Build degradation tests drive.
func writeStubHelper(t *testing.T, code int, stderrMsg string) (binary, logPath string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "cookiesync-keyhelper")
	logPath = filepath.Join(dir, "helper.log")
	body := fmt.Sprintf(`#!/bin/sh
printf '%%s %%s\n' "$1" "$2" >> %q
echo %q >&2
exit %d
`, logPath, stderrMsg, code)
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write stub helper: %v", err)
	}
	return binary, logPath
}
