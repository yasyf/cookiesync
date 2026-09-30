package daemon

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/auth"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
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
