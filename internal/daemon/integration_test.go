package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite" // register the sqlite driver for the test store

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/state"
)

// v24Schema is a Chrome v24 cookie store schema, enough for a real extract/apply/
// get_cookies round-trip against an ephemeral SQLite file.
const v24Schema = `
CREATE TABLE cookies (
    creation_utc INTEGER NOT NULL,
    host_key TEXT NOT NULL,
    top_frame_site_key TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    encrypted_value BLOB NOT NULL,
    path TEXT NOT NULL,
    expires_utc INTEGER NOT NULL,
    is_secure INTEGER NOT NULL,
    is_httponly INTEGER NOT NULL,
    last_access_utc INTEGER NOT NULL,
    has_expires INTEGER NOT NULL,
    is_persistent INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    samesite INTEGER NOT NULL,
    source_scheme INTEGER NOT NULL,
    source_port INTEGER NOT NULL,
    last_update_utc INTEGER NOT NULL,
    source_type INTEGER NOT NULL,
    has_cross_site_ancestor INTEGER NOT NULL
);
CREATE UNIQUE INDEX cookies_unique_index ON cookies(
    host_key, top_frame_site_key, has_cross_site_ancestor, name, path, source_scheme, source_port
);
`

// chromeStoreUnderHome points HOME at a temp dir and creates an empty Chrome v24
// cookie store for the Default profile there, so cookie.Lookup("chrome") resolves to
// it. It returns the chrome Browser the handlers will resolve.
func chromeStoreUnderHome(t *testing.T) cookie.Browser {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	browser, err := cookie.Lookup("chrome")
	if err != nil {
		t.Fatalf("lookup chrome: %v", err)
	}
	addChromeProfileStore(t, browser, "Default")
	return browser
}

// addChromeProfileStore creates an empty Chrome v24 cookie store for profile under
// the browser's (already HOME-redirected) profile root.
func addChromeProfileStore(t *testing.T, browser cookie.Browser, profile string) {
	t.Helper()
	if err := os.MkdirAll(browser.ProfileDir(profile), 0o700); err != nil {
		t.Fatalf("mkdir profile: %v", err)
	}
	db, err := sql.Open("sqlite", browser.CookiesDB(profile))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(v24Schema); err != nil {
		t.Fatalf("schema: %v", err)
	}
}

// TestGetCookiesMergesURLsFromCachedKey proves get_cookies, against a real store and a
// warm cache, decrypts and host-filters each url, unions the result, and emits the
// frozen {"cookies": [...]} wire shape — one cached-key decrypt, no prompt, no extra
// ssh. Two distinct hosts are seeded; a two-url call returns both.
func TestGetCookiesMergesURLsFromCachedKey(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))

	// Seed the store with two cookies on two hosts via the real apply path.
	seed := []cookie.Cookie{
		{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, IsSecure: true, SourceScheme: 2, SourcePort: 443},
		{HostKey: "api.example.com", Name: "tok", Value: "xyz", Path: "/", LastUpdateUTC: 13_350_000_000_000_001, SameSite: 1, IsSecure: true, SourceScheme: 2, SourcePort: 443},
	}
	if _, err := cookie.Apply(ctx, seed, browser, "Default", key); err != nil {
		t.Fatalf("seed apply: %v", err)
	}

	cache := newFakeCache()
	st := stateWith("me@laptop", "")
	fakeMesh(t, "me@laptop")
	d := New(&fakeConsent{}, cache, nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Default"), []byte(key), 0)

	got, err := d.handleGetCookies(ctx, map[string]any{
		"browser": "chrome",
		"urls":    []any{"https://x.com/", "https://api.example.com/"},
	})
	if err != nil {
		t.Fatalf("handleGetCookies: %v", err)
	}
	cookies := wireCookieNames(t, got)
	if len(cookies) != 2 || cookies["sid"].Value != "abc" || cookies["tok"].Value != "xyz" {
		t.Fatalf("get_cookies merged set = %+v, want sid=abc tok=xyz", cookies)
	}
	if cookies["sid"].HostKey != "x.com" || cookies["tok"].HostKey != "api.example.com" {
		t.Fatalf("host keys not preserved: %+v", cookies)
	}
}

// TestGetCookiesHostFilters proves get_cookies returns only the cookies the browser
// would send to the requested host — a single-url call for one host omits the other.
func TestGetCookiesHostFilters(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	seed := []cookie.Cookie{
		{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 1, IsSecure: true, SourceScheme: 2, SourcePort: 443},
		{HostKey: "other.com", Name: "nope", Value: "no", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 1, IsSecure: true, SourceScheme: 2, SourcePort: 443},
	}
	if _, err := cookie.Apply(ctx, seed, browser, "Default", key); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	cache := newFakeCache()
	fakeMesh(t, "me@laptop")
	d := New(&fakeConsent{}, cache, nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: stateWith("me@laptop", "")}, fixedState{st: stateWith("me@laptop", "")})
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Default"), []byte(key), 0)

	got, err := d.handleGetCookies(ctx, map[string]any{"browser": "chrome", "url": "https://x.com/"})
	if err != nil {
		t.Fatalf("handleGetCookies: %v", err)
	}
	cookies := wireCookieNames(t, got)
	if _, ok := cookies["nope"]; ok {
		t.Fatalf("get_cookies leaked the other host's cookie: %+v", cookies)
	}
	if _, ok := cookies["sid"]; !ok {
		t.Fatalf("get_cookies dropped the requested host's cookie: %+v", cookies)
	}
}

// TestExtractApplyRoundTripWireContract proves the peer-facing extract/apply pair: a
// warm cache extract emits {"cookies": [...]} for the WHOLE profile (not host-filtered),
// and an apply of a wire array writes the rows back and reports {"applied": n}. extract
// uses a real engine over the same store so the digest is recorded.
func TestExtractApplyRoundTripWireContract(t *testing.T) {
	ctx := context.Background()
	chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	cache := newFakeCache()
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Default"), []byte(key), 0)
	st := stateWith("me@laptop", "")
	fakeMesh(t, "me@laptop")
	d := New(&fakeConsent{key: key}, cache, newRealEngine(t, cache), staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	// Apply two cookies via the frozen wire array.
	in := []cookie.WireCookie{
		cookie.ToWire(cookie.Cookie{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, SourceScheme: 2, SourcePort: 443}),
		cookie.ToWire(cookie.Cookie{HostKey: "y.com", Name: "tok", Value: "xyz", Path: "/", LastUpdateUTC: 13_350_000_000_000_001, SameSite: 1, SourceScheme: 2, SourcePort: 443}),
	}
	applyRes, err := d.handleApply(ctx, map[string]any{"browser": "chrome", "cookies": wireArrayToAny(t, in)})
	if err != nil {
		t.Fatalf("handleApply: %v", err)
	}
	if got := marshalResult(t, applyRes); got != `{"applied":2}` {
		t.Fatalf("apply = %s, want {\"applied\":2}", got)
	}

	// Extract returns the whole profile (both hosts), undecorated by a url filter.
	extractRes, err := d.handleExtract(ctx, map[string]any{"browser": "chrome"})
	if err != nil {
		t.Fatalf("handleExtract: %v", err)
	}
	cookies := wireCookieNames(t, extractRes)
	if len(cookies) != 2 || cookies["sid"].Value != "abc" || cookies["tok"].Value != "xyz" {
		t.Fatalf("extract = %+v, want sid=abc tok=xyz", cookies)
	}
}

// TestApplySerializesPerEndpoint proves concurrent applies to the SAME endpoint queue
// behind its apply lock — the anti-echo digest record and store write never
// interleave, so the recorded digest always matches the store's final content.
func TestApplySerializesPerEndpoint(t *testing.T) {
	ctx := context.Background()
	chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	fakeMesh(t, "me@laptop")
	cache := newFakeCache()
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Default"), []byte(key), 0)
	st := stateWith("me@laptop", "")
	recorder := &countingRecorder{inner: engine.NewDigestRecorder(), hold: 20 * time.Millisecond}
	d := New(&fakeConsent{}, cache, engine.New(nil, cache, nil, recorder), staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	payload := wireArrayToAny(t, []cookie.WireCookie{
		cookie.ToWire(cookie.Cookie{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, SourceScheme: 2, SourcePort: 443}),
	})
	const n = 4
	type outcome struct {
		res any
		err error
	}
	done := make(chan outcome, n)
	for range n {
		go func() {
			res, err := d.handleApply(ctx, map[string]any{"browser": "chrome", "cookies": payload})
			done <- outcome{res: res, err: err}
		}()
	}
	for range n {
		out := <-done
		if out.err != nil {
			t.Errorf("apply: %v", out.err)
			continue
		}
		if got := marshalResult(t, out.res); got != `{"applied":1}` {
			t.Errorf("apply = %s, want {\"applied\":1}", got)
		}
	}
	if got := recorder.peak.Load(); got != 1 {
		t.Errorf("peak concurrent same-endpoint applies = %d, want 1 (apply must serialize per endpoint)", got)
	}
}

// TestApplyDistinctEndpointsOverlap proves the apply lock is per endpoint: applies to
// two different profiles are mid-write at the same moment, so one busy store never
// queues the rest of the fleet.
func TestApplyDistinctEndpointsOverlap(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	addChromeProfileStore(t, browser, "Work")
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	fakeMesh(t, "me@laptop")
	cache := newFakeCache()
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Default"), []byte(key), 0)
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Work"), []byte(key), 0)
	st := stateWith("me@laptop", "")
	arrived := make(chan string, 2)
	release := make(chan struct{})
	recorder := &meetRecorder{inner: engine.NewDigestRecorder(), arrived: arrived, release: release}
	d := New(&fakeConsent{}, cache, engine.New(nil, cache, nil, recorder), staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	payload := wireArrayToAny(t, []cookie.WireCookie{
		cookie.ToWire(cookie.Cookie{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, SourceScheme: 2, SourcePort: 443}),
	})
	done := make(chan error, 2)
	for _, profile := range []string{"Default", "Work"} {
		go func() {
			_, err := d.handleApply(ctx, map[string]any{"browser": "chrome", "profile": profile, "cookies": payload})
			done <- err
		}()
	}
	for i := range 2 {
		select {
		case <-arrived:
		case <-time.After(2 * time.Second):
			t.Fatalf("only %d of 2 distinct-endpoint applies were mid-write concurrently", i)
		}
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Errorf("apply: %v", err)
		}
	}
}

// convergeFixture wires a daemon whose engine converges one warm local endpoint
// (me@laptop:chrome:Default) against one canned remote peer, parking every
// RecordApplied at a rendezvous — so a test can hold the converge pass mid-critical-
// section, inside the endpoint's apply lock, and probe what a concurrent apply does.
type convergeFixture struct {
	d       *Daemon
	cache   *fakeCache
	key     cookie.AesKey
	arrived chan string
	release chan struct{}
	localID string
}

func newConvergeFixture(t *testing.T) *convergeFixture {
	t.Helper()
	ctx := context.Background()
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	fakeMesh(t, "me@laptop")
	cache := newFakeCache()
	localEP := state.Endpoint{Host: "me@laptop", Browser: "chrome", Profile: "Default"}
	peerEP := state.Endpoint{Host: "you@desktop", Browser: "chrome", Profile: "Default"}
	localID := string(localEP.ID())
	_ = cache.Put(ctx, localID, []byte(key), 0)
	store := &fakeStore{
		withLock: func(_ context.Context, fn func() error) error { return fn() },
		registry: newRegistry(localEP, peerEP),
	}
	runner := &recordingRunner{byMethod: map[string]string{
		"rpc extract": peerExtractReply(t, cookie.Cookie{HostKey: "x.com", Name: "sid", Value: "peer", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, SourceScheme: 2, SourcePort: 443}),
		"rpc apply":   `{"applied":1}`,
	}}
	arrived := make(chan string, 4)
	release := make(chan struct{})
	recorder := &meetRecorder{inner: engine.NewDigestRecorder(), arrived: arrived, release: release}
	st := stateWith("me@laptop", "")
	eng := engine.New(store, cache, runner, recorder)
	d := New(&fakeConsent{}, cache, eng, staticProbe(SessionSnapshot{}), runner, fixedState{st: st}, fixedState{st: st})
	return &convergeFixture{d: d, cache: cache, key: key, arrived: arrived, release: release, localID: localID}
}

// holdConvergeMidLocalWrite starts a sync pass and blocks until the converge is parked
// inside the local endpoint's apply lock, mid-RecordApplied. The returned channel
// carries the pass's error once fx.release is closed.
func (fx *convergeFixture) holdConvergeMidLocalWrite(ctx context.Context, t *testing.T) chan error {
	t.Helper()
	syncDone := make(chan error, 1)
	go func() {
		_, err := fx.d.handleSync(ctx, map[string]any{})
		syncDone <- err
	}()
	select {
	case ep := <-fx.arrived:
		if ep != fx.localID {
			t.Fatalf("converge first recorded %s, want the local endpoint %s", ep, fx.localID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("converge pass never reached its local write")
	}
	return syncDone
}

// TestConvergeLocalWriteSerializesWithApply proves a converge pass's local store write
// and a peer-driven apply for the SAME endpoint hold one mutex: while the converge is
// parked inside the endpoint's critical section, a concurrent apply queues outside it
// instead of interleaving its digest record with the in-flight write.
func TestConvergeLocalWriteSerializesWithApply(t *testing.T) {
	ctx := context.Background()
	chromeStoreUnderHome(t)
	fx := newConvergeFixture(t)
	syncDone := fx.holdConvergeMidLocalWrite(ctx, t)

	payload := wireArrayToAny(t, []cookie.WireCookie{
		cookie.ToWire(cookie.Cookie{HostKey: "y.com", Name: "tok", Value: "xyz", Path: "/", LastUpdateUTC: 13_350_000_000_000_001, SameSite: 1, SourceScheme: 2, SourcePort: 443}),
	})
	applyDone := make(chan error, 1)
	go func() {
		_, err := fx.d.handleApply(ctx, map[string]any{"browser": "chrome", "cookies": payload})
		applyDone <- err
	}()

	select {
	case ep := <-fx.arrived:
		t.Fatalf("apply for %s entered its critical section while the converge pass held the same endpoint's lock", ep)
	case <-time.After(300 * time.Millisecond):
	}

	close(fx.release)
	if err := <-syncDone; err != nil {
		t.Errorf("sync: %v", err)
	}
	if err := <-applyDone; err != nil {
		t.Errorf("apply: %v", err)
	}
}

// TestConvergeLocalWriteOverlapsDistinctApply proves the converge/apply lock is per
// endpoint: while a converge pass holds one endpoint's lock mid-write, an apply for a
// DIFFERENT endpoint enters its own critical section immediately, so one busy store
// never queues the rest of the fleet.
func TestConvergeLocalWriteOverlapsDistinctApply(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	addChromeProfileStore(t, browser, "Work")
	fx := newConvergeFixture(t)
	workID := endpointID("me@laptop", "chrome", "Work")
	_ = fx.cache.Put(ctx, workID, []byte(fx.key), 0)
	syncDone := fx.holdConvergeMidLocalWrite(ctx, t)

	payload := wireArrayToAny(t, []cookie.WireCookie{
		cookie.ToWire(cookie.Cookie{HostKey: "y.com", Name: "tok", Value: "xyz", Path: "/", LastUpdateUTC: 13_350_000_000_000_001, SameSite: 1, SourceScheme: 2, SourcePort: 443}),
	})
	applyDone := make(chan error, 1)
	go func() {
		_, err := fx.d.handleApply(ctx, map[string]any{"browser": "chrome", "profile": "Work", "cookies": payload})
		applyDone <- err
	}()

	select {
	case ep := <-fx.arrived:
		if ep != workID {
			t.Fatalf("second critical-section entry was %s, want %s", ep, workID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("distinct-endpoint apply queued behind the converge pass's lock; want overlap")
	}

	close(fx.release)
	if err := <-syncDone; err != nil {
		t.Errorf("sync: %v", err)
	}
	if err := <-applyDone; err != nil {
		t.Errorf("apply: %v", err)
	}
}

// TestColdExtractsSingleFlightOneConsent proves N concurrent extracts against a cold
// cache collapse into one primeAuth flight: the leader holds the consent prompt while
// the rest join its flight, so exactly one prompt fires and one Put seeds the cache —
// every caller extracts with the shared key.
func TestColdExtractsSingleFlightOneConsent(t *testing.T) {
	ctx := context.Background()
	chromeStoreUnderHome(t)
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	const n = 4
	consent := &gateConsent{
		key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts")),
		// entered holds one slot per caller so a regression that prompts more than
		// once fails on the calls counter instead of deadlocking the extra prompts.
		entered: make(chan struct{}, n),
		release: make(chan struct{}),
	}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	done := make(chan error, n)
	for range n {
		go func() {
			_, err := d.handleExtract(ctx, map[string]any{"browser": "chrome"})
			done <- err
		}()
	}

	<-consent.entered
	// Every caller has probed the cold cache once gets reaches n; the leader is held
	// mid-prompt. A straggler that misses the flight starts a fresh one, whose cache
	// re-probe returns the leader's key without a second prompt or Put — no settle
	// sleep needed.
	waitFor(t, func() bool { return cache.getCalls() >= n })
	close(consent.release)

	for range n {
		if err := <-done; err != nil {
			t.Errorf("extract: %v", err)
		}
	}
	if got := consent.calls.Load(); got != 1 {
		t.Errorf("consent prompts = %d, want 1 (concurrent cold extracts must share one flight)", got)
	}
	if got := cache.putCalls(); got != 1 {
		t.Errorf("cache puts = %d, want 1 (waiters must reuse the leader's key)", got)
	}
}

// TestPrimeAuthStragglerAfterWarmCacheDoesNotReprompt proves a fresh flight over an
// already-warm cache returns the cached key without prompting or re-putting — the
// cache re-probe that closes the double-prompt window a straggler opens by starting
// its flight just after the previous one completed.
func TestPrimeAuthStragglerAfterWarmCacheDoesNotReprompt(t *testing.T) {
	ctx := context.Background()
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	_ = cache.Put(ctx, endpointID("me@laptop", "chrome", "Default"), []byte(consent.key), 0)

	key, err := d.primeAuth(ctx, "chrome", "Default", consentReason)
	if err != nil {
		t.Fatalf("primeAuth: %v", err)
	}
	if string(key) != string(consent.key) {
		t.Fatalf("primeAuth returned the wrong key")
	}
	if len(consent.promptedReasons) != 0 {
		t.Fatalf("a flight over a warm cache must not prompt, got %v", consent.promptedReasons)
	}
	if got := cache.putCalls(); got != 1 {
		t.Fatalf("cache puts = %d, want 1 (the seed only; the re-probe must not re-put)", got)
	}
}

// TestPrimeAuthFlightSurvivesLeaderCancel proves the flight runs detached from the
// leader's ctx: a leader whose caller disconnects mid-consent returns its own
// ctx.Err() while the prompt keeps running, and a surviving waiter still gets the key
// from that same flight — one prompt, one Put.
func TestPrimeAuthFlightSurvivesLeaderCancel(t *testing.T) {
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	consent := &gateConsent{
		key:     cookie.DeriveKey(cookie.SafeStorageKey("peanuts")),
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := d.primeAuth(leaderCtx, "chrome", "Default", consentReason)
		leaderDone <- err
	}()
	<-consent.entered

	waiterDone := make(chan error, 1)
	go func() {
		key, err := d.primeAuth(context.Background(), "chrome", "Default", consentReason)
		if err == nil && string(key) != string(consent.key) {
			err = errors.New("waiter got the wrong key")
		}
		waiterDone <- err
	}()

	cancelLeader()
	select {
	case err := <-leaderDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled leader = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled leader stayed parked behind its own flight")
	}

	close(consent.release)
	if err := <-waiterDone; err != nil {
		t.Fatalf("waiter after leader cancel: %v", err)
	}
	if got := consent.calls.Load(); got != 1 {
		t.Errorf("consent prompts = %d, want 1 (the flight must survive the leader)", got)
	}
	if got := cache.putCalls(); got != 1 {
		t.Errorf("cache puts = %d, want 1 (the surviving flight must seed the cache)", got)
	}
}

// TestPrimeAuthCanceledWaiterReturnsWhileFlightContinues proves a waiter whose own
// conn dies is not parked behind the leader's prompt: it returns its ctx.Err()
// immediately while the flight runs on and still primes the cache for the survivors.
func TestPrimeAuthCanceledWaiterReturnsWhileFlightContinues(t *testing.T) {
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	consent := &gateConsent{
		key:     cookie.DeriveKey(cookie.SafeStorageKey("peanuts")),
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	leaderDone := make(chan error, 1)
	go func() {
		_, err := d.primeAuth(context.Background(), "chrome", "Default", consentReason)
		leaderDone <- err
	}()
	<-consent.entered

	waiterCtx, cancelWaiter := context.WithCancel(context.Background())
	cancelWaiter()
	waiterDone := make(chan error, 1)
	go func() {
		_, err := d.primeAuth(waiterCtx, "chrome", "Default", consentReason)
		waiterDone <- err
	}()
	select {
	case err := <-waiterDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled waiter = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled waiter stayed parked behind the in-flight prime")
	}

	close(consent.release)
	if err := <-leaderDone; err != nil {
		t.Fatalf("leader: %v", err)
	}
	if got := consent.calls.Load(); got != 1 {
		t.Errorf("consent prompts = %d, want 1 (the canceled waiter must not re-prompt)", got)
	}
	if _, ok, _ := cache.Get(context.Background(), endpointID("me@laptop", "chrome", "Default")); !ok {
		t.Errorf("the flight must still prime the cache after a waiter cancel")
	}
}

// TestDistinctEndpointPrimesSerializeThePrompt proves promptGate: N concurrent cold
// primes for DISTINCT endpoints each prompt once, but at most one consent sheet is in
// flight at a time — the cross-endpoint serialization the old global dispatch mutex
// provided, now scoped to just the interactive prompt.
func TestDistinctEndpointPrimesSerializeThePrompt(t *testing.T) {
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	consent := &countingConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts")), hold: 20 * time.Millisecond}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	profiles := []string{"Default", "Work", "P3", "P4"}
	done := make(chan error, len(profiles))
	for _, profile := range profiles {
		go func() {
			_, err := d.primeAuth(context.Background(), "chrome", profile, consentReason)
			done <- err
		}()
	}
	for range profiles {
		if err := <-done; err != nil {
			t.Errorf("primeAuth: %v", err)
		}
	}
	if got := int(consent.calls.Load()); got != len(profiles) {
		t.Errorf("consent prompts = %d, want %d (one per distinct endpoint)", got, len(profiles))
	}
	if got := consent.peak.Load(); got != 1 {
		t.Errorf("peak concurrent prompts = %d, want 1 (distinct-endpoint primes must serialize the sheet)", got)
	}
}

// TestRequestConsentAnswersWhileRoutedReleaseInFlight is the same-host routed-consent
// cycle regression for promptGate: while this host's own outbound routed release is
// mid-ssh (a hard route from an attended host), an inbound request_consent must still
// reach the Touch ID prompt — the gate is never held across routedRelease.
func TestRequestConsentAnswersWhileRoutedReleaseInFlight(t *testing.T) {
	me := currentUser(t)
	self := "me@laptop"
	peer := "you@desktop"
	endpoint := endpointID(self, "chrome", "Default")
	nonce := "gate-nonce"

	fakeMesh(t, self, peer)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	inner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_consent": approvedReply(t, nonce, endpoint)},
	}
	runner := &gatedRunner{inner: inner, match: "request_consent", arrived: make(chan struct{}, 1), release: make(chan struct{})}
	st := stateWith(self, peer, stateEndpoint(peer, "chrome", "Default"))
	st.ConsentRouteHard = true
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(me)), runner, fixedState{st: st}, fixedState{st: st})
	pinnedNonce(d, nonce)

	primeDone := make(chan error, 1)
	go func() {
		_, err := d.primeAuth(context.Background(), "chrome", "Default", consentReason)
		primeDone <- err
	}()
	<-runner.arrived

	inboundDone := make(chan error, 1)
	go func() {
		got, err := d.handleRequestConsent(context.Background(), map[string]any{
			"browser": "chrome", "nonce": "n2", "endpoint": "them@host:chrome:Work",
		})
		if err == nil && marshalResult(t, got) != `{"endpoint":"them@host:chrome:Work","nonce":"n2","status":"approved"}` {
			err = errors.New("inbound consent did not approve: " + marshalResult(t, got))
		}
		inboundDone <- err
	}()
	select {
	case err := <-inboundDone:
		if err != nil {
			t.Fatalf("inbound request_consent mid-routed-release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("inbound request_consent blocked behind the outbound routed release — promptGate is held across ssh")
	}

	close(runner.release)
	if err := <-primeDone; err != nil {
		t.Fatalf("routed prime: %v", err)
	}
}

// gatedRunner parks any Run whose command contains match — send on arrived, wait for
// release — so a test holds an outbound ssh mid-flight; everything else passes through
// to inner.
type gatedRunner struct {
	inner   *recordingRunner
	match   string
	arrived chan struct{}
	release chan struct{}
}

func (r *gatedRunner) Run(ctx context.Context, target, cmd string, stdin []byte) (string, error) {
	if strings.Contains(cmd, r.match) {
		r.arrived <- struct{}{}
		<-r.release
	}
	return r.inner.Run(ctx, target, cmd, stdin)
}

// waitFor polls cond every 5ms, failing the test when it does not hold within 2s.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("condition not reached within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// wireCookieNames decodes a {"cookies": [...]} handler result into a by-name map of
// wire cookies, asserting the envelope shape.
func wireCookieNames(t *testing.T, result any) map[string]cookie.WireCookie {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var envelope struct {
		Cookies []cookie.WireCookie `json:"cookies"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("decode cookies envelope: %v (%s)", err, data)
	}
	out := map[string]cookie.WireCookie{}
	for _, c := range envelope.Cookies {
		out[c.Name] = c
	}
	return out
}

// peerExtractReply renders the frozen {"cookies": [...]} reply a peer's rpc extract
// streams back, carrying the given cookies as wire records.
func peerExtractReply(t *testing.T, cookies ...cookie.Cookie) string {
	t.Helper()
	wire := make([]cookie.WireCookie, len(cookies))
	for i, c := range cookies {
		wire[i] = cookie.ToWire(c)
	}
	data, err := json.Marshal(map[string]any{"cookies": wire})
	if err != nil {
		t.Fatalf("marshal extract reply: %v", err)
	}
	return string(data)
}

// wireArrayToAny renders a wire-cookie slice into the []any map-tree a JSON request
// param carries, so a handler param matches what the transport delivers.
func wireArrayToAny(t *testing.T, in []cookie.WireCookie) []any {
	t.Helper()
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal wire array: %v", err)
	}
	var out []any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode wire array: %v", err)
	}
	return out
}

// newRealEngine builds an engine whose only role in these handler tests is to carry the
// shared anti-echo recorder (handleApply records through engine.Recorder()). extract/
// apply do not call Sync/Reconcile, so the store and ssh runner are unused.
func newRealEngine(t *testing.T, cache *fakeCache) *engine.Engine {
	t.Helper()
	return engine.New(nil, cache, nil, engine.NewDigestRecorder())
}
