package watch

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/state"
	synckitwatch "github.com/yasyf/synckit/watch"
)

// scriptedResolver returns digests from a script, advancing one per call and holding
// the last, so successive evaluations observe a self-echo (same digest) or a real
// change (a new one) on demand. It stands in for the real store fingerprint.
type scriptedResolver struct {
	mu      sync.Mutex
	digests []string
	calls   int
}

func (r *scriptedResolver) Resolve(_ context.Context, _ string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := r.digests[r.calls]
	if r.calls < len(r.digests)-1 {
		r.calls++
	}
	return d, nil
}

// fakeConverger records every local Sync call so a test asserts how many local
// converges a settle drove, and signals each one so the test can wait without sleeping.
type fakeConverger struct {
	mu     sync.Mutex
	calls  int
	origin []string
	fired  chan struct{}
	onSync func() // optional hook, run inside Sync to model the converge's own write
}

func newFakeConverger() *fakeConverger { return &fakeConverger{fired: make(chan struct{}, 16)} }

func (c *fakeConverger) Sync(_ context.Context, origin string) ([]engine.Result, error) {
	c.mu.Lock()
	c.calls++
	c.origin = append(c.origin, origin)
	hook := c.onSync
	c.mu.Unlock()
	if hook != nil {
		hook()
	}
	c.fired <- struct{}{}
	return nil, nil
}

func (c *fakeConverger) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *fakeConverger) setOnSync(fn func()) {
	c.mu.Lock()
	c.onSync = fn
	c.mu.Unlock()
}

// fakeRunner records every ssh peer notification so a test asserts the peer fan-out.
type fakeRunner struct {
	mu    sync.Mutex
	calls []string
}

func (r *fakeRunner) Run(_ context.Context, target, _ string, _ []byte) (string, error) {
	r.mu.Lock()
	r.calls = append(r.calls, target)
	r.mu.Unlock()
	return "", nil
}

func (r *fakeRunner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// newWiredEngine builds the real cookiesync watch composition — the scripted
// resolver, the real rpcNotifier (fake converger + fake runner), the real
// EngineRecorder — over the public synckit engine with a tiny debounce so OnEvent
// fires promptly. It returns the engine, the recorder the sync layer would record
// through, and the two recorders of effect.
func newWiredEngine(t *testing.T, resolver synckitwatch.Resolver[string], hosts []string) (*synckitwatch.Engine[string], EngineRecorder, *fakeConverger, *fakeRunner) {
	t.Helper()
	converger := newFakeConverger()
	runner := &fakeRunner{}
	notifier := &rpcNotifier{self: hosts[0], converger: converger, runner: runner}
	core := synckitwatch.NewEngine[string](resolver, notifier, endpointKey, time.Millisecond, hosts)
	return core, EngineRecorder{engine: core}, converger, runner
}

const epID = "me@laptop:chrome:Default"

// waitFor polls cond until true or the deadline, failing the test on timeout. The
// debounce is sub-millisecond, so a settle resolves well within the window.
func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// consistentlyZero asserts a counter stays zero across the debounce window plus
// slack, proving a suppressed event never fires after settling.
func consistentlyZero(t *testing.T, count func() int, what string) {
	t.Helper()
	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := count(); got != 0 {
			t.Fatalf("%s = %d, want 0 (event was not suppressed)", what, got)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestSelfInducedWriteIsSuppressed proves the anti-echo invariant (a): the sync layer
// records the digest it is about to write via RecordApplied, then the store settles to
// that same digest — and the engine recognizes its own echo and runs no converge. This
// is the termination guarantee: an apply never triggers a reconcile of itself.
func TestSelfInducedWriteIsSuppressed(t *testing.T) {
	resolver := &scriptedResolver{digests: []string{"fpApplied"}}
	core, recorder, converger, runner := newWiredEngine(t, resolver, []string{"me@laptop", "you@desktop"})
	ctx := context.Background()

	// The sync layer records the digest of the set it is about to apply, then the
	// write lands and the filesystem event for it arrives.
	recorder.RecordApplied(epID, cookie.Digest("fpApplied"))
	core.OnEvent(ctx, epID)

	// The settle must fingerprint "fpApplied" == the seeded digest and suppress it:
	// no local converge, no peer notify, ever.
	consistentlyZero(t, converger.count, "local converges after a self-induced write")
	consistentlyZero(t, runner.count, "peer notifies after a self-induced write")
}

// TestExternalChangeConvergesOnceAndNotifiesPeers proves invariant (b): a genuine
// external write (a new digest the engine never recorded) drives exactly one debounced
// local converge and one notify per peer. A burst of events coalesces into one settle.
func TestExternalChangeConvergesOnceAndNotifiesPeers(t *testing.T) {
	resolver := &scriptedResolver{digests: []string{"fpExternal"}}
	core, _, converger, runner := newWiredEngine(t, resolver, []string{"me@laptop", "you@desktop", "她@air"})
	ctx := context.Background()

	// A write burst across the Cookies DB and its -wal/-shm sidecars.
	core.OnEvent(ctx, epID)
	core.OnEvent(ctx, epID)
	core.OnEvent(ctx, epID)

	waitFor(t, func() bool { return converger.count() == 1 }, "exactly one local converge")
	waitFor(t, func() bool { return runner.count() == 2 }, "one notify per peer (2 peers)")

	// The local converge ran with no origin (a from-scratch local pass), and the burst
	// coalesced — not one converge per event.
	if got := converger.count(); got != 1 {
		t.Fatalf("local converges = %d, want exactly 1 (burst coalesced)", got)
	}
	converger.mu.Lock()
	origin := converger.origin
	converger.mu.Unlock()
	if len(origin) != 1 || origin[0] != "" {
		t.Fatalf("local converge origins = %v, want one empty origin", origin)
	}
}

// TestReconcileApplyEchoTerminates is the loop-termination proof (c): a real change
// converges (settle 1), the converge records the merged digest before its write, and
// the write's filesystem event settles to that recorded digest (settle 2) — which is
// suppressed. So reconcile -> apply -> fs event does NOT loop: exactly one converge.
func TestReconcileApplyEchoTerminates(t *testing.T) {
	// Settle 1 resolves the external digest; settle 2 (the converge's own write)
	// resolves the merged digest the converge recorded. Both are scripted; the engine
	// must act on the first and suppress the second.
	resolver := &scriptedResolver{digests: []string{"fpExternal", "fpMerged"}}
	core, recorder, converger, runner := newWiredEngine(t, resolver, []string{"me@laptop", "you@desktop"})
	ctx := context.Background()

	// The converger models the local converge writing a merged set: it records the
	// merged digest (seeding the engine) the way applyTo does, before its write.
	converger.setOnSync(func() { recorder.RecordApplied(epID, cookie.Digest("fpMerged")) })

	core.OnEvent(ctx, epID) // external change -> settle 1 -> converge
	waitFor(t, func() bool { return converger.count() == 1 }, "the external change to converge once")

	// The converge's write produces its own filesystem event.
	core.OnEvent(ctx, epID) // settle 2 -> fingerprints fpMerged == seeded -> suppressed

	// No second converge: the loop terminated. Assert the count stays at 1.
	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := converger.count(); got != 1 {
			t.Fatalf("local converges = %d, want 1 (apply echo must not re-converge)", got)
		}
		time.Sleep(2 * time.Millisecond)
	}
	if got := runner.count(); got != 1 {
		t.Fatalf("peer notifies = %d, want 1 (only the real change notified)", got)
	}
}

// TestResolverDecryptionFreeDigestRoundTrips proves the real storeResolver fingerprints
// a live SQLite cookie store off its raw rows — no decryption — and that the digest is
// exactly cookie.LogicalDigest of those rows. It runs against a real ephemeral store,
// the boundary the watch loop actually fingerprints.
func TestResolverDecryptionFreeDigestRoundTrips(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	seed := []cookie.Cookie{
		{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, IsSecure: true, SourceScheme: 2, SourcePort: 443},
		{HostKey: "y.com", Name: "tok", Value: "xyz", Path: "/", LastUpdateUTC: 13_350_000_000_000_001, SameSite: 1, IsSecure: true, SourceScheme: 2, SourcePort: 443},
	}
	if _, err := cookie.Apply(ctx, seed, browser, "Default", key); err != nil {
		t.Fatalf("seed apply: %v", err)
	}

	st := stateWith("me@laptop", state.Endpoint{Host: "me@laptop", Browser: "chrome", Profile: "Default"})
	resolver := storeResolver{store: fixedStore{st: st}}

	got, err := resolver.Resolve(ctx, epID)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	rows, err := cookie.Read(ctx, browser, "Default")
	if err != nil {
		t.Fatalf("read rows: %v", err)
	}
	want := string(cookie.LogicalDigest(rows))
	if got != want {
		t.Fatalf("resolved digest = %q, want %q (decryption-free LogicalDigest of raw rows)", got, want)
	}
	if got == "" {
		t.Fatal("resolved digest is empty for a non-empty store")
	}
}

// TestResolverMissingEndpointErrors proves the resolver errors (which the engine logs
// and skips, never notifying) when the id is no longer tracked — a remove that raced
// the event.
func TestResolverMissingEndpointErrors(t *testing.T) {
	st := stateWith("me@laptop") // no endpoints
	resolver := storeResolver{store: fixedStore{st: st}}
	if _, err := resolver.Resolve(context.Background(), epID); err == nil {
		t.Fatal("Resolve of an untracked endpoint = nil error, want a not-tracked error")
	}
}
