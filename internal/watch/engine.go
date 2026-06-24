// Package watch runs the cookiesync watch loop: it watches each present local
// browser endpoint's cookie store and, when a real (logical-digest-changed) write
// settles, converges that endpoint's union locally and notifies every peer to
// converge too. It wires cookiesync's domain layer — a decryption-free store
// fingerprint and an ssh-over-rpc notifier — into the generic anti-echo engine in
// github.com/yasyf/synckit/watch, fixing the engine's identity type to an endpoint's
// stable id string so the engine's per-id dedup ledger is the same ledger the sync
// layer records applied digests through.
//
// The anti-echo invariant: before any write, the sync layer records the logical
// digest of the set it is about to apply via the shared [EngineRecorder] (which
// seeds the engine's dedup ledger). Because a cookie's last_update_utc is preserved
// on write, the store the write produces fingerprints back to that recorded digest,
// so the filesystem event it triggers resolves to a fingerprint the engine already
// holds and is suppressed as the daemon's own echo — the loop terminates, no echo
// storm.
package watch

import (
	"context"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/state"
	synckitwatch "github.com/yasyf/synckit/watch"
)

// endpointKey is the synckit watch engine's stable digest key for an endpoint: its
// id string itself. Keying the engine on the endpoint id (not the endpoint struct)
// makes the engine's per-id ledger key identical to the endpoint id the sync layer
// records applied digests under, so one ledger serves both the watch dedup and the
// anti-echo seed.
func endpointKey(id string) string { return id }

// Engine is the cookiesync watch engine: the generic synckit anti-echo core wired to
// cookiesync's store fingerprint and rpc notifier, plus the [EngineRecorder] that
// shares its dedup ledger with the sync layer. The daemon builds one, hands the
// recorder to the sync engine, then runs the fsnotify loop ([Watcher.Run]) over the
// same engine — so the watch dedup and the apply-time anti-echo seed are one ledger.
type Engine struct {
	core     *synckitwatch.Engine[string]
	notifier *rpcNotifier
}

// NewEngine builds the watch engine over the state store, this host's self target, the
// peer mesh, and the debounce window. resolver fingerprints a local store
// decryption-free; the notifier converges this host locally for the self entry and
// ssh-notifies each peer for the rest. The returned engine's [Engine.SetConverger]
// must be called with the sync engine before the loop runs — the notifier needs it,
// and it cannot be supplied at construction because the sync engine in turn needs this
// engine's recorder, a cycle this two-step wiring breaks.
func NewEngine(store EndpointLookup, self string, hosts []string, debounce time.Duration, runner engine.SSHRunner) *Engine {
	notifier := &rpcNotifier{self: self, runner: runner}
	core := synckitwatch.NewEngine[string](storeResolver{store: store}, notifier, endpointKey, debounce, hosts)
	return &Engine{core: core, notifier: notifier}
}

// SetConverger binds the local converge the notifier runs for the self entry. It is
// called once after construction, before the loop runs.
func (e *Engine) SetConverger(c LocalConverger) { e.notifier.converger = c }

// Recorder returns the anti-echo ledger seam the sync layer records applied digests
// through, backed by this engine's own dedup ledger. The daemon hands it to the sync
// engine so a converge's recorded digest seeds this engine and the induced filesystem
// event is suppressed.
func (e *Engine) Recorder() cookie.Recorder { return EngineRecorder{engine: e.core} }

// EngineRecorder is the anti-echo ledger the sync layer records applied digests
// through, backed by the watch engine's own per-id dedup ledger. RecordApplied seeds
// the engine immediately before a write, so the filesystem event that write produces
// is recognized as the engine's own echo and suppressed. It is the single ledger
// shared by the converge pass, the apply handler, and the watch loop — there is no
// second map that could drift from the engine's. It satisfies cookie.Recorder.
type EngineRecorder struct {
	engine *synckitwatch.Engine[string]
}

// RecordApplied seeds the engine's dedup ledger with digest for endpointID, so the
// write the sync layer is about to make is later recognized as the daemon's own echo.
func (r EngineRecorder) RecordApplied(endpointID string, digest cookie.Digest) {
	r.engine.Seed(endpointID, string(digest))
}

// LocalConverger is the slice of the sync engine the notifier drives for the self
// entry: a local convergent-reconcile pass with no origin, so this host pulls every
// peer's cookies, merges, and applies locally. Defined here, where the notifier
// consumes it; the daemon's *engine.Engine satisfies it.
type LocalConverger interface {
	Sync(ctx context.Context, origin string) ([]engine.Result, error)
}

// EndpointLookup resolves the live state the resolver and the loop read this host's
// present endpoints from. The state store satisfies it. Defined here, where it is
// consumed.
type EndpointLookup interface {
	Load(ctx context.Context) (*state.State, error)
}
