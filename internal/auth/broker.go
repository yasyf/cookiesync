package auth

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/presence"
	synckit "github.com/yasyf/synckit/rpc"
	"golang.org/x/sync/singleflight"
)

// StatusTimeout bounds the session probe and cache read behind a Status query.
// A client deadline does not cross the socket, so a wedged probe or a
// locked-keybag helper round-trip would block the doctor's 2s read into an
// i/o-timeout FAIL; on the bound the host is reported locked — data the doctor
// renders OK-with-note, not an error. Under the doctor's 2s so the reply lands
// first; a var so tests shrink it.
var StatusTimeout = 1500 * time.Millisecond

// errStatusTimeout is the cause the status read stamps on its own deadline, so
// a probe or unwrap that outran StatusTimeout is told apart from a parent
// cancel via context.Cause — only the former reports the host locked.
var errStatusTimeout = errors.New("auth status probe/read exceeded StatusTimeout")

// batchResult is one batchFlight flight's outcome: the per-browser outcome for
// every browser the flight evaluated — read-only to waiters — the TTL its
// released keys were cached under, and the consent surface the flight actually
// used. Carrying the whole outcome lets a waiter for a distinct endpoint of a
// covered browser tell a covered-but-errored result from a genuinely uncovered
// one (re-lead its own flight).
type batchResult struct {
	outcomes map[cookie.BrowserName]cookie.KeyOutcome
	ttl      time.Duration
	surface  Surface
}

// Broker is the single owner of every key path: it holds the grants store, the
// key cache, the prompt gate, the release singleflight, and the consent nonce
// source, and serves keys only through Key, LocalKeys, and the grant-blind
// CachedKey data-plane read.
//
// batchFlight collapses concurrent Key calls into one flight per release mode,
// requestor, and browser, so a burst of cold releases from one principal for
// one browser costs one consent evaluation while distinct principals each face
// their own tap; the mode key keeps an inbound approval off the local flight,
// so it never parks behind this host's own outbound routed release (the
// same-host routed-consent cycle), and the browser key keeps one browser's
// routed failure from being delivered as another browser's result. promptGate
// serializes the interactive Touch ID sheets across flights;
// it is held only around the consent.ObtainKeys call inside releaseAllLocal,
// never across routedRelease or any outbound ssh, or that same cycle deadlocks.
type Broker struct {
	consent cookie.Consent
	cache   Cache
	probe   Probe
	runner  SSHRunner
	state   StateLoader

	// KeybagProbe is the ioreg-only console read Status uses (netstat stays
	// off this path); defaults to probe — production pins presence.Console.
	KeybagProbe Probe

	// Nonce mints routed-consent nonces; a field so a test can pin the echo
	// binding. Defaults to the crypto/rand source.
	Nonce func() (string, error)

	batchFlight singleflight.Group

	grantMu sync.Mutex
	grants  map[string]time.Time // requestor + ":" + browser → expiry; pruned on read

	promptGate sync.Mutex
}

// NewBroker builds the broker over injected collaborators. KeybagProbe defaults
// to probe and Nonce to the crypto/rand source; override the fields after
// construction to pin them.
func NewBroker(consent cookie.Consent, c Cache, probe Probe, runner SSHRunner, st StateLoader) *Broker {
	return &Broker{
		consent:     consent,
		cache:       c,
		probe:       probe,
		runner:      runner,
		state:       st,
		KeybagProbe: probe,
		Nonce:       newNonce,
		grants:      map[string]time.Time{},
	}
}

// Key obtains the Safe Storage key for req via the presence gate that applies
// and caches it under the endpoint's TTL. A warm key is returned silently only
// while the requestor holds a live grant for the browser; anything else
// releases anew — one consent evaluation, human or routed — which grants the
// requestor every browser it covered and refreshes the cache. Concurrent calls
// from one requestor collapse into one batch flight per mode and browser, whose
// released keys every waiter shares; the flight runs detached from every caller's ctx,
// bounded only by the dispatch timeout, so a caller that disconnects
// mid-consent neither poisons the flight for the survivors nor stays parked
// behind it. A flight that did not cover this browser (a foreign leader's
// batch) is retried with this browser leading. In ModeApprover the attended
// pre-flight check folds in: no live session fails Unavailable before any gate.
// The returned Surface is the gate the covering flight actually used — reported
// even alongside an error once a flight ran, so a caller sequencing releases
// never stacks a second sheet.
func (b *Broker) Key(ctx context.Context, req Req) (cookie.AesKey, Surface, error) {
	if req.Mode == ModeApprover {
		snap, err := b.probe(ctx)
		if err != nil {
			return nil, SurfaceNone, &approverUnavailableError{err: err}
		}
		live, err := presence.Attended(snap)
		if err != nil {
			return nil, SurfaceNone, err
		}
		if !live {
			return nil, SurfaceNone, &AuthRequired{Msg: "no live session to approve consent"}
		}
	}
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, SurfaceNone, err
	}
	id := endpointID(self, req.Browser, req.Profile)
	cached, warm, err := b.cache.Get(ctx, id)
	if err != nil {
		if req.Mode == ModeApprover {
			return nil, SurfaceNone, &approverUnavailableError{err: err}
		}
		return nil, SurfaceNone, err
	}
	if warm && b.Granted(req.Requestor, cookie.BrowserName(req.Browser)) {
		return cookie.AesKey(cached), SurfaceNone, nil
	}
	for {
		ch := b.batchFlight.DoChan("local-batch:"+string(req.Mode)+":"+req.Requestor+":"+req.Browser, func() (any, error) {
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), synckit.DispatchTimeout)
			defer cancel()
			return b.releaseAndCacheKey(fctx, req, self, id)
		})
		select {
		case res := <-ch:
			if res.Err != nil {
				surface := SurfaceNone
				if batch, ok := res.Val.(*batchResult); ok && batch != nil {
					surface = batch.surface
				}
				return nil, surface, res.Err
			}
			batch := res.Val.(*batchResult)
			oc, ok := batch.outcomes[cookie.BrowserName(req.Browser)]
			if !ok {
				continue
			}
			if oc.Err != nil {
				return nil, batch.surface, oc.Err
			}
			if oc.Missing {
				return nil, batch.surface, &cookie.ConsentError{Msg: fmt.Sprintf("could not read %q from the Keychain (denied or missing)", oc.Browser.KeychainService)}
			}
			// Load-bearing: a concurrent Put's heal can retire the epoch right
			// after the flight's Put, evicting id — re-publish to stay warm;
			// a degraded re-publish caps the grant, never extends it.
			_, warm, err := b.cache.Get(ctx, id)
			if err != nil {
				return nil, batch.surface, err
			}
			if !warm {
				degraded, err := b.cache.Put(ctx, id, []byte(oc.Key), batch.ttl)
				if err != nil {
					return nil, batch.surface, err
				}
				if capped := effectiveTTL(batch.ttl, degraded); capped < batch.ttl {
					b.CapGrant(req.Requestor, cookie.BrowserName(req.Browser), capped)
				}
			}
			return oc.Key, batch.surface, nil
		case <-ctx.Done():
			return nil, SurfaceNone, ctx.Err()
		}
	}
}

// LocalKeys sweeps every tracked local endpoint for requestor under the given
// prompt budget, releasing where the budget allows and reporting one Outcome
// per unit — per endpoint under OneFlight, per distinct browser under PrimeAll.
// A warm+granted endpoint is served silently; the first cold unit leads a
// release flight; what happens after depends on the budget (see Budget). Under
// PrimeAll a zero tracked local browser set fails closed with AuthRequired, a
// final rescan records each browser's still-warm endpoint ids, and a sweep that
// left nothing warm fails closed — the first release error when one happened,
// else AuthRequired — never an empty success.
func (b *Broker) LocalKeys(ctx context.Context, requestor, reason string, budget Budget) ([]Outcome, error) {
	st, err := b.state.Load(ctx)
	if err != nil {
		return nil, err
	}
	return b.LocalKeysWithState(ctx, requestor, reason, budget, st)
}

// LocalKeysWithState runs a LocalKeys sweep against the caller's state snapshot.
func (b *Broker) LocalKeysWithState(ctx context.Context, requestor, reason string, budget Budget, st *state.State) ([]Outcome, error) {
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	locals := make([]state.Endpoint, 0)
	for _, ep := range st.Endpoints() {
		if ep.Host == self {
			locals = append(locals, ep)
		}
	}
	sort.Slice(locals, func(i, j int) bool { return locals[i].ID() < locals[j].ID() })
	if budget == PrimeAll {
		if len(locals) == 0 {
			return nil, &AuthRequired{Msg: "no local browsers are tracked; run cookiesync browser add"}
		}
		return b.primeAll(ctx, requestor, reason, self, locals)
	}
	return b.oneFlight(ctx, requestor, reason, locals)
}

// oneFlight is the OneFlight sweep: one Outcome per tracked local endpoint, at
// most one release flight for the whole call — whatever surface it used — and a
// budget-spent skip for everything still cold after it.
func (b *Broker) oneFlight(ctx context.Context, requestor, reason string, locals []state.Endpoint) ([]Outcome, error) {
	outcomes := make([]Outcome, 0, len(locals))
	prompted := false
	for _, ep := range locals {
		oc := Outcome{Browser: ep.Browser, Profile: ep.Profile, Endpoint: string(ep.ID())}
		cached, warm, err := b.cache.Get(ctx, oc.Endpoint)
		if err != nil {
			return nil, err
		}
		switch {
		case warm && b.Granted(requestor, cookie.BrowserName(ep.Browser)):
			oc.Key = cookie.AesKey(cached)
		case !prompted:
			prompted = true
			key, _, err := b.Key(ctx, Req{Requestor: requestor, Browser: ep.Browser, Profile: ep.Profile, Reason: reason, Mode: ModeLocal})
			if err != nil {
				oc.Err = err
			} else {
				oc.Key = key
			}
		default:
			oc.Skipped = true
		}
		outcomes = append(outcomes, oc)
	}
	return outcomes, nil
}

// primeAll is the PrimeAll sweep: one Outcome per distinct local browser in
// id-sorted order (each keyed by its first tracked profile). The loop keys off
// each flight's ACTUAL consent surface — never a call-start snapshot a mid-call
// presence flip could stale out: the first local sheet covers the whole tracked
// batch, so later browsers ride its grant and anything still cold is a
// fail-closed skip, while a cold host routes every browser to a live peer (one
// routed tap each, siblings bulk-cached by the routed release itself).
func (b *Broker) primeAll(ctx context.Context, requestor, reason, self string, locals []state.Endpoint) ([]Outcome, error) {
	var outcomes []Outcome
	idsByBrowser := map[string][]string{}
	for _, ep := range locals {
		if _, seen := idsByBrowser[ep.Browser]; !seen {
			outcomes = append(outcomes, Outcome{Browser: ep.Browser, Profile: ep.Profile, Endpoint: endpointID(self, ep.Browser, ep.Profile)})
		}
		idsByBrowser[ep.Browser] = append(idsByBrowser[ep.Browser], string(ep.ID()))
	}

	var firstErr error
	prompted := false
	for i := range outcomes {
		oc := &outcomes[i]
		_, warm, err := b.cache.Get(ctx, oc.Endpoint)
		if err != nil {
			return nil, err
		}
		if warm && b.Granted(requestor, cookie.BrowserName(oc.Browser)) {
			continue
		}
		if prompted {
			oc.Skipped = true
			continue
		}
		key, surface, err := b.Key(ctx, Req{Requestor: requestor, Browser: oc.Browser, Profile: oc.Profile, Reason: reason, Mode: ModeLocal})
		if surface == SurfaceLocal {
			prompted = true
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			oc.Err = err
			continue
		}
		oc.Key = key
	}

	// The verification rescan: report only endpoints still warm, so a demote
	// that raced the sweep never yields an empty success.
	warmTotal := 0
	for i := range outcomes {
		for _, id := range idsByBrowser[outcomes[i].Browser] {
			_, warm, err := b.cache.Get(ctx, id)
			if err != nil {
				return nil, err
			}
			if warm {
				outcomes[i].Warm = append(outcomes[i].Warm, id)
				warmTotal++
			}
		}
	}
	if warmTotal == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, &AuthRequired{Msg: "no primed key stayed warm; retry cookiesync auth"}
	}
	return outcomes, nil
}

// Status reports the key state for one endpoint under StatusTimeout so a status
// read never blocks the caller. Only a keybag probe that itself outruns the
// bound (or fails on it) forces KeybagLocked true and skips the cache; after a
// successful probe KeybagLocked is the probe's verdict, and a cache read that
// outruns the bound is swallowed as Authenticated false rather than an error.
// Any other probe or read failure propagates; context.Cause tells the bound
// apart from a parent cancel so a caller that went away is never reported
// locked.
func (b *Broker) Status(ctx context.Context, endpointID string) (Status, error) {
	sctx, cancel := context.WithTimeoutCause(ctx, StatusTimeout, errStatusTimeout)
	defer cancel()

	snap, err := b.KeybagProbe(sctx)
	if err != nil {
		if !errors.Is(context.Cause(sctx), errStatusTimeout) {
			return Status{}, err
		}
		return Status{Degraded: b.cache.Degraded(), KeybagLocked: true}, nil
	}
	locked, err := keybagLocked(snap)
	if err != nil {
		return Status{}, err
	}

	_, ok, err := b.cache.Get(sctx, endpointID)
	if err != nil && !errors.Is(context.Cause(sctx), errStatusTimeout) {
		return Status{}, err
	}
	return Status{Authenticated: ok, Degraded: b.cache.Degraded(), KeybagLocked: locked}, nil
}

// CachedKey is the grant-blind data-plane read the engine's local source uses
// for extract and apply: the warm key for endpointID, never a release and never
// a grant check. Consent-gated reads go through Key.
func (b *Broker) CachedKey(ctx context.Context, endpointID string) ([]byte, bool, error) {
	return b.cache.Get(ctx, endpointID)
}
