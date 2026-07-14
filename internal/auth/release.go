package auth

import (
	"context"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/presence"
	synckit "github.com/yasyf/synckit/rpc"
)

// releaseAndCacheKey is one batchFlight flight: it re-probes the cache — a
// straggler whose fresh flight starts just after another flight primed the
// endpoint is served the warm key instead of re-prompting, but only inside the
// requestor's live grant — then releases keys behind the presence gate that
// applies and caches them under the effective TTL.
func (b *Broker) releaseAndCacheKey(ctx context.Context, req Req, self, id string) (*batchResult, error) {
	st, err := b.state.Load(ctx)
	if err != nil {
		return nil, err
	}
	if b.Granted(req.Requestor, cookie.BrowserName(req.Browser)) {
		cached, ok, err := b.cache.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if ok {
			name := cookie.BrowserName(req.Browser)
			return &batchResult{
				outcomes: map[cookie.BrowserName]cookie.KeyOutcome{name: {Key: cookie.AesKey(cached)}},
				ttl:      st.Settings.AuthTTL,
			}, nil
		}
	}
	return b.releaseKey(ctx, st, req, self, id)
}

// releaseKey obtains Safe Storage keys behind the presence gate that applies,
// deriving the routed/local split once inside the flight. In ModeLocal a hard
// consent route (ConsentRouteHard) to a live ConsentRouteTo peer wins outright
// — this host routes the gate even when it looks locally attended — and a cold
// local session routes the gate to the active peer; a routed approval releases
// just the requested browser's key. This one rule serves every console release
// — prime, get_cookies, and extract alike. Otherwise — and always in
// ModeApprover, where this host is the routed gate's terminus and must never
// route onward — the whole local batch releases behind one Touch ID evaluation
// in releaseAllLocal. The prompt gate is never held across routedRelease: an
// inbound request_consent must stay promptable while this host's own outbound
// route is in flight, or the same-host routed-consent cycle deadlocks.
func (b *Broker) releaseKey(ctx context.Context, st *state.State, req Req, self, id string) (*batchResult, error) {
	if req.Mode == ModeLocal {
		routed, err := b.routesConsent(ctx, st)
		if err != nil {
			return nil, err
		}
		if routed {
			return b.routedBatch(ctx, st, req, self, id)
		}
	}
	return b.releaseAllLocal(ctx, st, req, self, id)
}

// routesConsent reports whether a ModeLocal release routes the user-presence
// gate to a peer instead of prompting Touch ID locally: a hard consent route
// (ConsentRouteHard) to a live ConsentRouteTo peer wins outright — this host
// routes even when it looks locally attended — and a cold local session routes
// to the active peer. It is derived once inside each release flight
// (releaseKey), never snapshotted at call start, so the routed/local split a
// caller observes is always the one its flight actually used.
func (b *Broker) routesConsent(ctx context.Context, st *state.State) (bool, error) {
	if st.ConsentRouteHard && st.ConsentRouteTo != "" {
		live, err := b.peerIsLive(ctx, st.ConsentRouteTo)
		if err != nil {
			return false, err
		}
		if live {
			return true, nil
		}
	}
	snap, err := b.probe(ctx)
	if err != nil {
		return false, err
	}
	live, err := presence.Attended(snap)
	if err != nil {
		return false, err
	}
	return !live, nil
}

// routedBatch releases the requested browser's key through the routed-consent
// handshake, caches it under every tracked local endpoint of that browser —
// every profile shares its Safe Storage key, so a routed approval bulk-warms
// siblings exactly like a local release, with the requested endpoint put LAST
// so it survives any heal a sibling Put triggers — and grants the requestor
// that one browser: a routed approval gates one browser, never the local batch.
// The grant window derives from the Puts' reported publish epochs: any key
// published degraded caps it at degradedAuthTTL.
func (b *Broker) routedBatch(ctx context.Context, st *state.State, req Req, self, id string) (*batchResult, error) {
	bw, err := cookie.Lookup(cookie.BrowserName(req.Browser))
	if err != nil {
		return nil, err
	}
	key, err := b.routedRelease(ctx, bw, req.Browser, req.Profile)
	if err != nil {
		return nil, err
	}
	configured := st.Settings.AuthTTL
	publishedDegraded := false
	for _, ep := range st.Endpoints() {
		if ep.Host != self || ep.Browser != req.Browser {
			continue
		}
		if epID := string(ep.ID()); epID != id {
			degraded, err := b.cache.Put(ctx, epID, []byte(key), configured)
			if err != nil {
				return nil, err
			}
			publishedDegraded = publishedDegraded || degraded
		}
	}
	degraded, err := b.cache.Put(ctx, id, []byte(key), configured)
	if err != nil {
		return nil, err
	}
	publishedDegraded = publishedDegraded || degraded
	ttl := effectiveTTL(configured, publishedDegraded)
	name := cookie.BrowserName(req.Browser)
	b.Grant(req.Requestor, []cookie.BrowserName{name}, ttl)
	return &batchResult{
		outcomes: map[cookie.BrowserName]cookie.KeyOutcome{name: {Browser: bw, Key: key}},
		ttl:      ttl,
		surface:  SurfaceRouted,
	}, nil
}

// releaseAllLocal is the single choke point where Touch ID taps happen: one
// consent evaluation covering every tracked local browser plus the requested
// one, under promptGate so a local flight and an approver flight never stack
// two sheets. The prompt reason names the requestor best-effort, and the
// evaluation grants the requestor every browser it released, the grant window
// capped at degradedAuthTTL whenever any Put reported publishing under a
// degraded epoch. Every ok browser's key is cached under
// all of its tracked local endpoint ids with the requested endpoint id put
// LAST: a mid-batch heal evicts the pre-heal epoch's entries, so the requested
// id, put after any heal its own batch triggers, survives Enclave-wrapped. The
// whole batch's per-browser outcome is returned — a browser that failed
// (Missing or Err) is carried in the outcomes, not cached, so a waiter for a
// distinct browser is served while the leader's browser is denied; only a
// whole-batch failure (ObtainKeys errored) fails the flight. Every error at or
// past the consent evaluation still carries a SurfaceLocal batchResult, so a
// caller knows a sheet already fired and never stacks a second one.
func (b *Broker) releaseAllLocal(ctx context.Context, st *state.State, req Req, self, id string) (*batchResult, error) {
	requested := cookie.BrowserName(req.Browser)
	names := []cookie.BrowserName{requested}
	seen := map[cookie.BrowserName]bool{requested: true}
	bulkIDs := map[cookie.BrowserName][]string{}
	for _, ep := range st.Endpoints() {
		if ep.Host != self {
			continue
		}
		name := cookie.BrowserName(ep.Browser)
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
		if epID := string(ep.ID()); epID != id {
			bulkIDs[name] = append(bulkIDs[name], epID)
		}
	}
	browsers := make([]cookie.Browser, len(names))
	for i, name := range names {
		bw, err := cookie.Lookup(name)
		if err != nil {
			return nil, err
		}
		browsers[i] = bw
	}
	pid, hasPID := synckit.PeerPID(ctx)
	reason := requestorReason(ctx, req.Requestor, req.Reason, pid, hasPID)
	b.promptGate.Lock()
	obtained, err := b.consent.ObtainKeys(ctx, browsers, reason)
	b.promptGate.Unlock()
	if err != nil {
		return &batchResult{surface: SurfaceLocal}, err
	}
	configured := st.Settings.AuthTTL
	publishedDegraded := false
	outcomes := make(map[cookie.BrowserName]cookie.KeyOutcome, len(obtained))
	released := make([]cookie.BrowserName, 0, len(obtained))
	for i, outcome := range obtained {
		outcomes[names[i]] = outcome
		if outcome.Missing || outcome.Err != nil {
			continue
		}
		released = append(released, names[i])
		for _, epID := range bulkIDs[names[i]] {
			degraded, err := b.cache.Put(ctx, epID, []byte(outcome.Key), configured)
			if err != nil {
				return &batchResult{surface: SurfaceLocal}, err
			}
			publishedDegraded = publishedDegraded || degraded
		}
	}
	if oc := outcomes[requested]; !oc.Missing && oc.Err == nil {
		degraded, err := b.cache.Put(ctx, id, []byte(oc.Key), configured)
		if err != nil {
			return &batchResult{surface: SurfaceLocal}, err
		}
		publishedDegraded = publishedDegraded || degraded
	}
	ttl := effectiveTTL(configured, publishedDegraded)
	b.Grant(req.Requestor, released, ttl)
	return &batchResult{outcomes: outcomes, ttl: ttl, surface: SurfaceLocal}, nil
}
