package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/state"
	synckit "github.com/yasyf/synckit/rpc"
)

// releaseMode selects the presence gates a prime may use. A local prime walks the
// full ladder — hard consent route, local Touch ID, routed fallback. An approver
// prime (an inbound request_consent) is the routed gate's terminus: it only ever
// releases locally, so routedRelease is structurally unreachable and a 3+ mesh can
// never loop an approval back out.
type releaseMode string

const (
	releaseLocal    releaseMode = "local"
	releaseApprover releaseMode = "approver"
)

// batchResult is one batchFlight flight's outcome: the per-browser outcome for every
// browser the flight evaluated — read-only to waiters — and the TTL its released keys
// were cached under. Carrying the whole outcome, not just the successes, lets a waiter
// for a distinct endpoint of a covered browser tell a covered-but-errored result
// (its key failed) from a genuinely uncovered one (re-lead its own flight).
type batchResult struct {
	outcomes map[cookie.BrowserName]cookie.KeyOutcome
	ttl      time.Duration
}

// handleSync converges the union of every tracked endpoint, suppressing the origin
// peer, and reports the frozen {"converged": bool, "cookies": int} shape — or
// {"converged": false, "reason": str} when no warm local endpoint anchored a union
// this pass. cookies is the size of the converged union (the largest converged group),
// matching the Python single-anchor len(merged).
func (d *Daemon) handleSync(ctx context.Context, params map[string]any) (any, error) {
	origin := optionalString(params, "origin", "")
	results, err := d.engine.Sync(ctx, origin)
	if err != nil {
		return nil, err
	}
	cookies, ok := convergedSummary(results)
	if !ok {
		return map[string]any{"converged": false, "reason": noAnchorReason(results)}, nil
	}
	return map[string]any{"converged": true, "cookies": cookies}, nil
}

// handleReconcile runs a full reconcile pass over every tracked endpoint and reports
// the frozen {"groups": {endpoint_id: cookie_count}} shape, one entry per endpoint that
// converged a group this pass.
func (d *Daemon) handleReconcile(ctx context.Context, _ map[string]any) (any, error) {
	results, err := d.engine.Reconcile(ctx)
	if err != nil {
		return nil, err
	}
	groups := map[string]any{}
	for _, r := range results {
		if r.Outcome == engine.OutcomeConverged {
			groups[r.ID] = r.Cookies
		}
	}
	return map[string]any{"groups": groups}, nil
}

// convergedSummary reports the cookie count of the largest converged group — the
// single representative of the converged union — and whether any endpoint converged at
// all this pass.
func convergedSummary(results []engine.Result) (cookies int, ok bool) {
	for _, r := range results {
		if r.Outcome != engine.OutcomeConverged {
			continue
		}
		ok = true
		if r.Cookies > cookies {
			cookies = r.Cookies
		}
	}
	return cookies, ok
}

// noAnchorReason explains why a sync converged nothing: a cold local endpoint needs
// auth; only-remote endpoints mean there is nothing local to anchor. Mirrors the
// Python "no warm local endpoint to anchor the union".
func noAnchorReason(results []engine.Result) string {
	for _, r := range results {
		if r.Outcome == engine.OutcomeSkippedCold {
			return "no warm local endpoint to anchor the union; run cookiesync auth"
		}
	}
	return "no warm local endpoint to anchor the union"
}

// handleExtract returns this host's decrypted cookies for a browser as wire records,
// priming the cache behind the per-requestor consent gate first (so a peer's pull does
// not fail on a cold key, and a warm key is served silently only inside the caller's
// live grant). extract is the one method a remote peer drives, so its requestor is the
// origin param a peer forwards, else the local requestor ladder (peerRequestor). Emits
// the frozen {"cookies": [...]}.
func (d *Daemon) handleExtract(ctx context.Context, params map[string]any) (any, error) {
	browser, err := stringParam(params, "browser")
	if err != nil {
		return nil, err
	}
	profile := optionalString(params, "profile", defaultProfile)
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := d.primeAuth(ctx, peerRequestor(ctx, params), browser, profile, consentReason, releaseLocal); err != nil {
		return nil, err
	}
	extracted, err := engine.NewCachedKeySource(d.cache, self).Extract(ctx, browser, profile)
	if err != nil {
		return nil, err
	}
	return cookiesPayload(extracted.Cookies), nil
}

// handleApply ingests a merged wire cookie array and writes it to this host's store,
// recording the anti-echo digest before the write so the induced filesystem event is
// recognized as the daemon's own echo. Concurrent applies to the same endpoint
// serialize behind the engine's per-endpoint apply lock — the same mutex a converge
// pass's local write holds — keeping the recorded digest true to the store's final
// content; distinct endpoints apply concurrently. Emits the frozen {"applied": int}.
func (d *Daemon) handleApply(ctx context.Context, params map[string]any) (any, error) {
	browser, err := stringParam(params, "browser")
	if err != nil {
		return nil, err
	}
	profile := optionalString(params, "profile", defaultProfile)
	cookies, err := wireCookiesParam(params, "cookies")
	if err != nil {
		return nil, err
	}
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	id := endpointID(self, browser, profile)
	defer d.engine.ApplyLock(id).Unlock()
	d.engine.Recorder().RecordApplied(id, cookie.LogicalDigest(cookies))
	applied, err := engine.NewCachedKeySource(d.cache, self).Apply(ctx, browser, profile, cookies)
	if err != nil {
		return nil, err
	}
	return map[string]any{"applied": applied}, nil
}

// handleWhoami reports this host's console session state, the frozen
// {"on_console", "locked", "console_user", "screen_shared"} shape.
func (d *Daemon) handleWhoami(ctx context.Context, _ map[string]any) (any, error) {
	return sessionSummary(ctx, d.probe)
}

// handlePrimeAuth obtains the Safe Storage key (behind one Touch ID tap when a session
// is live, else by routing the gate to the active peer) and caches it under the
// endpoint TTL. Emits the frozen {"primed": true, "endpoint": str}.
func (d *Daemon) handlePrimeAuth(ctx context.Context, params map[string]any) (any, error) {
	browser, err := stringParam(params, "browser")
	if err != nil {
		return nil, err
	}
	profile := optionalString(params, "profile", defaultProfile)
	reason := optionalString(params, "reason", consentReason)
	if _, err := d.primeAuth(ctx, requestorID(ctx, params), browser, profile, reason, releaseLocal); err != nil {
		return nil, err
	}
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"primed": true, "endpoint": endpointID(self, browser, profile)}, nil
}

// handleAuthStatus reports whether the endpoint's key is warm in the cache and whether
// the cache is degraded to process memory (Secure Enclave presence unavailable at
// open, not yet healed by a Put), the frozen {"endpoint", "authenticated", "degraded"}
// shape.
func (d *Daemon) handleAuthStatus(ctx context.Context, params map[string]any) (any, error) {
	browser, err := stringParam(params, "browser")
	if err != nil {
		return nil, err
	}
	profile := optionalString(params, "profile", defaultProfile)
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	id := endpointID(self, browser, profile)
	_, ok, err := d.cache.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return map[string]any{"endpoint": id, "authenticated": ok, "degraded": d.cache.Degraded()}, nil
}

// handleGetCookies renders one or more urls' cookies, merged into one set, behind the
// per-requestor consent gate: a warm cached key is served silently only inside the
// requestor's live grant; otherwise the release runs — one Touch ID evaluation with a
// live session, else the routed gate, failing closed with AuthRequired on a cold
// unattended mesh. New CLIs send "urls" (one or more hosts); older ones send a single
// "url" — both are accepted, and every host is decrypted with the same released key
// (one prime covers them all) and unioned by logical identity. Emits the frozen
// {"cookies": [...]}.
func (d *Daemon) handleGetCookies(ctx context.Context, params map[string]any) (any, error) {
	browser, err := stringParam(params, "browser")
	if err != nil {
		return nil, err
	}
	profile := optionalString(params, "profile", defaultProfile)
	urls, err := urlsParam(params)
	if err != nil {
		return nil, err
	}
	key, err := d.primeAuth(ctx, requestorID(ctx, params), browser, profile, consentReason, releaseLocal)
	if err != nil {
		return nil, err
	}
	b, err := cookie.Lookup(cookie.BrowserName(browser))
	if err != nil {
		return nil, err
	}
	sets := make([][]cookie.Cookie, 0, len(urls))
	for _, url := range urls {
		// fallback=false: the merge pass uses only the released key, never the
		// cross-browser get-cookie sweep.
		extracted, err := cookie.Extract(ctx, url, b, key, profile, false, false)
		if err != nil {
			return nil, err
		}
		sets = append(sets, extracted.Cookies)
	}
	return cookiesPayload(cookie.Merge(sets...)), nil
}

// primeAuth obtains the Safe Storage key for requestor via the presence gate
// (releaseKey) and caches it under the endpoint's TTL. Authorization is per requestor,
// never global cache warmth: a warm key is returned silently only while requestor
// holds a live grant for the browser; anything else releases anew — one consent
// evaluation, human or routed — which grants requestor every browser it covered and
// refreshes the cache. Concurrent calls from one requestor — same endpoint or
// distinct — collapse into one batchFlight flight per mode, whose released keys every
// waiter shares. The flight runs detached from every caller's ctx, bounded only by
// the dispatch timeout, so a caller that disconnects mid-consent neither poisons the
// flight for the survivors nor stays parked behind it: it returns its own ctx.Err()
// immediately while the flight (and the prompt) runs on. A flight that did not cover
// this browser (a foreign leader's batch) is retried with this browser leading. On a
// verified routed approval this host releases its own key non-interactively — the key
// never leaves this box. A cold remote mesh fails closed with AuthRequired. Mirrors
// the Python prime_auth.
func (d *Daemon) primeAuth(ctx context.Context, requestor, browser, profile, reason string, mode releaseMode) (cookie.AesKey, error) {
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	id := endpointID(self, browser, profile)
	cached, warm, err := d.cache.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if warm && d.granted(requestor, cookie.BrowserName(browser)) {
		return cookie.AesKey(cached), nil
	}
	for {
		ch := d.batchFlight.DoChan("local-batch:"+string(mode)+":"+requestor, func() (any, error) {
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), synckit.DispatchTimeout)
			defer cancel()
			return d.releaseAndCacheKey(fctx, requestor, self, id, browser, profile, reason, mode)
		})
		select {
		case res := <-ch:
			if res.Err != nil {
				return nil, res.Err
			}
			batch := res.Val.(*batchResult)
			oc, ok := batch.outcomes[cookie.BrowserName(browser)]
			if !ok {
				continue
			}
			if oc.Err != nil {
				return nil, oc.Err
			}
			if oc.Missing {
				return nil, &cookie.ConsentError{Msg: fmt.Sprintf("could not read %q from the Keychain (denied or missing)", oc.Browser.KeychainService)}
			}
			_, warm, err := d.cache.Get(ctx, id)
			if err != nil {
				return nil, err
			}
			if !warm {
				if err := d.cache.Put(ctx, id, []byte(oc.Key), batch.ttl); err != nil {
					return nil, err
				}
			}
			return oc.Key, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// releaseAndCacheKey is one batchFlight flight: it re-probes the cache — a straggler
// whose fresh flight starts just after another flight primed the endpoint is served
// the warm key instead of re-prompting, but only inside requestor's live grant — then
// releases keys behind the presence gate that applies and caches them under the
// effective TTL.
func (d *Daemon) releaseAndCacheKey(ctx context.Context, requestor, self, id, browser, profile, reason string, mode releaseMode) (*batchResult, error) {
	st, err := d.state.Load(ctx)
	if err != nil {
		return nil, err
	}
	if d.granted(requestor, cookie.BrowserName(browser)) {
		cached, ok, err := d.cache.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if ok {
			name := cookie.BrowserName(browser)
			return &batchResult{
				outcomes: map[cookie.BrowserName]cookie.KeyOutcome{name: {Key: cookie.AesKey(cached)}},
				ttl:      d.effectiveTTL(st.Settings.AuthTTL),
			}, nil
		}
	}
	return d.releaseKey(ctx, st, requestor, self, id, browser, profile, reason, mode)
}

// releaseKey obtains Safe Storage keys behind the presence gate that applies. In
// releaseLocal mode a hard consent route (ConsentRouteHard) to a live ConsentRouteTo
// peer wins outright — this host routes the gate even when it looks locally attended —
// and a cold local session routes the gate to the active peer; a routed approval
// releases just the requested browser's key. Otherwise — and always in releaseApprover
// mode, where this host is the routed gate's terminus and must never route onward —
// the whole local batch releases behind one Touch ID evaluation in releaseAllLocal.
// The prompt gate is never held across routedRelease: an inbound request_consent must
// stay promptable while this host's own outbound route is in flight, or the same-host
// routed-consent cycle deadlocks.
func (d *Daemon) releaseKey(ctx context.Context, st *state.State, requestor, self, id, browser, profile, reason string, mode releaseMode) (*batchResult, error) {
	if mode == releaseLocal {
		if st.ConsentRouteHard && st.ConsentRouteTo != "" {
			live, err := d.peerIsLive(ctx, st.ConsentRouteTo)
			if err != nil {
				return nil, err
			}
			if live {
				return d.routedBatch(ctx, st, requestor, id, browser, profile)
			}
		}
		live, err := HasActiveSession(ctx, d.probe)
		if err != nil {
			return nil, err
		}
		if !live {
			return d.routedBatch(ctx, st, requestor, id, browser, profile)
		}
	}
	return d.releaseAllLocal(ctx, st, requestor, self, id, browser, reason)
}

// routedBatch releases the requested browser's key through the routed-consent
// handshake, caches it under the requested endpoint, and grants requestor that one
// browser — a routed approval gates one browser, never the local batch.
func (d *Daemon) routedBatch(ctx context.Context, st *state.State, requestor, id, browser, profile string) (*batchResult, error) {
	b, err := cookie.Lookup(cookie.BrowserName(browser))
	if err != nil {
		return nil, err
	}
	key, err := d.routedRelease(ctx, b, browser, profile)
	if err != nil {
		return nil, err
	}
	ttl := d.effectiveTTL(st.Settings.AuthTTL)
	if err := d.cache.Put(ctx, id, []byte(key), ttl); err != nil {
		return nil, err
	}
	name := cookie.BrowserName(browser)
	d.grant(requestor, []cookie.BrowserName{name}, ttl)
	return &batchResult{
		outcomes: map[cookie.BrowserName]cookie.KeyOutcome{name: {Browser: b, Key: key}},
		ttl:      ttl,
	}, nil
}

// releaseAllLocal is the single choke point where Touch ID taps happen: one consent
// evaluation covering every tracked local browser plus the requested one, under
// promptGate so a local flight and an approver flight never stack two sheets. The
// prompt reason names the requestor best-effort, and the evaluation grants requestor
// every browser it released under the same effective TTL its keys are cached for.
// Every ok browser's key is cached under all of its tracked local endpoint ids —
// every profile of a browser shares its Safe Storage key — with the requested
// endpoint id put LAST: a mid-batch heal (the healingWrapper swap runs EvictAll)
// drops earlier Puts, so the requested id is verified after the batch and re-Put if a
// heal raced past it. The whole batch's per-browser outcome is returned — a browser
// that failed (Missing or Err) is carried in the outcomes, not cached, so a waiter for
// a distinct browser is served while the leader's browser is denied. Only a
// whole-batch failure (ObtainKeys errored — a denied sheet, a locked keybag, a helper
// that cannot run) fails the flight; a single browser's failure is surfaced to that
// browser's requestor by primeAuth.
func (d *Daemon) releaseAllLocal(ctx context.Context, st *state.State, requestor, self, id, browser, reason string) (*batchResult, error) {
	requested := cookie.BrowserName(browser)
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
		b, err := cookie.Lookup(name)
		if err != nil {
			return nil, err
		}
		browsers[i] = b
	}
	pid, hasPID := synckit.PeerPID(ctx)
	reason = requestorReason(ctx, requestor, reason, pid, hasPID)
	d.promptGate.Lock()
	obtained, err := d.consent.ObtainKeys(ctx, browsers, reason)
	d.promptGate.Unlock()
	if err != nil {
		return nil, err
	}
	ttl := d.effectiveTTL(st.Settings.AuthTTL)
	outcomes := make(map[cookie.BrowserName]cookie.KeyOutcome, len(obtained))
	released := make([]cookie.BrowserName, 0, len(obtained))
	for i, outcome := range obtained {
		outcomes[names[i]] = outcome
		if outcome.Missing || outcome.Err != nil {
			continue
		}
		released = append(released, names[i])
		for _, epID := range bulkIDs[names[i]] {
			if err := d.cache.Put(ctx, epID, []byte(outcome.Key), ttl); err != nil {
				return nil, err
			}
		}
	}
	d.grant(requestor, released, ttl)
	if oc := outcomes[requested]; !oc.Missing && oc.Err == nil {
		if err := d.cache.Put(ctx, id, []byte(oc.Key), ttl); err != nil {
			return nil, err
		}
		_, warm, err := d.cache.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if !warm {
			if err := d.cache.Put(ctx, id, []byte(oc.Key), ttl); err != nil {
				return nil, err
			}
		}
	}
	return &batchResult{outcomes: outcomes, ttl: ttl}, nil
}

// cookiesPayload is the frozen {"cookies": [...]} envelope a cookie set crosses the
// boundary as, each cookie in the frozen wire shape.
func cookiesPayload(cookies []cookie.Cookie) map[string]any {
	wire := make([]cookie.WireCookie, len(cookies))
	for i, c := range cookies {
		wire[i] = cookie.ToWire(c)
	}
	return map[string]any{"cookies": wire}
}

// wireCookiesParam reads the "cookies" param — a JSON array of wire cookie objects —
// back into the cookie model, re-marshaling the decoded any-tree through the frozen
// wire decoder so the field order and types match the apply contract exactly.
func wireCookiesParam(params map[string]any, key string) ([]cookie.Cookie, error) {
	raw, ok := params[key]
	if !ok {
		return nil, fmt.Errorf("missing required param %q", key)
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("re-encode %q: %w", key, err)
	}
	cookies, err := cookie.UnmarshalCookies(data)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", key, err)
	}
	return cookies, nil
}

// urlsParam reads the dual url/urls field: a non-empty "urls" list wins; otherwise the
// single "url" string is used. At least one url is required.
func urlsParam(params map[string]any) ([]string, error) {
	if raw, ok := params["urls"].([]any); ok && len(raw) > 0 {
		urls := make([]string, len(raw))
		for i, v := range raw {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("urls[%d] is %T, want string", i, v)
			}
			urls[i] = s
		}
		return urls, nil
	}
	url, err := stringParam(params, "url")
	if err != nil {
		return nil, errors.New("get_cookies requires url or urls")
	}
	return []string{url}, nil
}
