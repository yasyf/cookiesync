package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/hostregistry"
	synckit "github.com/yasyf/synckit/rpc"
)

// unionSSHConcurrency bounds the concurrent ssh dials getCookiesAll's remote leg makes,
// so a wide mesh does not open one ssh process per remote endpoint at once.
const unionSSHConcurrency = 4

// releaseMode selects whether a release derives the routed/local consent split or is
// pinned to a local terminus. A local prime walks the full ladder — hard consent route,
// local Touch ID, routed fallback — deriving the routed/local split once inside the
// flight (routesConsent), so every console release shares one routing rule and a
// mid-call presence flip cannot split one requestor's prompts across two flights. An
// approver prime (an inbound request_consent) is the routed gate's terminus: it only
// ever releases locally, so routedRelease is structurally unreachable and a 3+ mesh can
// never loop an approval back out.
type releaseMode string

const (
	releaseLocal    releaseMode = "local"
	releaseApprover releaseMode = "approver"
)

// consentSurface identifies which presence gate a release flight actually used: none
// (served from a warm cache inside a live grant), a local Touch ID evaluation, or a
// routed peer approval. A caller that sequences multiple primes keys its loop off each
// flight's actual surface — never a call-start routing snapshot, which a mid-call
// presence flip could stale out into a second sheet or a surprise route.
type consentSurface int

const (
	surfaceNone consentSurface = iota
	surfaceLocal
	surfaceRouted
)

// batchResult is one batchFlight flight's outcome: the per-browser outcome for every
// browser the flight evaluated — read-only to waiters — the TTL its released keys
// were cached under, and the consent surface the flight actually used. Carrying the
// whole outcome, not just the successes, lets a waiter for a distinct endpoint of a
// covered browser tell a covered-but-errored result (its key failed) from a genuinely
// uncovered one (re-lead its own flight).
type batchResult struct {
	outcomes map[cookie.BrowserName]cookie.KeyOutcome
	ttl      time.Duration
	surface  consentSurface
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
	if _, _, err := d.primeAuth(ctx, peerRequestor(ctx, params), browser, profile, consentReason, releaseLocal); err != nil {
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

// handlePrimeAuth obtains the Safe Storage key and caches it under the endpoint TTL. With
// a "browser" param it primes that one endpoint — behind one Touch ID tap when a session
// is live, else by routing the gate to the active peer — and emits the frozen
// {"primed": true, "endpoint": str}. With no "browser" it primes every registered local
// browser via primeAuthAll, emitting {"primed": true, "endpoints": [...], "warnings": [...]}.
func (d *Daemon) handlePrimeAuth(ctx context.Context, params map[string]any) (any, error) {
	reason := optionalString(params, "reason", consentReason)
	browser := optionalString(params, "browser", "")
	if browser == "" {
		return d.primeAuthAll(ctx, requestorID(ctx, params), reason)
	}
	profile := optionalString(params, "profile", defaultProfile)
	if _, _, err := d.primeAuth(ctx, requestorID(ctx, params), browser, profile, reason, releaseLocal); err != nil {
		return nil, err
	}
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"primed": true, "endpoint": endpointID(self, browser, profile)}, nil
}

// primeAuthAll primes every registered local browser behind at most one Touch ID sheet,
// looping the single-browser primeAuth over the distinct local browsers in sorted order.
// A live session leads one batch flight whose releaseAllLocal covers every tracked local
// browser, so any browser still cold after it was Missing or denied in that batch —
// surfaced as a warning, never a second sheet. A cold session routes consent per browser
// to a live peer (decision 1), caching each routed key under all of that browser's
// tracked local endpoint ids, since every profile of a browser shares its Safe Storage
// key. Zero tracked local browsers fails closed with AuthRequired — the CLI
// auto-registers before calling, so this is the backstop; a loop that primes nothing
// returns the first underlying error. Emits {"primed": true, "endpoints": [sorted ids],
// "warnings": [...]}.
func (d *Daemon) primeAuthAll(ctx context.Context, requestor, reason string) (map[string]any, error) {
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	st, err := d.state.Load(ctx)
	if err != nil {
		return nil, err
	}
	locals := make([]state.Endpoint, 0)
	for _, ep := range st.Endpoints() {
		if ep.Host == self {
			locals = append(locals, ep)
		}
	}
	if len(locals) == 0 {
		return nil, &AuthRequired{Msg: "no local browsers are tracked; run cookiesync browser add"}
	}
	sort.Slice(locals, func(i, j int) bool { return locals[i].ID() < locals[j].ID() })

	// Distinct browsers in id-sorted order (each with its first tracked profile) plus
	// every browser's full set of tracked local endpoint ids — all profiles of a browser
	// share one key, so a routed prime bulk-caches the others and the final scan reports
	// them all.
	type browserPrime struct{ browser, profile string }
	var order []browserPrime
	idsByBrowser := map[string][]string{}
	for _, ep := range locals {
		if _, seen := idsByBrowser[ep.Browser]; !seen {
			order = append(order, browserPrime{browser: ep.Browser, profile: ep.Profile})
		}
		idsByBrowser[ep.Browser] = append(idsByBrowser[ep.Browser], string(ep.ID()))
	}

	// Each per-browser prime derives the routed/local split inside its own unified
	// flight, and the loop keys off each flight's ACTUAL consent surface — never a
	// call-start snapshot a mid-call presence flip could stale out. A cold host routes
	// every browser to a live peer (one routed tap each, the routed key bulk-cached
	// under the browser's other tracked profiles); the first flight that evaluates
	// consent locally covers the whole tracked batch behind one sheet, so every later
	// browser rides that grant and anything still cold after it (Missing or denied) is
	// a fail-closed skip — a flip never costs a second sheet or a surprise route.
	var warnings []string
	var firstErr error
	prompted := false
	for _, bp := range order {
		id := endpointID(self, bp.browser, bp.profile)
		_, warm, err := d.cache.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if warm && d.granted(requestor, cookie.BrowserName(bp.browser)) {
			continue
		}
		if prompted {
			warnings = append(warnings, fmt.Sprintf("skip %s: not released by the one-tap batch (missing or denied)", bp.browser))
			continue
		}
		key, surface, err := d.primeAuth(ctx, requestor, bp.browser, bp.profile, reason, releaseLocal)
		if surface == surfaceLocal {
			prompted = true
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			warnings = append(warnings, fmt.Sprintf("skip %s: %v", bp.browser, err))
			continue
		}
		if surface == surfaceRouted {
			ttl := d.effectiveTTL(st.Settings.AuthTTL)
			for _, other := range idsByBrowser[bp.browser] {
				if other == id {
					continue
				}
				if err := d.cache.Put(ctx, other, []byte(key), ttl); err != nil {
					return nil, err
				}
			}
		}
	}

	endpoints := make([]string, 0, len(locals))
	for _, ep := range locals {
		id := string(ep.ID())
		_, warm, err := d.cache.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if warm {
			endpoints = append(endpoints, id)
		}
	}
	if len(endpoints) == 0 {
		return nil, firstErr
	}
	sort.Strings(endpoints)
	reply := map[string]any{"primed": true, "endpoints": endpoints}
	if len(warnings) > 0 {
		reply["warnings"] = warnings
	}
	return reply, nil
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

// handleGetCookies renders cookies for one or more urls, merged into one set. With a
// "browser" param it reads that one endpoint via getCookiesSingle — the frozen
// {"cookies": [...]} path a peer's ssh leg drives. With no "browser" it unions every
// registered endpoint — local browsers and remote hosts over ssh — via getCookiesAll,
// emitting {"cookies": [...], "warnings": [...]}. The recursion guard lives in the CLI:
// the remote leg always sends --browser, so a peer daemon takes the single path and
// never re-fans-out the union over ssh.
func (d *Daemon) handleGetCookies(ctx context.Context, params map[string]any) (any, error) {
	if optionalString(params, "browser", "") == "" {
		urls, err := urlsParam(params)
		if err != nil {
			return nil, err
		}
		return d.getCookiesAll(ctx, requestorID(ctx, params), urls)
	}
	return d.getCookiesSingle(ctx, params)
}

// getCookiesSingle renders one browser's cookies for every url, merged into one set,
// behind the per-requestor consent gate: a warm cached key is served silently only
// inside the requestor's live grant; otherwise the release runs through the one unified
// routing rule (routesConsent) — a hard route or a cold local session routes the gate to
// a live peer, else a live local session prompts one Touch ID sheet, failing closed with
// AuthRequired only when routing finds no live approver. A local caller sends no origin;
// a peer-driven read (origin set, so peerRequestor keys the grant "host:"+origin exactly
// like extract) names the origin in the prompt and routes per this host's own consent
// config when cold — often bouncing the sheet back to the calling Mac, which is by
// design. New CLIs send "urls" (one or more hosts); older ones send a single "url" — both
// are accepted, and every host is decrypted with the same released key (one prime covers
// them all) and unioned by logical identity. Emits the frozen {"cookies": [...]}.
func (d *Daemon) getCookiesSingle(ctx context.Context, params map[string]any) (any, error) {
	browser, err := stringParam(params, "browser")
	if err != nil {
		return nil, err
	}
	profile := optionalString(params, "profile", defaultProfile)
	urls, err := urlsParam(params)
	if err != nil {
		return nil, err
	}
	reason := consentReason
	if origin := optionalString(params, "origin", ""); origin != "" {
		reason = fmt.Sprintf("send them to %s", origin)
	}
	key, _, err := d.primeAuth(ctx, peerRequestor(ctx, params), browser, profile, reason, releaseLocal)
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

// getCookiesAll unions the cookies for every url across every registered endpoint —
// local browsers and remote hosts — best-effort: an endpoint that fails is skipped with
// a per-endpoint warning, and only a total shutout is an error. Zero endpoints at all is
// the AuthRequired backstop (the CLI auto-registers locals first). The local leg runs
// sequentially behind at most one release flight (decision 8): a warm+granted endpoint
// serves from cache; else the first cold endpoint runs one unified release — a live local
// session prompts one sheet and grants the whole local batch (later browsers ride it),
// while a cold session routes consent to a live peer per this host's config — and
// anything still cold after that one flight is a "skip cold" warning. The remote leg fans
// out in parallel over a bounded ssh semaphore — never errgroup, whose first-error cancel
// would abort the best-effort union. Deliberate asymmetry: the all path keys grants by
// the local requestor ladder — it is never peer-driven, since the recursion guard forbids
// a peer re-fanning out — where only the single path is peer-driven and origin-keyed.
// MergeRanked breaks last_update_utc ties for the local machine. Emits
// {"cookies": [...], "warnings": [...]}.
func (d *Daemon) getCookiesAll(ctx context.Context, requestor string, urls []string) (any, error) {
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	st, err := d.state.Load(ctx)
	if err != nil {
		return nil, err
	}
	var locals, remotes []state.Endpoint
	for _, ep := range st.Endpoints() {
		if ep.Host == self {
			locals = append(locals, ep)
			continue
		}
		remotes = append(remotes, ep)
	}
	if len(locals)+len(remotes) == 0 {
		return nil, &AuthRequired{Msg: "no browsers are tracked; run cookiesync browser add"}
	}

	var sets []cookie.RankedSet
	var warnings []string

	// LOCAL leg: sequential, at most one release flight for the whole call. The first
	// cold endpoint runs one unified release (releaseLocal) — a live session prompts once
	// and grants the whole batch (later browsers ride the grant), a cold session routes
	// consent to a live peer — with the routed/local split decided inside the one flight
	// rather than a per-call snapshot a mid-call presence flip could stale out. Anything
	// still cold after that one flight is a "skip cold" warning.
	prompted := false
	for _, ep := range locals {
		id := string(ep.ID())
		name := cookie.BrowserName(ep.Browser)
		cached, warm, err := d.cache.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		var key cookie.AesKey
		switch {
		case warm && d.granted(requestor, name):
			key = cookie.AesKey(cached)
		case !prompted:
			released, _, err := d.primeAuth(ctx, requestor, ep.Browser, ep.Profile, consentReason, releaseLocal)
			prompted = true
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("skip cold %s: run cookiesync auth (%v)", id, err))
				continue
			}
			key = released
		default:
			warnings = append(warnings, fmt.Sprintf("skip cold %s: run cookiesync auth", id))
			continue
		}
		b, err := cookie.Lookup(name)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skip %s: %v", id, err))
			continue
		}
		urlSets := make([][]cookie.Cookie, 0, len(urls))
		for _, url := range urls {
			// fallback=false: only the released key, never the cross-browser sweep — same
			// as the single path.
			extracted, err := cookie.Extract(ctx, url, b, key, ep.Profile, false, false)
			if err != nil {
				urlSets = nil
				warnings = append(warnings, fmt.Sprintf("skip %s: %v", id, err))
				break
			}
			urlSets = append(urlSets, extracted.Cookies)
		}
		if urlSets == nil {
			continue
		}
		sets = append(sets, cookie.RankedSet{Cookies: cookie.Merge(urlSets...), Local: true})
	}

	// REMOTE leg: parallel over a bounded semaphore, best-effort.
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, unionSSHConcurrency)
	for _, ep := range remotes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cookies, err := d.remoteGetCookies(ctx, ep.Host, ep.Browser, ep.Profile, urls)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("skip %s: %v", ep.ID(), err))
				return
			}
			sets = append(sets, cookie.RankedSet{Cookies: cookies, Local: false})
		}()
	}
	wg.Wait()

	if len(sets) == 0 {
		return nil, errors.New("no endpoint contributed cookies; run cookiesync auth")
	}
	reply := cookiesPayload(cookie.MergeRanked(sets...))
	if len(warnings) > 0 {
		reply["warnings"] = warnings
	}
	return reply, nil
}

// remoteGetCookies drives a peer's single-browser get_cookies over ssh and parses the
// wire cookies it streams back, mirroring routedRelease's runner precedent. --browser is
// always sent so the peer daemon takes the single path (the recursion guard), and origin
// is this host's mesh self so the peer's grant keys "host:"+self like extract — the
// first union pull prompts the peer once, then its grant window keeps the rest silent.
// The call gets the extract-style window (DispatchTimeout - 30s): a peer may hold a Touch
// ID sheet open, so a short I/O timeout would kill a legitimate prompt.
func (d *Daemon) remoteGetCookies(ctx context.Context, host, browser, profile string, urls []string) ([]cookie.Cookie, error) {
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	quoted := make([]string, len(urls))
	for i, url := range urls {
		quoted[i] = hostregistry.ShellQuote(url)
	}
	// The "--" end-of-flags marker fences the urls off from the peer's flag parser: a url
	// is untrusted CLI input, and one shaped like a flag (e.g. "--browser=") would
	// otherwise be parsed as one on the peer — defeating the recursion guard or
	// overriding the origin the peer keys its grant on. After "--" every url is a
	// positional, whatever its spelling.
	cmd := fmt.Sprintf(
		"cookiesync rpc get_cookies --browser %s --profile %s --origin %s -- %s",
		hostregistry.ShellQuote(browser), hostregistry.ShellQuote(profile),
		hostregistry.ShellQuote(self), strings.Join(quoted, " "),
	)
	rctx, cancel := context.WithTimeout(ctx, synckit.DispatchTimeout-30*time.Second)
	defer cancel()
	out, err := d.runner.Run(rctx, host, cmd, nil)
	if err != nil {
		return nil, err
	}
	var payload struct {
		Cookies []cookie.WireCookie `json:"cookies"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		return nil, fmt.Errorf("parse rpc get_cookies from %s: %w", host, err)
	}
	cookies := make([]cookie.Cookie, len(payload.Cookies))
	for i, w := range payload.Cookies {
		cookies[i] = cookie.FromWire(w)
	}
	return cookies, nil
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
// never leaves this box. A cold remote mesh fails closed with AuthRequired. The
// returned consentSurface is the gate the covering flight actually used — reported
// even alongside an error once a flight ran, so a caller sequencing primes can tell a
// fired-and-denied local sheet from a failed route and never stacks a second sheet.
// Mirrors the Python prime_auth.
func (d *Daemon) primeAuth(ctx context.Context, requestor, browser, profile, reason string, mode releaseMode) (cookie.AesKey, consentSurface, error) {
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, surfaceNone, err
	}
	id := endpointID(self, browser, profile)
	cached, warm, err := d.cache.Get(ctx, id)
	if err != nil {
		return nil, surfaceNone, err
	}
	if warm && d.granted(requestor, cookie.BrowserName(browser)) {
		return cookie.AesKey(cached), surfaceNone, nil
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
				surface := surfaceNone
				if batch, ok := res.Val.(*batchResult); ok && batch != nil {
					surface = batch.surface
				}
				return nil, surface, res.Err
			}
			batch := res.Val.(*batchResult)
			oc, ok := batch.outcomes[cookie.BrowserName(browser)]
			if !ok {
				continue
			}
			if oc.Err != nil {
				return nil, batch.surface, oc.Err
			}
			if oc.Missing {
				return nil, batch.surface, &cookie.ConsentError{Msg: fmt.Sprintf("could not read %q from the Keychain (denied or missing)", oc.Browser.KeychainService)}
			}
			_, warm, err := d.cache.Get(ctx, id)
			if err != nil {
				return nil, batch.surface, err
			}
			if !warm {
				if err := d.cache.Put(ctx, id, []byte(oc.Key), batch.ttl); err != nil {
					return nil, batch.surface, err
				}
			}
			return oc.Key, batch.surface, nil
		case <-ctx.Done():
			return nil, surfaceNone, ctx.Err()
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

// releaseKey obtains Safe Storage keys behind the presence gate that applies, deriving
// the routed/local split once inside the flight. In releaseLocal mode a hard consent
// route (ConsentRouteHard) to a live ConsentRouteTo peer wins outright — this host routes
// the gate even when it looks locally attended — and a cold local session routes the gate
// to the active peer; a routed approval releases just the requested browser's key. This
// one rule serves every console release — prime, get_cookies, and extract alike — so a
// cold browser-less cookies read routes exactly like auth, and a peer-driven get_cookies
// routes per this host's own config (often back to the calling Mac). Otherwise — and
// always in releaseApprover mode, where this host is the routed gate's terminus and must
// never route onward — the whole local batch releases behind one Touch ID evaluation in
// releaseAllLocal. The prompt gate is never held across routedRelease: an inbound
// request_consent must stay promptable while this host's own outbound route is in flight,
// or the same-host routed-consent cycle deadlocks.
func (d *Daemon) releaseKey(ctx context.Context, st *state.State, requestor, self, id, browser, profile, reason string, mode releaseMode) (*batchResult, error) {
	if mode == releaseLocal {
		routed, err := d.routesConsent(ctx, st)
		if err != nil {
			return nil, err
		}
		if routed {
			return d.routedBatch(ctx, st, requestor, id, browser, profile)
		}
	}
	return d.releaseAllLocal(ctx, st, requestor, self, id, browser, reason)
}

// routesConsent reports whether a releaseLocal prime routes the user-presence gate to a
// peer instead of prompting Touch ID locally: a hard consent route (ConsentRouteHard) to
// a live ConsentRouteTo peer wins outright — this host routes even when it looks locally
// attended — and a cold local session routes to the active peer. It is derived once
// inside each release flight (releaseKey), never snapshotted at call start, so the
// routed/local split a caller observes is always the one its flight actually used.
func (d *Daemon) routesConsent(ctx context.Context, st *state.State) (bool, error) {
	if st.ConsentRouteHard && st.ConsentRouteTo != "" {
		live, err := d.peerIsLive(ctx, st.ConsentRouteTo)
		if err != nil {
			return false, err
		}
		if live {
			return true, nil
		}
	}
	live, err := HasActiveSession(ctx, d.probe)
	if err != nil {
		return false, err
	}
	return !live, nil
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
		surface:  surfaceRouted,
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
// browser's requestor by primeAuth. Every error at or past the consent evaluation
// still carries a surfaceLocal batchResult, so a caller knows a sheet already fired
// and never stacks a second one.
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
		return &batchResult{surface: surfaceLocal}, err
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
				return &batchResult{surface: surfaceLocal}, err
			}
		}
	}
	d.grant(requestor, released, ttl)
	if oc := outcomes[requested]; !oc.Missing && oc.Err == nil {
		if err := d.cache.Put(ctx, id, []byte(oc.Key), ttl); err != nil {
			return &batchResult{surface: surfaceLocal}, err
		}
		_, warm, err := d.cache.Get(ctx, id)
		if err != nil {
			return &batchResult{surface: surfaceLocal}, err
		}
		if !warm {
			if err := d.cache.Put(ctx, id, []byte(oc.Key), ttl); err != nil {
				return &batchResult{surface: surfaceLocal}, err
			}
		}
	}
	return &batchResult{outcomes: outcomes, ttl: ttl, surface: surfaceLocal}, nil
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
