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

	"github.com/yasyf/cookiesync/internal/auth"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/state"
	consentkit "github.com/yasyf/synckit/consent"
	"github.com/yasyf/synckit/hostregistry"
)

// unionSSHConcurrency bounds the concurrent ssh dials getCookiesAll's remote leg makes,
// so a wide mesh does not open one ssh process per remote endpoint at once.
const unionSSHConcurrency = 4

// unionReadTimeout bounds one peer's get_cookies leg in the browser-less union read; the
// union is a background data-plane read — a wedged peer costs seconds, never the consent
// window, because the peer's own release flight is detached (the broker runs it under
// context.WithoutCancel), so a Touch ID sheet pending there survives the killed ssh and
// the next union pull rides the resulting grant. Mirrors engine's fetchTimeout. A var so
// tests shrink it.
var unionReadTimeout = 15 * time.Second

// brokerKeys adapts the broker's grant-blind cached-key read to the engine's
// KeyCache seam, so the extract/apply data plane reads keys without reaching
// the release machinery.
type brokerKeys struct {
	broker *auth.Broker
}

func (k brokerKeys) Get(ctx context.Context, endpointID string) ([]byte, bool, error) {
	return k.broker.CachedKey(ctx, endpointID)
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
	req := auth.Req{Requestor: peerRequestor(ctx, params), Browser: browser, Profile: profile, Reason: consentReason, Mode: auth.ModeLocal}
	if _, _, err := d.broker.Key(ctx, req); err != nil {
		return nil, err
	}
	extracted, err := engine.NewCachedKeySource(brokerKeys{d.broker}, self).Extract(ctx, browser, profile)
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
	cookies = cookie.FilterSyncable(cookies, float64(time.Now().UnixNano())/1e9)
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	id := endpointID(self, browser, profile)
	defer d.engine.ApplyLock(id).Unlock()
	d.engine.Recorder().RecordApplied(id, cookie.LogicalDigest(cookies))
	applied, err := engine.NewCachedKeySource(brokerKeys{d.broker}, self).Apply(ctx, browser, profile, cookies)
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

// sessionSummary is this host's console session state shaped for the whoami RPC,
// byte-for-byte the Python session_summary. console_user is null (a nil any) when no
// GUI session is attached.
func sessionSummary(ctx context.Context, probe Probe) (map[string]any, error) {
	snapshot, err := probe(ctx)
	if err != nil {
		return nil, err
	}
	var consoleUser any
	if snapshot.ConsoleUser != "" {
		consoleUser = snapshot.ConsoleUser
	}
	return map[string]any{
		"on_console":    snapshot.OnConsole,
		"locked":        snapshot.Locked,
		"console_user":  consoleUser,
		"screen_shared": snapshot.ScreenShared,
	}, nil
}

// handlePrimeAuth obtains the Safe Storage key and caches it under the endpoint TTL.
// With a "browser" param it primes that one endpoint via the broker — behind one Touch
// ID tap when a session is live, else by routing the gate to the active peer — and
// emits the frozen {"primed": true, "endpoint": str}. With no "browser" it primes every
// registered local browser via LocalKeys(PrimeAll), emitting
// {"primed": true, "endpoints": [...], "warnings": [...]}.
func (d *Daemon) handlePrimeAuth(ctx context.Context, params map[string]any) (any, error) {
	reason := optionalString(params, "reason", consentReason)
	browser := optionalString(params, "browser", "")
	if browser == "" {
		return d.primeAuthAll(ctx, requestorID(ctx, params), reason)
	}
	profile := optionalString(params, "profile", defaultProfile)
	req := auth.Req{Requestor: requestorID(ctx, params), Browser: browser, Profile: profile, Reason: reason, Mode: auth.ModeLocal}
	if _, _, err := d.broker.Key(ctx, req); err != nil {
		return nil, err
	}
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"primed": true, "endpoint": endpointID(self, browser, profile)}, nil
}

// primeAuthAll renders the browser-less prime_auth reply from a PrimeAll broker
// sweep: a warning per skipped or failed browser, the verified-warm endpoint ids
// sorted, the frozen {"primed": true, "endpoints": [...], "warnings": [...]}.
func (d *Daemon) primeAuthAll(ctx context.Context, requestor, reason string) (map[string]any, error) {
	outcomes, err := d.broker.LocalKeys(ctx, requestor, reason, auth.PrimeAll)
	if err != nil {
		return nil, err
	}
	var endpoints, warnings []string
	for _, oc := range outcomes {
		switch {
		case oc.Skipped:
			warnings = append(warnings, fmt.Sprintf("skip %s: not released by the one-tap batch (missing or denied)", oc.Browser))
		case oc.Err != nil:
			warnings = append(warnings, fmt.Sprintf("skip %s: %v", oc.Browser, oc.Err))
		}
		endpoints = append(endpoints, oc.Warm...)
	}
	sort.Strings(endpoints)
	reply := map[string]any{"primed": true, "endpoints": endpoints}
	if len(warnings) > 0 {
		reply["warnings"] = warnings
	}
	return reply, nil
}

// handleAuthStatus reports whether the endpoint's key is warm in the cache, whether the
// cache is degraded to process memory, and whether the daemon user's keybag is
// unavailable — the frozen {"endpoint", "authenticated", "degraded", "keybag_locked"}
// shape, rendered from the broker's Status read (which bounds the probe and cache read
// under auth.StatusTimeout so a status query never blocks the caller).
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
	status, err := d.broker.Status(ctx, id)
	if err != nil {
		return nil, err
	}
	return map[string]any{"endpoint": id, "authenticated": status.Authenticated, "degraded": status.Degraded, "keybag_locked": status.KeybagLocked}, nil
}

// handleRequestConsent shows the Touch ID prompt to the person at this machine for the
// requesting endpoint and echoes the requester's nonce + endpoint VERBATIM to bind the
// approval — no key crosses the wire. The approval runs the broker's approver-mode
// release for the requested browser+profile on behalf of the requesting endpoint's
// host, so the same tap warms this host's own cache and grants that host a consent
// window. Returns {"status": "approved", "nonce", "endpoint"} on a live tap,
// {"status": "denied"} when declined, or {"status": "unavailable"} when this host
// cannot approve because it has no live session, a locked keybag, or a broken key
// cache. Other release failures propagate to the RPC caller.
func (d *Daemon) handleRequestConsent(ctx context.Context, params map[string]any) (any, error) {
	browserID, err := stringParam(params, "browser")
	if err != nil {
		return nil, err
	}
	profile := optionalString(params, "profile", defaultProfile)
	nonce, err := stringParam(params, "nonce")
	if err != nil {
		return nil, err
	}
	endpoint, err := stringParam(params, "endpoint")
	if err != nil {
		return nil, err
	}
	host, _, _ := strings.Cut(endpoint, ":")
	req := auth.Req{
		Requestor: "host:" + host,
		Browser:   browserID,
		Profile:   profile,
		Reason:    fmt.Sprintf("sync them to %s", endpoint),
		Mode:      auth.ModeApprover,
	}
	_, _, keyErr := d.broker.Key(ctx, req)
	switch auth.Classify(keyErr) {
	case consentkit.VerdictOK:
		return map[string]any{"status": "approved", "nonce": nonce, "endpoint": endpoint}, nil
	case consentkit.VerdictDenied:
		return map[string]any{"status": "denied"}, nil
	case consentkit.VerdictUnavailable:
		return map[string]any{"status": "unavailable"}, nil
	default:
		return nil, keyErr
	}
}

// handleRequestBridgeConsent approves a routed live-bridge seed for a peer: a
// STRICT biometric prompt (no passcode) to the person here, whose key is
// discarded, echoing the requester's nonce + endpoint VERBATIM to bind the
// approval. No key crosses the wire. Returns {"status":"approved", nonce,
// endpoint} on a live tap, {"status":"denied"} when declined, or
// {"status":"unavailable"} when this host has no live session, a locked keybag,
// or no enrolled bridge vault — so the requester's routing advances to another
// peer. Other release failures propagate to the RPC caller.
func (d *Daemon) handleRequestBridgeConsent(ctx context.Context, params map[string]any) (any, error) {
	browserID, err := stringParam(params, "browser")
	if err != nil {
		return nil, err
	}
	profile := optionalString(params, "profile", defaultProfile)
	nonce, err := stringParam(params, "nonce")
	if err != nil {
		return nil, err
	}
	endpoint, err := stringParam(params, "endpoint")
	if err != nil {
		return nil, err
	}
	host, _, _ := strings.Cut(endpoint, ":")
	approveErr := d.broker.ApproveBridge(ctx, auth.Req{
		Requestor: "host:" + host,
		Browser:   browserID,
		Profile:   profile,
		Origin:    host,
		Mode:      auth.ModeApprover,
	})
	switch auth.ClassifyBridgeApproval(approveErr) {
	case consentkit.VerdictOK:
		return map[string]any{"status": "approved", "nonce": nonce, "endpoint": endpoint}, nil
	case consentkit.VerdictDenied:
		return map[string]any{"status": "denied"}, nil
	case consentkit.VerdictUnavailable:
		return map[string]any{"status": "unavailable"}, nil
	default:
		return nil, approveErr
	}
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
// behind the per-requestor consent gate the broker owns: a warm cached key is served
// silently only inside the requestor's live grant; otherwise the release runs through
// the one unified routing rule, failing closed with AuthRequired only when routing
// finds no live approver. A local caller sends no origin; a peer-driven read (origin
// set, so peerRequestor keys the grant "host:"+origin exactly like extract) names the
// origin in the prompt and routes per this host's own consent config when cold. Every
// host is decrypted with the same released key (one prime covers them all) and unioned
// by logical identity. Emits the exact v1 cookie envelope.
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
	req := auth.Req{Requestor: peerRequestor(ctx, params), Browser: browser, Profile: profile, Reason: reason, Mode: auth.ModeLocal}
	key, _, err := d.broker.Key(ctx, req)
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
// a per-endpoint warning, and only a total shutout is an error. Zero endpoints at all
// is the AuthRequired backstop (the CLI auto-registers locals first). The local leg is
// one LocalKeys(OneFlight) broker sweep — at most one release flight for the whole
// call, everything still cold after it a "skip cold" warning. The remote leg fans out
// in parallel over a bounded ssh semaphore — never errgroup, whose first-error cancel
// would abort the best-effort union. Deliberate asymmetry: the all path keys grants by
// the local requestor ladder — it is never peer-driven, since the recursion guard
// forbids a peer re-fanning out — where only the single path is peer-driven and
// origin-keyed. MergeRanked breaks last_update_utc ties for the local machine. Emits
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
	var remotes []state.Endpoint
	for _, ep := range st.Endpoints() {
		if ep.Host != self {
			remotes = append(remotes, ep)
		}
	}
	outcomes, err := d.broker.LocalKeysWithState(ctx, requestor, consentReason, auth.OneFlight, st)
	if err != nil {
		return nil, err
	}
	if len(outcomes)+len(remotes) == 0 {
		return nil, &consentkit.AuthRequired{Msg: "no browsers are tracked; run cookiesync browser add"}
	}

	var sets []cookie.RankedSet
	var warnings []string

	// LOCAL leg: render the broker sweep — a released or warm key extracts,
	// everything else is a per-endpoint skip warning.
	for _, oc := range outcomes {
		switch {
		case oc.Err != nil:
			warnings = append(warnings, renderLocalKeyWarning(oc.Endpoint, oc.Err))
			continue
		case oc.Skipped:
			warnings = append(warnings, fmt.Sprintf("skip cold %s: run cookiesync auth", oc.Endpoint))
			continue
		}
		b, err := cookie.Lookup(cookie.BrowserName(oc.Browser))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skip %s: %v", oc.Endpoint, err))
			continue
		}
		urlSets := make([][]cookie.Cookie, 0, len(urls))
		for _, url := range urls {
			// fallback=false: only the released key, never the cross-browser
			// sweep — same as the single path.
			extracted, err := cookie.Extract(ctx, url, b, oc.Key, oc.Profile, false, false)
			if err != nil {
				urlSets = nil
				warnings = append(warnings, fmt.Sprintf("skip %s: %v", oc.Endpoint, err))
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
	var pending []string
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
				var peerErr *PeerReadError
				if errors.As(err, &peerErr) {
					warnings = append(warnings, renderPeerReadWarning(string(ep.ID()), peerErr))
					if peerErr.TimedOut {
						pending = append(pending, peerErr.Host)
					}
					return
				}
				warnings = append(warnings, fmt.Sprintf("skip %s: %v", ep.ID(), err))
				return
			}
			sets = append(sets, cookie.RankedSet{Cookies: cookies, Local: false})
		}()
	}
	wg.Wait()

	if len(sets) == 0 {
		return nil, noContributionError(warnings, pending)
	}
	reply := cookiesPayload(cookie.MergeRanked(sets...))
	if len(warnings) > 0 {
		reply["warnings"] = warnings
	}
	return reply, nil
}

// handleGetWebStorage renders the web storage (localStorage + sessionStorage) for one
// or more urls' origins. It is LOCAL-only — no ssh remote fan-out — and consent-gated
// exactly like get_cookies. With a "browser" param it scopes to that one endpoint via
// getWebStorageSingle (so a browser-scoped cookies pull pairs with the SAME browser's
// web storage — never mixing one browser's cookie identity with another's localStorage
// token). With no "browser" it unions every registered local browser via
// getWebStorageAll.
func (d *Daemon) handleGetWebStorage(ctx context.Context, params map[string]any) (any, error) {
	if optionalString(params, "browser", "") == "" {
		return d.getWebStorageAll(ctx, params)
	}
	return d.getWebStorageSingle(ctx, params)
}

// getWebStorageSingle renders one browser's web storage for every url, consent-gated by
// the same broker release getCookiesSingle uses, then DISCARDING the released key — web
// storage is stored unencrypted, so only the consent side-effect (the tap and the
// requestor grant) is needed. It fails closed with AuthRequired when the release does,
// never serving storage without consent. Emits the frozen {"origins": [...]}.
func (d *Daemon) getWebStorageSingle(ctx context.Context, params map[string]any) (any, error) {
	browser, err := stringParam(params, "browser")
	if err != nil {
		return nil, err
	}
	profile := optionalString(params, "profile", defaultProfile)
	urls, err := urlsParam(params)
	if err != nil {
		return nil, err
	}
	req := auth.Req{Requestor: requestorID(ctx, params), Browser: browser, Profile: profile, Reason: consentReason, Mode: auth.ModeLocal}
	if _, _, err := d.broker.Key(ctx, req); err != nil {
		return nil, err
	}
	b, err := cookie.Lookup(cookie.BrowserName(browser))
	if err != nil {
		return nil, err
	}
	origins, err := cookie.ExtractWebStorage(ctx, urls, b, profile)
	if err != nil {
		return nil, err
	}
	return originsPayload(origins), nil
}

// getWebStorageAll unions the web storage for every url across every registered LOCAL
// browser, best-effort. Its consent gate is the same LocalKeys(OneFlight) sweep as
// getCookiesAll's local leg, with every released key DISCARDED — a warm+granted
// endpoint serves silently, anything still cold is a skip warning, and a requestor
// already granted by an earlier get_cookies call rides that grant with no extra tap.
// Origins are folded in endpoint-id order, so an (origin, name) collision resolves
// deterministically to the lowest endpoint id. Emits {"origins": [...], "warnings":
// [...]}.
func (d *Daemon) getWebStorageAll(ctx context.Context, params map[string]any) (any, error) {
	urls, err := urlsParam(params)
	if err != nil {
		return nil, err
	}
	outcomes, err := d.broker.LocalKeys(ctx, requestorID(ctx, params), consentReason, auth.OneFlight)
	if err != nil {
		return nil, err
	}
	if len(outcomes) == 0 {
		return nil, &consentkit.AuthRequired{Msg: "no local browsers are tracked; run cookiesync browser add"}
	}

	acc := map[string]*originAcc{}
	var warnings []string
	for _, oc := range outcomes {
		switch {
		case oc.Err != nil:
			warnings = append(warnings, renderLocalKeyWarning(oc.Endpoint, oc.Err))
			continue
		case oc.Skipped:
			warnings = append(warnings, fmt.Sprintf("skip cold %s: run cookiesync auth", oc.Endpoint))
			continue
		}
		b, err := cookie.Lookup(cookie.BrowserName(oc.Browser))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skip %s: %v", oc.Endpoint, err))
			continue
		}
		origins, err := cookie.ExtractWebStorage(ctx, urls, b, oc.Profile)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skip %s: %v", oc.Endpoint, err))
			continue
		}
		mergeOrigins(acc, origins)
	}
	reply := originsPayload(collectOrigins(acc))
	if len(warnings) > 0 {
		reply["warnings"] = warnings
	}
	return reply, nil
}

// remoteGetCookies drives a peer's single-browser get_cookies over ssh and parses the
// wire cookies it streams back. --browser is always sent so the peer daemon takes the
// single path (the recursion guard), and origin is this host's mesh self so the peer's
// grant keys "host:"+self like extract — the first union pull prompts the peer once,
// then its grant window keeps the rest silent. The call gets a short data-plane bound
// (unionReadTimeout): a peer stuck behind a pending consent is killed in seconds rather
// than held for the whole consent window, because that peer's release flight is
// detached and survives the killed ssh — the approval it earns there makes the next
// union pull silent.
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
	rctx, cancel := context.WithTimeout(ctx, unionReadTimeout)
	defer cancel()
	out, err := d.runner.Run(rctx, host, cmd, nil)
	if err != nil {
		return nil, newPeerReadError(host, errors.Is(rctx.Err(), context.DeadlineExceeded), err)
	}
	cookies, err := cookie.UnmarshalCookies([]byte(out))
	if err != nil {
		return nil, &PeerReadError{Host: host, Err: fmt.Errorf("parse rpc get_cookies: %w", err)}
	}
	return cookies, nil
}

// cookiesPayload is the frozen {"cookies": [...]} envelope a cookie set crosses the
// boundary as, each cookie in the frozen wire shape.
func cookiesPayload(cookies []cookie.Cookie) map[string]any {
	wire := make([]cookie.WireCookie, len(cookies))
	for i, c := range cookies {
		wire[i] = cookie.ToWire(c)
	}
	return map[string]any{"protocol_version": cookie.ProtocolVersion, "cookies": wire}
}

// originAcc unions one origin's web storage across endpoints, first contributor winning
// per entry name so a collision resolves deterministically to the earliest (lowest
// endpoint-id) fold.
type originAcc struct {
	origin      string
	local       []cookie.WebStorageEntry
	session     []cookie.WebStorageEntry
	localSeen   map[string]bool
	sessionSeen map[string]bool
}

// mergeOrigins folds one endpoint's origins into acc, keyed by origin string, keeping the
// first value seen for each (origin, name) pair.
func mergeOrigins(acc map[string]*originAcc, origins []cookie.OriginStorage) {
	for _, o := range origins {
		a := acc[o.Origin]
		if a == nil {
			a = &originAcc{origin: o.Origin, localSeen: map[string]bool{}, sessionSeen: map[string]bool{}}
			acc[o.Origin] = a
		}
		for _, e := range o.LocalStorage {
			if a.localSeen[e.Name] {
				continue
			}
			a.localSeen[e.Name] = true
			a.local = append(a.local, e)
		}
		for _, e := range o.SessionStorage {
			if a.sessionSeen[e.Name] {
				continue
			}
			a.sessionSeen[e.Name] = true
			a.session = append(a.session, e)
		}
	}
}

// collectOrigins flattens acc into an origin-sorted slice with name-sorted entries.
func collectOrigins(acc map[string]*originAcc) []cookie.OriginStorage {
	out := make([]cookie.OriginStorage, 0, len(acc))
	for _, a := range acc {
		sortStorageEntries(a.local)
		sortStorageEntries(a.session)
		out = append(out, cookie.OriginStorage{Origin: a.origin, LocalStorage: a.local, SessionStorage: a.session})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Origin < out[j].Origin })
	return out
}

func sortStorageEntries(entries []cookie.WebStorageEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
}

// originsPayload is the exact v1 web-storage envelope.
func originsPayload(origins []cookie.OriginStorage) map[string]any {
	wire := make([]cookie.WireOrigin, len(origins))
	for i, o := range origins {
		wire[i] = cookie.OriginToWire(o)
	}
	return map[string]any{"protocol_version": cookie.ProtocolVersion, "origins": wire}
}

// wireCookiesParam reads the "cookies" param — a JSON array of wire cookie objects —
// back into the cookie model, re-marshaling the decoded any-tree through the frozen
// wire decoder so the field order and types match the apply contract exactly.
func wireCookiesParam(params map[string]any, key string) ([]cookie.Cookie, error) {
	raw, ok := params[key]
	if !ok {
		return nil, fmt.Errorf("missing required param %q", key)
	}
	protocol, ok := params["protocol_version"]
	if !ok {
		return nil, errors.New("missing required param \"protocol_version\"")
	}
	data, err := json.Marshal(map[string]any{"protocol_version": protocol, "cookies": raw})
	if err != nil {
		return nil, fmt.Errorf("re-encode %q: %w", key, err)
	}
	cookies, err := cookie.UnmarshalCookies(data)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", key, err)
	}
	return cookies, nil
}

// urlsParam reads the exact v1 non-empty "urls" list.
func urlsParam(params map[string]any) ([]string, error) {
	raw, ok := params["urls"].([]any)
	if !ok || len(raw) == 0 {
		return nil, errors.New("get_cookies requires non-empty urls")
	}
	urls := make([]string, len(raw))
	for i, v := range raw {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("urls[%d] is %T, want non-empty string", i, v)
		}
		urls[i] = s
	}
	return urls, nil
}
