package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
)

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
// priming the cache behind consent first when it is cold (so a peer's pull does not
// fail on a cold key). Emits the frozen {"cookies": [...]}.
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
	id := endpointID(self, browser, profile)
	if _, ok, err := d.cache.Get(ctx, id); err != nil {
		return nil, err
	} else if !ok {
		if _, err := d.primeAuth(ctx, browser, profile, consentReason); err != nil {
			return nil, err
		}
	}
	extracted, err := engine.NewCachedKeySource(d.cache, self).Extract(ctx, browser, profile)
	if err != nil {
		return nil, err
	}
	return cookiesPayload(extracted.Cookies), nil
}

// handleApply ingests a merged wire cookie array and writes it to this host's store,
// recording the anti-echo digest before the write so the induced filesystem event is
// recognized as the daemon's own echo. Emits the frozen {"applied": int}.
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
	d.engine.Recorder().RecordApplied(endpointID(self, browser, profile), cookie.LogicalDigest(cookies))
	applied, err := engine.NewCachedKeySource(d.cache, self).Apply(ctx, browser, profile, cookies)
	if err != nil {
		return nil, err
	}
	return map[string]any{"applied": applied}, nil
}

// handleWhoami reports this host's console session state, the frozen
// {"on_console", "locked", "console_user"} shape.
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
	if _, err := d.primeAuth(ctx, browser, profile, reason); err != nil {
		return nil, err
	}
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{"primed": true, "endpoint": endpointID(self, browser, profile)}, nil
}

// handleAuthStatus reports whether the endpoint's key is warm in the cache, the frozen
// {"endpoint", "authenticated"} shape.
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
	return map[string]any{"endpoint": id, "authenticated": ok}, nil
}

// handleGetCookies renders one or more urls' cookies from the cached key, merged into
// one set, failing closed with AuthRequired when the cache is cold. New CLIs send
// "urls" (one or more hosts); older ones send a single "url" — both are accepted, and
// every host is decrypted with the same cached key (no extra prompt) and unioned by
// logical identity. Emits the frozen {"cookies": [...]}.
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
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	id := endpointID(self, browser, profile)
	key, ok, err := d.cache.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &AuthRequired{Msg: fmt.Sprintf("no cached key for %s; run cookiesync auth", id)}
	}
	b, err := cookie.Lookup(cookie.BrowserName(browser))
	if err != nil {
		return nil, err
	}
	sets := make([][]cookie.Cookie, 0, len(urls))
	for _, url := range urls {
		// fallback=false: the merge pass uses only the cached key, never the
		// cross-browser get-cookie sweep, so a get_cookies call never prompts.
		extracted, err := cookie.Extract(ctx, url, b, cookie.AesKey(key), profile, false, false)
		if err != nil {
			return nil, err
		}
		sets = append(sets, extracted.Cookies)
	}
	return cookiesPayload(cookie.Merge(sets...)), nil
}

// primeAuth obtains the Safe Storage key and caches it under the endpoint's TTL. A
// live local session releases it behind one Touch ID tap here; otherwise the
// user-presence check is routed to the active peer, and on a verified approval this
// host releases its own key non-interactively — the key never leaves this box. A cold
// remote mesh fails closed with AuthRequired. Mirrors the Python prime_auth.
func (d *Daemon) primeAuth(ctx context.Context, browser, profile, reason string) (cookie.AesKey, error) {
	st, err := d.state.Load(ctx)
	if err != nil {
		return nil, err
	}
	b, err := cookie.Lookup(cookie.BrowserName(browser))
	if err != nil {
		return nil, err
	}
	live, err := HasActiveSession(ctx, d.probe)
	if err != nil {
		return nil, err
	}
	var key cookie.AesKey
	if live {
		key, err = d.consent.ObtainKey(ctx, b, reason)
	} else {
		key, err = d.routedRelease(ctx, b, browser, profile)
	}
	if err != nil {
		return nil, err
	}
	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	id := endpointID(self, browser, profile)
	if err := d.cache.Put(ctx, id, []byte(key), st.Settings.AuthTTL); err != nil {
		return nil, err
	}
	return key, nil
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
