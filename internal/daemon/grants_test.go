package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// TestPrimeAuthGrantsArePerRequestor proves authorization is per requesting principal,
// not global cache warmth: requestor A's tap does not grant requestor B — B's first
// prime over the warm cache prompts its own evaluation — and each is then silent
// inside its own window, until a grant expires and re-prompts.
func TestPrimeAuthGrantsArePerRequestor(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	if _, _, err := d.primeAuth(ctx, "host:h1", "chrome", "Default", consentReason, releaseLocal); err != nil {
		t.Fatalf("A's prime: %v", err)
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("A's cold prime = %d evaluations, want 1", len(consent.batchCalls))
	}
	if !d.granted("host:h1", "chrome") {
		t.Fatalf("A's tap must grant host:h1 chrome")
	}

	if _, _, err := d.primeAuth(ctx, "host:h2", "chrome", "Default", consentReason, releaseLocal); err != nil {
		t.Fatalf("B's prime: %v", err)
	}
	if len(consent.batchCalls) != 2 {
		t.Fatalf("B over the warm cache = %d evaluations, want 2 (A's tap must not grant B)", len(consent.batchCalls))
	}

	if _, _, err := d.primeAuth(ctx, "host:h1", "chrome", "Default", consentReason, releaseLocal); err != nil {
		t.Fatalf("A's repeat prime: %v", err)
	}
	if _, _, err := d.primeAuth(ctx, "host:h2", "chrome", "Default", consentReason, releaseLocal); err != nil {
		t.Fatalf("B's repeat prime: %v", err)
	}
	if len(consent.batchCalls) != 2 {
		t.Fatalf("granted repeats = %d evaluations, want 2 (each requestor is silent inside its window)", len(consent.batchCalls))
	}

	// Re-grant with a negative ttl: the overwrite expires host:h1's grant.
	d.grant("host:h1", []cookie.BrowserName{"chrome"}, -time.Second)
	if _, _, err := d.primeAuth(ctx, "host:h1", "chrome", "Default", consentReason, releaseLocal); err != nil {
		t.Fatalf("A's prime after expiry: %v", err)
	}
	if len(consent.batchCalls) != 3 {
		t.Fatalf("expired grant = %d evaluations, want 3 (an expired grant must re-prompt)", len(consent.batchCalls))
	}
}

// TestExtractOriginThreadsRequestorIdentity proves the optional origin param carries
// the calling peer's identity into the grant table end-to-end: a peer's first pull
// prompts once and grants "host:<origin>", its repeat is silent, a different origin
// over the same warm cache prompts anew, and a call with no origin falls back to the
// local requestor ladder ("local" on a bare test context).
func TestExtractOriginThreadsRequestorIdentity(t *testing.T) {
	ctx := context.Background()
	chromeStoreUnderHome(t)
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	if _, err := d.handleExtract(ctx, map[string]any{"browser": "chrome", "origin": "you@desktop"}); err != nil {
		t.Fatalf("extract with origin: %v", err)
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("first pull = %d evaluations, want 1", len(consent.batchCalls))
	}
	if !d.granted("host:you@desktop", "chrome") {
		t.Fatalf("extract with origin must grant host:you@desktop chrome")
	}

	if _, err := d.handleExtract(ctx, map[string]any{"browser": "chrome", "origin": "you@desktop"}); err != nil {
		t.Fatalf("repeat extract with origin: %v", err)
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("same-origin repeat = %d evaluations, want 1 (silent inside the window)", len(consent.batchCalls))
	}

	if _, err := d.handleExtract(ctx, map[string]any{"browser": "chrome", "origin": "them@mini"}); err != nil {
		t.Fatalf("extract with a different origin: %v", err)
	}
	if len(consent.batchCalls) != 2 {
		t.Fatalf("new origin over the warm cache = %d evaluations, want 2", len(consent.batchCalls))
	}
	if !d.granted("host:them@mini", "chrome") {
		t.Fatalf("the second pull must grant host:them@mini chrome")
	}

	if _, err := d.handleExtract(ctx, map[string]any{"browser": "chrome"}); err != nil {
		t.Fatalf("extract without origin: %v", err)
	}
	if len(consent.batchCalls) != 3 {
		t.Fatalf("originless extract = %d evaluations, want 3 (an old peer falls back to the local ladder)", len(consent.batchCalls))
	}
	if !d.granted("local", "chrome") {
		t.Fatalf("an originless extract on a bare context must grant local chrome")
	}
}

// TestGetCookiesUngrantedRequestorPromptsThenSilent proves get_cookies joined the
// per-requestor gate: a warm cache with no grant still prompts — that is the point —
// and the same requestor's next call inside the window is silent.
func TestGetCookiesUngrantedRequestorPromptsThenSilent(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	seed := []cookie.Cookie{
		{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 1, IsSecure: true, SourceScheme: 2, SourcePort: 443},
	}
	if _, err := cookie.Apply(ctx, seed, browser, "Default", key); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "")
	consent := &fakeConsent{key: key}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	_, _ = cache.Put(ctx, endpointID(self, "chrome", "Default"), []byte(key), 0)

	got, err := d.handleGetCookies(ctx, map[string]any{"browser": "chrome", "url": "https://x.com/"})
	if err != nil {
		t.Fatalf("handleGetCookies: %v", err)
	}
	if cookies := wireCookieNames(t, got); cookies["sid"].Value != "abc" {
		t.Fatalf("get_cookies = %+v, want sid=abc", cookies)
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("ungranted get_cookies over a warm cache = %d evaluations, want 1 (warmth alone must not serve)", len(consent.batchCalls))
	}

	if _, err := d.handleGetCookies(ctx, map[string]any{"browser": "chrome", "url": "https://x.com/"}); err != nil {
		t.Fatalf("repeat handleGetCookies: %v", err)
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("granted repeat = %d evaluations, want 1 (silent inside the window)", len(consent.batchCalls))
	}
}

// TestRequestorID proves the local requestor ladder: an explicit requestor token wins
// ("req:" + token) and a bare context with no token and no socket peer is "local".
// requestorID never reads origin — that is the forgery guard, pinned here by the
// "forged origin is ignored" case. The socket peer's "sid:" rung is proven end-to-end
// over a real transport in TestPeerSIDRequestorOverSocket, since a session-carrying
// ctx can only come from Serve.
func TestRequestorID(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"requestor token wins", map[string]any{"requestor": "claude"}, "req:claude"},
		{"forged origin is ignored", map[string]any{"origin": "you@desktop"}, "local"},
		{"empty requestor falls through", map[string]any{"requestor": ""}, "local"},
		{"no requestor no sid is local", map[string]any{}, "local"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := requestorID(context.Background(), tc.params); got != tc.want {
				t.Fatalf("requestorID(%v) = %q, want %q", tc.params, got, tc.want)
			}
		})
	}
}

// TestPeerRequestor proves the origin-honoring requestor for the one method a peer
// drives (extract): a forwarded origin wins ("host:" + origin), and with no origin it
// falls back to the local requestorID ladder — a requestor token, else "local".
func TestPeerRequestor(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"origin wins", map[string]any{"origin": "you@desktop"}, "host:you@desktop"},
		{"empty origin falls to the local ladder", map[string]any{"origin": ""}, "local"},
		{"no origin uses the requestor token", map[string]any{"requestor": "claude"}, "req:claude"},
		{"no origin no token is local", map[string]any{}, "local"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := peerRequestor(context.Background(), tc.params); got != tc.want {
				t.Fatalf("peerRequestor(%v) = %q, want %q", tc.params, got, tc.want)
			}
		})
	}
}

// TestPrimeAuthForgedOriginCannotRideHostGrant is the forgery regression for the local
// prime path: a same-uid caller that forges an origin param must not resolve to
// "host:<forged>" and ride a live host grant. With the endpoint pre-warmed AND a live
// "host:evil" grant planted, prime_auth with origin=evil still forces a fresh consent
// evaluation — it resolves to the local ladder, never the forged host.
func TestPrimeAuthForgedOriginCannotRideHostGrant(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "")
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	consent := &fakeConsent{key: key}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	_, _ = cache.Put(ctx, endpointID(self, "chrome", "Default"), []byte(key), 0)
	d.grant("host:evil", []cookie.BrowserName{"chrome"}, time.Hour)

	if _, err := d.handlePrimeAuth(ctx, map[string]any{"browser": "chrome", "origin": "evil"}); err != nil {
		t.Fatalf("handlePrimeAuth forged origin: %v", err)
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("forged-origin prime = %d evaluations, want 1 (a warm cache and a host:evil grant must not serve a forged origin)", len(consent.batchCalls))
	}
	if !d.granted("local", "chrome") {
		t.Fatalf("the forged-origin prime must resolve to the local requestor and grant local:chrome")
	}
}

// TestGetCookiesUnionForgedOriginCannotRideHostGrant is the forgery regression for the
// browser-less union path. That path is never peer-driven — the recursion guard forbids
// a peer re-fanning out — so it resolves the requestor via the origin-blind requestorID
// ladder, and a same-uid caller that forges an origin must not ride a live host grant
// over a warm cache. Despite a pre-warmed key and a live "host:evil" grant, a union
// get_cookies with origin=evil forces its own consent evaluation for the local endpoint
// and grants only the local requestor. The single path's peer-driven origin trust (the
// extract envelope, decision 7) is the deliberate asymmetry, pinned separately by
// TestGetCookiesSinglePeerDrivenGrantKeysOrigin.
func TestGetCookiesUnionForgedOriginCannotRideHostGrant(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	seed := []cookie.Cookie{
		{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 1, IsSecure: true, SourceScheme: 2, SourcePort: 443},
	}
	if _, err := cookie.Apply(ctx, seed, browser, "Default", key); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "", stateEndpoint(self, "chrome", "Default"))
	consent := &fakeConsent{key: key}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	_, _ = cache.Put(ctx, endpointID(self, "chrome", "Default"), []byte(key), 0)
	d.grant("host:evil", []cookie.BrowserName{"chrome"}, time.Hour)

	got, err := d.handleGetCookies(ctx, map[string]any{"url": "https://x.com/", "origin": "evil"})
	if err != nil {
		t.Fatalf("handleGetCookies union forged origin: %v", err)
	}
	if cookies := wireCookieNames(t, got); cookies["sid"].Value != "abc" {
		t.Fatalf("get_cookies = %+v, want sid=abc", cookies)
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("forged-origin union get_cookies = %d evaluations, want 1 (a warm cache and a host:evil grant must not serve a forged origin)", len(consent.batchCalls))
	}
	if !d.granted("local", "chrome") {
		t.Fatalf("the forged-origin union get_cookies must resolve to the local requestor and grant local:chrome")
	}
}
