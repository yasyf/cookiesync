package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os/user"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
)

// liveSession is a snapshot of a real person at the keyboard: on console, unlocked.
// The console user is filled in per-test from the current user so HasActiveSession is
// true.
func liveSession(user string) SessionSnapshot {
	return SessionSnapshot{OnConsole: true, Locked: false, ConsoleUser: user}
}

// marshalResult renders a handler's result the way the wire transport does (one JSON
// object), so a test asserts the exact bytes a peer would read.
func marshalResult(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	return string(data)
}

// TestRenderLocalKeyWarningClassifiesFailures pins the distinct operator guidance for
// retryable, declined, and fatal local release outcomes.
func TestRenderLocalKeyWarningClassifiesFailures(t *testing.T) {
	endpoint := "me@laptop:chrome:Default"
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "unavailable",
			err:  &AuthRequired{Msg: "no live approver"},
			want: "skip cold me@laptop:chrome:Default: run cookiesync auth (no live approver)",
		},
		{
			name: "denied",
			err:  &cookie.ConsentError{Msg: "user declined"},
			want: "skip cold me@laptop:chrome:Default: consent declined (user declined)",
		},
		{
			name: "fatal",
			err:  errors.New("unknown browser"),
			want: "skip cold me@laptop:chrome:Default: unknown browser",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderLocalKeyWarning(endpoint, tc.err); got != tc.want {
				t.Fatalf("renderLocalKeyWarning() = %q, want %q", got, tc.want)
			}
		})
	}
}

type countingStateLoader struct {
	st    *state.State
	loads int
}

func (s *countingStateLoader) Load(context.Context) (*state.State, error) {
	s.loads++
	return s.st, nil
}

// TestGetCookiesAllUsesOneStateSnapshot proves the endpoint list and local key sweep
// consume the same state load instead of observing two independently loaded snapshots.
func TestGetCookiesAllUsesOneStateSnapshot(t *testing.T) {
	ctx := context.Background()
	browser := chromeStoreUnderHome(t)
	key := cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))
	seed := []cookie.Cookie{{HostKey: "x.com", Name: "sid", Value: "abc", Path: "/", LastUpdateUTC: 13_350_000_000_000_000, SameSite: 2, IsSecure: true, SourceScheme: 2, SourcePort: 443}}
	if _, err := cookie.Apply(ctx, seed, browser, "Default", key); err != nil {
		t.Fatalf("seed apply: %v", err)
	}

	self := "me@laptop"
	fakeMesh(t, self)
	loader := &countingStateLoader{st: stateWith(self, "", stateEndpoint(self, "chrome", "Default"))}
	cache := newFakeCache()
	d := New(&fakeConsent{key: key}, cache, nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, loader, fixedState{st: loader.st})
	_, _ = cache.Put(ctx, endpointID(self, "chrome", "Default"), []byte(key), 0)
	d.grant("local", []cookie.BrowserName{"chrome"}, time.Hour)

	got, err := d.handleGetCookies(ctx, map[string]any{"url": "https://x.com/"})
	if err != nil {
		t.Fatalf("handleGetCookies union: %v", err)
	}
	if loader.loads != 1 {
		t.Fatalf("state loads = %d, want one shared snapshot", loader.loads)
	}
	if cookies := wireCookieNames(t, got); cookies["sid"].Value != "abc" {
		t.Fatalf("union cookies = %+v, want sid=abc", cookies)
	}
}

// TestHandleWhoamiWireShape proves whoami emits exactly the frozen
// {"on_console", "locked", "console_user"} keys, with console_user null when headless
// and a string when a GUI session is attached.
func TestHandleWhoamiWireShape(t *testing.T) {
	tests := []struct {
		name string
		snap SessionSnapshot
		want string
	}{
		{
			name: "live unlocked console",
			snap: SessionSnapshot{OnConsole: true, Locked: false, ConsoleUser: "alice"},
			want: `{"console_user":"alice","locked":false,"on_console":true,"screen_shared":false}`,
		},
		{
			name: "locked console",
			snap: SessionSnapshot{OnConsole: true, Locked: true, ConsoleUser: "alice"},
			want: `{"console_user":"alice","locked":true,"on_console":true,"screen_shared":false}`,
		},
		{
			name: "headless: console_user is null",
			snap: SessionSnapshot{OnConsole: false, Locked: false, ConsoleUser: ""},
			want: `{"console_user":null,"locked":false,"on_console":false,"screen_shared":false}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := New(&fakeConsent{}, newFakeCache(), nil, staticProbe(tc.snap), &recordingRunner{}, fixedState{}, fixedState{})
			got, err := d.handleWhoami(context.Background(), map[string]any{})
			if err != nil {
				t.Fatalf("handleWhoami: %v", err)
			}
			if marshalResult(t, got) != tc.want {
				t.Fatalf("whoami = %s, want %s", marshalResult(t, got), tc.want)
			}
		})
	}
}

// TestSessionSummaryNullsConsoleUserWhenHeadless proves the whoami summary maps an
// absent console user to a JSON null (a nil any), not an empty string.
func TestSessionSummaryNullsConsoleUserWhenHeadless(t *testing.T) {
	got, err := sessionSummary(context.Background(), staticProbe(SessionSnapshot{OnConsole: false}))
	if err != nil {
		t.Fatalf("sessionSummary: %v", err)
	}
	if got["console_user"] != nil {
		t.Fatalf("console_user = %v, want nil", got["console_user"])
	}
}

// TestHandleAuthStatusWireShape proves auth_status reports cache warmth, degradation, and
// keybag availability under the frozen {"endpoint", "authenticated", "degraded", "locked"}
// shape (alphabetical keys): authenticated once a key is cached, degraded over a
// memory-wrapped cache, and locked whenever the daemon user's keybag is unavailable — the
// screen locked, no console session, or another user on console via fast user switching.
// A presence-refused unwrap is a plain cache miss now (the cache demotes itself), so the
// incident surface is the cold degraded rows.
func TestHandleAuthStatusWireShape(t *testing.T) {
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	id := endpointID("me@laptop", "chrome", "Default")
	me := currentUser(t)
	attended := liveSession(me)
	lockedScreen := SessionSnapshot{OnConsole: true, Locked: true}
	otherUser := SessionSnapshot{OnConsole: true, Locked: false, ConsoleUser: me + "-other"}

	tests := []struct {
		name     string
		warm     bool
		degraded bool
		snap     SessionSnapshot
		want     string
	}{
		{
			name: "attended cold healthy",
			snap: attended,
			want: `{"authenticated":false,"degraded":false,"endpoint":"me@laptop:chrome:Default","keybag_locked":false}`,
		},
		{
			name: "attended warm healthy",
			warm: true,
			snap: attended,
			want: `{"authenticated":true,"degraded":false,"endpoint":"me@laptop:chrome:Default","keybag_locked":false}`,
		},
		{
			name:     "attended warm degraded",
			warm:     true,
			degraded: true,
			snap:     attended,
			want:     `{"authenticated":true,"degraded":true,"endpoint":"me@laptop:chrome:Default","keybag_locked":false}`,
		},
		{
			name: "warm healthy locked screen",
			warm: true,
			snap: lockedScreen,
			want: `{"authenticated":true,"degraded":false,"endpoint":"me@laptop:chrome:Default","keybag_locked":true}`,
		},
		{
			name:     "degraded locked screen",
			degraded: true,
			snap:     lockedScreen,
			want:     `{"authenticated":false,"degraded":true,"endpoint":"me@laptop:chrome:Default","keybag_locked":true}`,
		},
		{
			name:     "cold degraded fast user switching",
			degraded: true,
			snap:     otherUser,
			want:     `{"authenticated":false,"degraded":true,"endpoint":"me@laptop:chrome:Default","keybag_locked":true}`,
		},
		{
			name:     "cold degraded session-absent console",
			degraded: true,
			snap:     SessionSnapshot{},
			want:     `{"authenticated":false,"degraded":true,"endpoint":"me@laptop:chrome:Default","keybag_locked":true}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newFakeCache()
			c.degraded = tc.degraded
			if tc.warm {
				_, _ = c.Put(context.Background(), id, []byte("k"), 0)
			}
			d := New(&fakeConsent{}, c, nil, staticProbe(tc.snap), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
			got, err := d.handleAuthStatus(context.Background(), map[string]any{"browser": "chrome"})
			if err != nil {
				t.Fatalf("handleAuthStatus: %v", err)
			}
			if marshalResult(t, got) != tc.want {
				t.Fatalf("auth_status = %s, want %s", marshalResult(t, got), tc.want)
			}
		})
	}
}

// TestHandleAuthStatusPropagatesGetErrors proves the swallow is narrow: only a read
// that outran authStatusTimeout is reported as unauthenticated; any real Get error
// propagates raw, attended or locked alike.
func TestHandleAuthStatusPropagatesGetErrors(t *testing.T) {
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	me := currentUser(t)
	plain := errors.New("cache-unwrap exited 1 (key missing or decrypt failed): boom")

	tests := []struct {
		name   string
		getErr error
		snap   SessionSnapshot
	}{
		{
			name:   "plain error while attended propagates",
			getErr: plain,
			snap:   liveSession(me),
		},
		{
			name:   "plain error while locked propagates",
			getErr: plain,
			snap:   SessionSnapshot{OnConsole: true, Locked: true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := newFakeCache()
			c.getErr = tc.getErr
			d := New(&fakeConsent{}, c, nil, staticProbe(tc.snap), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
			_, err := d.handleAuthStatus(context.Background(), map[string]any{"browser": "chrome"})
			if !errors.Is(err, tc.getErr) {
				t.Fatalf("handleAuthStatus err = %v, want it to carry %v", err, tc.getErr)
			}
		})
	}
}

// TestHandleAuthStatusPropagatesProbeError proves a session-probe failure fails the whole
// call loudly, with no reply, rather than defaulting the keybag state.
func TestHandleAuthStatusPropagatesProbeError(t *testing.T) {
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	probeErr := errors.New("run ioreg: boom")
	probe := func(context.Context) (SessionSnapshot, error) { return SessionSnapshot{}, probeErr }
	d := New(&fakeConsent{}, newFakeCache(), nil, probe, &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handleAuthStatus(context.Background(), map[string]any{"browser": "chrome"})
	if !errors.Is(err, probeErr) {
		t.Fatalf("handleAuthStatus err = %v, want it to carry the probe error %v", err, probeErr)
	}
	if got != nil {
		t.Fatalf("handleAuthStatus returned a reply %v alongside the probe error", got)
	}
}

// TestHandlePrimeAuthLiveSession proves prime_auth with a live local session prompts
// Touch ID once with the given reason, caches the key under the endpoint, and returns
// the frozen {"primed": true, "endpoint": str}.
func TestHandlePrimeAuthLiveSession(t *testing.T) {
	me := currentUser(t)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	cache := newFakeCache()
	st := stateWith("me@laptop", "")
	fakeMesh(t, "me@laptop")
	d := New(consent, cache, nil, staticProbe(liveSession(me)), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handlePrimeAuth(context.Background(), map[string]any{"browser": "chrome", "reason": "post a tweet"})
	if err != nil {
		t.Fatalf("handlePrimeAuth: %v", err)
	}
	if marshalResult(t, got) != `{"endpoint":"me@laptop:chrome:Default","primed":true}` {
		t.Fatalf("prime_auth = %s", marshalResult(t, got))
	}
	if len(consent.promptedReasons) != 1 || consent.promptedReasons[0] != "post a tweet" {
		t.Fatalf("prompted reasons = %v, want one [post a tweet]", consent.promptedReasons)
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("a live session must not use the unprompted release")
	}
	id := endpointID("me@laptop", "chrome", "Default")
	if _, ok, _ := cache.Get(context.Background(), id); !ok {
		t.Fatalf("prime_auth did not cache the key under %s", id)
	}
}

// TestHandlePrimeAuthDefaultReason proves prime_auth falls back to the frozen consent
// reason when the caller sends none.
func TestHandlePrimeAuthDefaultReason(t *testing.T) {
	me := currentUser(t)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	fakeMesh(t, "me@laptop")
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(me)), &recordingRunner{}, fixedState{st: stateWith("me@laptop", "")}, fixedState{st: stateWith("me@laptop", "")})

	if _, err := d.handlePrimeAuth(context.Background(), map[string]any{"browser": "chrome"}); err != nil {
		t.Fatalf("handlePrimeAuth: %v", err)
	}
	if len(consent.promptedReasons) != 1 || consent.promptedReasons[0] != consentReason {
		t.Fatalf("default reason = %v, want [%q]", consent.promptedReasons, consentReason)
	}
}

// TestHandlePrimeAuthHardRouteOverridesLocalSession proves a hard consent route to a
// live peer wins outright: even with a live local session, prime_auth routes the gate to
// the peer (releasing via the unprompted path) instead of prompting Touch ID locally,
// and still caches the released key under the endpoint.
func TestHandlePrimeAuthHardRouteOverridesLocalSession(t *testing.T) {
	me := currentUser(t)
	self := "me@laptop"
	peer := "you@desktop"
	endpoint := endpointID(self, "chrome", "Default")
	nonce := "hard-route-nonce"

	fakeMesh(t, self, peer)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_consent": approvedReply(t, nonce, endpoint)},
	}
	st := stateWith(self, peer, stateEndpoint(peer, "chrome", "Default"))
	st.ConsentRouteHard = true
	cache := newFakeCache()
	// The LOCAL session is also live — the hard route must still win.
	d := New(consent, cache, nil, staticProbe(liveSession(me)), runner, fixedState{st: st}, fixedState{st: st})
	pinnedNonce(d, nonce)

	got, err := d.handlePrimeAuth(context.Background(), map[string]any{"browser": "chrome"})
	if err != nil {
		t.Fatalf("handlePrimeAuth: %v", err)
	}
	if marshalResult(t, got) != `{"endpoint":"me@laptop:chrome:Default","primed":true}` {
		t.Fatalf("prime_auth = %s", marshalResult(t, got))
	}
	if len(consent.promptedReasons) != 0 {
		t.Fatalf("hard route must not prompt Touch ID locally, got prompts %v", consent.promptedReasons)
	}
	if consent.unpromptedCalled != 1 {
		t.Fatalf("hard route must release via the routed unprompted path exactly once, got %d", consent.unpromptedCalled)
	}
	if _, ok, _ := cache.Get(context.Background(), endpoint); !ok {
		t.Fatalf("prime_auth did not cache the routed key under %s", endpoint)
	}
}

// TestHandlePrimeAuthHardRoutePeerOfflineFallsBackLocal proves a hard route whose target
// is offline does not override local presence: prime_auth falls back to the local Touch
// ID path when this host is attended.
func TestHandlePrimeAuthHardRoutePeerOfflineFallsBackLocal(t *testing.T) {
	me := currentUser(t)
	self := "me@laptop"
	peer := "you@desktop"

	fakeMesh(t, self, peer)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	// The routed target is locked, so peerIsLive is false and the hard route cannot fire.
	runner := &recordingRunner{replies: map[string]string{"cookiesync rpc whoami": deadWhoami}}
	st := stateWith(self, peer, stateEndpoint(peer, "chrome", "Default"))
	st.ConsentRouteHard = true
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(me)), runner, fixedState{st: st}, fixedState{st: st})

	if _, err := d.handlePrimeAuth(context.Background(), map[string]any{"browser": "chrome", "reason": "post a tweet"}); err != nil {
		t.Fatalf("handlePrimeAuth: %v", err)
	}
	if len(consent.promptedReasons) != 1 || consent.promptedReasons[0] != "post a tweet" {
		t.Fatalf("an offline hard-route target must fall back to local Touch ID, got prompts %v", consent.promptedReasons)
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("the local fallback must not use the routed unprompted release, got %d", consent.unpromptedCalled)
	}
	if _, ok, _ := cache.Get(context.Background(), endpointID(self, "chrome", "Default")); !ok {
		t.Fatalf("prime_auth did not cache the locally-released key")
	}
}

// TestHandlePrimeAuthSoftRouteDoesNotOverrideLocalSession is the regression guard for a
// non-hard route: with ConsentRouteHard unset, a live local session still prompts Touch
// ID locally and the routed target is never even probed, exactly as before the override.
func TestHandlePrimeAuthSoftRouteDoesNotOverrideLocalSession(t *testing.T) {
	me := currentUser(t)
	self := "me@laptop"
	peer := "you@desktop"

	fakeMesh(t, self, peer)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	// The peer is live, but the route is soft (ConsentRouteHard defaults false).
	runner := &recordingRunner{replies: map[string]string{"cookiesync rpc whoami": liveWhoami}}
	st := stateWith(self, peer, stateEndpoint(peer, "chrome", "Default"))
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(me)), runner, fixedState{st: st}, fixedState{st: st})

	if _, err := d.handlePrimeAuth(context.Background(), map[string]any{"browser": "chrome", "reason": "local tap"}); err != nil {
		t.Fatalf("handlePrimeAuth: %v", err)
	}
	if len(consent.promptedReasons) != 1 || consent.promptedReasons[0] != "local tap" {
		t.Fatalf("a soft route must not override a live local session, got prompts %v", consent.promptedReasons)
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("a soft route with a live local session must not route, got %d unprompted releases", consent.unpromptedCalled)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("a soft route must not probe the peer when locally attended, got calls %+v", runner.calls)
	}
}

// TestHandleGetCookiesColdCacheFailsClosed proves get_cookies on a cold, unattended
// host with no live peer fails closed with AuthRequired, rather than returning an
// empty set.
func TestHandleGetCookiesColdCacheFailsClosed(t *testing.T) {
	fakeMesh(t, "me@laptop")
	d := New(&fakeConsent{}, newFakeCache(), nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: stateWith("me@laptop", "")}, fixedState{st: stateWith("me@laptop", "")})

	_, err := d.handleGetCookies(context.Background(), map[string]any{"browser": "chrome", "url": "https://x.com"})
	var authErr *AuthRequired
	if !errors.As(err, &authErr) {
		t.Fatalf("get_cookies cold = %v, want *AuthRequired", err)
	}
}

// TestHandleGetWebStorageNoLocalBrowsersFailsClosed proves get_web_storage is the
// local-only backstop: with no tracked local browser it fails closed with AuthRequired
// rather than serving an empty document.
func TestHandleGetWebStorageNoLocalBrowsersFailsClosed(t *testing.T) {
	fakeMesh(t, "me@laptop")
	d := New(&fakeConsent{}, newFakeCache(), nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: stateWith("me@laptop", "")}, fixedState{st: stateWith("me@laptop", "")})

	_, err := d.handleGetWebStorage(context.Background(), map[string]any{"url": "https://x.com"})
	var authErr *AuthRequired
	if !errors.As(err, &authErr) {
		t.Fatalf("get_web_storage with no local browsers = %v, want *AuthRequired", err)
	}
}

// TestHandleGetWebStorageColdUnattendedReturnsNoStorage proves the consent gate: on a
// cold, unattended host with no live peer, get_web_storage releases nothing, reads no
// storage (the prime fails before ExtractWebStorage), and returns an empty origins set
// with a skip warning — never leaking web storage without consent, and never prompting
// Touch ID on an unattended host (an unattended release routes, it does not tap).
func TestHandleGetWebStorageColdUnattendedReturnsNoStorage(t *testing.T) {
	fakeMesh(t, "me@laptop")
	consent := &fakeConsent{}
	st := stateWith("me@laptop", "", stateEndpoint("me@laptop", "chrome", "Default"))
	d := New(consent, newFakeCache(), nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handleGetWebStorage(context.Background(), map[string]any{"url": "https://x.com"})
	if err != nil {
		t.Fatalf("get_web_storage cold: %v", err)
	}
	reply, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("get_web_storage reply = %T, want map[string]any", got)
	}
	origins, ok := reply["origins"].([]cookie.WireOrigin)
	if !ok {
		t.Fatalf("origins = %T, want []cookie.WireOrigin", reply["origins"])
	}
	if len(origins) != 0 {
		t.Fatalf("cold get_web_storage leaked %d origins without consent", len(origins))
	}
	if reply["warnings"] == nil {
		t.Fatalf("cold get_web_storage should warn about the skipped endpoint")
	}
	if len(consent.promptedReasons) != 0 {
		t.Fatalf("an unattended host must route consent, not prompt Touch ID; got %v", consent.promptedReasons)
	}
}

// TestHandleGetWebStorageSingleColdFailsClosed proves the browser-scoped path fails
// closed: a cold, unattended host with no live peer returns AuthRequired rather than
// serving one browser's web storage without consent.
func TestHandleGetWebStorageSingleColdFailsClosed(t *testing.T) {
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "", stateEndpoint("me@laptop", "chrome", "Default"))
	d := New(&fakeConsent{}, newFakeCache(), nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	_, err := d.handleGetWebStorage(context.Background(), map[string]any{"browser": "chrome", "url": "https://x.com"})
	var authErr *AuthRequired
	if !errors.As(err, &authErr) {
		t.Fatalf("browser-scoped get_web_storage cold = %v, want *AuthRequired", err)
	}
}

// TestGetCookiesDualURLField proves get_cookies accepts both the new "urls" list and
// the legacy single "url" field (the dual-field backward-compat contract).
func TestGetCookiesDualURLField(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]any
		want   []string
	}{
		{"urls list wins", map[string]any{"urls": []any{"https://a.com", "https://b.com"}, "url": "https://ignored.com"}, []string{"https://a.com", "https://b.com"}},
		{"single url fallback", map[string]any{"url": "https://only.com"}, []string{"https://only.com"}},
		{"empty urls falls back to url", map[string]any{"urls": []any{}, "url": "https://fallback.com"}, []string{"https://fallback.com"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := urlsParam(tc.params)
			if err != nil {
				t.Fatalf("urlsParam: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("urls = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("urls[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestGetCookiesRequiresURL proves get_cookies errors when neither url nor urls is
// present, rather than serving an empty document.
func TestGetCookiesRequiresURL(t *testing.T) {
	if _, err := urlsParam(map[string]any{"browser": "chrome"}); err == nil {
		t.Fatalf("urlsParam with no url/urls should error")
	}
}

// currentUser returns this process's username, the console user a live session must
// match for HasActiveSession.
func currentUser(t *testing.T) string {
	t.Helper()
	me, err := user.Current()
	if err != nil {
		t.Fatalf("resolve current user: %v", err)
	}
	return me.Username
}

// stateEndpoint builds a tracked endpoint for the test mesh.
func stateEndpoint(host, browser, profile string) state.Endpoint {
	return state.Endpoint{Host: host, Browser: browser, Profile: profile}
}

// primeAllReply decodes the browser-less prime_auth wire shape.
type primeAllReply struct {
	Primed    bool     `json:"primed"`
	Endpoints []string `json:"endpoints"`
	Warnings  []string `json:"warnings"`
}

// decodePrimeAll renders a handler result through the wire transport and decodes the
// all-mode prime_auth reply, asserting the envelope shape.
func decodePrimeAll(t *testing.T, result any) primeAllReply {
	t.Helper()
	var reply primeAllReply
	if err := json.Unmarshal([]byte(marshalResult(t, result)), &reply); err != nil {
		t.Fatalf("decode prime_auth all reply: %v", err)
	}
	return reply
}

// TestPrimeAuthAllLivePrimesEveryBrowserInOneEvaluation proves the browser-less
// prime_auth over a live session runs exactly ONE consent evaluation covering every
// tracked local browser and reports every tracked local endpoint id (all profiles
// warmed by the single batch), never a peer endpoint.
func TestPrimeAuthAllLivePrimesEveryBrowserInOneEvaluation(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(
		self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "chrome", "Work"),
		stateEndpoint(self, "arc", "Default"),
		stateEndpoint("you@desktop", "chrome", "Default"),
	)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handlePrimeAuth(ctx, map[string]any{})
	if err != nil {
		t.Fatalf("handlePrimeAuth all: %v", err)
	}
	reply := decodePrimeAll(t, got)
	if !reply.Primed {
		t.Fatalf("primed = false, want true")
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("consent evaluations = %d, want 1 (all-mode over a live session costs one sheet)", len(consent.batchCalls))
	}
	want := []string{
		endpointID(self, "arc", "Default"),
		endpointID(self, "chrome", "Default"),
		endpointID(self, "chrome", "Work"),
	}
	if !slices.Equal(reply.Endpoints, want) {
		t.Fatalf("endpoints = %v, want %v (every tracked local endpoint, sorted)", reply.Endpoints, want)
	}
	if len(reply.Warnings) != 0 {
		t.Fatalf("warnings = %v, want none", reply.Warnings)
	}
	for _, id := range want {
		if _, ok, _ := cache.Get(ctx, id); !ok {
			t.Errorf("endpoint %s not warmed by the all-mode prime", id)
		}
	}
	if _, ok, _ := cache.Get(ctx, endpointID("you@desktop", "chrome", "Default")); ok {
		t.Errorf("a peer endpoint must never be warmed by a local all-mode prime")
	}
}

// TestPrimeAuthAllMissingBrowserWarnsWithoutSecondSheet proves the never-a-second-sheet
// invariant: when the one batch reports a browser Missing, the all-mode prime surfaces a
// warning naming it and still runs exactly ONE consent evaluation, priming the released
// browser.
func TestPrimeAuthAllMissingBrowserWarnsWithoutSecondSheet(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(
		self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "arc", "Default"),
	)
	consent := &partialGateConsent{
		key:     cookie.DeriveKey(cookie.SafeStorageKey("peanuts")),
		failFor: "arc",
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	close(consent.release)
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handlePrimeAuth(ctx, map[string]any{})
	if err != nil {
		t.Fatalf("handlePrimeAuth all: %v", err)
	}
	reply := decodePrimeAll(t, got)
	if n := consent.batches.Load(); n != 1 {
		t.Fatalf("consent evaluations = %d, want 1 (a Missing browser must not start a second sheet)", n)
	}
	if !slices.Equal(reply.Endpoints, []string{endpointID(self, "chrome", "Default")}) {
		t.Fatalf("endpoints = %v, want only the released chrome endpoint", reply.Endpoints)
	}
	if len(reply.Warnings) != 1 || !strings.Contains(reply.Warnings[0], "arc") {
		t.Fatalf("warnings = %v, want one naming arc", reply.Warnings)
	}
	if _, ok, _ := cache.Get(ctx, endpointID(self, "arc", "Default")); ok {
		t.Errorf("the Missing browser must not be warmed")
	}
}

// TestPrimeAuthAllColdRoutesConsentPerBrowser proves the cold-session path: with no live
// local session each per-browser prime re-derives the routed split and routes consent per
// distinct browser to a live peer (one request_consent each, never per profile),
// bulk-caching a browser's other tracked profiles under the routed key.
func TestPrimeAuthAllColdRoutesConsentPerBrowser(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peer := "you@desktop"
	nonce := "all-route-nonce"
	fakeMesh(t, self, peer)
	st := stateWith(
		self, "",
		stateEndpoint(self, "chrome", "Default"),
		stateEndpoint(self, "chrome", "Work"),
		stateEndpoint(self, "arc", "Default"),
	)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies: map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{
			endpointID(self, "arc", "Default"):    approvedReply(t, nonce, endpointID(self, "arc", "Default")),
			endpointID(self, "chrome", "Default"): approvedReply(t, nonce, endpointID(self, "chrome", "Default")),
		},
	}
	cache := newFakeCache()
	// A cold, unattended local session forces the routed path.
	d := New(consent, cache, nil, staticProbe(SessionSnapshot{}), runner, fixedState{st: st}, fixedState{st: st})
	pinnedNonce(d, nonce)

	got, err := d.handlePrimeAuth(ctx, map[string]any{})
	if err != nil {
		t.Fatalf("handlePrimeAuth all cold: %v", err)
	}
	reply := decodePrimeAll(t, got)
	consents := 0
	for _, call := range runner.calls {
		if strings.Contains(call.cmd, "request_consent") {
			consents++
		}
	}
	if consents != 2 {
		t.Fatalf("routed request_consent calls = %d, want 2 (one per distinct browser)", consents)
	}
	if consent.unpromptedCalled != 2 {
		t.Fatalf("routed unprompted releases = %d, want 2 (one per browser)", consent.unpromptedCalled)
	}
	want := []string{
		endpointID(self, "arc", "Default"),
		endpointID(self, "chrome", "Default"),
		endpointID(self, "chrome", "Work"),
	}
	if !slices.Equal(reply.Endpoints, want) {
		t.Fatalf("endpoints = %v, want %v", reply.Endpoints, want)
	}
	if _, ok, _ := cache.Get(ctx, endpointID(self, "chrome", "Work")); !ok {
		t.Errorf("chrome:Work must be warmed by the bulk Put after chrome's routed prime")
	}
}

// TestPrimeAuthAllColdToLiveFlipKeepsOneSheet proves the loop keys off each flight's
// ACTUAL consent surface, never a call-start routing snapshot: the console is cold when
// the call starts — arc's flight routes consent to the live peer — and flips live before
// chrome's flight, which leads exactly ONE local batch (where chrome is Missing). A
// stale routed snapshot would disable the one-sheet guard and let the Missing browser
// fire a second local sheet; here the flip costs one routed approval plus one local
// evaluation, and the Missing browser is a skip warning.
func TestPrimeAuthAllColdToLiveFlipKeepsOneSheet(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peer := "you@desktop"
	nonce := "flip-live-nonce"
	fakeMesh(t, self, peer)
	st := stateWith(
		self, "",
		stateEndpoint(self, "arc", "Default"),
		stateEndpoint(self, "chrome", "Default"),
	)
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts")), missingFor: "chrome"}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_consent": approvedReply(t, nonce, endpointID(self, "arc", "Default"))},
	}
	cache := newFakeCache()
	d := New(consent, cache, nil, flipProbe(SessionSnapshot{}, liveSession(currentUser(t))), runner, fixedState{st: st}, fixedState{st: st})
	pinnedNonce(d, nonce)

	got, err := d.handlePrimeAuth(ctx, map[string]any{})
	if err != nil {
		t.Fatalf("handlePrimeAuth all: %v", err)
	}
	reply := decodePrimeAll(t, got)
	consents := 0
	for _, call := range runner.calls {
		if strings.Contains(call.cmd, "request_consent") {
			consents++
		}
	}
	if consents != 1 {
		t.Fatalf("routed request_consent calls = %d, want 1 (only arc's flight saw the cold console)", consents)
	}
	if consent.unpromptedCalled != 1 {
		t.Fatalf("routed unprompted releases = %d, want 1", consent.unpromptedCalled)
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("local consent evaluations = %d, want 1 (a Missing browser after the flip must never fire a second sheet)", len(consent.batchCalls))
	}
	if !slices.Equal(reply.Endpoints, []string{endpointID(self, "arc", "Default")}) {
		t.Fatalf("endpoints = %v, want only the arc endpoint", reply.Endpoints)
	}
	if len(reply.Warnings) != 1 || !strings.Contains(reply.Warnings[0], "skip chrome") {
		t.Fatalf("warnings = %v, want one skipping chrome", reply.Warnings)
	}
	if _, ok, _ := cache.Get(ctx, endpointID(self, "chrome", "Default")); ok {
		t.Errorf("the Missing browser must not be warmed")
	}
}

// TestPrimeAuthAllHardRouteFlipDoesNotSkipLaterBrowsers proves the mirror flip: the
// hard-route peer is dead when the first flight derives routing — so that flight leads
// ONE local batch covering every tracked browser — and comes alive right after. Later
// browsers ride the batch's grant: none may be skipped as "not released by the one-tap
// batch" (the stale live-at-start snapshot regression), no consent is routed, and the
// batch bulk-caches every profile.
func TestPrimeAuthAllHardRouteFlipDoesNotSkipLaterBrowsers(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peer := "you@desktop"
	nonce := "hard-route-flip-nonce"
	fakeMesh(t, self, peer)
	st := stateWith(
		self, peer,
		stateEndpoint(self, "arc", "Default"),
		stateEndpoint(self, "arc", "Work"),
		stateEndpoint(self, "chrome", "Default"),
	)
	st.ConsentRouteHard = true
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		onceByMethod: map[string]string{"rpc whoami": deadWhoami},
		replies:      map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod:     map[string]string{"request_consent": approvedReply(t, nonce, endpointID(self, "arc", "Default"))},
	}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), runner, fixedState{st: st}, fixedState{st: st})
	pinnedNonce(d, nonce)

	got, err := d.handlePrimeAuth(ctx, map[string]any{})
	if err != nil {
		t.Fatalf("handlePrimeAuth all: %v", err)
	}
	reply := decodePrimeAll(t, got)
	if len(reply.Warnings) != 0 {
		t.Fatalf("warnings = %v, want none (a routed flip must not skip later browsers)", reply.Warnings)
	}
	want := []string{
		endpointID(self, "arc", "Default"),
		endpointID(self, "arc", "Work"),
		endpointID(self, "chrome", "Default"),
	}
	if !slices.Equal(reply.Endpoints, want) {
		t.Fatalf("endpoints = %v, want %v (every tracked endpoint primed by the one batch)", reply.Endpoints, want)
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("local consent evaluations = %d, want 1", len(consent.batchCalls))
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("unprompted releases = %d, want 0 (the dead-peer flight must release locally)", consent.unpromptedCalled)
	}
	for _, call := range runner.calls {
		if strings.Contains(call.cmd, "request_consent") {
			t.Fatalf("no consent may be routed after the local batch covered every browser, got %+v", runner.calls)
		}
	}
}

// TestPrimeAuthAllZeroLocalEndpointsFailsClosed proves the backstop: an all-mode prime
// with no tracked local browser fails closed with AuthRequired.
func TestPrimeAuthAllZeroLocalEndpointsFailsClosed(t *testing.T) {
	self := "me@laptop"
	fakeMesh(t, self, "you@desktop")
	st := stateWith(self, "", stateEndpoint("you@desktop", "chrome", "Default"))
	d := New(&fakeConsent{}, newFakeCache(), nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	_, err := d.handlePrimeAuth(context.Background(), map[string]any{})
	var authErr *AuthRequired
	if !errors.As(err, &authErr) {
		t.Fatalf("all-mode prime with zero local endpoints = %v, want *AuthRequired", err)
	}
}

// TestPrimeAuthAllStaleRescanFailsClosed proves the verification backstop: when every
// release succeeds but a demote staleifies the cache before the final rescan, the
// all-mode prime fails closed with AuthRequired — never an empty {"primed": true}.
func TestPrimeAuthAllStaleRescanFailsClosed(t *testing.T) {
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "", stateEndpoint(self, "chrome", "Default"))
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	cache := &staleRescanCache{fakeCache: newFakeCache()}
	d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handlePrimeAuth(context.Background(), map[string]any{})
	var authErr *AuthRequired
	if !errors.As(err, &authErr) {
		t.Fatalf("all-mode prime with a stale rescan = %v, %v, want *AuthRequired", got, err)
	}
	if cache.putCalls() == 0 {
		t.Fatalf("the release must have cached keys before the rescan went stale")
	}
}
