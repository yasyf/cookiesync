package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os/user"
	"testing"

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
			want: `{"console_user":"alice","locked":false,"on_console":true}`,
		},
		{
			name: "locked console",
			snap: SessionSnapshot{OnConsole: true, Locked: true, ConsoleUser: "alice"},
			want: `{"console_user":"alice","locked":true,"on_console":true}`,
		},
		{
			name: "headless: console_user is null",
			snap: SessionSnapshot{OnConsole: false, Locked: false, ConsoleUser: ""},
			want: `{"console_user":null,"locked":false,"on_console":false}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := New(&fakeConsent{}, newFakeCache(), nil, staticProbe(tc.snap), &recordingRunner{}, fixedState{})
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

// TestHandleAuthStatusWireShape proves auth_status reports cache warmth under the
// frozen {"endpoint", "authenticated"} shape: true once a key is cached for the
// endpoint, false otherwise.
func TestHandleAuthStatusWireShape(t *testing.T) {
	cache := newFakeCache()
	st := stateWith("me@laptop", "")
	d := New(&fakeConsent{}, cache, nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: st})
	id := endpointID("me@laptop", "chrome", "Default")

	cold, err := d.handleAuthStatus(context.Background(), map[string]any{"browser": "chrome"})
	if err != nil {
		t.Fatalf("auth_status cold: %v", err)
	}
	if got := marshalResult(t, cold); got != `{"authenticated":false,"endpoint":"me@laptop:chrome:Default"}` {
		t.Fatalf("cold auth_status = %s", got)
	}

	_ = cache.Put(context.Background(), id, []byte("k"), 0)
	warm, err := d.handleAuthStatus(context.Background(), map[string]any{"browser": "chrome", "profile": "Default"})
	if err != nil {
		t.Fatalf("auth_status warm: %v", err)
	}
	if got := marshalResult(t, warm); got != `{"authenticated":true,"endpoint":"me@laptop:chrome:Default"}` {
		t.Fatalf("warm auth_status = %s", got)
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
	d := New(consent, cache, nil, staticProbe(liveSession(me)), &recordingRunner{}, fixedState{st: st})

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
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(me)), &recordingRunner{}, fixedState{st: stateWith("me@laptop", "")})

	if _, err := d.handlePrimeAuth(context.Background(), map[string]any{"browser": "chrome"}); err != nil {
		t.Fatalf("handlePrimeAuth: %v", err)
	}
	if len(consent.promptedReasons) != 1 || consent.promptedReasons[0] != consentReason {
		t.Fatalf("default reason = %v, want [%q]", consent.promptedReasons, consentReason)
	}
}

// TestHandleGetCookiesColdCacheFailsClosed proves get_cookies fails closed with
// AuthRequired when no key is cached, rather than prompting or returning an empty set.
func TestHandleGetCookiesColdCacheFailsClosed(t *testing.T) {
	d := New(&fakeConsent{}, newFakeCache(), nil, staticProbe(SessionSnapshot{}), &recordingRunner{}, fixedState{st: stateWith("me@laptop", "")})

	_, err := d.handleGetCookies(context.Background(), map[string]any{"browser": "chrome", "url": "https://x.com"})
	var authErr *AuthRequired
	if !errors.As(err, &authErr) {
		t.Fatalf("get_cookies cold = %v, want *AuthRequired", err)
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
