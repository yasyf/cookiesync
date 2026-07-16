package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// approvedReply is a peer's request_consent JSON echoing nonce and endpoint.
func approvedReply(t *testing.T, nonce, endpoint string) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{"status": "approved", "nonce": nonce, "endpoint": endpoint})
	if err != nil {
		t.Fatalf("marshal approved reply: %v", err)
	}
	return string(data)
}

// liveWhoami is a peer whoami reply for an on-console, unlocked session.
const liveWhoami = `{"on_console":true,"locked":false,"console_user":"peer"}`

// deadWhoami is a peer whoami reply for a locked session.
const deadWhoami = `{"on_console":true,"locked":true,"console_user":"peer"}`

// pinnedNonce wires a daemon's nonce source to a fixed value, so a test can assert the
// approval binds to exactly that nonce.
func pinnedNonce(d *Daemon, nonce string) {
	d.broker.Router.Nonce = func() (string, error) { return nonce, nil }
}

// TestHandleRequestConsentUnavailableWithoutSession proves request_consent returns
// {"status":"unavailable"} when this host has no live session to prompt, and never
// touches the consent gate.
func TestHandleRequestConsentUnavailableWithoutSession(t *testing.T) {
	fakeMesh(t, "me@laptop")
	consent := &fakeConsent{}
	d := New(consent, newFakeCache(), nil, staticProbe(SessionSnapshot{OnConsole: false}), &recordingRunner{}, fixedState{}, fixedState{})

	got, err := d.handleRequestConsent(context.Background(), map[string]any{
		"browser": "chrome", "nonce": "n", "endpoint": "e",
	})
	if err != nil {
		t.Fatalf("handleRequestConsent: %v", err)
	}
	if marshalResult(t, got) != `{"status":"unavailable"}` {
		t.Fatalf("unavailable = %s", marshalResult(t, got))
	}
	if len(consent.promptedReasons) != 0 {
		t.Fatalf("unavailable must not prompt, got %v", consent.promptedReasons)
	}
}

// TestHandleRequestConsentDeniedOnDecline proves a declined Touch ID prompt yields
// {"status":"denied"} with no nonce or endpoint echo.
func TestHandleRequestConsentDeniedOnDecline(t *testing.T) {
	me := currentUser(t)
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	consent := &fakeConsent{obtainErr: &cookie.ConsentError{Msg: "Touch ID authentication was cancelled or denied"}}
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(me)), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handleRequestConsent(context.Background(), map[string]any{
		"browser": "chrome", "nonce": "n", "endpoint": "e",
	})
	if err != nil {
		t.Fatalf("handleRequestConsent: %v", err)
	}
	if marshalResult(t, got) != `{"status":"denied"}` {
		t.Fatalf("denied = %s", marshalResult(t, got))
	}
}

// TestHandleRequestConsentKeybagLockedIsUnavailable proves a keybag-locked release —
// the screen locked between the session probe and the tap — yields
// {"status":"unavailable"}, the retryable reply, never "denied".
func TestHandleRequestConsentKeybagLockedIsUnavailable(t *testing.T) {
	me := currentUser(t)
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	consent := &fakeConsent{obtainErr: &cookie.ConsentError{
		Msg: "the keychain keybag is locked (screen locked or no user present); retry after unlock",
		Err: cookie.ErrKeybagLocked,
	}}
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(me)), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handleRequestConsent(context.Background(), map[string]any{
		"browser": "chrome", "nonce": "n", "endpoint": "e",
	})
	if err != nil {
		t.Fatalf("handleRequestConsent: %v", err)
	}
	if marshalResult(t, got) != `{"status":"unavailable"}` {
		t.Fatalf("keybag locked = %s, want unavailable", marshalResult(t, got))
	}
}

// TestHandleRequestConsentProbeErrorReturnsUnavailable proves a flaky approver-side
// presence probe — the 2s-bounded ioreg exec failing outright — answers
// {"status":"unavailable"} so the requesting host tries the next approver, never a
// raw RPC error that kills its routed release. The consent gate is never reached.
func TestHandleRequestConsentProbeErrorReturnsUnavailable(t *testing.T) {
	fakeMesh(t, "me@laptop")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	probe := func(context.Context) (SessionSnapshot, error) {
		return SessionSnapshot{}, errors.New("ioreg: signal: killed")
	}
	d := New(consent, newFakeCache(), nil, probe, &recordingRunner{}, fixedState{}, fixedState{})

	got, err := d.handleRequestConsent(context.Background(), map[string]any{
		"browser": "chrome", "nonce": "n", "endpoint": "them@host:chrome:Default",
	})
	if err != nil {
		t.Fatalf("handleRequestConsent over a failed probe must not error, got %v", err)
	}
	if marshalResult(t, got) != `{"status":"unavailable"}` {
		t.Fatalf("probe error = %s, want unavailable", marshalResult(t, got))
	}
	if len(consent.promptedReasons) != 0 || len(consent.batchCalls) != 0 {
		t.Fatalf("a failed probe must never reach the consent gate, got prompts %v and batches %v", consent.promptedReasons, consent.batchCalls)
	}
}

// TestApproverBrokenCacheReturnsUnavailableNotError is the mesh-failover fix: an
// approver whose key cache is broken — a Get that fails outright, the demoted-cache
// shape a live incident produced — answers {"status":"unavailable"} so the requesting
// host scans for another approver, never a raw RPC error that kills its routed release.
func TestApproverBrokenCacheReturnsUnavailableNotError(t *testing.T) {
	me := currentUser(t)
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	c := newFakeCache()
	c.getErr = errors.New("cache-unwrap exited 1 (key missing or decrypt failed): boom")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	d := New(consent, c, nil, staticProbe(liveSession(me)), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handleRequestConsent(context.Background(), map[string]any{
		"browser": "chrome", "nonce": "n", "endpoint": "them@host:chrome:Default",
	})
	if err != nil {
		t.Fatalf("handleRequestConsent over a broken cache must not error, got %v", err)
	}
	if marshalResult(t, got) != `{"status":"unavailable"}` {
		t.Fatalf("broken approver cache = %s, want unavailable", marshalResult(t, got))
	}
}

// TestHandleRequestConsentFatalErrorPropagates proves only retryable approver
// failures become unavailable; a genuine release failure returns a raw RPC error.
func TestHandleRequestConsentFatalErrorPropagates(t *testing.T) {
	me := currentUser(t)
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(me)), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handleRequestConsent(context.Background(), map[string]any{
		"browser": "unknown", "nonce": "n", "endpoint": "them@host:unknown:Default",
	})
	if err == nil || err.Error() != `unknown browser "unknown"` {
		t.Fatalf("handleRequestConsent err = %v, want raw unknown-browser error", err)
	}
	if got != nil {
		t.Fatalf("handleRequestConsent returned a reply %v alongside the fatal error", got)
	}
}

// TestHandleRequestConsentApprovedEchoesExactly proves an approved prompt echoes the
// requester's nonce and endpoint VERBATIM, binding the approval to that one request —
// the approver's own endpoint ids stay cache keys and never enter the reply.
func TestHandleRequestConsentApprovedEchoesExactly(t *testing.T) {
	me := currentUser(t)
	fakeMesh(t, "me@laptop")
	st := stateWith("me@laptop", "")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(me)), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	nonce := "nonce-xyz-123"
	endpoint := "them@host:chrome:Work"
	got, err := d.handleRequestConsent(context.Background(), map[string]any{
		"browser": "chrome", "nonce": nonce, "endpoint": endpoint,
	})
	if err != nil {
		t.Fatalf("handleRequestConsent: %v", err)
	}
	want := `{"endpoint":"them@host:chrome:Work","nonce":"nonce-xyz-123","status":"approved"}`
	if marshalResult(t, got) != want {
		t.Fatalf("approved = %s, want %s", marshalResult(t, got), want)
	}
	// The prompt names the exact requesting endpoint.
	if len(consent.promptedReasons) != 1 || consent.promptedReasons[0] != "sync them to "+endpoint {
		t.Fatalf("prompt reason = %v, want [sync them to %s]", consent.promptedReasons, endpoint)
	}
}

// TestRoutedApprovalWarmsApproverCache proves an approval joins the release path: the
// approving tap caches this host's own key under the REQUESTED browser+profile — the
// profile threaded from the requester's params, not the default — and grants the
// requesting host a consent window, so a repeat routed request inside it is approved
// silently. The grant is the requesting host's alone: a following LOCAL prime over the
// same warm cache still prompts.
func TestRoutedApprovalWarmsApproverCache(t *testing.T) {
	ctx := context.Background()
	me := currentUser(t)
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	cache := newFakeCache()
	d := New(consent, cache, nil, staticProbe(liveSession(me)), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handleRequestConsent(ctx, map[string]any{
		"browser": "chrome", "profile": "Work", "nonce": "n1", "endpoint": "them@host:chrome:Work",
	})
	if err != nil {
		t.Fatalf("handleRequestConsent: %v", err)
	}
	if marshalResult(t, got) != `{"endpoint":"them@host:chrome:Work","nonce":"n1","status":"approved"}` {
		t.Fatalf("approved = %s", marshalResult(t, got))
	}
	if len(consent.batchCalls) != 1 || consent.batchCalls[0].reason != "sync them to them@host:chrome:Work" {
		t.Fatalf("batch calls = %+v, want one with the requesting endpoint's reason", consent.batchCalls)
	}
	// The threaded profile decides the cache key: Work is warm, Default stays cold.
	if _, ok, _ := cache.Get(ctx, endpointID(self, "chrome", "Work")); !ok {
		t.Fatalf("the approval must warm the approver's own chrome:Work endpoint")
	}
	if _, ok, _ := cache.Get(ctx, endpointID(self, "chrome", "Default")); ok {
		t.Fatalf("the approval warmed chrome:Default — the requester's profile was dropped")
	}

	// A repeat routed request from the SAME host rides its grant: approved, no new
	// consent evaluation.
	again, err := d.handleRequestConsent(ctx, map[string]any{
		"browser": "chrome", "profile": "Work", "nonce": "n2", "endpoint": "them@host:chrome:Work",
	})
	if err != nil {
		t.Fatalf("repeat handleRequestConsent: %v", err)
	}
	if marshalResult(t, again) != `{"endpoint":"them@host:chrome:Work","nonce":"n2","status":"approved"}` {
		t.Fatalf("repeat approval = %s", marshalResult(t, again))
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("consent evaluations = %d, want 1 (the requesting host's grant must approve silently)", len(consent.batchCalls))
	}

	// A following local prime is a DIFFERENT requestor: the warm cache alone must not
	// serve it — it prompts its own evaluation.
	res, err := d.handlePrimeAuth(ctx, map[string]any{"browser": "chrome", "profile": "Work"})
	if err != nil {
		t.Fatalf("handlePrimeAuth after approval: %v", err)
	}
	if marshalResult(t, res) != `{"endpoint":"me@laptop:chrome:Work","primed":true}` {
		t.Fatalf("prime after approval = %s", marshalResult(t, res))
	}
	if len(consent.batchCalls) != 2 {
		t.Fatalf("consent evaluations = %d, want 2 (the requesting host's grant must not cover a local prime)", len(consent.batchCalls))
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("an approver-side prime must never use the unprompted release, got %d", consent.unpromptedCalled)
	}
}

// TestApproverPrimeNeverRoutesUnderHardRoute proves the approver-mode release skips the
// whole routing ladder: even with ConsentRouteHard set to a peer, an inbound
// request_consent releases locally and never dials ssh — the transport double fails
// the test on any dial, closing the 3+ mesh routing-loop hazard.
func TestApproverPrimeNeverRoutesUnderHardRoute(t *testing.T) {
	me := currentUser(t)
	self := "me@laptop"
	peer := "you@desktop"
	fakeMesh(t, self, peer)
	st := stateWith(self, peer, stateEndpoint(peer, "chrome", "Default"))
	st.ConsentRouteHard = true
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(me)), &forbiddenRunner{t: t}, fixedState{st: st}, fixedState{st: st})

	got, err := d.handleRequestConsent(context.Background(), map[string]any{
		"browser": "chrome", "nonce": "n", "endpoint": "them@host:chrome:Default",
	})
	if err != nil {
		t.Fatalf("handleRequestConsent: %v", err)
	}
	if marshalResult(t, got) != `{"endpoint":"them@host:chrome:Default","nonce":"n","status":"approved"}` {
		t.Fatalf("approved = %s", marshalResult(t, got))
	}
	if len(consent.batchCalls) != 1 {
		t.Fatalf("consent evaluations = %d, want 1 local batch", len(consent.batchCalls))
	}
	if consent.unpromptedCalled != 0 {
		t.Fatalf("an approver-mode prime must never release via the routed unprompted path")
	}
}

// TestHandleRequestConsentIgnoresConsentRouteTo locks in the routing invariant: the
// consent gate on the receiving side decides purely on THIS host's local session and
// never re-routes, even when ConsentRouteTo points at another peer. The route override
// lives only in the broker's outbound path (Key -> routedRelease's candidate loop:
// consent_route_to first, then the mesh peers); if handleRequestConsent honored it too,
// an A->B request would bounce B->A and ping-pong.
// So it must never touch the runner regardless of the local decision.
func TestHandleRequestConsentIgnoresConsentRouteTo(t *testing.T) {
	self := "me@laptop"
	routeTo := "elsewhere@box"
	me := currentUser(t)
	fakeMesh(t, self, routeTo)
	st := stateWith(self, routeTo, stateEndpoint(routeTo, "chrome", "Default"))

	tests := []struct {
		name string
		snap SessionSnapshot
		want string
	}{
		{
			name: "no local session: unavailable, never routes",
			snap: SessionSnapshot{OnConsole: false},
			want: `{"status":"unavailable"}`,
		},
		{
			name: "live local session: approves locally, never routes",
			snap: liveSession(me),
			want: `{"endpoint":"them@host:chrome:Work","nonce":"n","status":"approved"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
			runner := &recordingRunner{}
			d := New(consent, newFakeCache(), nil, staticProbe(tc.snap), runner, fixedState{st: st}, fixedState{st: st})

			got, err := d.handleRequestConsent(context.Background(), map[string]any{
				"browser": "chrome", "nonce": "n", "endpoint": "them@host:chrome:Work",
			})
			if err != nil {
				t.Fatalf("handleRequestConsent: %v", err)
			}
			if marshalResult(t, got) != tc.want {
				t.Fatalf("handleRequestConsent = %s, want %s", marshalResult(t, got), tc.want)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("handleRequestConsent must not route with ConsentRouteTo set, got ssh calls %+v", runner.calls)
			}
		})
	}
}
