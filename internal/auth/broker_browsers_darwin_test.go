package auth

import (
	"context"
	"errors"
	"testing"

	consentkit "github.com/yasyf/synckit/consent"
	"github.com/yasyf/synckit/presence"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// TestLocalKeysOneFlightBudget proves the data-read budget: two cold browsers on
// a cold host spend the ONE flight on the first (a routed release), and the
// second is a budget-exhausted skip — never a second flight, whatever surface
// the first used.
func TestLocalKeysOneFlightBudget(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peer := "you@desktop"
	nonce := "one-flight-nonce"
	fakeMesh(t, self, peer)
	st := stateWith(self, "",
		stateEndpoint(self, "arc", "Default"),
		stateEndpoint(self, "chrome", "Default"),
	)
	arcEndpoint := endpointID(self, "arc", "Default")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies:  map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{"request_consent": approvedReply(t, nonce, arcEndpoint)},
	}
	cache := newFakeCache()
	b := newTestBroker(consent, cache, staticProbe(presence.SessionSnapshot{}), runner, st)
	pinnedNonce(b, nonce)

	outcomes, err := b.LocalKeys(ctx, "local", testConsentReason, OneFlight)
	if err != nil {
		t.Fatalf("LocalKeys(OneFlight): %v", err)
	}
	if len(outcomes) != 2 {
		t.Fatalf("outcomes = %d, want one per tracked endpoint", len(outcomes))
	}
	if outcomes[0].Endpoint != arcEndpoint || outcomes[0].Err != nil || outcomes[0].Skipped || string(outcomes[0].Key) != string(consent.key) {
		t.Fatalf("first outcome = %+v, want arc released via the one routed flight", outcomes[0])
	}
	if !outcomes[1].Skipped || outcomes[1].Key != nil || outcomes[1].Err != nil {
		t.Fatalf("second outcome = %+v, want a budget-exhausted skip", outcomes[1])
	}
	if got := runner.consentCalls(); got != 1 {
		t.Fatalf("routed request_consent calls = %d, want 1 (the budget is one flight)", got)
	}
	if consent.unpromptedCalled != 1 {
		t.Fatalf("unprompted releases = %d, want 1", consent.unpromptedCalled)
	}
}

// TestLocalKeysPrimeAllRoutesEachColdBrowser proves the auth budget: a routed
// release gates one browser, so on a cold host every distinct cold browser
// leads its own routed flight — one request_consent each — and each browser's
// endpoints verify warm.
func TestLocalKeysPrimeAllRoutesEachColdBrowser(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peer := "you@desktop"
	nonce := "prime-all-nonce"
	fakeMesh(t, self, peer)
	st := stateWith(self, "",
		stateEndpoint(self, "arc", "Default"),
		stateEndpoint(self, "chrome", "Default"),
	)
	arcEndpoint := endpointID(self, "arc", "Default")
	chromeEndpoint := endpointID(self, "chrome", "Default")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies: map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{
			arcEndpoint:    approvedReply(t, nonce, arcEndpoint),
			chromeEndpoint: approvedReply(t, nonce, chromeEndpoint),
		},
	}
	cache := newFakeCache()
	b := newTestBroker(consent, cache, staticProbe(presence.SessionSnapshot{}), runner, st)
	pinnedNonce(b, nonce)

	outcomes, err := b.LocalKeys(ctx, "local", testConsentReason, PrimeAll)
	if err != nil {
		t.Fatalf("LocalKeys(PrimeAll): %v", err)
	}
	if got := runner.consentCalls(); got != 2 {
		t.Fatalf("routed request_consent calls = %d, want 2 (one per distinct cold browser)", got)
	}
	if consent.unpromptedCalled != 2 {
		t.Fatalf("unprompted releases = %d, want 2", consent.unpromptedCalled)
	}
	if len(outcomes) != 2 {
		t.Fatalf("outcomes = %d, want one per distinct browser", len(outcomes))
	}
	for _, oc := range outcomes {
		if oc.Err != nil || oc.Skipped {
			t.Fatalf("outcome %+v, want every browser released", oc)
		}
		if len(oc.Warm) != 1 || oc.Warm[0] != oc.Endpoint {
			t.Fatalf("outcome %s Warm = %v, want its endpoint verified warm", oc.Browser, oc.Warm)
		}
	}
}

// TestConcurrentDistinctBrowserKeysNeverShareAFlight is the per-browser
// singleflight regression: one requestor's concurrent Key calls for TWO
// browsers, where browser A's routed release fails (its approver answers
// unavailable and no other candidate exists) while browser B's approver
// approves — B must get its own key, never A's routed error.
func TestConcurrentDistinctBrowserKeysNeverShareAFlight(t *testing.T) {
	ctx := context.Background()
	self := "me@laptop"
	peer := "you@desktop"
	nonce := "distinct-browser-nonce"
	fakeMesh(t, self, peer)
	st := stateWith(self, "",
		stateEndpoint(self, "arc", "Default"),
		stateEndpoint(self, "chrome", "Default"),
	)
	arcEndpoint := endpointID(self, "arc", "Default")
	chromeEndpoint := endpointID(self, "chrome", "Default")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	runner := &recordingRunner{
		replies: map[string]string{"cookiesync rpc whoami": liveWhoami},
		byMethod: map[string]string{
			arcEndpoint:    `{"status":"unavailable"}`,
			chromeEndpoint: approvedReply(t, nonce, chromeEndpoint),
		},
	}
	b := newTestBroker(consent, newFakeCache(), staticProbe(presence.SessionSnapshot{}), runner, st)
	pinnedNonce(b, nonce)

	type result struct {
		key cookie.AesKey
		err error
	}
	arcDone := make(chan result, 1)
	chromeDone := make(chan result, 1)
	go func() {
		key, _, err := b.Key(ctx, Req{Requestor: "local", Browser: "arc", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal})
		arcDone <- result{key, err}
	}()
	go func() {
		key, _, err := b.Key(ctx, Req{Requestor: "local", Browser: "chrome", Profile: "Default", Reason: testConsentReason, Mode: ModeLocal})
		chromeDone <- result{key, err}
	}()

	arc := <-arcDone
	chrome := <-chromeDone
	var authErr *consentkit.AuthRequired
	if !errors.As(arc.err, &authErr) {
		t.Fatalf("arc (unavailable approver, no fallback) = %v, want *consentkit.AuthRequired", arc.err)
	}
	if chrome.err != nil {
		t.Fatalf("chrome must not receive arc's routed failure, got %v", chrome.err)
	}
	if string(chrome.key) != string(consent.key) {
		t.Fatalf("chrome key = %q, want the released key", chrome.key)
	}
}
