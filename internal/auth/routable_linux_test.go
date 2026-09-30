//go:build linux

package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/synckit/presence"
)

// TestRoutedConsentRefusesBrowserNoMacApproverHolds proves a cold Linux host
// refuses to route consent for a browser whose registry entry is not
// ConsentRoutable, before any peer is probed and without releasing a key, on
// both the cookie and the bridge handshake.
func TestRoutedConsentRefusesBrowserNoMacApproverHolds(t *testing.T) {
	self := "me@vm"
	peer := "you@desktop"
	chromium := cookie.Browser{Name: "chromium", Display: "Chromium", SecretServiceApplication: "chromium"}
	for _, tc := range []struct {
		name  string
		route func(*Broker) (cookie.AesKey, error)
	}{
		{"cookie release", func(b *Broker) (cookie.AesKey, error) {
			return b.routedRelease(context.Background(), chromium, "chromium", "Default")
		}},
		{"bridge release", func(b *Broker) (cookie.AesKey, error) {
			return b.routedBridgeRelease(context.Background(), chromium, "chromium", "Default")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakeMesh(t, self, peer)
			consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
			runner := &recordingRunner{replies: map[string]string{"cookiesync rpc whoami": liveWhoami}}
			st := stateWith(self, peer, stateEndpoint(peer, "chrome", "Default"))
			b := newTestBroker(consent, newFakeCache(), staticProbe(presence.SessionSnapshot{}), runner, st)

			key, err := tc.route(b)
			var unroutable *unroutableBrowserError
			if !errors.As(err, &unroutable) {
				t.Fatalf("routed consent for chromium = %x, %v; want *unroutableBrowserError", key, err)
			}
			if unroutable.browser != "chromium" {
				t.Fatalf("refusal names %q, want chromium", unroutable.browser)
			}
			if want := `browser "chromium" cannot route consent: no Mac approver registers it`; err.Error() != want {
				t.Fatalf("refusal = %q, want %q", err.Error(), want)
			}
			if key != nil {
				t.Fatalf("refusal released a key: %x", key)
			}
			if len(runner.calls) != 0 {
				t.Fatalf("refusal dialed peers: %+v", runner.calls)
			}
			if consent.unpromptedCalled != 0 || len(consent.promptedReasons) != 0 {
				t.Fatalf("refusal touched consent: unprompted=%d prompts=%v", consent.unpromptedCalled, consent.promptedReasons)
			}
		})
	}
}

// TestRoutedConsentWalksEveryLinuxRegistryBrowser proves the registry declares
// every Linux browser routable, so a routed release reaches the approver walk.
func TestRoutedConsentWalksEveryLinuxRegistryBrowser(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	registry, err := cookie.Registry()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	if len(registry) == 0 {
		t.Fatal("the Linux registry is empty")
	}
	for name, browser := range registry {
		if err := routable(browser); err != nil {
			t.Fatalf("registry browser %s is not routable: %v", name, err)
		}
	}
}
