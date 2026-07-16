package auth

import (
	"context"
	"fmt"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/synckit/hostregistry"
)

// consentMethod names the approver RPC the routed handshake shells: a cookie
// release taps request_consent (passcode-or-biometric), a bridge seed taps
// request_bridge_consent (strict biometric). The handshake, echo binding, and
// unprompted own-key release are otherwise identical.
type consentMethod string

const (
	consentCookie consentMethod = "request_consent"
	consentBridge consentMethod = "request_bridge_consent"
)

// routedRelease routes the cookie-release presence gate to a live peer and, on
// the first bound approval, releases this host's own key non-interactively —
// the key never crosses the wire.
func (b *Broker) routedRelease(ctx context.Context, browser cookie.Browser, browserID, profile string) (cookie.AesKey, error) {
	return b.routedConsent(ctx, consentCookie, browser, browserID, profile)
}

// routedBridgeRelease routes the bridge-seed presence gate exactly like
// routedRelease, but the approver taps request_bridge_consent (strict
// biometric). The key never crosses the wire and is neither cached nor granted
// — a bridge seeds once and discards it.
func (b *Broker) routedBridgeRelease(ctx context.Context, browser cookie.Browser, browserID, profile string) (cookie.AesKey, error) {
	return b.routedConsent(ctx, consentBridge, browser, browserID, profile)
}

// routedConsent walks the approver candidates — a set consent_route_to first,
// then every mesh peer — through the generic Router, releasing this host's own
// key non-interactively after the first bound approval. Candidate composition
// (RouteTo-first) is cookiesync's; the Router owns probe-gating, failover, and
// the exact nonce+endpoint echo binding. A routed denial surfaces as the
// Router's terminal *consentkit.Denied, an unbound approval as its fail-closed
// *consentkit.AuthRequired; both propagate.
func (b *Broker) routedConsent(ctx context.Context, method consentMethod, browser cookie.Browser, browserID, profile string) (cookie.AesKey, error) {
	st, err := b.state.Load(ctx)
	if err != nil {
		return nil, err
	}
	self, peers, err := mesh.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	endpoint := endpointID(self, browserID, profile)
	candidates := make([]string, 0, len(peers)+1)
	if st.ConsentRouteTo != "" {
		candidates = append(candidates, st.ConsentRouteTo)
	}
	for _, peer := range peers {
		if peer != st.ConsentRouteTo {
			candidates = append(candidates, peer)
		}
	}
	if _, err := b.Router.Route(ctx, candidates, endpoint, func(_, nonce string) (string, []byte, error) {
		cmd := fmt.Sprintf(
			"cookiesync rpc %s --browser %s --profile %s --nonce %s --endpoint %s",
			method, hostregistry.ShellQuote(browserID), hostregistry.ShellQuote(profile),
			hostregistry.ShellQuote(nonce), hostregistry.ShellQuote(endpoint),
		)
		return cmd, nil, nil
	}); err != nil {
		return nil, err
	}
	return b.consent.ObtainKeyUnprompted(ctx, browser)
}
