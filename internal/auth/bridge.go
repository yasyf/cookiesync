package auth

import (
	"context"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/presence"
	synckit "github.com/yasyf/synckit/rpc"
)

// bridgeAuthTTL is the lifetime of a CDP-bridge capability grant — shorter than
// the cookie AuthTTL, so a bridge is re-gated well before a cookie release would
// be.
const bridgeAuthTTL = 10 * time.Minute

// ReleaseBridge gates the live CDP bridge behind a strict biometrics-only tap
// (ObtainKeyBiometric: no passcode, no non-interactive fallback), returning the
// key, its consent surface, and the lease TTL the daemon session registry caps
// under. It never touches b.grants or b.cache entries — only b.cache.Degraded()
// for the TTL — so a warm cookie grant can never make it silent; the key seeds a
// session once and is discarded. A routed host sends the presence gate to a live
// peer over the strict request_bridge_consent handshake and then reads its own
// key non-interactively — the key never crosses the wire.
func (b *Broker) ReleaseBridge(ctx context.Context, st *state.State, req Req) (cookie.AesKey, Surface, time.Duration, error) {
	routed, err := b.routesConsent(ctx, st)
	if err != nil {
		return nil, SurfaceNone, 0, err
	}
	bw, err := cookie.Lookup(cookie.BrowserName(req.Browser))
	if err != nil {
		return nil, SurfaceNone, 0, err
	}
	if routed {
		key, err := b.routedBridgeRelease(ctx, bw, req.Browser, req.Profile)
		if err != nil {
			return nil, SurfaceNone, 0, err
		}
		return key, SurfaceRouted, effectiveTTL(bridgeAuthTTL, b.cache.Degraded()), nil
	}
	pid, hasPID := synckit.PeerPID(ctx)
	reason := "open a live browser bridge"
	if req.Origin != "" {
		reason = "open a live browser bridge for " + req.Origin
	}
	reason = requestorReason(ctx, req.Requestor, reason, pid, hasPID)
	b.promptGate.Lock()
	key, err := b.consent.ObtainKeyBiometric(ctx, bw, reason)
	b.promptGate.Unlock()
	if err != nil {
		return nil, SurfaceNone, 0, err
	}
	return key, SurfaceLocal, effectiveTTL(bridgeAuthTTL, b.cache.Degraded()), nil
}

// ApproveBridge is the approver terminus of a routed bridge consent: it verifies
// this host is attended, then gates a STRICT biometric tap whose key is
// discarded — only the human's presence is proven, and no key crosses the wire.
// The returned error is the verdict source: nil approves, a cold host or locked
// keybag or missing bridge vault routes the requester on, a decline denies.
func (b *Broker) ApproveBridge(ctx context.Context, req Req) error {
	snap, err := b.probe(ctx)
	if err != nil {
		return err
	}
	live, err := presence.Attended(snap)
	if err != nil {
		return err
	}
	if !live {
		return &AuthRequired{Msg: "no live session to approve bridge consent"}
	}
	bw, err := cookie.Lookup(cookie.BrowserName(req.Browser))
	if err != nil {
		return err
	}
	pid, hasPID := synckit.PeerPID(ctx)
	reason := "approve a live browser bridge"
	if req.Origin != "" {
		reason = "approve a live browser bridge for " + req.Origin
	}
	reason = requestorReason(ctx, req.Requestor, reason, pid, hasPID)
	b.promptGate.Lock()
	_, err = b.consent.ObtainKeyBiometric(ctx, bw, reason)
	b.promptGate.Unlock()
	return err
}
