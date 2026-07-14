package auth

import (
	"context"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
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
// session once and is discarded. A cold host fails closed with AuthRequired
// until Phase B wires routing.
func (b *Broker) ReleaseBridge(ctx context.Context, st *state.State, req Req) (cookie.AesKey, Surface, time.Duration, error) {
	routed, err := b.routesConsent(ctx, st)
	if err != nil {
		return nil, SurfaceNone, 0, err
	}
	if routed {
		// TODO(phase-b): routed strict-biometric seed tap
		return nil, SurfaceNone, 0, &AuthRequired{Msg: "cross-host bridge routing not yet available; open the bridge on the attended host"}
	}
	bw, err := cookie.Lookup(cookie.BrowserName(req.Browser))
	if err != nil {
		return nil, SurfaceNone, 0, err
	}
	pid, hasPID := synckit.PeerPID(ctx)
	reason := requestorReason(ctx, req.Requestor, "open a live browser bridge", pid, hasPID)
	b.promptGate.Lock()
	key, err := b.consent.ObtainKeyBiometric(ctx, bw, reason)
	b.promptGate.Unlock()
	if err != nil {
		return nil, SurfaceNone, 0, err
	}
	return key, SurfaceLocal, effectiveTTL(bridgeAuthTTL, b.cache.Degraded()), nil
}
