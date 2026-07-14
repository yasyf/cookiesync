package daemon

import (
	"context"
	"strconv"

	synckit "github.com/yasyf/synckit/rpc"
)

// requestorID resolves the LOCAL principal a request acts for. It never reads
// origin, so a same-uid local process cannot forge a host grant on a local
// method. An explicit requestor token wins ("req:" + token); otherwise the
// local unix-socket client's login session keys the grant ("sid:" + peer
// session id); a transport with neither (tests, ServeConn) is "local".
func requestorID(ctx context.Context, params map[string]any) string {
	if tok := optionalString(params, "requestor", ""); tok != "" {
		return "req:" + tok
	}
	if sid, ok := synckit.PeerSID(ctx); ok {
		return "sid:" + strconv.Itoa(sid)
	}
	return "local"
}

// peerRequestor is requestorID for the two methods a remote peer drives:
// extract and the single-browser get_cookies. A peer forwards its mesh self as
// the origin param, which keys the grant ("host:" + origin); with no origin it
// falls back to the local requestorID ladder.
func peerRequestor(ctx context.Context, params map[string]any) string {
	if origin := optionalString(params, "origin", ""); origin != "" {
		return "host:" + origin
	}
	return requestorID(ctx, params)
}
