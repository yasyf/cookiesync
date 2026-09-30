package daemon

import (
	"context"
)

// requestorID resolves the LOCAL principal a request acts for. It never reads
// origin, so a same-uid local process cannot forge a host grant on a local
// method. An explicit requestor token wins ("req:" + token); otherwise the
// transport's session principal keys the grant (sessionRequestor), which on
// Linux refuses a socket caller whose session cannot be derived.
func requestorID(ctx context.Context, params map[string]any) (string, error) {
	if tok := optionalString(params, "requestor", ""); tok != "" {
		return "req:" + tok, nil
	}
	return sessionRequestor(ctx)
}

// peerRequestor is requestorID for the two methods a remote peer drives:
// extract and the single-browser get_cookies. A peer forwards its mesh self as
// the origin param, which keys the grant ("host:" + origin); with no origin it
// falls back to the local requestorID ladder.
func peerRequestor(ctx context.Context, params map[string]any) (string, error) {
	if origin := optionalString(params, "origin", ""); origin != "" {
		return "host:" + origin, nil
	}
	return requestorID(ctx, params)
}
