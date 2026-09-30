//go:build darwin

package daemon

import (
	"context"

	synckit "github.com/yasyf/synckit/rpc"
)

func peerSession(ctx context.Context) (int, bool) {
	return synckit.PeerSID(ctx)
}
