//go:build linux

package daemon

import (
	"context"

	synckit "github.com/yasyf/synckit/rpc"
	"golang.org/x/sys/unix"
)

// peerSession derives the dialing process's session from the SO_PEERCRED pid.
// A zero pid is a peer outside this pid namespace; getsid(0) would answer with
// the daemon's own session, so it reports no session instead.
func peerSession(ctx context.Context) (int, bool) {
	pid, ok := synckit.PeerPID(ctx)
	if !ok || pid <= 0 {
		return 0, false
	}
	sid, err := unix.Getsid(pid)
	if err != nil {
		return 0, false
	}
	return sid, true
}
