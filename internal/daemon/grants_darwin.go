//go:build darwin

package daemon

import (
	"context"
	"strconv"

	synckit "github.com/yasyf/synckit/rpc"
)

// sessionRequestor keys the grant on the local unix-socket client's login
// session ("sid:" + peer session id); a transport with none (tests) is "local".
func sessionRequestor(ctx context.Context) (string, error) {
	if sid, ok := synckit.PeerSID(ctx); ok {
		return "sid:" + strconv.Itoa(sid), nil
	}
	return "local", nil
}
