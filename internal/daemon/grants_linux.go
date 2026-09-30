//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	synckit "github.com/yasyf/synckit/rpc"
	"golang.org/x/sys/unix"
)

var errPeerOutsidePIDNamespace = errors.New("no socket peer, or a peer outside this pid namespace")

// requestorError refuses a socket caller whose login session cannot be derived
// from its SO_PEERCRED pid — a peer outside this pid namespace (pid 0) or one
// that exited before getsid ran — so no caller ever shares the local principal.
type requestorError struct {
	pid int
	err error
}

func (e *requestorError) Error() string {
	return fmt.Sprintf("cannot derive a requestor for socket peer pid %d (%v); pass a requestor token: export COOKIESYNC_REQUESTOR=\"$(cookiesync requestor)\"", e.pid, e.err)
}

func (e *requestorError) Unwrap() error { return e.err }

// sessionRequestor keys the grant on the dialing process's session ("sid:" +
// getsid(peer pid)). A dispatched caller whose session is underivable is
// refused; a transport with no caller at all is refused the same way.
func sessionRequestor(ctx context.Context) (string, error) {
	pid, ok := synckit.PeerPID(ctx)
	if !ok || pid <= 0 {
		return "", &requestorError{pid: pid, err: errPeerOutsidePIDNamespace}
	}
	sid, err := unix.Getsid(pid)
	if err != nil {
		return "", &requestorError{pid: pid, err: fmt.Errorf("getsid: %w", err)}
	}
	return "sid:" + strconv.Itoa(sid), nil
}
