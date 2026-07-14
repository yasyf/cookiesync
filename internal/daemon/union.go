package daemon

import (
	"errors"
	"fmt"
	"strings"

	"github.com/yasyf/cookiesync/internal/auth"
	"github.com/yasyf/synckit/hostregistry"
)

// PeerReadError reports a failed union read from one peer, including whether the
// union deadline fired and any diagnostic text captured by ssh.
type PeerReadError struct {
	Host     string
	TimedOut bool
	Stderr   string
	Err      error
}

// Error reports the peer and underlying read failure.
func (e *PeerReadError) Error() string {
	return fmt.Sprintf("read cookies from peer %s: %v", e.Host, e.Err)
}

// Unwrap returns the underlying peer read failure.
func (e *PeerReadError) Unwrap() error { return e.Err }

func newPeerReadError(host string, timedOut bool, err error) *PeerReadError {
	peerErr := &PeerReadError{Host: host, TimedOut: timedOut, Err: err}
	// ExecSSH surfaces every failure — a natural exit, a ctx-deadline group kill
	// included — as an *SSHError carrying whatever stderr the attempt captured.
	var sshErr *hostregistry.SSHError
	if errors.As(err, &sshErr) {
		peerErr.Stderr = strings.TrimSpace(sshErr.Stderr)
	}
	return peerErr
}

func renderPeerReadWarning(endpoint string, err *PeerReadError) string {
	switch {
	case err.TimedOut && err.Stderr != "":
		return fmt.Sprintf("skip %s: no reply from %s within %s; peer reported: %s", endpoint, err.Host, unionReadTimeout, err.Stderr)
	case err.TimedOut:
		return fmt.Sprintf("skip %s: no reply from %s within %s (consent may be pending there or the host is slow); run cookiesync doctor on %s and check the ssh identity's TCC / Full Disk Access grant", endpoint, err.Host, unionReadTimeout, err.Host)
	default:
		return fmt.Sprintf("skip %s: %v; is the daemon running on %s?", endpoint, err.Err, err.Host)
	}
}

func renderLocalKeyWarning(endpoint string, err error) string {
	switch auth.Classify(err) {
	case auth.VerdictUnavailable:
		return fmt.Sprintf("skip cold %s: run cookiesync auth (%v)", endpoint, err)
	case auth.VerdictDenied:
		return fmt.Sprintf("skip cold %s: consent declined (%v)", endpoint, err)
	case auth.VerdictFatal:
		return fmt.Sprintf("skip cold %s: %v", endpoint, err)
	case auth.VerdictOK:
		panic("auth.Classify returned VerdictOK for a local key error")
	}
	panic("auth.Classify returned an unknown verdict")
}
