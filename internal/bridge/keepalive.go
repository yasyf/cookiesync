package bridge

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/yasyf/daemonkit/proc"
	"github.com/yasyf/daemonkit/supervise"
	"github.com/yasyf/synckit/hostregistry"
)

// keepaliveRemoteCmd is the peer-side supervisor the origin shells: it reads the
// bridge capability off stdin and blocks until the origin closes the pipe.
const keepaliveRemoteCmd = "cookiesync rpc bridge_keepalive"

// Keepalive is a detached ssh child running the peer's bridge_keepalive over a
// held-open stdin pipe, so the peer reaps the proxied bridge the moment this side
// closes the pipe or dies. Daemonkit owns the ssh process identity,
// termination, and crash recovery.
type Keepalive struct {
	process   *supervise.SessionProcess
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// OpenKeepalive spawns the peer's keepalive supervisor over ssh to addr under
// ctx, writes capability to the child's stdin, and keeps the pipe open so the
// supervisor blocks until this side tears down or dies.
func OpenKeepalive(ctx context.Context, pool *supervise.Pool, addr, capability string, recorded func(context.Context, proc.Record) error) (*Keepalive, error) {
	argv := keepaliveArgv(addr)
	session, err := pool.StartSession(ctx, supervise.SessionProcessSpec{
		RecoveryClass:    proc.RecoveryTask,
		Path:             argv[0],
		Args:             argv[1:],
		Recorded:         recorded,
		ReadinessTimeout: 5 * time.Second,
		Ready: func(_ context.Context, _ proc.Record, conn net.Conn) error {
			if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return err
			}
			if _, err := io.WriteString(conn, capability+"\n"); err != nil {
				return fmt.Errorf("write keepalive capability: %w", err)
			}
			return conn.SetWriteDeadline(time.Time{})
		},
	})
	if err != nil {
		return nil, fmt.Errorf("start keepalive to %s: %w", addr, err)
	}
	done := make(chan struct{})
	go func() {
		_ = session.Wait(context.WithoutCancel(ctx))
		close(done)
	}()
	return &Keepalive{process: session, done: done}, nil
}

// keepaliveArgv builds the ssh argv for the supervisor, reusing hostregistry's
// dial options and brew-shellenv wrapping and swapping in the package's sshBin
// seam for test injection.
func keepaliveArgv(addr string) []string {
	argv := hostregistry.SSHArgv(addr, keepaliveRemoteCmd)
	argv[0] = sshBin
	return argv
}

// Done is closed when the ssh keepalive child exits — a transport drop the
// daemon's session watcher tears the proxy bridge down on.
func (k *Keepalive) Done() <-chan struct{} {
	return k.done
}

// Close stops and reaps the exact managed ssh keepalive. It is idempotent.
func (k *Keepalive) Close() error {
	k.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		k.closeErr = k.process.Stop(ctx)
	})
	return k.closeErr
}
