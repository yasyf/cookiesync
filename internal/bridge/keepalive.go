package bridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/yasyf/daemonkit"
)

// keepaliveRemoteCmd is the peer-side supervisor the origin shells: it reads the
// bridge capability off stdin and blocks until the origin closes the pipe.
const keepaliveRemoteCmd = "cookiesync rpc bridge_keepalive"

// keepaliveWriteTimeout bounds the one capability write.
const keepaliveWriteTimeout = 5 * time.Second

// Keepalive is a detached ssh child running the peer's bridge_keepalive over a
// held-open stdin pipe, so the peer reaps the proxied bridge the moment this side
// closes the pipe or dies. Daemonkit owns the ssh process identity,
// termination, and crash recovery.
type Keepalive struct {
	child     *daemonkit.Child
	stdin     net.Conn
	done      <-chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// OpenKeepalive spawns the peer's keepalive supervisor over ssh to addr under
// ctx, writes capability to the child's stdin, and keeps the channel open so the
// supervisor blocks until this side tears down or dies. ssh cannot take fd 3, so
// the channel is the stdio pair; its read half is drained rather than read,
// since a full pipe would block the peer.
func OpenKeepalive(ctx context.Context, spawner Spawner, target, addr, capability string) (*Keepalive, error) {
	argv, err := keepaliveArgv(target, addr)
	if err != nil {
		return nil, err
	}
	readyCtx, cancel := context.WithTimeout(ctx, keepaliveWriteTimeout)
	defer cancel()
	child, err := spawner.Spawn(readyCtx, daemonkit.Cmd{
		Path: argv[0], Args: argv[1:],
		Env:     bridgeEnvironment(),
		Session: true,
		Exec:    daemonkit.ServingSameUser(),
	}, daemonkit.ChannelStdio, io.Discard)
	if err != nil {
		return nil, fmt.Errorf("start keepalive to %s: %w", addr, err)
	}
	stdin, err := child.Conn()
	if err != nil {
		return nil, stopChild(ctx, child, fmt.Errorf("take keepalive stdin: %w", err))
	}
	if err := stdin.SetWriteDeadline(time.Now().Add(keepaliveWriteTimeout)); err != nil {
		return nil, stopChild(ctx, child, errors.Join(err, stdin.Close()))
	}
	if _, err := io.WriteString(stdin, capability+"\n"); err != nil {
		return nil, stopChild(ctx, child, errors.Join(fmt.Errorf("write keepalive capability: %w", err), stdin.Close()))
	}
	if err := stdin.SetWriteDeadline(time.Time{}); err != nil {
		return nil, stopChild(ctx, child, errors.Join(err, stdin.Close()))
	}
	go func() { _, _ = io.Copy(io.Discard, stdin) }()
	return &Keepalive{child: child, stdin: stdin, done: closed(child)}, nil
}

// keepaliveArgv builds the ssh argv for the supervisor, reusing hostregistry's
// dial options and brew-shellenv wrapping and swapping in the package's sshBin
// seam for test injection.
func keepaliveArgv(target, addr string) ([]string, error) {
	args, address, err := sealedSSHBase(target, addr)
	if err != nil {
		return nil, err
	}
	return append([]string{sshBin}, append(args, address, keepaliveRemoteCmd)...), nil
}

// Done is closed when the ssh keepalive child exits — a transport drop the
// daemon's session watcher tears the proxy bridge down on.
func (k *Keepalive) Done() <-chan struct{} {
	return k.done
}

// Close stops and reaps the exact managed ssh keepalive. It is idempotent.
func (k *Keepalive) Close() error {
	k.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), childSettlementTimeout)
		defer cancel()
		_, stopErr := k.child.Stop(ctx)
		k.closeErr = errors.Join(k.stdin.Close(), stopErr)
	})
	return k.closeErr
}
