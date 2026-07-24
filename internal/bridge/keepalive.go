package bridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/yasyf/daemonkit/proc"
)

// keepaliveRemoteCmd is the peer-side supervisor the origin shells: it reads the
// bridge capability off stdin and blocks until the origin closes the pipe.
const keepaliveRemoteCmd = "cookiesync rpc bridge_keepalive"

// Keepalive is a detached ssh child running the peer's bridge_keepalive over a
// held-open stdin pipe, so the peer reaps the proxied bridge the moment this side
// closes the pipe or dies. Daemonkit owns the ssh process identity,
// termination, and crash recovery.
type Keepalive struct {
	process   *proc.PreparedChild
	stdin     *os.File
	closeOnce sync.Once
	closeErr  error
}

// OpenKeepalive spawns the peer's keepalive supervisor over ssh to addr under
// ctx, writes capability to the child's stdin, and keeps the pipe open so the
// supervisor blocks until this side tears down or dies.
func OpenKeepalive(ctx context.Context, manager *proc.Manager, target, addr, capability string, recorded func(context.Context, proc.ProcessReceipt) error) (*Keepalive, error) {
	argv, err := keepaliveArgv(target, addr)
	if err != nil {
		return nil, err
	}
	readyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	child, _, err := prepareChild(readyCtx, manager, proc.SpawnConfig{
		RecoveryID: proc.RecoveryTaskID,
		Executable: argv[0], Args: argv[1:],
		Env:   bridgeEnvironment(),
		Stdin: proc.StdioPipe, Stdout: proc.StdioNull, Stderr: proc.StdioNull,
	}, recorded)
	if err != nil {
		return nil, fmt.Errorf("prepare keepalive to %s: %w", addr, err)
	}
	stdin, err := child.TakeStdin()
	if err != nil {
		return nil, stopPreparedChild(ctx, child, fmt.Errorf("take keepalive stdin: %w", err))
	}
	if err := child.Start(readyCtx); err != nil {
		_ = stdin.Close()
		return nil, stopPreparedChild(ctx, child, fmt.Errorf("start keepalive to %s: %w", addr, err))
	}
	if err := stdin.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = stdin.Close()
		return nil, stopPreparedChild(ctx, child, err)
	}
	if _, err := io.WriteString(stdin, capability+"\n"); err != nil {
		_ = stdin.Close()
		return nil, stopPreparedChild(ctx, child, fmt.Errorf("write keepalive capability: %w", err))
	}
	if err := stdin.SetWriteDeadline(time.Time{}); err != nil {
		_ = stdin.Close()
		return nil, stopPreparedChild(ctx, child, err)
	}
	return &Keepalive{process: child, stdin: stdin}, nil
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
	return k.process.Done()
}

// Close stops and reaps the exact managed ssh keepalive. It is idempotent.
func (k *Keepalive) Close() error {
	k.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		k.closeErr = errors.Join(k.stdin.Close(), k.process.Stop(ctx))
	})
	return k.closeErr
}
