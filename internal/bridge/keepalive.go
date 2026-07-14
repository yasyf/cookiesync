package bridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/yasyf/synckit/hostregistry"
)

// keepaliveRemoteCmd is the peer-side supervisor the origin shells: it reads the
// bridge capability off stdin and blocks until the origin closes the pipe.
const keepaliveRemoteCmd = "cookiesync rpc bridge_keepalive"

// Keepalive is a detached ssh child running the peer's bridge_keepalive over a
// held-open stdin pipe, so the peer reaps the proxied bridge the moment this side
// closes the pipe or dies. It owns its ssh child with the tunnel's group-SIGKILL
// discipline.
type Keepalive struct {
	cmd       *exec.Cmd
	cancel    context.CancelFunc
	stdin     io.WriteCloser
	done      chan struct{}
	closeOnce sync.Once
}

// OpenKeepalive spawns the peer's keepalive supervisor over ssh to addr under
// ctx, writes capability to the child's stdin, and keeps the pipe open so the
// supervisor blocks until this side tears down or dies. Canceling ctx group-kills
// the child.
func OpenKeepalive(ctx context.Context, addr, capability string) (*Keepalive, error) {
	runCtx, cancel := context.WithCancel(ctx)
	argv := keepaliveArgv(addr)
	cmd := exec.CommandContext(runCtx, argv[0], argv[1:]...) //nolint:gosec // G204: sshBin is a fixed binary; addr comes from trusted local mesh state, and the capability is fed over stdin, never argv.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 5 * time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("keepalive stdin pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start keepalive to %s: %w", addr, err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	// The capability crosses on stdin, never argv; the pipe stays open so its EOF is
	// the peer's teardown signal.
	if _, err := io.WriteString(stdin, capability+"\n"); err != nil {
		cancel() // group-kills; the reaper above closes done
		<-done
		return nil, fmt.Errorf("write keepalive capability: %w", err)
	}
	return &Keepalive{cmd: cmd, cancel: cancel, stdin: stdin, done: done}, nil
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

// Close group-SIGKILLs the ssh keepalive child and waits for it to reap. It is
// idempotent.
func (k *Keepalive) Close() error {
	k.closeOnce.Do(func() {
		k.cancel()
		<-k.done
	})
	return nil
}
