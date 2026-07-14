// Package bridge runs a throwaway, cookie-seeded Chrome over
// --remote-debugging-pipe and fronts it with a token-gated, single-client
// loopback WebSocket endpoint for agent-browser / connectOverCDP. It owns the
// browser mechanics only — launch, CDP seeding, and the WS relay; consent,
// grants, and the session registry live above it in internal/auth and
// internal/daemon.
package bridge

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const chromeHostBinary = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

// maxStderrBytes caps the retained Chrome stderr; the process outlives seeding,
// so the buffer keeps only the most recent bytes for diagnosis.
const maxStderrBytes = 64 << 10

// LaunchSpec configures a throwaway debuggable Chrome instance.
type LaunchSpec struct {
	HostBinary string // resolved Google Chrome executable path
	DataDir    string // private 0700 throwaway --user-data-dir (caller-owned)
	Headed     bool   // default true for fidelity; false => --headless=new
}

// Proc is a running Chrome child whose SOLE CDP transport is the inherited
// --remote-debugging-pipe. It owns the single pipe read-loop and a write mutex;
// both seeding (Conn) and the later WS relay (Server) multiplex over this one
// pipe.
type Proc struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	wpipe  *os.File // parent write end -> child fd 3 (CDP requests)
	rpipe  *os.File // parent read end  <- child fd 4 (CDP responses/events)

	dataDir     string
	browserUUID string

	writeMu   sync.Mutex
	id        atomic.Int64
	pendingMu sync.Mutex
	pending   map[int64]chan cdpMessage
	dead      error                            // set once the read-loop stops; guarded by pendingMu
	events    atomic.Pointer[func(cdpMessage)] // sink for id-less messages; seeding sets it
	relay     atomic.Pointer[func([]byte)]     // raw-frame sink; the WS relay sets it, superseding events
	stderr    *lockedBuffer                    // bounded ring of Chrome stderr, for diagnosis

	closeOnce sync.Once
	closeErr  error
}

// Launch starts Chrome with --remote-debugging-pipe on an isolated
// user-data-dir and completes the pipe handshake.
func Launch(ctx context.Context, spec LaunchSpec) (*Proc, error) {
	cmdRead, cmdWrite, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("cdp command pipe: %w", err)
	}
	evtRead, evtWrite, err := os.Pipe()
	if err != nil {
		_ = cmdRead.Close()
		_ = cmdWrite.Close()
		return nil, fmt.Errorf("cdp event pipe: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)

	args := []string{
		"--remote-debugging-pipe",
		"--user-data-dir=" + spec.DataDir,
		"--no-first-run",
		"--no-default-browser-check",
		"--no-startup-window",
		"--disable-background-networking",
		"--disable-sync",
		"--disable-component-update",
	}
	if !spec.Headed {
		args = append(args, "--headless=new")
	}

	cmd := exec.CommandContext(runCtx, spec.HostBinary, args...) //nolint:gosec // G204: HostBinary is a fixed local path resolved by ResolveHostBinary, not untrusted input.
	// ExtraFiles[0] becomes child fd 3 (Chrome reads CDP requests there);
	// ExtraFiles[1] becomes child fd 4 (Chrome writes responses/events there).
	cmd.ExtraFiles = []*os.File{cmdRead, evtWrite}
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 5 * time.Second

	if err := cmd.Start(); err != nil {
		cancel()
		_ = cmdRead.Close()
		_ = cmdWrite.Close()
		_ = evtRead.Close()
		_ = evtWrite.Close()
		return nil, fmt.Errorf("start chrome: %w", err)
	}
	// The child holds fd 3/fd 4 now; the parent keeps only its own ends.
	_ = cmdRead.Close()
	_ = evtWrite.Close()

	uuid, err := newBrowserUUID()
	if err != nil {
		cancel()
		_ = cmd.Wait()
		_ = cmdWrite.Close()
		_ = evtRead.Close()
		return nil, err
	}

	p := &Proc{
		cmd:         cmd,
		cancel:      cancel,
		wpipe:       cmdWrite,
		rpipe:       evtRead,
		dataDir:     spec.DataDir,
		browserUUID: uuid,
		pending:     make(map[int64]chan cdpMessage),
		stderr:      stderr,
	}
	go p.readLoop()

	hctx, hcancel := context.WithTimeout(ctx, 30*time.Second)
	defer hcancel()
	if _, err := (&Conn{proc: p}).Call(hctx, "", "Browser.getVersion", nil); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("cdp handshake (chrome stderr: %q): %w", stderr.String(), err)
	}
	return p, nil
}

// BrowserUUID returns the synthetic browser uuid minted at launch for the
// relay's WebSocket path.
func (p *Proc) BrowserUUID() string {
	return p.browserUUID
}

// Pid returns the Chrome child's process id, for the daemon's orphan sweep.
func (p *Proc) Pid() int {
	return p.cmd.Process.Pid
}

// Close group-SIGKILLs the Chrome process tree and removes the data dir. It is
// idempotent.
func (p *Proc) Close() error {
	p.closeOnce.Do(func() {
		p.cancel()
		_ = p.cmd.Wait() // the group was killed; the resulting wait error is expected
		_ = p.wpipe.Close()
		_ = p.rpipe.Close()
		p.closeErr = os.RemoveAll(p.dataDir)
	})
	return p.closeErr
}

// ResolveHostBinary returns the Google Chrome executable path, erroring if
// Chrome is not installed.
func ResolveHostBinary() (string, error) {
	if _, err := os.Stat(chromeHostBinary); err != nil {
		return "", fmt.Errorf("google chrome not installed at %s: %w", chromeHostBinary, err)
	}
	return chromeHostBinary, nil
}

func newBrowserUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate browser uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// lockedBuffer is a concurrency-safe sink for Chrome's stderr, which os/exec
// copies from a background goroutine while the parent may read it for
// diagnosis.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.buf.Write(p)
	if excess := b.buf.Len() - maxStderrBytes; excess > 0 {
		b.buf.Next(excess)
	}
	return n, err
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
