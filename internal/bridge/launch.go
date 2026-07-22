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
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yasyf/daemonkit/proc"
	"github.com/yasyf/daemonkit/supervise"
)

const chromeHostBinary = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

// maxStderrBytes caps the retained Chrome stderr; the process outlives seeding,
// so the buffer keeps only the most recent bytes for diagnosis.
const maxStderrBytes = 64 << 10

// LaunchSpec configures a throwaway debuggable Chrome instance.
type LaunchSpec struct {
	HostBinary string // resolved Google Chrome executable path
	RolePath   string // stable cookiesync role path hosting the fd adapter
	RoleArgs   []string
	DataDir    string // private 0700 throwaway --user-data-dir (caller-owned)
	Headed     bool   // default true for fidelity; false => --headless=new
	Recorded   func(context.Context, proc.Record) error
}

// Proc is a running Chrome child whose SOLE CDP transport is the inherited
// --remote-debugging-pipe. It owns the single pipe read-loop and a write mutex;
// both seeding (Conn) and the later WS relay (Server) multiplex over this one
// pipe.
type Proc struct {
	process   *supervise.SessionProcess
	transport net.Conn

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
func Launch(ctx context.Context, pool *supervise.Pool, spec LaunchSpec) (*Proc, error) {
	stderr := &lockedBuffer{}
	uuid, err := newBrowserUUID()
	if err != nil {
		return nil, err
	}
	p := &Proc{
		dataDir:     spec.DataDir,
		browserUUID: uuid,
		pending:     make(map[int64]chan cdpMessage),
		stderr:      stderr,
	}
	session, err := pool.StartSession(ctx, supervise.SessionProcessSpec{
		RecoveryClass: proc.RecoveryTask,
		Path:          spec.RolePath,
		Args: append(append([]string{}, spec.RoleArgs...),
			"_bridge-chrome-child", spec.HostBinary, spec.DataDir, strconv.FormatBool(spec.Headed)),
		Stderr:           stderr,
		Recorded:         spec.Recorded,
		ReadinessTimeout: 30 * time.Second,
		Ready: func(readyCtx context.Context, _ proc.Record, conn net.Conn) error {
			p.transport = conn
			go p.readLoop()
			if _, err := (&Conn{proc: p}).Call(readyCtx, "", "Browser.getVersion", nil); err != nil {
				return fmt.Errorf("cdp handshake (chrome stderr: %q): %w", stderr.String(), err)
			}
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("start chrome session: %w", err)
	}
	p.process = session
	return p, nil
}

// BrowserUUID returns the synthetic browser uuid minted at launch for the
// relay's WebSocket path.
func (p *Proc) BrowserUUID() string {
	return p.browserUUID
}

// Pid returns the exact daemonkit-managed Chrome process id.
func (p *Proc) Pid() int {
	return p.process.Record().PID
}

// Close settles the managed Chrome process and removes the data dir.
func (p *Proc) Close() error {
	return p.CloseContext(context.Background())
}

// CloseContext settles the managed Chrome process within ctx and removes the data dir.
func (p *Proc) CloseContext(ctx context.Context) error {
	p.closeOnce.Do(func() {
		p.closeErr = errors.Join(p.process.Stop(ctx), os.RemoveAll(p.dataDir))
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
