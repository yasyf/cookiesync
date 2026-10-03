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

	"github.com/yasyf/daemonkit"
)

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
}

// Proc is a running Chrome child whose SOLE CDP transport is the inherited
// --remote-debugging-pipe. It owns the single pipe read-loop and a write mutex;
// both seeding (Conn) and the later WS relay (Server) multiplex over this one
// pipe.
type Proc struct {
	child     *daemonkit.Child
	transport net.Conn

	dataDir     string
	browserUUID string
	handlers    *handlerTracker

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
// user-data-dir and completes the pipe handshake. The child takes its own
// session so Chrome's helper processes settle with it.
func Launch(ctx context.Context, spawner Spawner, spec LaunchSpec) (*Proc, error) {
	stderr := &lockedBuffer{}
	uuid, err := newBrowserUUID()
	if err != nil {
		return nil, err
	}
	nonce, err := newLaunchNonce()
	if err != nil {
		return nil, err
	}
	p := &Proc{
		dataDir:     spec.DataDir,
		browserUUID: uuid,
		pending:     make(map[int64]chan cdpMessage),
		stderr:      stderr,
	}
	readyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	child, err := spawner.Spawn(readyCtx, daemonkit.Cmd{
		Path: spec.RolePath,
		Args: append(append([]string{}, spec.RoleArgs...),
			ChromeChildVerb, spec.HostBinary, spec.DataDir, strconv.FormatBool(spec.Headed)),
		Env:     chromeEnvironment(spec.DataDir, spec.Headed, nonce),
		Session: true,
		Exec:    daemonkit.ServingSameUser(),
	}, daemonkit.ChannelStdio, stderr)
	if err != nil {
		return nil, fmt.Errorf("start chrome session: %w", err)
	}
	p.child = child
	p.handlers = trackHandlers(spec.DataDir, nonce)
	transport, err := child.Conn()
	if err != nil {
		return nil, errors.Join(stopChild(ctx, child, fmt.Errorf("bridge: take chrome cdp pipe: %w", err)), p.handlers.close())
	}
	p.transport = transport
	go p.readLoop()
	if _, err := (&Conn{proc: p}).Call(readyCtx, "", "Browser.getVersion", nil); err != nil {
		return nil, errors.Join(
			fmt.Errorf("cdp handshake (chrome stderr: %q): %w", stderr.String(), err),
			transport.Close(),
			stopChild(ctx, child, nil),
			p.handlers.close(),
		)
	}
	return p, nil
}

// BrowserUUID returns the synthetic browser uuid minted at launch for the
// relay's WebSocket path.
func (p *Proc) BrowserUUID() string {
	return p.browserUUID
}

// Pid returns the exact daemonkit-managed Chrome process id.
func (p *Proc) Pid() int {
	return p.child.PID()
}

// Close settles the managed Chrome process and removes the data dir.
func (p *Proc) Close() error {
	return p.CloseContext(context.Background())
}

// CloseContext settles the managed Chrome process within ctx, then every
// crashpad handler carrying this launch's evidence, and removes the data dir;
// a look-alike without that evidence is left running and named in the error.
// A ctx carrying no deadline gets childSettlementTimeout, which daemonkit's
// Stop requires.
func (p *Proc) CloseContext(ctx context.Context) error {
	p.closeOnce.Do(func() {
		ctx, cancel := budgeted(ctx, childSettlementTimeout)
		defer cancel()
		_, stopErr := p.child.Stop(ctx)
		p.closeErr = errors.Join(p.transport.Close(), stopErr, p.child.StderrErr(), p.handlers.close(), os.RemoveAll(p.dataDir)) //nolint:gosec // G703: dataDir is this session's own throwaway profile dir.
	})
	return p.closeErr
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
