package daemon

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yasyf/cookiesync/internal/auth"
	"github.com/yasyf/cookiesync/internal/bridge"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/paths"
)

const (
	// bridgeReapInterval backstops the per-session expiry timer.
	bridgeReapInterval = 30 * time.Second
	// bridgeSeedTimeout bounds the one-shot CDP seeding phase.
	bridgeSeedTimeout = 90 * time.Second
	// bridgeSubdir is the per-session workspace root under the config dir.
	bridgeSubdir = "bridge"
	// bridgeRecordFile is the orphan-sweep record inside a session dir.
	bridgeRecordFile = "session.json"
	// bridgeLockName is the daemon-ownership flock under bridgeSubdir; the sole
	// live daemon holds it, so a successor's sweep never reaps a sibling's bridges.
	bridgeLockName = "daemon.lock"
)

// errBridgeShutdown fails a fresh open that races closeAllBridges: rather than
// register a session no shutdown will ever tear down, the open unwinds itself.
var errBridgeShutdown = errors.New("bridge: daemon shutting down")

// bridgeSession is one live CDP-bridge session the daemon owns: its wire
// identity, the capability that proves possession, the browser and WS relay,
// and the detached cancel that unwinds it.
type bridgeSession struct {
	sessionID  string
	token      string
	capability string
	endpoint   string
	browser    string
	profile    string
	wsURL      string
	expiry     time.Time
	proc       *bridge.Proc
	server     *bridge.Server
	cancel     context.CancelFunc
	dataDir    string
}

// bridgeRecord is the on-disk record the orphan sweep reaps by: the process
// group to kill (PID == pgid via Setpgid), the dir to remove, and the launch-time
// identity (Start, Comm) that the sweep re-matches so pid reuse is never killed.
type bridgeRecord struct {
	PID      int    `json:"pid"`
	Endpoint string `json:"endpoint"`
	DataDir  string `json:"data_dir"`
	Start    string `json:"start"`
	Comm     string `json:"comm"`
}

// procIdentity pins a live process by its launch time and executable, the pair
// the orphan sweep re-checks so a recycled pid is never group-killed.
type procIdentity struct {
	start string
	comm  string
}

// live reports whether the session is leased into the future and its relay is
// not yet torn down by a client disconnect.
func (s *bridgeSession) live() bool {
	if !s.expiry.After(time.Now()) {
		return false
	}
	select {
	case <-s.server.Done():
		return false
	default:
		return true
	}
}

// openResult renders the frozen bridge_open reply.
func (s *bridgeSession) openResult() map[string]any {
	return map[string]any{
		"url":        s.wsURL,
		"endpoint":   s.endpoint,
		"browser":    s.browser,
		"profile":    s.profile,
		"capability": s.capability,
		"expires_in": time.Until(s.expiry).Seconds(),
	}
}

// handleBridgeOpen launches a cookie-seeded CDP bridge and registers its
// session, or silently re-attaches a caller that presents a live capability.
// Phase A is LOCAL-only: another host fails with a not-yet-available error.
func (d *Daemon) handleBridgeOpen(ctx context.Context, params map[string]any) (any, error) {
	requestor := requestorID(ctx, params)

	browser, err := stringParam(params, "browser")
	if err != nil {
		return nil, err
	}
	registry, err := cookie.Registry()
	if err != nil {
		return nil, err
	}
	browserObj, ok := registry[cookie.BrowserName(browser)]
	if !ok {
		return nil, fmt.Errorf("unknown browser %q", browser)
	}

	self, err := meshSelf(ctx)
	if err != nil {
		return nil, err
	}
	if host := optionalString(params, "host", self); host != self {
		return nil, fmt.Errorf("cross-host bridge not yet available; run it on %s", host)
	}

	profile, err := resolveBridgeProfile(browserObj, optionalString(params, "profile", defaultProfile))
	if err != nil {
		return nil, err
	}
	headed := optionalBool(params, "headed", true)
	endpoint := endpointID(self, browser, profile)

	// The capability is proof-of-possession: re-attach never taps or extends.
	if capability := optionalString(params, "capability", ""); capability != "" {
		if resp, ok := d.reattachBridge(capability, endpoint); ok {
			return resp, nil
		}
	}

	// Never collapsed: a shared open would piggyback one tap and share its token.
	return d.openBridge(ctx, requestor, endpoint, browser, profile, browserObj, headed)
}

// reattachBridge returns the live session's reply when capability keys it and
// its endpoint matches, without extending the lease.
func (d *Daemon) reattachBridge(capability, endpoint string) (any, bool) {
	d.bridgeMu.Lock()
	sess, ok := d.bridges[capability]
	d.bridgeMu.Unlock()
	if !ok || sess.endpoint != endpoint || !sess.live() {
		return nil, false
	}
	return sess.openResult(), true
}

// openBridge is the fresh-open critical path: the biometric tap, the seed read,
// launch, CDP seed, and WS relay. A deferred cleanup installed before launch
// tears down a half-open browser on any failure.
func (d *Daemon) openBridge(ctx context.Context, requestor, endpoint, browser, profile string, browserObj cookie.Browser, headed bool) (any, error) {
	st, err := d.state.Load(ctx)
	if err != nil {
		return nil, err
	}
	// The strict biometrics-only tap; a cold or routed host fails closed here.
	key, _, ttl, err := d.broker.ReleaseBridge(ctx, st, auth.Req{
		Requestor: requestor,
		Browser:   browser,
		Profile:   profile,
		Mode:      auth.ModeLocal,
	})
	if err != nil {
		return nil, err
	}

	storage, skipped, err := d.seedSource(ctx, browserObj, profile, key)
	if err != nil {
		return nil, fmt.Errorf("seed source %s/%s: %w", browser, profile, err)
	}
	hostBin, err := d.hostBinary()
	if err != nil {
		return nil, fmt.Errorf("resolve chrome: %w", err)
	}

	dir, err := paths.Dir()
	if err != nil {
		return nil, err
	}
	sessionID, err := mintID()
	if err != nil {
		return nil, err
	}
	dataDir := filepath.Join(dir, bridgeSubdir, sessionID)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create bridge data dir: %w", err)
	}

	// Detached from ctx (values kept, cancellation dropped) so the session
	// outlives the fast RPC; teardown is its only cancel.
	sessionCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	var proc *bridge.Proc
	var server *bridge.Server
	success := false
	defer func() {
		if success {
			return
		}
		cancel()
		if server != nil {
			_ = server.Close()
		}
		if proc != nil {
			_ = proc.Close() // group-kills chrome and removes dataDir
			return
		}
		_ = os.RemoveAll(dataDir)
	}()

	proc, err = bridge.Launch(sessionCtx, bridge.LaunchSpec{HostBinary: hostBin, DataDir: dataDir, Headed: headed})
	if err != nil {
		return nil, fmt.Errorf("launch bridge: %w", err)
	}
	// Record before any seeding so a crash mid-flow still leaves a sweepable,
	// identity-verified record of a fully-launched (soon logged-in) Chrome.
	if err := writeBridgeRecord(ctx, dataDir, proc.Pid(), endpoint); err != nil {
		return nil, err
	}
	// Seeding is bounded on the RPC ctx, not the session's long-lived context.
	if err := d.seedBridge(ctx, proc, storage); err != nil {
		return nil, err
	}

	token, err := mintSecret()
	if err != nil {
		return nil, err
	}
	server, err = proc.Serve(sessionCtx, token, "")
	if err != nil {
		return nil, fmt.Errorf("serve bridge: %w", err)
	}
	capability, err := mintSecret()
	if err != nil {
		return nil, err
	}

	sess := &bridgeSession{
		sessionID:  sessionID,
		token:      token,
		capability: capability,
		endpoint:   endpoint,
		browser:    browser,
		profile:    profile,
		wsURL:      server.URL(),
		expiry:     time.Now().Add(ttl),
		proc:       proc,
		server:     server,
		cancel:     cancel,
		dataDir:    dataDir,
	}

	d.bridgeMu.Lock()
	if d.bridgeShutdown {
		d.bridgeMu.Unlock()
		return nil, errBridgeShutdown // defer unwinds proc+server+dir
	}
	d.bridges[capability] = sess
	d.bridgeMu.Unlock()
	success = true

	go d.watchBridge(sessionCtx, capability, server, sess.expiry)

	result := sess.openResult()
	result["skipped"] = skipped
	return result, nil
}

// seedBridge dials the browser pipe and injects the storage state, bounded by a
// derived timeout.
func (d *Daemon) seedBridge(ctx context.Context, proc *bridge.Proc, storage cookie.StorageState) error {
	seedCtx, cancel := context.WithTimeout(ctx, bridgeSeedTimeout)
	defer cancel()
	conn, err := proc.Dial(seedCtx)
	if err != nil {
		return fmt.Errorf("dial bridge: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := bridge.Seed(seedCtx, conn, storage); err != nil {
		return fmt.Errorf("seed bridge: %w", err)
	}
	return nil
}

// watchBridge tears the session down on the first of a client disconnect, the
// lease expiry, or the session context's cancellation.
func (d *Daemon) watchBridge(ctx context.Context, capability string, server *bridge.Server, expiry time.Time) {
	timer := time.NewTimer(time.Until(expiry))
	defer timer.Stop()
	select {
	case <-server.Done():
	case <-timer.C:
	case <-ctx.Done():
	}
	d.teardownBridge(capability)
}

// teardownBridge removes the session and unwinds it. It is idempotent,
// reporting whether it was the call that removed the session.
func (d *Daemon) teardownBridge(capability string) bool {
	d.bridgeMu.Lock()
	sess, ok := d.bridges[capability]
	if ok {
		delete(d.bridges, capability)
	}
	d.bridgeMu.Unlock()
	if !ok {
		return false
	}
	sess.cancel()
	_ = sess.server.Close()
	_ = sess.proc.Close()
	return true
}

// handleBridgeStatus reports only the session the capability keys, never
// enumerating a caller's other sessions. Unknown or dead yields an empty result.
func (d *Daemon) handleBridgeStatus(_ context.Context, params map[string]any) (any, error) {
	capability, err := stringParam(params, "capability")
	if err != nil {
		return nil, err
	}
	d.bridgeMu.Lock()
	sess, ok := d.bridges[capability]
	d.bridgeMu.Unlock()
	if !ok || !sess.live() {
		return map[string]any{}, nil
	}
	return map[string]any{
		"endpoint":   sess.endpoint,
		"browser":    sess.browser,
		"profile":    sess.profile,
		"expires_in": time.Until(sess.expiry).Seconds(),
		"pid":        sess.proc.Pid(),
	}, nil
}

// handleBridgeClose tears down the session the capability keys.
func (d *Daemon) handleBridgeClose(_ context.Context, params map[string]any) (any, error) {
	capability, err := stringParam(params, "capability")
	if err != nil {
		return nil, err
	}
	return map[string]any{"closed": d.teardownBridge(capability)}, nil
}

// closeAllBridges stops the reaper and tears down every live session on
// shutdown. Setting bridgeShutdown under the lock before the snapshot closes the
// race with a fresh open: an open that registers after this returns instead sees
// the flag and unwinds itself, so no session outlives shutdown. Sessions are
// snapshotted under the lock and closed outside it, since teardown re-locks.
func (d *Daemon) closeAllBridges(_ context.Context) {
	d.bridgeStopOnce.Do(func() { close(d.bridgeStop) })
	d.bridgeMu.Lock()
	d.bridgeShutdown = true
	caps := make([]string, 0, len(d.bridges))
	for capability := range d.bridges {
		caps = append(caps, capability)
	}
	d.bridgeMu.Unlock()
	for _, capability := range caps {
		d.teardownBridge(capability)
	}
	if d.bridgeLock != nil {
		_ = d.bridgeLock.Close() // releases the daemon-ownership flock
		d.bridgeLock = nil
	}
}

// startBridgeReaper launches the expiry reaper; it runs until closeAllBridges.
func (d *Daemon) startBridgeReaper() {
	go d.reapBridges()
}

func (d *Daemon) reapBridges() {
	ticker := time.NewTicker(bridgeReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.reapExpiredBridges()
		case <-d.bridgeStop:
			return
		}
	}
}

func (d *Daemon) reapExpiredBridges() {
	now := time.Now()
	d.bridgeMu.Lock()
	expired := make([]string, 0, len(d.bridges))
	for capability, sess := range d.bridges {
		if !sess.expiry.After(now) {
			expired = append(expired, capability)
		}
	}
	d.bridgeMu.Unlock()
	for _, capability := range expired {
		d.teardownBridge(capability)
	}
}

// sweepOrphanBridges reaps sessions a crashed daemon left running. Its caller
// gates it behind the daemon-ownership flock, so no live sibling daemon owns
// these records — every one is a genuine orphan.
func (d *Daemon) sweepOrphanBridges(ctx context.Context) error {
	dir, err := paths.Dir()
	if err != nil {
		return err
	}
	matches, err := filepath.Glob(filepath.Join(dir, bridgeSubdir, "*", bridgeRecordFile))
	if err != nil {
		return fmt.Errorf("scan orphan bridges: %w", err)
	}
	for _, path := range matches {
		reapOrphanBridge(ctx, path)
	}
	return nil
}

// reapOrphanBridge group-kills a recorded bridge's Chrome only when the live pid
// still matches the launch-time identity — a recycled pid now belongs to some
// unrelated process and must not be killed — then always removes the session dir.
func reapOrphanBridge(ctx context.Context, recordPath string) {
	sessionDir := filepath.Dir(recordPath)
	raw, err := os.ReadFile(recordPath) //nolint:gosec // G304: recordPath is a glob match under our own 0700 config dir.
	if err != nil {
		_ = os.RemoveAll(sessionDir)
		return
	}
	var rec bridgeRecord
	if err := json.Unmarshal(raw, &rec); err != nil || rec.PID <= 0 {
		_ = os.RemoveAll(sessionDir)
		return
	}
	if id, ok, err := probeProcess(ctx, rec.PID); err == nil && ok && id.start == rec.Start && id.comm == rec.Comm {
		_ = syscall.Kill(-rec.PID, syscall.SIGKILL)
	}
	_ = os.RemoveAll(sessionDir)
}

// probeProcess reads a pid's start time and executable via ps. A dead pid yields
// ok=false with no error; lstart is the leading five whitespace fields
// ("Mon Jul 14 10:23:45 2026"), comm the executable path (the remainder).
func probeProcess(ctx context.Context, pid int) (procIdentity, bool, error) {
	out, err := exec.CommandContext(ctx, "ps", "-o", "lstart=", "-o", "comm=", "-p", strconv.Itoa(pid)).Output() //nolint:gosec // G204: a fixed ps invocation with a numeric pid, no shell, no tainted input.
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return procIdentity{}, false, nil // ps exits non-zero for an absent pid
		}
		return procIdentity{}, false, fmt.Errorf("probe process %d: %w", pid, err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 6 {
		return procIdentity{}, false, fmt.Errorf("probe process %d: unexpected ps output %q", pid, out)
	}
	return procIdentity{start: strings.Join(fields[:5], " "), comm: strings.Join(fields[5:], " ")}, true, nil
}

// acquireBridgeOwnership takes the exclusive daemon-ownership flock so only the
// sole live daemon sweeps orphans. The lock is advisory and auto-released when
// this process dies (a SIGKILL'd owner frees it for its successor); its fd is
// O_CLOEXEC (Go's default), so an exec'd Chrome never inherits it and keeps it
// held past the daemon's death. A held lock (a live sibling) yields owned=false.
func (d *Daemon) acquireBridgeOwnership() (bool, error) {
	dir, err := paths.Dir()
	if err != nil {
		return false, err
	}
	lockDir := filepath.Join(dir, bridgeSubdir)
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return false, fmt.Errorf("create bridge dir: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(lockDir, bridgeLockName), os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // G304: bridgeLockName is a fixed name under our own 0700 config dir.
	if err != nil {
		return false, fmt.Errorf("open bridge ownership lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return false, nil
		}
		return false, fmt.Errorf("lock bridge ownership: %w", err)
	}
	d.bridgeLock = f
	return true, nil
}

// resolveBridgeProfile validates profile against the browser's real profiles,
// rejecting anything not present — which also blocks path traversal.
func resolveBridgeProfile(browser cookie.Browser, profile string) (string, error) {
	profiles, err := browser.Profiles()
	if err != nil {
		return "", err
	}
	for _, p := range profiles {
		if p.Dir == profile {
			return profile, nil
		}
	}
	return "", fmt.Errorf("unknown profile %q for browser %s", profile, browser.Name)
}

// writeBridgeRecord persists the crash-durability record, capturing the freshly
// launched pid's identity so the sweep can distinguish it from a recycled pid.
func writeBridgeRecord(ctx context.Context, dataDir string, pid int, endpoint string) error {
	id, ok, err := probeProcess(ctx, pid)
	if err != nil {
		return fmt.Errorf("probe bridge process: %w", err)
	}
	if !ok {
		return fmt.Errorf("bridge process %d exited before it could be recorded", pid)
	}
	raw, err := json.Marshal(bridgeRecord{PID: pid, Endpoint: endpoint, DataDir: dataDir, Start: id.start, Comm: id.comm})
	if err != nil {
		return fmt.Errorf("marshal bridge record: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, bridgeRecordFile), raw, 0o600); err != nil {
		return fmt.Errorf("write bridge record: %w", err)
	}
	return nil
}

// mintSecret returns a 24-byte base64url secret for a token or capability.
func mintSecret() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mint bridge secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// mintID returns a short, non-secret hex id for on-disk session paths — never
// the token, which must never key a filesystem path.
func mintID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mint bridge id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// optionalBool reads a bool param, returning fallback when absent or mistyped.
func optionalBool(params map[string]any, key string, fallback bool) bool {
	if v, ok := params[key].(bool); ok {
		return v
	}
	return fallback
}
