package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yasyf/cookiesync/internal/auth"
	"github.com/yasyf/cookiesync/internal/bridge"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/mesh"
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

// session is one live bridge the daemon owns and tears down through a uniform
// seam: a local *bridgeSession fronting a cookie-seeded Chrome here, or a
// *proxyBridgeSession fronting a peer's bridge over an ssh -L tunnel. The
// registry, reaper, and shutdown drain hold sessions only through this seam.
type session interface {
	Capability() string
	Endpoint() string
	Expiry() time.Time
	Live() bool
	OpenResult() map[string]any
	StatusResult() map[string]any
	Teardown()
}

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
	proxyPort  int // loopback port an ssh -L forwards; 0 (absent) on a local open
	expiry     time.Time
	proc       *bridge.Proc
	server     *bridge.Server
	cancel     context.CancelFunc
	dataDir    string
}

// bridgeRecordKind distinguishes the two crash-durable record shapes the orphan
// sweep reaps: a local Chrome, or a proxy fronting a peer's bridge over ssh -L.
type bridgeRecordKind string

const (
	bridgeRecordLocal bridgeRecordKind = "local"
	bridgeRecordProxy bridgeRecordKind = "proxy"
)

// bridgeRecord is the on-disk record the orphan sweep reaps by: the process group
// to kill (PID == pgid via Setpgid), the dir to remove, and the launch-time
// identity (Start, Comm) the sweep re-matches so pid reuse is never killed. A
// Proxy record also carries the peer Host and Capability the sweep remote-closes
// B by, so an origin crash never strands B's logged-in Chrome until its TTL.
type bridgeRecord struct {
	ProtocolVersion uint64           `json:"protocol_version"`
	Kind            bridgeRecordKind `json:"kind"`
	PID             int              `json:"pid"`
	Endpoint        string           `json:"endpoint"`
	DataDir         string           `json:"data_dir"`
	Start           string           `json:"start"`
	Comm            string           `json:"comm"`
	Host            string           `json:"host,omitempty"`
	Capability      string           `json:"capability,omitempty"`
}

// procIdentity pins a live process by its launch time and executable, the pair
// the orphan sweep re-checks so a recycled pid is never group-killed.
type procIdentity struct {
	start string
	comm  string
}

// Capability is the secret that proves possession of this session.
func (s *bridgeSession) Capability() string { return s.capability }

// Endpoint is the host:browser:profile identity a re-attach must match.
func (s *bridgeSession) Endpoint() string { return s.endpoint }

// Expiry is when the lease lapses.
func (s *bridgeSession) Expiry() time.Time { return s.expiry }

// Live reports whether the session is leased into the future and its relay is
// not yet torn down by a client disconnect.
func (s *bridgeSession) Live() bool {
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

// OpenResult renders the frozen bridge_open reply. proxy_port is present only on
// a cross-host open (advertise set), so a local open stays byte-identical.
func (s *bridgeSession) OpenResult() map[string]any {
	result := map[string]any{
		"protocol_version": cookie.ProtocolVersion,
		"url":              s.wsURL,
		"endpoint":         s.endpoint,
		"browser":          s.browser,
		"profile":          s.profile,
		"capability":       s.capability,
		"expires_in":       time.Until(s.expiry).Seconds(),
	}
	if s.proxyPort != 0 {
		result["proxy_port"] = s.proxyPort
	}
	return result
}

// StatusResult renders the frozen bridge_status reply.
func (s *bridgeSession) StatusResult() map[string]any {
	return map[string]any{
		"protocol_version": cookie.ProtocolVersion,
		"endpoint":         s.endpoint,
		"browser":          s.browser,
		"profile":          s.profile,
		"expires_in":       time.Until(s.expiry).Seconds(),
		"pid":              s.proc.Pid(),
	}
}

// Teardown cancels the detached session context and closes its relay and Chrome;
// the caller removes the registry entry.
func (s *bridgeSession) Teardown() {
	s.cancel()
	_ = s.server.Close()
	_ = s.proc.Close()
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

	self, peers, err := mesh.Resolve(ctx)
	if err != nil {
		return nil, err
	}
	host := optionalString(params, "host", self)
	if host != self && !peerKnown(peers, host) {
		return nil, fmt.Errorf("unknown host %q: not a mesh peer", host)
	}

	headed := optionalBool(params, "headed", true)
	// origin names the originating host in the consent prompt (display only);
	// advertise (host:port) is baked into /json/version for an ssh -L client and
	// signals this open serves a cross-host proxy.
	origin := optionalString(params, "origin", "")
	advertise := optionalString(params, "advertise", "")
	// A cannot see B's profiles, so a cross-host open keeps the requested profile
	// verbatim; only a local open validates it against the real profiles on disk.
	profile := optionalString(params, "profile", defaultProfile)
	endpoint := endpointID(host, browser, profile)

	// The capability is proof-of-possession: re-attach never taps or extends, and
	// it short-circuits ahead of the cross-host dispatch so a live proxy is reused.
	if capability := optionalString(params, "capability", ""); capability != "" {
		if resp, ok := d.reattachBridge(capability, endpoint); ok {
			return resp, nil
		}
	}

	if host != self {
		return d.remoteBridgeOpen(ctx, self, host, browser, profile, headed)
	}

	resolved, err := resolveBridgeProfile(browserObj, profile)
	if err != nil {
		return nil, err
	}
	// Never collapsed: a shared open would piggyback one tap and share its token.
	return d.openBridge(ctx, requestor, endpoint, browser, resolved, browserObj, headed, origin, advertise)
}

// reattachBridge returns the live session's reply when capability keys it and
// its endpoint matches, without extending the lease.
func (d *Daemon) reattachBridge(capability, endpoint string) (any, bool) {
	d.bridgeMu.Lock()
	sess, ok := d.bridges[capability]
	d.bridgeMu.Unlock()
	if !ok || sess.Endpoint() != endpoint || !sess.Live() {
		return nil, false
	}
	return sess.OpenResult(), true
}

// openBridge is the fresh-open critical path: the biometric tap, the seed read,
// launch, CDP seed, and WS relay. A deferred cleanup installed before launch
// tears down a half-open browser on any failure.
func (d *Daemon) openBridge(ctx context.Context, requestor, endpoint, browser, profile string, browserObj cookie.Browser, headed bool, origin, advertise string) (any, error) {
	st, err := d.state.Load(ctx)
	if err != nil {
		return nil, err
	}
	// The strict biometrics-only tap; a cold or routed host fails closed here.
	key, _, ttl, err := d.broker.ReleaseBridge(ctx, st, auth.Req{
		Requestor: requestor,
		Browser:   browser,
		Profile:   profile,
		Origin:    origin,
		Mode:      auth.ModeLocal,
	})
	if err != nil {
		return nil, err
	}

	storage, counts, err := d.seedSource(ctx, browserObj, profile, key)
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
	seeded, err := d.seedBridge(ctx, proc, storage)
	if err != nil {
		return nil, err
	}
	for _, rc := range seeded.Rejected {
		fmt.Fprintf(os.Stderr, "cookiesync: chrome rejected cookie %s @ %s: %s\n", rc.Name, rc.Domain, rc.Reason)
	}

	token, err := mintSecret()
	if err != nil {
		return nil, err
	}
	server, err = proc.Serve(sessionCtx, token, advertise)
	if err != nil {
		return nil, fmt.Errorf("serve bridge: %w", err)
	}
	// A cross-host open advertises the origin's forwarded port; the loopback
	// listener port it forwards to is server.Addr(). A local open leaves it 0.
	proxyPort := 0
	if advertise != "" {
		proxyPort, err = portOf(server.Addr())
		if err != nil {
			return nil, err
		}
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
		proxyPort:  proxyPort,
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

	result := sess.OpenResult()
	result["seed"] = buildSeedReport(counts, seeded)
	return result, nil
}

// seedReport is the observability payload bridge_open returns: what the seed
// attempted, seeded, and dropped, with a per-cause breakdown that reconciles as
// Attempted == Seeded + Undecryptable + Expired + CDPRejected (Skipped is their
// sum). Rejected carries the cookies Chrome explicitly refused.
type seedReport struct {
	Attempted     int                     `json:"attempted"`
	Seeded        int                     `json:"seeded"`
	Skipped       int                     `json:"skipped"`
	Undecryptable int                     `json:"undecryptable"`
	Expired       int                     `json:"expired"`
	CDPRejected   int                     `json:"cdp_rejected"`
	Rejected      []bridge.RejectedCookie `json:"rejected,omitempty"`
}

// buildSeedReport folds the cookie-layer decrypt/expiry counts and the CDP-layer
// seed report into the single reconciling payload the client renders.
func buildSeedReport(counts cookie.SeedCounts, report bridge.SeedReport) seedReport {
	return seedReport{
		Attempted:     counts.Attempted,
		Seeded:        report.CookiesSeeded,
		Skipped:       counts.Undecryptable + counts.Expired + report.CDPRejected,
		Undecryptable: counts.Undecryptable,
		Expired:       counts.Expired,
		CDPRejected:   report.CDPRejected,
		Rejected:      report.Rejected,
	}
}

// seedBridge dials the browser pipe and injects the storage state, bounded by a
// derived timeout, returning the CDP seed report.
func (d *Daemon) seedBridge(ctx context.Context, proc *bridge.Proc, storage cookie.StorageState) (bridge.SeedReport, error) {
	seedCtx, cancel := context.WithTimeout(ctx, bridgeSeedTimeout)
	defer cancel()
	conn, err := proc.Dial(seedCtx)
	if err != nil {
		return bridge.SeedReport{}, fmt.Errorf("dial bridge: %w", err)
	}
	defer func() { _ = conn.Close() }()
	report, err := bridge.Seed(seedCtx, conn, storage)
	if err != nil {
		return bridge.SeedReport{}, fmt.Errorf("seed bridge: %w", err)
	}
	return report, nil
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
	sess.Teardown()
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
	if !ok || !sess.Live() {
		return map[string]any{"protocol_version": cookie.ProtocolVersion}, nil
	}
	return sess.StatusResult(), nil
}

// handleBridgeClose tears down the session the capability keys.
func (d *Daemon) handleBridgeClose(_ context.Context, params map[string]any) (any, error) {
	capability, err := stringParam(params, "capability")
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"protocol_version": cookie.ProtocolVersion,
		"closed":           d.teardownBridge(capability),
	}, nil
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
	// Concurrently: a proxy teardown makes a bounded best-effort ssh close, so
	// serial teardown of several unreachable peers would blow the shutdown budget.
	var wg sync.WaitGroup
	for _, capability := range caps {
		wg.Add(1)
		go func(capability string) {
			defer wg.Done()
			d.teardownBridge(capability)
		}(capability)
	}
	wg.Wait()
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
		if !sess.Expiry().After(now) {
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
		reapOrphanBridge(ctx, d.runner, path)
	}
	return nil
}

// reapOrphanBridge group-kills a recorded bridge's process group only when the
// live pid still matches the launch-time identity — a recycled pid now belongs to
// some unrelated process and must not be killed — best-effort remote-closes a
// proxy record's peer bridge, then always removes the session dir.
func reapOrphanBridge(ctx context.Context, runner engine.SSHRunner, recordPath string) {
	sessionDir := filepath.Dir(recordPath)
	raw, err := os.ReadFile(recordPath) //nolint:gosec // G304: recordPath is a glob match under our own 0700 config dir.
	if err != nil {
		_ = os.RemoveAll(sessionDir)
		return
	}
	var rec bridgeRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&rec); err != nil || rec.ProtocolVersion != cookie.ProtocolVersion || rec.PID <= 0 {
		_ = os.RemoveAll(sessionDir)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		_ = os.RemoveAll(sessionDir)
		return
	}
	if id, ok, err := probeProcess(ctx, rec.PID); err == nil && ok && id.start == rec.Start && id.comm == rec.Comm {
		_ = syscall.Kill(-rec.PID, syscall.SIGKILL)
	}
	if rec.Kind == bridgeRecordProxy {
		remoteBridgeClose(ctx, runner, rec.Host, rec.Capability)
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
	return writeRecord(ctx, dataDir, bridgeRecord{Kind: bridgeRecordLocal, PID: pid, Endpoint: endpoint, DataDir: dataDir})
}

// writeProxyBridgeRecord persists a cross-host bridge's forward: the ssh child pid
// plus the peer host and capability the sweep remote-closes B by.
func writeProxyBridgeRecord(ctx context.Context, dataDir string, pid int, endpoint, host, capability string) error {
	return writeRecord(ctx, dataDir, bridgeRecord{
		Kind: bridgeRecordProxy, PID: pid, Endpoint: endpoint, DataDir: dataDir, Host: host, Capability: capability,
	})
}

// writeRecord probes the live pid for its launch-time identity and persists the
// crash-durable record the orphan sweep reaps by.
func writeRecord(ctx context.Context, dataDir string, rec bridgeRecord) error {
	// Bound the ps probe so a wedged ps can't stretch the spawn→record window.
	pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	id, ok, err := probeProcess(pctx, rec.PID)
	if err != nil {
		return fmt.Errorf("probe bridge process: %w", err)
	}
	if !ok {
		return fmt.Errorf("bridge process %d exited before it could be recorded", rec.PID)
	}
	rec.ProtocolVersion, rec.Start, rec.Comm = cookie.ProtocolVersion, id.start, id.comm
	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal bridge record: %w", err)
	}
	// Write-then-rename so a crash (or a re-dial overwrite) never leaves a partial
	// record the sweep discards while its process leaks.
	final := filepath.Join(dataDir, bridgeRecordFile)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write bridge record: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("commit bridge record: %w", err)
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

// portOf parses the numeric port out of a 127.0.0.1:<port> listener address.
func portOf(addr string) (int, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("parse bridge listener addr %q: %w", addr, err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("parse bridge listener port %q: %w", port, err)
	}
	return p, nil
}

// optionalBool reads a bool param, returning fallback when absent or mistyped.
func optionalBool(params map[string]any, key string, fallback bool) bool {
	if v, ok := params[key].(bool); ok {
		return v
	}
	return fallback
}
