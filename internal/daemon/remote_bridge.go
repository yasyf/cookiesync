package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yasyf/cookiesync/internal/bridge"
	"github.com/yasyf/cookiesync/internal/engine"
	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/synckit/hostregistry"
	synckit "github.com/yasyf/synckit/rpc"
)

const (
	// remoteBridgeCloseTimeout bounds a best-effort remote bridge_close over ssh.
	remoteBridgeCloseTimeout = 15 * time.Second
	// remoteBridgeOpenAttempts caps the port-collision re-open loop: a fresh
	// loopback port lost the bind race with an unrelated listener.
	remoteBridgeOpenAttempts = 3
)

// remoteBridgeOpenTimeout bounds the peer bridge_open ssh leg, which may block on
// the peer's own consent tap (strict biometric, or routed to a third host).
// Mirrors the routed-consent leg's margin under the peer's DispatchTimeout. A var
// so tests shrink it.
var remoteBridgeOpenTimeout = synckit.DispatchTimeout - 30*time.Second

// bridgeTunnel is the ssh -L forward seam remoteBridgeOpen drives; *bridge.Tunnel
// satisfies it, and a test injects a fake behind d.openTunnel.
type bridgeTunnel interface {
	HostAddr() string
	Done() <-chan struct{}
	Close() error
}

// bridgeKeepalive is the ssh keepalive-supervisor seam; *bridge.Keepalive
// satisfies it, and a test injects a fake behind d.openKeepalive.
type bridgeKeepalive interface {
	Done() <-chan struct{}
	Close() error
}

// remoteBridgeReply is the peer's bridge_open reply as it crosses back over ssh:
// the ws url (its token embedded, never on argv), the peer's loopback proxy port
// the forward targets, and the peer-side capability the origin closes it by.
type remoteBridgeReply struct {
	URL        string  `json:"url"`
	Endpoint   string  `json:"endpoint"`
	Browser    string  `json:"browser"`
	Profile    string  `json:"profile"`
	Capability string  `json:"capability"`
	ExpiresIn  float64 `json:"expires_in"`
	ProxyPort  int     `json:"proxy_port"`
	Skipped    int     `json:"skipped"`
}

// proxyBridgeSession is a live cross-host bridge the origin fronts: the peer owns
// the cookie-seeded Chrome and taps its own consent, while this side owns only the
// ssh -L forward, the keepalive supervisor, and the peer capability it tears the
// bridge down by. It holds no local Chrome or relay.
type proxyBridgeSession struct {
	sessionID string
	capA      string
	capB      string
	host      string
	endpoint  string
	browser   string
	profile   string
	wsURL     string
	proxyPort int
	expiry    time.Time
	tunnel    bridgeTunnel
	keepalive bridgeKeepalive
	cancel    context.CancelFunc
	dataDir   string
	runner    engine.SSHRunner
}

// Capability is the origin-minted secret that proves possession of this proxy.
func (s *proxyBridgeSession) Capability() string { return s.capA }

// Endpoint is the peer host:browser:profile identity a re-attach must match.
func (s *proxyBridgeSession) Endpoint() string { return s.endpoint }

// Expiry is when the lease lapses, tracking the peer's own lease.
func (s *proxyBridgeSession) Expiry() time.Time { return s.expiry }

// Live reports whether the lease is unexpired and the ssh forward still up.
func (s *proxyBridgeSession) Live() bool {
	if !s.expiry.After(time.Now()) {
		return false
	}
	select {
	case <-s.tunnel.Done():
		return false
	default:
		return true
	}
}

// OpenResult renders the frozen bridge_open reply for the origin: the forwarded
// loopback url and this side's own capability, never the peer's.
func (s *proxyBridgeSession) OpenResult() map[string]any {
	return map[string]any{
		"url":        s.wsURL,
		"endpoint":   s.endpoint,
		"browser":    s.browser,
		"profile":    s.profile,
		"capability": s.capA,
		"expires_in": time.Until(s.expiry).Seconds(),
		"proxy_port": s.proxyPort,
	}
}

// StatusResult renders the frozen bridge_status reply. A proxy has no local Chrome
// pid, so it reports the forwarded loopback port in its place.
func (s *proxyBridgeSession) StatusResult() map[string]any {
	return map[string]any{
		"endpoint":   s.endpoint,
		"browser":    s.browser,
		"profile":    s.profile,
		"expires_in": time.Until(s.expiry).Seconds(),
		"proxy_port": s.proxyPort,
	}
}

// Teardown group-kills the forward and keepalive, removes the crash record, and
// best-effort closes the peer's bridge.
func (s *proxyBridgeSession) Teardown() {
	s.cancel()
	_ = s.tunnel.Close()
	_ = s.keepalive.Close()
	_ = os.RemoveAll(s.dataDir)
	remoteBridgeClose(context.Background(), s.runner, s.host, s.capB)
}

// handleBridgeKeepalive holds a peer-side bridge alive: it blocks until the
// origin's keepalive CLI socket closes (synckit cancels the dispatch ctx on that
// close), then reaps the bridge the capability keys.
func (d *Daemon) handleBridgeKeepalive(ctx context.Context, params map[string]any) (any, error) {
	capability, err := stringParam(params, "capability")
	if err != nil {
		return nil, err
	}
	<-ctx.Done()
	d.teardownBridge(capability)
	return map[string]any{"closed": true}, nil
}

// remoteBridgeOpen opens a bridge on a peer and fronts it locally: it shells the
// peer's own bridge_open (which taps consent on the peer and seeds the peer's
// cookies there — the key never crosses the wire), spawns an ssh -L forward back
// to the peer's loopback, proves it up, and registers a proxy session. A lost
// port-bind race re-opens on a fresh port, bounded by remoteBridgeOpenAttempts.
func (d *Daemon) remoteBridgeOpen(ctx context.Context, self, host, browser, profile string, headed bool) (any, error) {
	var lastErr error
	for attempt := 0; attempt < remoteBridgeOpenAttempts; attempt++ {
		result, retry, err := d.tryRemoteBridgeOpen(ctx, self, host, browser, profile, headed)
		if err == nil {
			return result, nil
		}
		lastErr = err
		if !retry {
			return nil, err
		}
	}
	return nil, fmt.Errorf("open cross-host bridge on %s after %d attempts: %w", host, remoteBridgeOpenAttempts, lastErr)
}

// tryRemoteBridgeOpen runs one cross-host open attempt. retry reports a
// port-collision the caller re-opens around; any other failure is terminal. Every
// failure past the peer open best-effort closes the peer's bridge before returning.
func (d *Daemon) tryRemoteBridgeOpen(ctx context.Context, self, host, browser, profile string, headed bool) (result any, retry bool, err error) {
	// Reserve a loopback port and hold it until the peer's bridge is open, so
	// nothing else grabs it between the advertise and the forward binding it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, false, fmt.Errorf("reserve bridge forward port: %w", err)
	}
	port, err := portOf(ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		return nil, false, err
	}

	reply, err := d.shellRemoteBridgeOpen(ctx, self, host, browser, profile, port, headed)
	// Anchor the lease at the reply, before the forward proof, so the origin's
	// expiry never overshoots the peer's by the proof latency.
	replyAt := time.Now()
	if err != nil {
		_ = ln.Close()
		// A reply that parsed a capability but failed validation still opened a peer
		// bridge; close it rather than leak it until the peer's TTL.
		if reply.Capability != "" {
			remoteBridgeClose(ctx, d.runner, host, reply.Capability)
		}
		return nil, false, err
	}
	token, err := bridgeToken(reply.URL)
	if err != nil {
		_ = ln.Close()
		remoteBridgeClose(ctx, d.runner, host, reply.Capability)
		return nil, false, err
	}
	// Release the reserved port so the forward can bind it.
	_ = ln.Close()

	sessionCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	var tunnel bridgeTunnel
	var keepalive bridgeKeepalive
	dataDir := ""
	success := false
	defer func() {
		if success {
			return
		}
		cancel()
		if tunnel != nil {
			_ = tunnel.Close()
		}
		if keepalive != nil {
			_ = keepalive.Close()
		}
		if dataDir != "" {
			_ = os.RemoveAll(dataDir)
		}
		remoteBridgeClose(ctx, d.runner, host, reply.Capability)
	}()

	// The workspace exists before the forward so onSpawn records the ssh child
	// before prove-up, leaving no unrecorded-tunnel crash window.
	dir, err := paths.Dir()
	if err != nil {
		return nil, false, err
	}
	sessionID, err := mintID()
	if err != nil {
		return nil, false, err
	}
	dataDir = filepath.Join(dir, bridgeSubdir, sessionID)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, false, fmt.Errorf("create proxy bridge dir: %w", err)
	}
	// onSpawn carries the peer host + capability the orphan sweep remote-closes B by.
	onSpawn := func(pid int) error {
		return writeProxyBridgeRecord(ctx, dataDir, pid, reply.Endpoint, host, reply.Capability)
	}
	tunnel, err = d.openTunnel(sessionCtx, bridge.TunnelSpec{
		Host: host, LocalPort: port, RemotePort: reply.ProxyPort, Token: token, WantWSURL: reply.URL,
	}, onSpawn)
	if err != nil {
		// Only a local-bind collision re-opens; every other ssh exit is terminal,
		// never re-tapping the peer's consent.
		return nil, errors.Is(err, bridge.ErrTunnelBindCollision), fmt.Errorf("forward to %s bridge: %w", host, err)
	}

	keepalive, err = d.openKeepalive(sessionCtx, tunnel.HostAddr(), reply.Capability)
	if err != nil {
		return nil, false, fmt.Errorf("supervise %s bridge: %w", host, err)
	}

	capA, err := mintSecret()
	if err != nil {
		return nil, false, err
	}
	sess := &proxyBridgeSession{
		sessionID: sessionID,
		capA:      capA,
		capB:      reply.Capability,
		host:      host,
		endpoint:  reply.Endpoint,
		browser:   reply.Browser,
		profile:   reply.Profile,
		wsURL:     reply.URL,
		proxyPort: port,
		expiry:    replyAt.Add(secondsToDuration(reply.ExpiresIn)),
		tunnel:    tunnel,
		keepalive: keepalive,
		cancel:    cancel,
		dataDir:   dataDir,
		runner:    d.runner,
	}

	d.bridgeMu.Lock()
	if d.bridgeShutdown {
		d.bridgeMu.Unlock()
		return nil, false, errBridgeShutdown // the defer unwinds forward, keepalive, dir, and the peer bridge
	}
	d.bridges[capA] = sess
	d.bridgeMu.Unlock()
	success = true

	go d.watchProxyBridge(sessionCtx, sess)

	out := sess.OpenResult()
	out["skipped"] = reply.Skipped
	return out, false, nil
}

// shellRemoteBridgeOpen shells the peer's own bridge_open over ssh, advertising
// this origin's forwarded loopback port and carrying no --host so the peer takes
// its local path. It sends no key or secret: --origin is display-only.
func (d *Daemon) shellRemoteBridgeOpen(ctx context.Context, self, host, browser, profile string, port int, headed bool) (remoteBridgeReply, error) {
	advertise := fmt.Sprintf("127.0.0.1:%d", port)
	cmd := fmt.Sprintf(
		"cookiesync rpc bridge_open --browser %s --profile %s --origin %s --advertise %s",
		hostregistry.ShellQuote(browser), hostregistry.ShellQuote(profile),
		hostregistry.ShellQuote(self), hostregistry.ShellQuote(advertise),
	)
	if !headed {
		cmd += " --headless"
	}
	rctx, cancel := context.WithTimeout(ctx, remoteBridgeOpenTimeout)
	defer cancel()
	out, err := d.runner.Run(rctx, host, cmd, nil)
	if err != nil {
		return remoteBridgeReply{}, fmt.Errorf("open bridge on %s: %w", host, err)
	}
	var reply remoteBridgeReply
	if err := json.Unmarshal([]byte(out), &reply); err != nil {
		return remoteBridgeReply{}, fmt.Errorf("parse bridge_open from %s: %w", host, err)
	}
	if reply.Capability == "" || reply.URL == "" || reply.ProxyPort == 0 {
		// Return the parsed reply so the caller can close a peer bridge whose
		// capability arrived; the raw JSON stays out of the error (it carries the
		// capability and the token-bearing url).
		return reply, fmt.Errorf("bridge_open from %s returned an incomplete reply", host)
	}
	return reply, nil
}

// watchProxyBridge tears the proxy down on the first of a forward or keepalive
// exit (a transport drop), the lease expiry, or the session context canceling.
func (d *Daemon) watchProxyBridge(ctx context.Context, sess *proxyBridgeSession) {
	timer := time.NewTimer(time.Until(sess.expiry))
	defer timer.Stop()
	select {
	case <-sess.tunnel.Done():
	case <-sess.keepalive.Done():
	case <-timer.C:
	case <-ctx.Done():
	}
	d.teardownBridge(sess.capA)
}

// remoteBridgeClose best-effort closes a peer's bridge over ssh, feeding the
// capability on stdin so it never lands in the peer's `ps`. Detached from ctx's
// cancellation so a torn-down parent still lets the cleanup run.
func remoteBridgeClose(ctx context.Context, runner engine.SSHRunner, host, capability string) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), remoteBridgeCloseTimeout)
	defer cancel()
	_, _ = runner.Run(cctx, host, "cookiesync rpc bridge_close", []byte(capability+"\n"))
}

// bridgeToken extracts the token path segment from a bridge ws url, the token
// gating the peer's /json/version and ws path that the forward proves up against.
func bridgeToken(wsURL string) (string, error) {
	// The url carries the token, so neither it nor url.Parse's echo of it (a
	// *url.Error embeds the raw input) enters the error.
	u, err := url.Parse(wsURL)
	if err != nil {
		return "", errors.New("bridge ws url is unparseable")
	}
	seg := strings.SplitN(strings.TrimPrefix(u.Path, "/"), "/", 2)
	if seg[0] == "" {
		return "", errors.New("bridge ws url has no token segment")
	}
	return seg[0], nil
}

// peerKnown reports whether host is a resolved mesh peer.
func peerKnown(peers []string, host string) bool {
	for _, p := range peers {
		if p == host {
			return true
		}
	}
	return false
}

// secondsToDuration converts a fractional-seconds lease TTL to a Duration.
func secondsToDuration(sec float64) time.Duration {
	return time.Duration(sec * float64(time.Second))
}
