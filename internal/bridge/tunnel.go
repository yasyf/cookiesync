package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yasyf/synckit/hostregistry"
)

// sshBin is the ssh binary the tunnel shells; a var so tests point it at a fake.
var sshBin = "ssh"

// tunnelDialOpts replicates synckit hostregistry's unexported per-attempt ssh
// options (BatchMode, a short ConnectTimeout, and keepalives) verbatim, since
// they are not exported. The forward adds ExitOnForwardFailure and -N on top.
var tunnelDialOpts = []string{
	"-o", "BatchMode=yes",
	"-o", "ConnectTimeout=3",
	"-o", "ServerAliveInterval=5",
	"-o", "ServerAliveCountMax=3",
}

// tunnelProveTimeout bounds the proven-up handshake over a freshly-spawned
// forward; a var so tests shrink it.
var tunnelProveTimeout = 15 * time.Second

// tunnelProbeInterval paces the proven-up retry and caps each /json/version GET;
// a var so tests shrink it.
var tunnelProbeInterval = 500 * time.Millisecond

// tunnelProbeClient never follows redirects: the bridge's /json/version is a
// synthetic endpoint that never 3xxs, and following one could reflect the
// token-bearing request path into an error via a Location header.
var tunnelProbeClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// ErrTunnelExited reports the ssh child died before the forward was proven up for
// a reason other than a local-bind collision — a dead dial candidate, an auth or
// network failure — which is terminal: the caller must not re-tap the peer.
var ErrTunnelExited = errors.New("bridge: ssh tunnel exited before it forwarded")

// ErrTunnelBindCollision reports the forward could not bind its 127.0.0.1 local
// port — an unrelated listener won the race — the one exit the caller re-allocates
// a fresh port and re-opens around.
var ErrTunnelBindCollision = errors.New("bridge: ssh tunnel local bind collision")

// errProbeUnreachable and errProbeDecode are fixed, token-free probe failures: the
// probe url and any adversarial response text (which could reflect the token) never
// enter them.
var (
	errProbeUnreachable = errors.New("json/version unreachable")
	errProbeDecode      = errors.New("json/version decode failed")
)

// TunnelSpec configures one detached `ssh -N -L` loopback forward from the
// origin-side pre-allocated port to a peer's bridge loopback port, proven up by
// a token-gated /json/version GET before it is published.
type TunnelSpec struct {
	Host       string // peer ssh target; DialAddrs resolves its ordered dial candidates
	LocalPort  int    // pre-allocated 127.0.0.1 origin port the forward binds
	RemotePort int    // peer loopback port the bridge server listens on
	Token      string // bridge token gating the peer's /json/version and ws path
	WantWSURL  string // the webSocketDebuggerUrl the proven-up GET must observe
}

// Tunnel is a detached `ssh -N -L` local forward that owns its ssh child with
// the same process-group-SIGKILL discipline as Launch, so teardown never leaks
// an ssh helper. It is proven up before OpenTunnel returns it.
type Tunnel struct {
	cmd       *exec.Cmd
	cancel    context.CancelFunc
	localPort int
	addr      string
	done      chan struct{}
	closeOnce sync.Once
}

// OpenTunnel spawns a proven-up ssh -L forward to spec.Host, dialing the ordered
// candidates hostregistry.DialAddrs resolves — LAN/.local first, the FQDN last —
// and advancing to the next on a dead candidate (ssh's ExitOnForwardFailure
// exits promptly, failing the proven-up probe). onSpawn is invoked with the ssh
// child's pid the instant it starts, before the prove-up wait, so the caller can
// record a crash-durable pointer to the live forward before it is registered. The
// child runs under ctx, so a caller that cancels ctx group-kills the forward. A
// local-bind collision short-circuits the candidate walk, since every addr shares
// the same local port — the caller re-allocates and re-opens on that alone.
func OpenTunnel(ctx context.Context, spec TunnelSpec, onSpawn func(pid int) error) (*Tunnel, error) {
	addrs, err := hostregistry.DialAddrs(spec.Host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, addr := range addrs {
		t, err := dialTunnel(ctx, addr, spec, onSpawn)
		if err == nil {
			return t, nil
		}
		if errors.Is(err, ErrTunnelBindCollision) {
			return nil, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("open ssh tunnel to %s: %w", spec.Host, lastErr)
}

// dialTunnel spawns one ssh forward to addr, records it via onSpawn, then proves
// it up, tearing the child down on any failure so a failed attempt leaks nothing.
func dialTunnel(ctx context.Context, addr string, spec TunnelSpec, onSpawn func(pid int) error) (*Tunnel, error) {
	runCtx, cancel := context.WithCancel(ctx)
	var stderr bytes.Buffer
	cmd := exec.CommandContext(runCtx, sshBin, tunnelArgv(addr, spec.LocalPort, spec.RemotePort)...) //nolint:gosec // G204: sshBin is a fixed binary; addr/ports come from trusted local mesh state, not untrusted input.
	cmd.Stderr = &stderr
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
		return nil, fmt.Errorf("start ssh tunnel to %s: %w", addr, err)
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	t := &Tunnel{cmd: cmd, cancel: cancel, localPort: spec.LocalPort, addr: addr, done: done}
	// Record the live child before proving it up, so an A-side crash during the
	// prove-up window still leaves the orphan sweep a pid to reap.
	if err := onSpawn(cmd.Process.Pid); err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("record ssh tunnel to %s: %w", addr, err)
	}
	probeURL := fmt.Sprintf("http://127.0.0.1:%d/%s/json/version", spec.LocalPort, spec.Token)
	if err := proveTunnelUp(ctx, done, &stderr, spec.LocalPort, probeURL, spec.WantWSURL); err != nil {
		_ = t.Close()
		return nil, err
	}
	return t, nil
}

// tunnelArgv builds the ssh argument vector for the forward: the replicated dial
// options, ExitOnForwardFailure so a dead peer exits rather than hangs, -N (no
// remote command), and an explicit 127.0.0.1-only local bind so the forward is
// never exposed off loopback.
func tunnelArgv(addr string, localPort, remotePort int) []string {
	args := append([]string{}, tunnelDialOpts...)
	return append(args,
		"-o", "ExitOnForwardFailure=yes",
		"-N",
		"-L", fmt.Sprintf("127.0.0.1:%d:127.0.0.1:%d", localPort, remotePort),
		addr,
	)
}

// proveTunnelUp polls the peer's /json/version through the forward until its
// webSocketDebuggerUrl matches the one the peer advertised — proof the forward
// reaches the right bridge — bounded by tunnelProveTimeout. The GET does not
// consume the bridge's single-client slot. A child that dies mid-probe is
// classified from its stderr: a local-bind collision the caller re-allocates
// around, or a terminal exit it must not re-tap. Diagnostics redact the token the
// probe/ws urls carry, so it never reaches a log.
func proveTunnelUp(ctx context.Context, done <-chan struct{}, stderr *bytes.Buffer, localPort int, probeURL, wantWSURL string) error {
	deadline := time.Now().Add(tunnelProveTimeout)
	for {
		select {
		case <-done:
			return classifyTunnelExit(stderr, localPort)
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		got, err := probeVersion(ctx, probeURL)
		if err == nil && got == wantWSURL {
			return nil
		}
		if !time.Now().Before(deadline) {
			if err != nil {
				return fmt.Errorf("prove ssh tunnel %s: %w", redactToken(probeURL), err)
			}
			// Never print got/wantWSURL: got is attacker-influenceable and could
			// reflect the token even in a url's host, which redactToken keeps.
			return fmt.Errorf("prove ssh tunnel %s: webSocketDebuggerUrl mismatch", redactToken(probeURL))
		}
		select {
		case <-time.After(tunnelProbeInterval):
		case <-done:
			return classifyTunnelExit(stderr, localPort)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// classifyTunnelExit reads an exited ssh child's stderr to tell a local-forward
// bind collision (retryable on a fresh port) from any other exit (auth, network,
// a dead peer — terminal), returning a bare sentinel so no ssh stderr text is
// surfaced.
func classifyTunnelExit(stderr *bytes.Buffer, localPort int) error {
	if isBindCollision(stderr.String(), localPort) {
		return ErrTunnelBindCollision
	}
	return ErrTunnelExited
}

// isBindCollision reports whether ssh exited because OUR local forward could not
// bind localPort. It requires a single stderr line to BOTH carry a bind diagnostic
// AND name localPort as a whole number, so an unrelated forwarding's collision (a
// foreign port, or our port only in a banner line) is never misread as ours and
// never re-taps the peer. ssh reports it as `bind [127.0.0.1]:<port>: Address
// already in use` or `cannot listen to port: <port>`.
func isBindCollision(stderr string, localPort int) bool {
	want := fmt.Sprintf("%d", localPort)
	for _, line := range strings.Split(stderr, "\n") {
		if p, ok := bindFailurePort(line); ok && p == want {
			return true
		}
	}
	return false
}

// bindFailurePort extracts the port ssh names at the syntactic port position of a
// local-forward bind failure — `bind [<addr>]:<port>: Address already in use` or
// `cannot listen to port: <port>` — or ok=false for any other line, so a port that
// merely co-occurs elsewhere on the line is never mistaken for the bound one.
func bindFailurePort(line string) (string, bool) {
	if strings.Contains(line, "Address already in use") {
		// Anchor to ssh's `bind [<addr>]:<port>:` prefix so a bracket later on the
		// line can't be mistaken for the bound port.
		b := strings.Index(line, "bind [")
		if b < 0 {
			return "", false
		}
		rest := line[b+len("bind ["):]
		k := strings.Index(rest, "]:")
		if k < 0 {
			return "", false
		}
		rest = rest[k+2:]
		j := strings.IndexByte(rest, ':')
		if j <= 0 {
			return "", false
		}
		return rest[:j], true
	}
	if i := strings.Index(line, "cannot listen to port: "); i >= 0 {
		return strings.TrimSpace(line[i+len("cannot listen to port: "):]), true
	}
	return "", false
}

// redactToken rebuilds a bridge url as scheme://host, dropping the path segment
// that carries the secret token so no error, log, or wrapped %w string leaks it.
func redactToken(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "<redacted-url>"
	}
	return u.Scheme + "://" + u.Host
}

// probeVersion GETs the token-gated /json/version and returns its
// webSocketDebuggerUrl, bounded by one probe interval.
func probeVersion(ctx context.Context, probeURL string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, tunnelProbeInterval)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, probeURL, nil)
	if err != nil {
		return "", errProbeUnreachable
	}
	// A transport error's text can reflect the token (Go parses a redirect Location
	// before CheckRedirect fires); return a fixed, token-free failure instead.
	resp, err := tunnelProbeClient.Do(req)
	if err != nil {
		return "", errProbeUnreachable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("json/version status %d", resp.StatusCode)
	}
	var v struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", errProbeDecode
	}
	return v.WebSocketDebuggerURL, nil
}

// Done is closed when the ssh forward exits — the signal the daemon's session
// watcher tears the proxy bridge down on.
func (t *Tunnel) Done() <-chan struct{} {
	return t.done
}

// LocalPort is the 127.0.0.1 port the forward binds, the loopback port a bridge
// client connects to.
func (t *Tunnel) LocalPort() int {
	return t.localPort
}

// HostAddr is the dial address the forward proved up on — the address a sibling
// keepalive to the same peer reuses so both cross the same route.
func (t *Tunnel) HostAddr() string {
	return t.addr
}

// Pid is the ssh forward child's pid (its process-group id via Setpgid), the id
// the origin's crash-durable record group-kills on an orphan sweep.
func (t *Tunnel) Pid() int {
	return t.cmd.Process.Pid
}

// Close group-SIGKILLs the ssh forward and waits for it to reap. It is
// idempotent.
func (t *Tunnel) Close() error {
	t.closeOnce.Do(func() {
		t.cancel()
		<-t.done
	})
	return nil
}
