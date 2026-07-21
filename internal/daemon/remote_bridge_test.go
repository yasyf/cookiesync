package daemon

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/bridge"
	"github.com/yasyf/cookiesync/internal/cookie"
)

// fakeTunnel stands in for a proven-up ssh -L forward behind the openTunnel seam.
type fakeTunnel struct {
	addr   string
	pid    int
	done   chan struct{}
	closed atomic.Bool
}

func (t *fakeTunnel) HostAddr() string      { return t.addr }
func (t *fakeTunnel) Pid() int              { return t.pid }
func (t *fakeTunnel) Done() <-chan struct{} { return t.done }
func (t *fakeTunnel) Close() error          { t.closed.Store(true); return nil }

// fakeKeepalive stands in for the ssh keepalive supervisor behind openKeepalive.
type fakeKeepalive struct {
	done   chan struct{}
	closed atomic.Bool
}

func (k *fakeKeepalive) Done() <-chan struct{} { return k.done }
func (k *fakeKeepalive) Close() error          { k.closed.Store(true); return nil }

// proxyBridgeSessionFor reads the proxy session a capability keys, for asserting
// the fields remoteBridgeOpen registered.
func proxyBridgeSessionFor(d *Daemon, capability string) (*proxyBridgeSession, bool) {
	d.bridgeMu.Lock()
	defer d.bridgeMu.Unlock()
	s, ok := d.bridges[capability]
	if !ok {
		return nil, false
	}
	ps, ok := s.(*proxyBridgeSession)
	return ps, ok
}

// cannedBridgeOpenReply is the peer's bridge_open reply the recordingRunner
// serves: the ws url advertises the origin's forwarded loopback and embeds the
// peer token, and capB is the peer-side capability the origin manages it by.
const cannedBridgeOpenReply = `{"protocol_version":1,"url":"ws://127.0.0.1:5555/tok-b/devtools/browser/uuid-b","endpoint":"you@desktop:chrome:Default","browser":"chrome","profile":"Default","capability":"cap-b-secret","expires_in":600,"proxy_port":6000,"seed":{"attempted":5,"seeded":2,"skipped":3,"undecryptable":1,"expired":1,"cdp_rejected":1}}`

// newProxyDaemon builds a daemon wired for a cross-host open: a mesh with the peer
// present, a runner serving the canned bridge_open reply, and the tunnel/keepalive
// seams pointed at fakes that record the spec and addr they were handed.
func newProxyDaemon(t *testing.T, runner *recordingRunner) (*Daemon, *bridge.TunnelSpec, *string) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	fakeMesh(t, "me@laptop", "you@desktop")
	st := stateWith("me@laptop", "")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(currentUser(t))), runner, fixedState{st: st}, fixedState{st: st})

	var gotSpec bridge.TunnelSpec
	var gotKeepaliveAddr string
	d.openTunnel = func(_ context.Context, spec bridge.TunnelSpec, onSpawn func(int) error) (bridgeTunnel, error) {
		gotSpec = spec
		// os.Getpid keeps the record's ps probe on a live pid; onSpawn writes the
		// crash-durable record before prove-up, exactly as the real OpenTunnel does.
		pid := os.Getpid()
		if err := onSpawn(pid); err != nil {
			return nil, err
		}
		return &fakeTunnel{addr: "desktop.local", pid: pid, done: make(chan struct{})}, nil
	}
	d.openKeepalive = func(_ context.Context, addr, _ string) (bridgeKeepalive, error) {
		gotKeepaliveAddr = addr
		return &fakeKeepalive{done: make(chan struct{})}, nil
	}
	return d, &gotSpec, &gotKeepaliveAddr
}

// TestRemoteBridgeOpenDispatch proves the cross-host open shells the peer's own
// bridge_open with --origin and the forwarded --advertise and NO --host, feeds the
// reply's token + proxy port into the forward, supervises it over the tunnel's
// proven-up addr, and registers a proxy session under a locally-minted capability
// that never leaks the peer's.
func TestRemoteBridgeOpenDispatch(t *testing.T) {
	runner := &recordingRunner{byMethod: map[string]string{"bridge_open": cannedBridgeOpenReply}}
	d, gotSpec, gotKeepaliveAddr := newProxyDaemon(t, runner)
	t.Cleanup(func() { d.closeAllBridges(context.Background()) })

	got, err := d.handleBridgeOpen(context.Background(), map[string]any{"browser": "chrome", "host": "you@desktop"})
	if err != nil {
		t.Fatalf("cross-host bridge_open: %v", err)
	}
	open := got.(map[string]any)

	capA, _ := open["capability"].(string)
	if capA == "" || capA == "cap-b-secret" {
		t.Fatalf("proxy capability = %q, want a locally-minted secret, never the peer's", capA)
	}
	if url, _ := open["url"].(string); url != "ws://127.0.0.1:5555/tok-b/devtools/browser/uuid-b" {
		t.Fatalf("proxy url = %q, want the peer's advertised ws url", url)
	}
	if ep, _ := open["endpoint"].(string); ep != "you@desktop:chrome:Default" {
		t.Fatalf("proxy endpoint = %q", ep)
	}
	if pp, _ := open["proxy_port"].(int); pp == 0 {
		t.Fatalf("proxy_port = %v, want the forwarded loopback port", open["proxy_port"])
	}
	if sd, _ := open["seed"].(seedReport); sd.Skipped != 3 || sd.Attempted != 5 || sd.Seeded != 2 {
		t.Fatalf("seed = %+v, want the peer's breakdown forwarded through", open["seed"])
	}

	// The forward got the peer's token, proxy port, and advertised ws url.
	if gotSpec.Host != "you@desktop" || gotSpec.RemotePort != 6000 || gotSpec.Token != "tok-b" {
		t.Fatalf("tunnel spec = %+v", *gotSpec)
	}
	if gotSpec.WantWSURL != "ws://127.0.0.1:5555/tok-b/devtools/browser/uuid-b" {
		t.Fatalf("tunnel WantWSURL = %q", gotSpec.WantWSURL)
	}
	if *gotKeepaliveAddr != "desktop.local" {
		t.Fatalf("keepalive addr = %q, want the tunnel's proven-up addr", *gotKeepaliveAddr)
	}

	// The shelled bridge_open carried --origin + --advertise 127.0.0.1: and NO --host.
	shelled := shelledCmd(t, runner, "bridge_open")
	if !strings.Contains(shelled, "--origin 'me@laptop'") {
		t.Fatalf("shelled bridge_open missing --origin: %q", shelled)
	}
	if !strings.Contains(shelled, "--advertise '127.0.0.1:") {
		t.Fatalf("shelled bridge_open missing loopback --advertise: %q", shelled)
	}
	if strings.Contains(shelled, "--host") {
		t.Fatalf("shelled bridge_open must not carry --host (peer defaults to local): %q", shelled)
	}

	// A proxy session is registered under capA, holding the peer capability for close.
	sess, ok := proxyBridgeSessionFor(d, capA)
	if !ok {
		t.Fatalf("no proxy session under capA %q", capA)
	}
	if sess.capB != "cap-b-secret" {
		t.Fatalf("proxy capB = %q, want the peer capability", sess.capB)
	}
	if got := bridgeCount(d); got != 1 {
		t.Fatalf("live sessions = %d, want 1", got)
	}
}

// TestRemoteBridgeOpenRejectsUnknownHost proves an open aimed at a host outside the
// mesh peer set is refused before any ssh, never shelled.
func TestRemoteBridgeOpenRejectsUnknownHost(t *testing.T) {
	runner := &recordingRunner{byMethod: map[string]string{"bridge_open": cannedBridgeOpenReply}}
	d, _, _ := newProxyDaemon(t, runner)

	_, err := d.handleBridgeOpen(context.Background(), map[string]any{"browser": "chrome", "host": "stranger@host"})
	if err == nil || !strings.Contains(err.Error(), "unknown host") {
		t.Fatalf("open to a non-peer = %v, want an unknown-host reject", err)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.calls) != 0 {
		t.Fatalf("a rejected host still shelled ssh: %+v", runner.calls)
	}
}

// TestRemoteBridgeReattachPrecedesDispatch proves a live proxy capability
// re-attaches — same reply, no fresh ssh open — ahead of the cross-host branch.
func TestRemoteBridgeReattachPrecedesDispatch(t *testing.T) {
	runner := &recordingRunner{byMethod: map[string]string{"bridge_open": cannedBridgeOpenReply}}
	d, _, _ := newProxyDaemon(t, runner)
	t.Cleanup(func() { d.closeAllBridges(context.Background()) })

	sess := &proxyBridgeSession{
		capA:      "cap-a-live",
		capB:      "cap-b-secret",
		host:      "you@desktop",
		endpoint:  "you@desktop:chrome:Default",
		browser:   "chrome",
		profile:   "Default",
		wsURL:     "ws://127.0.0.1:5555/tok-b/devtools/browser/uuid-b",
		proxyPort: 5555,
		expiry:    time.Now().Add(time.Minute),
		tunnel:    &fakeTunnel{done: make(chan struct{})},
		keepalive: &fakeKeepalive{done: make(chan struct{})},
		cancel:    func() {},
		runner:    runner,
	}
	d.bridges["cap-a-live"] = sess

	got, err := d.handleBridgeOpen(context.Background(), map[string]any{
		"browser": "chrome", "host": "you@desktop", "capability": "cap-a-live",
	})
	if err != nil {
		t.Fatalf("re-attach: %v", err)
	}
	if url, _ := got.(map[string]any)["url"].(string); url != sess.wsURL {
		t.Fatalf("re-attach url = %q, want %q", url, sess.wsURL)
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.calls) != 0 {
		t.Fatalf("re-attach shelled a fresh open: %+v", runner.calls)
	}
}

// TestHandleBridgeKeepaliveReapsOnSocketClose proves the keepalive handler blocks
// until its dispatch ctx cancels (the origin CLI socket closing), then tears down
// the bridge the capability keys — group-killing the forward and best-effort
// closing the peer's bridge.
func TestHandleBridgeKeepaliveReapsOnSocketClose(t *testing.T) {
	runner := &recordingRunner{}
	d, _, _ := newProxyDaemon(t, runner)

	tunnel := &fakeTunnel{done: make(chan struct{})}
	sess := &proxyBridgeSession{
		capA:      "cap-a",
		capB:      "cap-b-secret",
		host:      "you@desktop",
		endpoint:  "you@desktop:chrome:Default",
		browser:   "chrome",
		profile:   "Default",
		expiry:    time.Now().Add(time.Minute),
		tunnel:    tunnel,
		keepalive: &fakeKeepalive{done: make(chan struct{})},
		cancel:    func() {},
		runner:    runner,
	}
	d.bridges["cap-a"] = sess

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = d.handleBridgeKeepalive(ctx, map[string]any{"capability": "cap-a"})
		close(done)
	}()

	// The hold blocks while the socket is open.
	select {
	case <-done:
		t.Fatal("keepalive handler returned before the socket closed")
	case <-time.After(50 * time.Millisecond):
	}

	cancel() // the origin CLI socket closed → synckit cancels the dispatch ctx
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("keepalive handler did not reap after the socket closed")
	}

	if got := bridgeCount(d); got != 0 {
		t.Fatalf("session survived keepalive reap: live = %d", got)
	}
	if !tunnel.closed.Load() {
		t.Fatal("keepalive reap did not group-kill the forward")
	}
	call := shelledCall(t, runner, "bridge_close")
	if !strings.Contains(call.stdin, "cap-b-secret") {
		t.Fatalf("keepalive reap did not pass capB over stdin: cmd=%q stdin=%q", call.cmd, call.stdin)
	}
	if strings.Contains(call.cmd, "cap-b-secret") {
		t.Fatalf("capB leaked into the ssh argv (visible to peer ps): %q", call.cmd)
	}
}

// TestRemoteBridgeOpenRetriesOnlyOnForwardExit proves ONLY a genuine local-bind
// collision re-opens to the attempt cap; every other ssh exit — a plain forward
// exit or a prove-up mismatch — is terminal and never re-taps the peer. Either way
// each abandoned peer bridge is best-effort closed.
func TestRemoteBridgeOpenRetriesOnlyOnForwardExit(t *testing.T) {
	tests := []struct {
		name      string
		tunnelErr error
		wantOpens int
	}{
		{"local-bind collision retries to the cap", bridge.ErrTunnelBindCollision, remoteBridgeOpenAttempts},
		{"a plain forward exit is terminal", bridge.ErrTunnelExited, 1},
		{"a prove-up mismatch is terminal", errors.New("prove ssh tunnel: url mismatch"), 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &recordingRunner{byMethod: map[string]string{"bridge_open": cannedBridgeOpenReply}}
			d, _, _ := newProxyDaemon(t, runner)
			d.openTunnel = func(context.Context, bridge.TunnelSpec, func(int) error) (bridgeTunnel, error) {
				return nil, tc.tunnelErr
			}

			_, err := d.handleBridgeOpen(context.Background(), map[string]any{"browser": "chrome", "host": "you@desktop"})
			if err == nil {
				t.Fatal("a forward that never comes up must fail the open")
			}
			if got := countCmds(runner, "bridge_open"); got != tc.wantOpens {
				t.Fatalf("bridge_open shells = %d, want %d", got, tc.wantOpens)
			}
			if got := countCmds(runner, "bridge_close"); got != tc.wantOpens {
				t.Fatalf("bridge_close shells = %d, want %d (one per abandoned peer bridge)", got, tc.wantOpens)
			}
			if got := bridgeCount(d); got != 0 {
				t.Fatalf("a failed open registered a session: %d", got)
			}
		})
	}
}

// TestRemoteBridgeOpenClosesIncompleteReply proves a reply carrying the peer
// capability but missing the url/proxy_port closes the peer bridge rather than leak
// it, registers nothing, and never surfaces the capability or token in the error.
func TestRemoteBridgeOpenClosesIncompleteReply(t *testing.T) {
	incomplete := `{"protocol_version":1,"capability":"cap-b-secret","endpoint":"you@desktop:chrome:Default","browser":"chrome","profile":"Default","expires_in":600}`
	runner := &recordingRunner{byMethod: map[string]string{"bridge_open": incomplete}}
	d, _, _ := newProxyDaemon(t, runner)

	_, err := d.handleBridgeOpen(context.Background(), map[string]any{"browser": "chrome", "host": "you@desktop"})
	if err == nil {
		t.Fatal("an incomplete reply must fail the open")
	}
	if strings.Contains(err.Error(), "cap-b-secret") || strings.Contains(err.Error(), "tok-b") {
		t.Fatalf("error leaked the capability or token: %v", err)
	}
	if got := countCmds(runner, "bridge_close"); got != 1 {
		t.Fatalf("bridge_close on an incomplete reply = %d, want 1", got)
	}
	if got := bridgeCount(d); got != 0 {
		t.Fatalf("an incomplete reply registered a session: %d", got)
	}
}

// TestBridgeTokenMalformedURLRedacts proves an unparseable ws url — whose path
// carries the token — never leaks it through the error url.Parse would echo.
func TestBridgeTokenMalformedURLRedacts(t *testing.T) {
	_, err := bridgeToken("ws://127.0.0.1:5555/tok-secret/%zz")
	if err == nil {
		t.Fatal("a malformed ws url must fail bridgeToken")
	}
	if strings.Contains(err.Error(), "tok-secret") {
		t.Fatalf("bridgeToken leaked the token from a parse error: %v", err)
	}
}

// countCmds counts the recorded ssh commands containing sub.
func countCmds(runner *recordingRunner, sub string) int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	n := 0
	for _, c := range runner.calls {
		if strings.Contains(c.cmd, sub) {
			n++
		}
	}
	return n
}

// shelledCmd returns the single recorded ssh command containing sub, failing if
// there is not exactly one.
func shelledCmd(t *testing.T, runner *recordingRunner, sub string) string {
	t.Helper()
	return shelledCall(t, runner, sub).cmd
}

// shelledCall returns the single recorded ssh call whose command contains sub,
// failing if there is not exactly one — the whole call so a test asserts its stdin.
func shelledCall(t *testing.T, runner *recordingRunner, sub string) runnerCall {
	t.Helper()
	runner.mu.Lock()
	defer runner.mu.Unlock()
	var found []runnerCall
	for _, c := range runner.calls {
		if strings.Contains(c.cmd, sub) {
			found = append(found, c)
		}
	}
	if len(found) != 1 {
		t.Fatalf("recorded %d ssh commands containing %q, want 1: %+v", len(found), sub, runner.calls)
	}
	return found[0]
}
