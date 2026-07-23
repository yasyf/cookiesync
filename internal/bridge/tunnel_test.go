package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yasyf/daemonkit/proc"
	"github.com/yasyf/daemonkit/supervise"
	"github.com/yasyf/synckit/hostregistry"
)

// TestTunnelArgv proves the ssh argument vector replicates hostregistry's dial
// options, adds ExitOnForwardFailure and -N, and binds the local forward to
// 127.0.0.1 only (never the wildcard).
func TestTunnelArgv(t *testing.T) {
	got := tunnelArgv("you@desktop", 5000, 6000)
	want := []string{
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=3",
		"-o", "ServerAliveInterval=5",
		"-o", "ServerAliveCountMax=3",
		"-o", "ExitOnForwardFailure=yes",
		"-N",
		"-L", "127.0.0.1:5000:127.0.0.1:6000",
		"you@desktop",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tunnelArgv = %v, want %v", got, want)
	}
	// The forward must never bind the wildcard.
	if strings.Contains(strings.Join(got, " "), "0.0.0.0:") || strings.Contains(strings.Join(got, " "), "*:") {
		t.Fatalf("tunnelArgv exposed a non-loopback bind: %v", got)
	}
}

// versionServer serves a token-gated /json/version returning wsURL, mimicking
// the bridge Server's proven-up surface without a real Chrome.
func versionServer(t *testing.T, token, wsURL string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+token+"/json/version" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"webSocketDebuggerUrl": wsURL})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestProveTunnelUpMatches proves the probe publishes only once the forwarded
// /json/version echoes the exact advertised webSocketDebuggerUrl.
func TestProveTunnelUpMatches(t *testing.T) {
	token := "tok-abc"
	wsURL := "ws://127.0.0.1:5000/tok-abc/devtools/browser/uuid-1"
	srv := versionServer(t, token, wsURL)

	done := make(chan struct{}) // never closes: the child stays alive
	probeURL := srv.URL + "/" + token + "/json/version"
	if err := proveTunnelUp(context.Background(), done, &bytes.Buffer{}, 5000, probeURL, wsURL); err != nil {
		t.Fatalf("proveTunnelUp on a matching endpoint: %v", err)
	}
}

// TestProveTunnelUpMismatchFailsClosed proves a forward that reaches the wrong
// bridge (a webSocketDebuggerUrl that does not echo the advertised one) is never
// published — the probe fails after the bounded deadline.
func TestProveTunnelUpMismatchFailsClosed(t *testing.T) {
	token := "tok-abc"
	srv := versionServer(t, token, "ws://127.0.0.1:5000/tok-abc/devtools/browser/WRONG")

	old := tunnelProveTimeout
	tunnelProveTimeout = 150 * time.Millisecond
	tunnelProbeInterval = 10 * time.Millisecond
	t.Cleanup(func() { tunnelProveTimeout = old; tunnelProbeInterval = 500 * time.Millisecond })

	done := make(chan struct{})
	probeURL := srv.URL + "/" + token + "/json/version"
	err := proveTunnelUp(context.Background(), done, &bytes.Buffer{}, 5000, probeURL, "ws://127.0.0.1:5000/tok-abc/devtools/browser/uuid-1")
	if err == nil {
		t.Fatalf("proveTunnelUp must fail closed on a webSocketDebuggerUrl mismatch")
	}
	if errors.Is(err, ErrTunnelExited) {
		t.Fatalf("a mismatch must be a probe failure, not ErrTunnelExited: %v", err)
	}
	// The token lives in the probe/ws url path; it must never reach the error string.
	if strings.Contains(err.Error(), token) {
		t.Fatalf("mismatch error leaked the token %q: %v", token, err)
	}
}

// TestProveTunnelUpChildExit proves an ssh child that dies for a non-collision
// reason before the forward comes up is a terminal ErrTunnelExited (not a timeout,
// not a collision), so the caller fails fast without re-tapping the peer.
func TestProveTunnelUpChildExit(t *testing.T) {
	done := make(chan struct{})
	close(done) // the ssh child already exited
	stderr := bytes.NewBufferString("ssh: connect to host desktop port 22: Connection refused\n")
	err := proveTunnelUp(context.Background(), done, stderr, 41000, "http://127.0.0.1:1/tok/json/version", "ws://x")
	if !errors.Is(err, ErrTunnelExited) {
		t.Fatalf("proveTunnelUp on a dead child = %v, want ErrTunnelExited", err)
	}
	if errors.Is(err, ErrTunnelBindCollision) {
		t.Fatalf("a connection-refused exit must not be a bind collision: %v", err)
	}
}

// TestProveTunnelUpBindCollision proves an ssh child that exited because OUR local
// forward could not bind its port is ErrTunnelBindCollision — the one exit the
// caller re-allocates a fresh port and re-opens around.
func TestProveTunnelUpBindCollision(t *testing.T) {
	done := make(chan struct{})
	close(done)
	stderr := bytes.NewBufferString("bind [127.0.0.1]:41000: Address already in use\nCould not request local forwarding.\n")
	err := proveTunnelUp(context.Background(), done, stderr, 41000, "http://127.0.0.1:1/tok/json/version", "ws://x")
	if !errors.Is(err, ErrTunnelBindCollision) {
		t.Fatalf("proveTunnelUp on a bind failure = %v, want ErrTunnelBindCollision", err)
	}
}

// TestProveTunnelUpForeignForwardCollisionIsTerminal proves a bind collision on an
// UNRELATED forward's port (not ours) is terminal, never re-tapping the peer — the
// classifier keys strictly on our own local port.
func TestProveTunnelUpForeignForwardCollisionIsTerminal(t *testing.T) {
	done := make(chan struct{})
	close(done)
	stderr := bytes.NewBufferString("bind [127.0.0.1]:41000: Address already in use\nCould not request local forwarding.\n")
	err := proveTunnelUp(context.Background(), done, stderr, 51000, "http://127.0.0.1:1/tok/json/version", "ws://x")
	if !errors.Is(err, ErrTunnelExited) {
		t.Fatalf("a foreign-forward collision = %v, want terminal ErrTunnelExited", err)
	}
	if errors.Is(err, ErrTunnelBindCollision) {
		t.Fatalf("a collision on someone else's port must not re-tap the peer: %v", err)
	}
}

// TestProveTunnelUpCollisionPrecision proves the classifier only calls a collision
// when the bind diagnostic and our exact port share one line — a foreign-port
// failure with our port only in a banner, or our port as a digit-substring of a
// larger number, both stay terminal and never re-tap the peer.
func TestProveTunnelUpCollisionPrecision(t *testing.T) {
	tests := []struct {
		name   string
		stderr string
	}{
		{
			"our port only in a banner, foreign port collides",
			"debug1: Local forwarding listening on 127.0.0.1 port 41000.\nbind [127.0.0.1]:51000: Address already in use\n",
		},
		{
			"our port is a digit-substring of the colliding port",
			"bind [127.0.0.1]:141000: Address already in use\n",
		},
		{
			"foreign-port collision names our port later on the same line",
			"bind [127.0.0.1]:51000: Address already in use; advertised port 41000\n",
		},
		{
			"foreign-port collision with a bracket-shaped tail naming our port",
			"bind [127.0.0.1]:51000: Address already in use; advertised [x]:41000:\n",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan struct{})
			close(done)
			err := proveTunnelUp(context.Background(), done, bytes.NewBufferString(tc.stderr), 41000, "http://127.0.0.1:1/tok/json/version", "ws://x")
			if !errors.Is(err, ErrTunnelExited) || errors.Is(err, ErrTunnelBindCollision) {
				t.Fatalf("want terminal ErrTunnelExited, got %v", err)
			}
		})
	}
}

// TestProveTunnelUpProbeFailureRedactsToken proves a probe that fails to connect
// (a live child, no server) never leaks the token the probe url's path carries —
// the underlying *url.Error's echo of the url is stripped.
func TestProveTunnelUpProbeFailureRedactsToken(t *testing.T) {
	token := "tok-secret-xyz"
	old := tunnelProveTimeout
	tunnelProveTimeout = 80 * time.Millisecond
	tunnelProbeInterval = 10 * time.Millisecond
	t.Cleanup(func() { tunnelProveTimeout = old; tunnelProbeInterval = 500 * time.Millisecond })

	done := make(chan struct{}) // the child stays alive; only the probe fails
	// 127.0.0.1:9 (discard) is closed here → connection refused, a *url.Error.
	probeURL := "http://127.0.0.1:9/" + token + "/json/version"
	err := proveTunnelUp(context.Background(), done, &bytes.Buffer{}, 41000, probeURL, "ws://127.0.0.1:9/"+token+"/x")
	if err == nil {
		t.Fatal("proveTunnelUp against a dead probe port must fail")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("probe-failure error leaked the token: %v", err)
	}
}

// TestRedactToken proves a bridge url is reduced to scheme://host so the secret
// token in its path never reaches an error or log.
func TestRedactToken(t *testing.T) {
	got := redactToken("ws://127.0.0.1:5000/tok-abc/devtools/browser/uuid-1")
	if got != "ws://127.0.0.1:5000" {
		t.Fatalf("redactToken = %q, want ws://127.0.0.1:5000", got)
	}
	if strings.Contains(got, "tok-abc") {
		t.Fatalf("redactToken leaked the token: %q", got)
	}
}

// TestOpenTunnelDialsAddrsInOrder proves OpenTunnel walks hostregistry.DialAddrs
// in order — LAN/.local candidates first, the ssh target last — advancing to the
// next when a forward fails to come up, behind the sshBin seam.
func TestOpenTunnelDialsAddrsInOrder(t *testing.T) {
	target := "you@desktop"
	seedDialAddrs(t, target, []string{"desktop.local", "desktop.lan"})

	recordPath := filepath.Join(t.TempDir(), "ssh-args")
	t.Setenv("SSH_TUNNEL_RECORD", recordPath)
	restore := sshBin
	sshBin = fakeSSHScript(t)
	t.Cleanup(func() { sshBin = restore })

	tunnelProveTimeout = 200 * time.Millisecond
	tunnelProbeInterval = 10 * time.Millisecond
	t.Cleanup(func() { tunnelProveTimeout = 15 * time.Second; tunnelProbeInterval = 500 * time.Millisecond })

	// Every fake ssh exits 0 without forwarding, so no candidate proves up and
	// OpenTunnel exhausts the ordered list.
	ctx := t.Context()
	_, err := OpenTunnel(ctx, testProcessPool(ctx, t), TunnelSpec{
		Host: target, LocalPort: 41000, RemotePort: 42000, Token: "tok", WantWSURL: "ws://never",
	}, nil)
	if err == nil {
		t.Fatalf("OpenTunnel over fake ssh that never forwards must fail")
	}

	dialed := recordedAddrs(t, recordPath)
	want := []string{"desktop.local", "desktop.lan", target}
	if !reflect.DeepEqual(dialed, want) {
		t.Fatalf("dialed addrs = %v, want DialAddrs order %v", dialed, want)
	}
}

func TestTunnelStartErrorMapsManagedEarlyExit(t *testing.T) {
	ctx := t.Context()
	_, startErr := testProcessPool(ctx, t).Start(ctx, supervise.ProcessSpec{
		RecoveryClass:    proc.RecoveryTask,
		Path:             "/usr/bin/false",
		ReadinessTimeout: 5 * time.Second,
		Ready: func(readyCtx context.Context, _ proc.Record) error {
			<-readyCtx.Done()
			return readyCtx.Err()
		},
	})
	if !errors.Is(startErr, supervise.ErrProcessExitedBeforeReadiness) {
		t.Fatalf("managed false start = %v, want typed early exit", startErr)
	}
	err := fmtTunnelStartError("desktop.local", startErr)
	if !errors.Is(err, ErrTunnelExited) || !errors.Is(err, supervise.ErrProcessExitedBeforeReadiness) {
		t.Fatalf("mapped early exit = %v, want product and daemonkit identities", err)
	}
}

func TestTunnelStartErrorClassifiesOnlyTypedEarlyExit(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"typed child exit", errors.Join(supervise.ErrProcessExitedBeforeReadiness, errors.New("exit status 255")), true},
		{"context cancellation", context.Canceled, false},
		{"readiness timeout", context.DeadlineExceeded, false},
		{"readiness mismatch", errors.New("webSocketDebuggerUrl mismatch"), false},
		{"recorded failure", errors.New("accept managed process record: fsync failed"), false},
		{"tracking failure", errors.New("track managed process: store failed"), false},
		{"admission failure", supervise.ErrClosed, false},
		{"start failure", errors.New("start managed process: executable missing"), false},
		{"gate failure", errors.New("release managed process gate: broken pipe"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := fmtTunnelStartError("desktop.local", tc.err)
			if got := errors.Is(err, ErrTunnelExited); got != tc.want {
				t.Fatalf("ErrTunnelExited = %t, want %t: %v", got, tc.want, err)
			}
			if !errors.Is(err, tc.err) {
				t.Fatalf("underlying error identity lost: %v", err)
			}
		})
	}
}

// seedDialAddrs writes a synckit state.json under a temp XDG_CONFIG_HOME mapping
// target to its ordered LAN dial addresses, so hostregistry.DialAddrs resolves
// them without a real registration.
func seedDialAddrs(t *testing.T, target string, addrs []string) {
	t.Helper()
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if err := hostregistry.Mesh.InitializeState(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		if err := hostregistry.Mesh.AddAddr(context.Background(), target, addr); err != nil {
			t.Fatal(err)
		}
	}
}

// fakeSSHScript writes an executable stand-in for ssh that records its dial
// address (the last positional arg) and exits 0 without forwarding.
func fakeSSHScript(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-ssh.sh")
	script := "#!/bin/sh\neval \"last=\\${$#}\"\nprintf '%s\\n' \"$last\" >> \"$SSH_TUNNEL_RECORD\"\nexit 0\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil { //nolint:gosec // G306: an executable test fixture under the test's own temp dir.
		t.Fatalf("write fake ssh: %v", err)
	}
	return path
}

// recordedAddrs reads the dial addresses the fake ssh recorded, in order.
func recordedAddrs(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is the test's own temp record file.
	if err != nil {
		t.Fatalf("read ssh record: %v", err)
	}
	var addrs []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line != "" {
			addrs = append(addrs, line)
		}
	}
	return addrs
}
