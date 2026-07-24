package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/synckit/rpc"
)

// recordingRunner captures each ssh call and returns a canned stdout, so the backend's
// command shape and stdin payload are asserted without a real ssh.
type recordingRunner struct {
	calls []sshCall
	reply string
}

type sshCall struct {
	target string
	cmd    string
	stdin  []byte
}

func (r *recordingRunner) Run(_ context.Context, target, remoteCmd string, stdin []byte) (string, error) {
	r.calls = append(r.calls, sshCall{target: target, cmd: remoteCmd, stdin: append([]byte(nil), stdin...)})
	return r.reply, nil
}

// TestSSHBackendExtractParsesContract proves SSHBackend.Extract shells the rpc
// extract command and parses the exact v1 cookie envelope.
func TestSSHBackendExtractParsesContract(t *testing.T) {
	runner := &recordingRunner{
		reply: `{"protocol_version":1,"cookies":[{"host_key":".x.com","name":"sid","value":"abc","path":"/","expires_utc":13400000000000000,"last_update_utc":13350000000000000,"creation_utc":13300000000000000,"is_secure":true,"is_httponly":true,"samesite":2,"source_scheme":2,"source_port":443,"top_frame_site_key":"","has_cross_site_ancestor":0}]}`,
	}
	backend := NewSSHBackend(runner, "you@desktop", "me@laptop")

	got, err := backend.Extract(context.Background(), "chrome", "Default")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(got.Cookies) != 1 || got.Cookies[0].Value != "abc" || got.Cookies[0].HostKey != ".x.com" {
		t.Fatalf("parsed cookies = %+v", got.Cookies)
	}

	if len(runner.calls) != 1 {
		t.Fatalf("expected one ssh call, got %d", len(runner.calls))
	}
	call := runner.calls[0]
	if call.target != "you@desktop" {
		t.Fatalf("ssh target = %q, want you@desktop", call.target)
	}
	for _, want := range []string{
		"cookiesync rpc extract",
		"--browser 'chrome'",
		"--profile 'Default'",
		"--origin 'me@laptop'",
	} {
		if !strings.Contains(call.cmd, want) {
			t.Fatalf("extract command %q missing %q", call.cmd, want)
		}
	}
}

// TestSSHBackendApplyPipesWireEnvelope proves SSHBackend.Apply sends only the
// exact v1 cookie envelope and returns the applied count.
func TestSSHBackendApplyPipesWireEnvelope(t *testing.T) {
	runner := &recordingRunner{reply: `{"applied":2}`}
	backend := NewSSHBackend(runner, "you@desktop", "me@laptop")

	cookies := []cookie.Cookie{ck(".x.com", "sid", "v", 1), ck(".y.com", "tok", "w", 2)}
	n, err := backend.Apply(context.Background(), "arc", "Work", cookies)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if n != 2 {
		t.Fatalf("applied = %d, want 2", n)
	}

	call := runner.calls[0]
	for _, want := range []string{"cookiesync rpc apply", "--browser 'arc'", "--profile 'Work'", "--origin 'me@laptop'"} {
		if !strings.Contains(call.cmd, want) {
			t.Fatalf("apply command %q missing %q", call.cmd, want)
		}
	}
	parsed, err := cookie.UnmarshalCookies(call.stdin)
	if err != nil {
		t.Fatalf("apply stdin not parseable as wire cookies: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("apply stdin has %d cookies, want 2", len(parsed))
	}
}

// TestExtractTimeoutTracksDispatchWindow pins extractTimeout to the peer handler's
// rpc.DispatchTimeout: a routed consent keeps nearly the peer's full dispatch window
// for the human's Touch ID tap, and the extract gives up 30s before the peer's own
// deadline fires. Guards against shrinking the window with a hardcoded value again.
func TestExtractTimeoutTracksDispatchWindow(t *testing.T) {
	if want := rpc.DispatchTimeout - 30*time.Second; extractTimeout != want {
		t.Fatalf("extractTimeout = %v, want %v (rpc.DispatchTimeout - 30s)", extractTimeout, want)
	}
}

// wedgedRunner blocks until the call's deadline kills it, then reports the kill the way
// exec.CommandContext does — a bare exit error that loses the context cause — so the
// deadline test proves the backend restores context.DeadlineExceeded itself.
type wedgedRunner struct{}

func (wedgedRunner) Run(ctx context.Context, _, _ string, _ []byte) (string, error) {
	<-ctx.Done()
	return "", errors.New("signal: killed")
}

// TestSSHBackendDeadlines proves a wedged peer makes Extract and Apply fail at their
// per-call deadline with an error that is context.DeadlineExceeded and names the
// operation and peer.
func TestSSHBackendDeadlines(t *testing.T) {
	restoreExtract, restoreApply := extractTimeout, applyTimeout
	extractTimeout, applyTimeout = 25*time.Millisecond, 25*time.Millisecond
	t.Cleanup(func() { extractTimeout, applyTimeout = restoreExtract, restoreApply })

	backend := NewSSHBackend(wedgedRunner{}, "you@desktop", "me@laptop")
	tests := []struct {
		name string
		call func(context.Context) error
		want string
	}{
		{
			name: "extract",
			call: func(ctx context.Context) error {
				_, err := backend.Extract(ctx, "chrome", "Default")
				return err
			},
			want: "rpc extract on you@desktop",
		},
		{
			name: "apply",
			call: func(ctx context.Context) error {
				_, err := backend.Apply(ctx, "chrome", "Default", []cookie.Cookie{ck(".x.com", "sid", "v", 1)})
				return err
			},
			want: "rpc apply on you@desktop",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			err := tt.call(context.Background())
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Fatalf("%s took %v, want failure at the ~25ms deadline", tt.name, elapsed)
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("%s error = %v, want context.DeadlineExceeded", tt.name, err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("%s error %q does not name the operation and peer %q", tt.name, err, tt.want)
			}
		})
	}
}
