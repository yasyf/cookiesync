package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/synckit/hostregistry"
	"github.com/yasyf/synckit/rpc"
)

// SSH option set mirrors synckit's host transport: BatchMode plus connect/keepalive
// timeouts so a wedged peer fails fast instead of hanging a converge.
var sshOpts = []string{
	"-o", "BatchMode=yes",
	"-o", "ConnectTimeout=5",
	"-o", "ServerAliveInterval=5",
	"-o", "ServerAliveCountMax=3",
}

// Per-call deadlines for the two remote rpc calls, vars so tests shrink them.
var (
	// extractTimeout bounds a remote extract, which may block on a routed human
	// consent — a Touch ID tap on the peer. Derived from the peer handler's own
	// rpc.DispatchTimeout: the human keeps nearly that full window, and the 30s
	// margin makes us give up just before the peer's deadline fires.
	extractTimeout = rpc.DispatchTimeout - 30*time.Second
	// applyTimeout bounds a remote store write; no human is in the loop.
	applyTimeout = 60 * time.Second
)

// brewShellenv sources Homebrew's environment first, since a non-interactive ssh on
// macOS lacks brew — and thus a brew-installed cookiesync — on PATH.
const brewShellenv = `eval "$(/opt/homebrew/bin/brew shellenv)" && `

// SSHRunner runs a remote command over ssh, optionally piping stdin, and returns its
// stdout. It is the boundary the ssh-backed peer source crosses; tests inject a fake
// so the backend's payload shape is exercised without a real ssh. Defined here, where
// the SSHBackend consumes it.
type SSHRunner interface {
	// Run executes remoteCmd on target over ssh, piping stdin when non-nil, and
	// returns its stdout.
	Run(ctx context.Context, target, remoteCmd string, stdin []byte) (string, error)
}

// execSSHRunner is the production SSHRunner: it shells ssh with the standard option
// set and the brew-shellenv wrap.
type execSSHRunner struct{}

// NewExecSSHRunner returns the default SSHRunner that shells out to ssh.
func NewExecSSHRunner() SSHRunner {
	return execSSHRunner{}
}

func (execSSHRunner) Run(ctx context.Context, target, remoteCmd string, stdin []byte) (string, error) {
	args := append(append([]string{}, sshOpts...), target, brewShellenv+remoteCmd)
	cmd := exec.CommandContext(ctx, "ssh", args...) //nolint:gosec // G204: this sync tool's job is to run ssh; target/remoteCmd come from trusted local state (registered hosts), not untrusted input.
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("ssh %s: %w: %s", target, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// SSHBackend is a peer host's cookie store, reached by driving its daemon over ssh.
// The peer decrypts in its own GUI session, so cookies cross the wire already
// decrypted and the peer's Safe Storage key never leaves its machine. Origin is this
// host's own target, forwarded on every call so the peer's daemon suppresses the echo
// back to us. It is the ssh half of the Source seam.
type SSHBackend struct {
	runner SSHRunner
	target string
	origin string
}

// NewSSHBackend builds a peer source for target over runner, tagging every call with
// origin (this host) so the peer suppresses the echo.
func NewSSHBackend(runner SSHRunner, target, origin string) SSHBackend {
	return SSHBackend{runner: runner, target: target, origin: origin}
}

// Extract drives the peer's "cookiesync rpc extract" and parses the wire cookie
// records it streams back.
func (b SSHBackend) Extract(ctx context.Context, browser, profile string) (Extracted, error) {
	out, err := b.run(ctx, extractTimeout, "rpc extract", b.extractCmd(browser, profile), nil)
	if err != nil {
		return Extracted{}, err
	}
	var payload struct {
		Cookies []cookie.WireCookie `json:"cookies"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		return Extracted{}, fmt.Errorf("parse rpc extract from %s: %w", b.target, err)
	}
	cookies := make([]cookie.Cookie, len(payload.Cookies))
	for i, w := range payload.Cookies {
		cookies[i] = cookie.FromWire(w)
	}
	return Extracted{Cookies: cookies}, nil
}

// Apply pipes the merged set as a JSON array of wire records to the peer's "cookiesync
// rpc apply" stdin and returns the rows written.
func (b SSHBackend) Apply(ctx context.Context, browser, profile string, cookies []cookie.Cookie) (int, error) {
	body, err := json.Marshal(toWire(cookies))
	if err != nil {
		return 0, err
	}
	out, err := b.run(ctx, applyTimeout, "rpc apply", b.applyCmd(browser, profile), body)
	if err != nil {
		return 0, err
	}
	var payload struct {
		Applied int `json:"applied"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		return 0, fmt.Errorf("parse rpc apply from %s: %w", b.target, err)
	}
	return payload.Applied, nil
}

// run drives one remote rpc call bounded by timeout. A failure names the operation and
// peer; when the deadline killed the call the wrapped error is the context's, since
// exec.CommandContext reports the kill as a bare exit error that loses
// context.DeadlineExceeded.
func (b SSHBackend) run(ctx context.Context, timeout time.Duration, op, remoteCmd string, stdin []byte) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := b.runner.Run(ctx, b.target, remoteCmd, stdin)
	if err == nil {
		return out, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		err = ctxErr
	}
	return "", fmt.Errorf("%s on %s: %w", op, b.target, err)
}

func (b SSHBackend) extractCmd(browser, profile string) string {
	return fmt.Sprintf(
		"cookiesync rpc extract --browser %s --profile %s --origin %s",
		hostregistry.ShellQuote(browser), hostregistry.ShellQuote(profile), hostregistry.ShellQuote(b.origin),
	)
}

func (b SSHBackend) applyCmd(browser, profile string) string {
	return fmt.Sprintf(
		"cookiesync rpc apply --browser %s --profile %s --origin %s",
		hostregistry.ShellQuote(browser), hostregistry.ShellQuote(profile), hostregistry.ShellQuote(b.origin),
	)
}

func toWire(cookies []cookie.Cookie) []cookie.WireCookie {
	wire := make([]cookie.WireCookie, len(cookies))
	for i, c := range cookies {
		wire[i] = cookie.ToWire(c)
	}
	return wire
}
