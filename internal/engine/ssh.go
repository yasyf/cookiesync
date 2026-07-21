package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/synckit/hostregistry"
	"github.com/yasyf/synckit/rpc"
)

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

// SSHRunner runs a remote command over ssh, optionally piping stdin, and returns its
// stdout. It is the boundary the ssh-backed peer source crosses; tests inject a fake
// so the backend's payload shape is exercised without a real ssh. Defined here, where
// the SSHBackend consumes it.
type SSHRunner interface {
	// Run executes remoteCmd on target over ssh, piping stdin when non-nil, and
	// returns its stdout.
	Run(ctx context.Context, target, remoteCmd string, stdin []byte) (string, error)
}

type hostRegistrySSHRunner struct{}

// NewExecSSHRunner returns the production SSHRunner backed by hostregistry.ExecSSH.
func NewExecSSHRunner() SSHRunner {
	return hostRegistrySSHRunner{}
}

func (hostRegistrySSHRunner) Run(ctx context.Context, target, remoteCmd string, stdin []byte) (string, error) {
	return hostregistry.ExecSSH(ctx, target, remoteCmd, stdin)
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
	cookies, err := cookie.UnmarshalCookies([]byte(out))
	if err != nil {
		return Extracted{}, fmt.Errorf("parse rpc extract from %s: %w", b.target, err)
	}
	return Extracted{Cookies: cookies}, nil
}

// Apply pipes the merged set as a JSON array of wire records to the peer's "cookiesync
// rpc apply" stdin and returns the rows written.
func (b SSHBackend) Apply(ctx context.Context, browser, profile string, cookies []cookie.Cookie) (int, error) {
	body, err := cookie.MarshalCookies(cookies)
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
