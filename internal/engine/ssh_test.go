package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/cregistry"
	"github.com/yasyf/synckit/syncservice"
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

// TestSSHBackendExtractParsesContract proves SSHBackend.Extract shells the frozen rpc
// extract command (with quoted browser/profile/origin) and parses the {"cookies": [...]}
// reply into the cookie model.
func TestSSHBackendExtractParsesContract(t *testing.T) {
	runner := &recordingRunner{
		reply: `{"cookies":[{"host_key":".x.com","name":"sid","value":"abc","path":"/","expires_utc":13400000000000000,"last_update_utc":13350000000000000,"creation_utc":13300000000000000,"is_secure":true,"is_httponly":true,"samesite":2,"source_scheme":2,"source_port":443,"top_frame_site_key":"","has_cross_site_ancestor":0}]}`,
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

// TestSSHBackendApplyPipesWireArray proves SSHBackend.Apply shells the frozen rpc apply
// command and pipes a bare JSON array of wire cookies to its stdin, returning the
// applied count from the reply.
func TestSSHBackendApplyPipesWireArray(t *testing.T) {
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
	// stdin must be a bare JSON array (the frozen apply payload), not an envelope.
	if !strings.HasPrefix(strings.TrimSpace(string(call.stdin)), "[") {
		t.Fatalf("apply stdin is not a bare array: %s", call.stdin)
	}
	parsed, err := cookie.UnmarshalCookies(call.stdin)
	if err != nil {
		t.Fatalf("apply stdin not parseable as wire cookies: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("apply stdin has %d cookies, want 2", len(parsed))
	}
}

// fakeStateGetter serves a canned svc.get_state reply and records its Close, so the
// fetcher's parse and its Close-on-defer contract are asserted without spawning ssh. It
// has NO write method — that absence is the structural loop guard: the fetcher cannot
// mutate the peer because its only collaborator exposes a read and a close.
type fakeStateGetter struct {
	raw    syncservice.RawRegistry
	closed bool
}

func (g *fakeStateGetter) GetState(context.Context) (syncservice.RawRegistry, error) {
	return g.raw, nil
}

func (g *fakeStateGetter) Close() error {
	g.closed = true
	return nil
}

// TestSSHFetcherRoundTrip proves the fetcher parses the registry JSON svc.get_state
// emits back into a convergent registry, and closes the client when done.
func TestSSHFetcherRoundTrip(t *testing.T) {
	reg := cregistry.New[state.EndpointMeta]()
	ep := state.Endpoint{Host: "you@desktop", Browser: "chrome", Profile: "Default"}
	reg.Add(string(ep.ID()), ep.Meta(), 42)
	body, err := MarshalRegistry(reg)
	if err != nil {
		t.Fatalf("MarshalRegistry: %v", err)
	}

	getter := &fakeStateGetter{raw: syncservice.RawRegistry(body)}
	fetcher := newSSHFetcher(func(string) stateGetter { return getter })
	got, err := fetcher.Fetch(context.Background(), "you@desktop")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	entry, ok := got[string(ep.ID())]
	if !ok || entry.Value != ep.Meta() {
		t.Fatalf("fetched registry = %+v, want endpoint %s", got, ep.ID())
	}
	if !getter.closed {
		t.Fatalf("fetcher did not close the typed client")
	}
}
