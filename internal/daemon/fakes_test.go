package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/mesh"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/cregistry"
)

// fakeMesh points the shared mesh seam at a fake reposync that reports this self target
// and peers, so the consent scan probes reposync's peers — not this host's tracked
// endpoints — without a real reposync install.
func fakeMesh(t *testing.T, self string, peers ...string) {
	t.Helper()
	if peers == nil {
		peers = []string{}
	}
	payload, err := json.Marshal(struct {
		Version int      `json:"version"`
		Self    string   `json:"self"`
		Hosts   []string `json:"hosts"`
	}{1, self, peers})
	if err != nil {
		t.Fatalf("marshal mesh: %v", err)
	}
	script := filepath.Join(t.TempDir(), "reposync")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat <<'JSON'\n"+string(payload)+"\nJSON\n"), 0o755); err != nil { //nolint:gosec // the fake reposync must be executable.
		t.Fatalf("write fake reposync: %v", err)
	}
	prev := mesh.Bin
	mesh.Bin = script
	t.Cleanup(func() { mesh.Bin = prev })
}

// fakeConsent records its calls and returns a canned key (or a canned error from
// ObtainKey to simulate a declined prompt), so the consent path runs without Touch ID
// or the signed helper.
type fakeConsent struct {
	key              cookie.AesKey
	obtainErr        error
	promptedReasons  []string
	unpromptedCalled int
}

func (c *fakeConsent) ObtainKey(_ context.Context, _ cookie.Browser, reason string) (cookie.AesKey, error) {
	c.promptedReasons = append(c.promptedReasons, reason)
	if c.obtainErr != nil {
		return nil, c.obtainErr
	}
	return c.key, nil
}

func (c *fakeConsent) ObtainKeyUnprompted(_ context.Context, _ cookie.Browser) (cookie.AesKey, error) {
	c.unpromptedCalled++
	return c.key, nil
}

// fakeCache is an in-memory key cache double: it stores raw keys without wrapping, so
// the handler logic is exercised without the Secure Enclave. It records Put calls.
type fakeCache struct {
	mu      sync.Mutex
	entries map[string][]byte
	puts    []string
}

func newFakeCache() *fakeCache {
	return &fakeCache{entries: map[string][]byte{}}
}

func (c *fakeCache) Get(_ context.Context, id string) ([]byte, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key, ok := c.entries[id]
	return key, ok, nil
}

func (c *fakeCache) Put(_ context.Context, id string, key []byte, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[id] = key
	c.puts = append(c.puts, id)
	return nil
}

// fixedState is a StateLoader returning a fixed snapshot.
type fixedState struct {
	st *state.State
}

func (s fixedState) Load(_ context.Context) (*state.State, error) {
	return s.st, nil
}

// recordingRunner serves a canned ssh reply, matched first by target (perTarget),
// then by exact remoteCmd (replies), then by a command substring (byMethod), and
// records every call so a test asserts the exact ssh traffic the routed-consent path
// made without a real ssh.
type recordingRunner struct {
	mu        sync.Mutex
	perTarget map[string]string // target -> reply (wins; for distinguishing peers)
	replies   map[string]string // exact remoteCmd -> reply
	byMethod  map[string]string // command substring -> reply
	calls     []runnerCall
	err       error
}

type runnerCall struct {
	target string
	cmd    string
}

func (r *recordingRunner) Run(_ context.Context, target, cmd string, _ []byte) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, runnerCall{target: target, cmd: cmd})
	if r.err != nil {
		return "", r.err
	}
	if reply, ok := r.perTarget[target]; ok {
		return reply, nil
	}
	if reply, ok := r.replies[cmd]; ok {
		return reply, nil
	}
	for sub, reply := range r.byMethod {
		if strings.Contains(cmd, sub) {
			return reply, nil
		}
	}
	return "", nil
}

// staticProbe returns a fixed session snapshot.
func staticProbe(snap SessionSnapshot) Probe {
	return func(_ context.Context) (SessionSnapshot, error) { return snap, nil }
}

// stateWith builds a State with the given self target, consent route, and endpoints.
func stateWith(self, route string, endpoints ...state.Endpoint) *state.State {
	return &state.State{
		SelfTarget:     self,
		Settings:       state.DefaultSettings(),
		ConsentRouteTo: route,
		Browsers:       newRegistry(endpoints...),
	}
}

// newRegistry builds a present-everywhere convergent registry from endpoints, each
// stamped at a fixed time so the test view is deterministic.
func newRegistry(endpoints ...state.Endpoint) cregistry.Registry[state.EndpointMeta] {
	reg := cregistry.New[state.EndpointMeta]()
	at := cregistry.UnixMicros(time.Unix(1, 0))
	for _, ep := range endpoints {
		reg.Add(string(ep.ID()), ep.Meta(), at)
	}
	return reg
}
