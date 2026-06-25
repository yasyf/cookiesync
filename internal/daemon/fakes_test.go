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
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/cregistry"
)

// fakeMesh seeds the shared synckit host registry with this self target and peers, so
// the handlers key on the mesh self and the consent scan probes the mesh's peers — not
// this host's tracked endpoints — without a real registration. hostregistry.Mesh keys
// off XDG_CONFIG_HOME, so writing under a temp XDG isolates each test's mesh.
func fakeMesh(t *testing.T, self string, peers ...string) {
	t.Helper()
	if peers == nil {
		peers = []string{}
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg == "" {
		xdg = t.TempDir()
		t.Setenv("XDG_CONFIG_HOME", xdg)
	}
	dir := filepath.Join(xdg, "synckit")
	if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // G703: dir is under this test's own XDG_CONFIG_HOME temp root, not user-supplied.
		t.Fatalf("mkdir synckit: %v", err)
	}
	payload, err := json.Marshal(struct {
		Self  string   `json:"self"`
		Hosts []string `json:"hosts"`
	}{self, peers})
	if err != nil {
		t.Fatalf("marshal mesh: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), payload, 0o600); err != nil { //nolint:gosec // G703: path is under this test's own XDG_CONFIG_HOME temp root, not user-supplied.
		t.Fatalf("write mesh state: %v", err)
	}
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
