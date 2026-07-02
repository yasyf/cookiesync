package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
	key       cookie.AesKey
	obtainErr error

	mu               sync.Mutex
	promptedReasons  []string
	unpromptedCalled int
}

func (c *fakeConsent) ObtainKey(_ context.Context, _ cookie.Browser, reason string) (cookie.AesKey, error) {
	c.mu.Lock()
	c.promptedReasons = append(c.promptedReasons, reason)
	c.mu.Unlock()
	if c.obtainErr != nil {
		return nil, c.obtainErr
	}
	return c.key, nil
}

func (c *fakeConsent) ObtainKeyUnprompted(_ context.Context, _ cookie.Browser) (cookie.AesKey, error) {
	c.mu.Lock()
	c.unpromptedCalled++
	c.mu.Unlock()
	return c.key, nil
}

// gateConsent blocks every ObtainKey until release closes, counting entries — the
// consent double a concurrency test holds mid-prompt to prove concurrent cold primes
// join one flight instead of prompting again. Like the real Touch ID gate, it honors
// ctx: a canceled prompt returns ctx.Err().
type gateConsent struct {
	key     cookie.AesKey
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (c *gateConsent) ObtainKey(ctx context.Context, _ cookie.Browser, _ string) (cookie.AesKey, error) {
	c.calls.Add(1)
	c.entered <- struct{}{}
	select {
	case <-c.release:
		return c.key, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *gateConsent) ObtainKeyUnprompted(_ context.Context, _ cookie.Browser) (cookie.AesKey, error) {
	panic("gateConsent: unexpected unprompted release")
}

// countingConsent tracks the peak number of concurrent ObtainKey prompts, holding
// each for hold so an unserialized overlap is observable — the double that proves
// promptGate admits one consent sheet at a time.
type countingConsent struct {
	key        cookie.AesKey
	hold       time.Duration
	calls      atomic.Int32
	concurrent atomic.Int32
	peak       atomic.Int32
}

func (c *countingConsent) ObtainKey(_ context.Context, _ cookie.Browser, _ string) (cookie.AesKey, error) {
	c.calls.Add(1)
	n := c.concurrent.Add(1)
	for {
		p := c.peak.Load()
		if n <= p || c.peak.CompareAndSwap(p, n) {
			break
		}
	}
	time.Sleep(c.hold)
	c.concurrent.Add(-1)
	return c.key, nil
}

func (c *countingConsent) ObtainKeyUnprompted(_ context.Context, _ cookie.Browser) (cookie.AesKey, error) {
	panic("countingConsent: unexpected unprompted release")
}

// fakeCache is an in-memory key cache double: it stores raw keys without wrapping, so
// the handler logic is exercised without the Secure Enclave. It records Put calls and
// counts Gets, so a concurrency test can tell when every caller has probed the cache.
type fakeCache struct {
	degraded bool

	mu      sync.Mutex
	entries map[string][]byte
	puts    []string
	gets    int
}

func newFakeCache() *fakeCache {
	return &fakeCache{entries: map[string][]byte{}}
}

func (c *fakeCache) Get(_ context.Context, id string) ([]byte, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gets++
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

func (c *fakeCache) getCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gets
}

func (c *fakeCache) putCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.puts)
}

func (c *fakeCache) Degraded() bool {
	return c.degraded
}

// fixedState is a StateLoader and RegistryLoader returning a fixed snapshot. Its
// LoadRegistry returns the snapshot's browsers registry (empty when unset), enough for
// the svc.get_state routing the dispatcher tests exercise.
type fixedState struct {
	st *state.State
}

func (s fixedState) Load(_ context.Context) (*state.State, error) {
	return s.st, nil
}

func (s fixedState) LoadRegistry(_ context.Context) (cregistry.Registry[state.EndpointMeta], error) {
	if s.st == nil {
		return cregistry.New[state.EndpointMeta](), nil
	}
	return s.st.Browsers, nil
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

// fakeStore satisfies engine.Store with an injected WithLock, so a dispatcher test
// gates or counts the converge pass's flock section without a real state file. Its
// registry paths serve the seeded registry (empty when unset), enough for a clean
// no-endpoint pass or a converge over fixture endpoints.
type fakeStore struct {
	withLock func(ctx context.Context, fn func() error) error
	registry cregistry.Registry[state.EndpointMeta]
}

func (s *fakeStore) WithLock(ctx context.Context, fn func() error) error {
	return s.withLock(ctx, fn)
}

func (s *fakeStore) LoadRegistry(_ context.Context) (cregistry.Registry[state.EndpointMeta], error) {
	if s.registry == nil {
		return cregistry.New[state.EndpointMeta](), nil
	}
	return s.registry, nil
}

func (s *fakeStore) SaveRegistryUnlocked(_ context.Context, _ cregistry.Registry[state.EndpointMeta]) error {
	return nil
}

// countingRecorder tracks the peak number of concurrent RecordApplied calls — the
// first statement inside handleApply's per-endpoint critical section — holding each
// call for hold so an unserialized overlap is observable, then forwards to inner.
type countingRecorder struct {
	inner      cookie.Recorder
	hold       time.Duration
	concurrent atomic.Int32
	peak       atomic.Int32
}

func (r *countingRecorder) RecordApplied(endpointID string, digest cookie.Digest) {
	n := r.concurrent.Add(1)
	for {
		p := r.peak.Load()
		if n <= p || r.peak.CompareAndSwap(p, n) {
			break
		}
	}
	time.Sleep(r.hold)
	r.inner.RecordApplied(endpointID, digest)
	r.concurrent.Add(-1)
}

// meetRecorder parks every RecordApplied at a rendezvous — send on arrived, wait for
// release — so a test proves two applies are mid-critical-section at the same time.
type meetRecorder struct {
	inner   cookie.Recorder
	arrived chan string
	release chan struct{}
}

func (r *meetRecorder) RecordApplied(endpointID string, digest cookie.Digest) {
	r.arrived <- endpointID
	<-r.release
	r.inner.RecordApplied(endpointID, digest)
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
