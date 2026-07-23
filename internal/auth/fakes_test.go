package auth

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cache"
	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/cookiesync/internal/state"
	"github.com/yasyf/synckit/cregistry"
	"github.com/yasyf/synckit/hostregistry"
	"github.com/yasyf/synckit/presence"
)

// testConsentReason mirrors the daemon's frozen default prompt reason.
const testConsentReason = "sync them across your Macs"

// liveWhoami is a peer whoami reply for an on-console, unlocked session.
const liveWhoami = `{"on_console":true,"locked":false,"console_user":"peer"}`

// deadWhoami is a peer whoami reply for a locked session.
const deadWhoami = `{"on_console":true,"locked":true,"console_user":"peer"}`

// fakeMesh seeds the shared synckit host registry with this self target and
// peers under a temp XDG_CONFIG_HOME, so mesh.Resolve answers without a real
// registration.
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
	if err := hostregistry.Mesh.InitializeState(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := hostregistry.Mesh.Update(context.Background(), func(g *hostregistry.Registry) error { g.Self = self; g.Hosts = peers; return nil }); err != nil {
		t.Fatal(err)
	}
}

// fakeConsent records its calls and returns a canned key (or a canned error
// from the batch to simulate a declined prompt; a missingFor browser reports
// Missing), so the consent path runs without Touch ID or the signed helper.
type fakeConsent struct {
	key        cookie.AesKey
	obtainErr  error
	missingFor cookie.BrowserName

	// biometricKey and biometricErr script ObtainKeyBiometric independently of
	// the passcode-capable paths, so a bridge test proves it took the strict
	// biometric seam and not ObtainKey/ObtainKeys.
	biometricKey cookie.AesKey
	biometricErr error

	mu               sync.Mutex
	promptedReasons  []string
	batchCalls       []consentBatchCall
	biometricReasons []string
	unpromptedCalled int
}

// consentBatchCall is one recorded fakeConsent.ObtainKeys invocation.
type consentBatchCall struct {
	browsers []cookie.BrowserName
	reason   string
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

func (c *fakeConsent) ObtainKeys(_ context.Context, browsers []cookie.Browser, reason string) ([]cookie.KeyOutcome, error) {
	names := make([]cookie.BrowserName, len(browsers))
	outcomes := make([]cookie.KeyOutcome, len(browsers))
	for i, b := range browsers {
		names[i] = b.Name
		if b.Name == c.missingFor {
			outcomes[i] = cookie.KeyOutcome{Browser: b, Missing: true}
			continue
		}
		outcomes[i] = cookie.KeyOutcome{Browser: b, Key: c.key}
	}
	c.mu.Lock()
	c.promptedReasons = append(c.promptedReasons, reason)
	c.batchCalls = append(c.batchCalls, consentBatchCall{browsers: names, reason: reason})
	c.mu.Unlock()
	if c.obtainErr != nil {
		return nil, c.obtainErr
	}
	return outcomes, nil
}

func (c *fakeConsent) ObtainKeyUnprompted(_ context.Context, _ cookie.Browser) (cookie.AesKey, error) {
	c.mu.Lock()
	c.unpromptedCalled++
	c.mu.Unlock()
	return c.key, nil
}

func (c *fakeConsent) ObtainKeyBiometric(_ context.Context, _ cookie.Browser, reason string) (cookie.AesKey, error) {
	c.mu.Lock()
	c.biometricReasons = append(c.biometricReasons, reason)
	c.mu.Unlock()
	if c.biometricErr != nil {
		return nil, c.biometricErr
	}
	return c.biometricKey, nil
}

// biometricCount reports how many times ObtainKeyBiometric was invoked.
func (c *fakeConsent) biometricCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.biometricReasons)
}

// promptCount reports how many times ObtainKey or ObtainKeys was invoked — the
// passcode-capable paths a bridge release must never reach.
func (c *fakeConsent) promptCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.promptedReasons)
}

// fakeCache is an in-memory key cache double storing raw keys without wrapping.
// It records Put calls with their TTLs — mirroring the real cache's degraded
// contract: a degraded Put caps the recorded entry TTL and reports the degraded
// publish — so a TTL test asserts the effective derivation and an ordering test
// asserts requested-last.
type fakeCache struct {
	degraded bool
	getErr   error
	// missGets scripts cold answers per 1-indexed Get call, choreographing an
	// epoch retire between a flight's Put and the post-flight re-probe.
	missGets map[int]bool

	mu       sync.Mutex
	entries  map[string][]byte
	puts     []string
	ttls     map[string]time.Duration
	getCalls int
}

func newFakeCache() *fakeCache {
	return &fakeCache{entries: map[string][]byte{}, ttls: map[string]time.Duration{}}
}

func (c *fakeCache) Get(_ context.Context, id string) ([]byte, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.getErr != nil {
		return nil, false, c.getErr
	}
	c.getCalls++
	if c.missGets[c.getCalls] {
		return nil, false, nil
	}
	key, ok := c.entries[id]
	return key, ok, nil
}

func (c *fakeCache) Put(_ context.Context, id string, key []byte, ttl time.Duration) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.degraded && ttl > cache.DegradedTTL {
		ttl = cache.DegradedTTL
	}
	c.entries[id] = key
	c.puts = append(c.puts, id)
	c.ttls[id] = ttl
	return c.degraded, nil
}

func (c *fakeCache) putTTL(id string) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ttls[id]
}

func (c *fakeCache) putOrder() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.puts...)
}

func (c *fakeCache) Degraded() bool {
	return c.degraded
}

// fixedState is a StateLoader returning a fixed snapshot.
type fixedState struct {
	st *state.State
}

func (s fixedState) Load(_ context.Context) (*state.State, error) {
	return s.st, nil
}

// recordingRunner serves a canned ssh reply, matched first by target
// (perTarget), then by exact remoteCmd (replies), then by a command substring
// (byMethod), and records every call so a test asserts the exact ssh traffic
// the routed-consent path made without a real ssh.
type recordingRunner struct {
	mu        sync.Mutex
	perTarget map[string]string
	replies   map[string]string
	byMethod  map[string]string
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

// consentCalls counts the recorded request_consent dials.
func (r *recordingRunner) consentCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if strings.Contains(c.cmd, "request_consent") {
			n++
		}
	}
	return n
}

// approverMesh scripts a mesh of approvers per target: whoami answers from
// whoami (absent = dead, wedgedWhoami = parked until the probe context dies),
// request_consent answers from consentErr, then consent (absent = a transport
// failure, wedgedConsent = parked until the consent context dies). Every dial
// is recorded.
type approverMesh struct {
	whoami        map[string]string
	consent       map[string]string
	consentErr    map[string]error
	wedgedWhoami  string
	wedgedConsent string

	mu    sync.Mutex
	calls []runnerCall
}

func (r *approverMesh) Run(ctx context.Context, target, cmd string, _ []byte) (string, error) {
	r.mu.Lock()
	r.calls = append(r.calls, runnerCall{target: target, cmd: cmd})
	r.mu.Unlock()
	if strings.Contains(cmd, "whoami") {
		if target == r.wedgedWhoami {
			<-ctx.Done()
			return "", ctx.Err()
		}
		if reply, ok := r.whoami[target]; ok {
			return reply, nil
		}
		return deadWhoami, nil
	}
	if target == r.wedgedConsent {
		<-ctx.Done()
		return "", ctx.Err()
	}
	if err, ok := r.consentErr[target]; ok {
		return "", err
	}
	if reply, ok := r.consent[target]; ok {
		return reply, nil
	}
	return "", sshTransportFailure(target)
}

var (
	exit255Once sync.Once
	exit255Err  error
)

// sshTransportFailure fabricates ExecSSH's connection-failure shape: an
// *hostregistry.SSHError wrapping a real exit-255 *exec.ExitError.
func sshTransportFailure(addr string) error {
	exit255Once.Do(func() {
		exit255Err = exec.Command("/bin/sh", "-c", "exit 255").Run()
	})
	return &hostregistry.SSHError{Addr: addr, Stderr: "connect refused", Err: exit255Err}
}

// consentTargets lists the targets that received a request_consent, in order.
func (r *approverMesh) consentTargets() []string {
	return r.consentTargetsFor("request_consent")
}

// consentTargetsFor lists the targets asked via the given consent verb, in order
// — request_bridge_consent for the bridge handshake, which request_consent is
// not a substring of.
func (r *approverMesh) consentTargetsFor(verb string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var targets []string
	for _, c := range r.calls {
		if strings.Contains(c.cmd, verb) {
			targets = append(targets, c.target)
		}
	}
	return targets
}

// probedTargets lists the targets that received a whoami probe, in order.
func (r *approverMesh) probedTargets() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var targets []string
	for _, c := range r.calls {
		if strings.Contains(c.cmd, "whoami") {
			targets = append(targets, c.target)
		}
	}
	return targets
}

// whoamiErrMesh wraps an approverMesh, failing the whoami leg for one target
// with a fixed error; every other call delegates to the embedded mesh.
type whoamiErrMesh struct {
	*approverMesh
	target string
	err    error
}

func (r *whoamiErrMesh) Run(ctx context.Context, target, cmd string, stdin []byte) (string, error) {
	if target == r.target && strings.Contains(cmd, "whoami") {
		r.mu.Lock()
		r.calls = append(r.calls, runnerCall{target: target, cmd: cmd})
		r.mu.Unlock()
		return "", r.err
	}
	return r.approverMesh.Run(ctx, target, cmd, stdin)
}

// staticProbe returns a fixed session snapshot.
func staticProbe(snap presence.SessionSnapshot) Probe {
	return func(_ context.Context) (presence.SessionSnapshot, error) { return snap, nil }
}

// liveSession is a snapshot of a real person at the keyboard: on console,
// unlocked, owned by user.
func liveSession(user string) presence.SessionSnapshot {
	return presence.SessionSnapshot{OnConsole: true, Locked: false, ConsoleUser: user}
}

// currentUser returns this process's username, the console user a live session
// must match to be attended.
func currentUser(t *testing.T) string {
	t.Helper()
	me, err := user.Current()
	if err != nil {
		t.Fatalf("resolve current user: %v", err)
	}
	return me.Username
}

// stateEndpoint builds a tracked endpoint for the test mesh.
func stateEndpoint(host, browser, profile string) state.Endpoint {
	return state.Endpoint{Host: host, Browser: browser, Profile: profile}
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

// newRegistry builds a present-everywhere convergent registry from endpoints,
// each stamped at a fixed time so the test view is deterministic.
func newRegistry(endpoints ...state.Endpoint) cregistry.Registry[state.EndpointMeta] {
	reg := cregistry.New[state.EndpointMeta]()
	at := cregistry.UnixMicros(time.Unix(1, 0))
	for _, ep := range endpoints {
		reg.Add(string(ep.ID()), ep.Meta(), at)
	}
	return reg
}

// approvedReply is a peer's request_consent JSON echoing nonce and endpoint.
func approvedReply(t *testing.T, nonce, endpoint string) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{"status": "approved", "nonce": nonce, "endpoint": endpoint})
	if err != nil {
		t.Fatalf("marshal approved reply: %v", err)
	}
	return string(data)
}

// newTestBroker wires a broker over the given fakes with a live attended probe.
func newTestBroker(consent cookie.Consent, c Cache, probe Probe, runner SSHRunner, st *state.State) *Broker {
	return NewBroker(consent, c, probe, runner, fixedState{st: st})
}
