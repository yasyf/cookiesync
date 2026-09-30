//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yasyf/daemonkit"
	synckit "github.com/yasyf/synckit/rpc"
	"golang.org/x/sys/unix"

	"github.com/yasyf/cookiesync/internal/cookie"
)

func ownProcessName(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	comm := filepath.Base(executable)
	if len(comm) > 15 {
		comm = comm[:15]
	}
	return comm
}

func exitedPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run true: %v", err)
	}
	return cmd.Process.Pid
}

const requestorHint = `; pass a requestor token: export COOKIESYNC_REQUESTOR="$(cookiesync requestor)"`

func TestRequestorIDWithoutACallerIsRefused(t *testing.T) {
	refusal := "cannot derive a requestor for socket peer pid 0 (no socket peer, or a peer outside this pid namespace)" + requestorHint
	tests := []struct {
		name    string
		resolve func(context.Context, map[string]any) (string, error)
		params  map[string]any
	}{
		{"a forged origin never rescues a local method", requestorID, map[string]any{"origin": "you@desktop"}},
		{"an empty requestor token falls through to the refusal", requestorID, map[string]any{"requestor": ""}},
		{"no token is refused", requestorID, map[string]any{}},
		{"an empty origin falls through to the refusal", peerRequestor, map[string]any{"origin": ""}},
		{"no origin and no token is refused", peerRequestor, map[string]any{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.resolve(context.Background(), tc.params)
			if err == nil {
				t.Fatalf("resolved %q for a context with no caller, want the refusal %q", got, refusal)
			}
			if got != "" || err.Error() != refusal || !errors.Is(err, errPeerOutsidePIDNamespace) {
				t.Fatalf("resolve = %q, %v, want an empty principal and the refusal %q", got, err, refusal)
			}
		})
	}
}

func TestRequestorIDFromPeerCredentials(t *testing.T) {
	sid, err := unix.Getsid(os.Getpid())
	if err != nil {
		t.Fatalf("getsid: %v", err)
	}
	exited := exitedPID(t)
	tests := []struct {
		name    string
		pid     int
		params  map[string]any
		want    string
		refusal string
	}{
		{"a token wins over the peer session", os.Getpid(), map[string]any{"requestor": "agent-1"}, "req:agent-1", ""},
		{"a token wins over an underivable session", 0, map[string]any{"requestor": "agent-1"}, "req:agent-1", ""},
		{"a peer pid keys the grant on its session", os.Getpid(), map[string]any{}, "sid:" + strconv.Itoa(sid), ""},
		{
			"a peer outside the pid namespace is refused", 0,
			map[string]any{},
			"",
			"cannot derive a requestor for socket peer pid 0 (no socket peer, or a peer outside this pid namespace)" + requestorHint,
		},
		{
			"an exited peer is refused", exited,
			map[string]any{},
			"",
			"cannot derive a requestor for socket peer pid " + strconv.Itoa(exited) + " (getsid: no such process)" + requestorHint,
		},
		{"origin never keys a local method", os.Getpid(), map[string]any{"origin": "them@mac"}, "sid:" + strconv.Itoa(sid), ""},
		{
			"origin never rescues an underivable session", 0,
			map[string]any{"origin": "them@mac"},
			"",
			"cannot derive a requestor for socket peer pid 0 (no socket peer, or a peer outside this pid namespace)" + requestorHint,
		},
	}
	dispatcher := synckit.NewDispatcher()
	dispatcher.Register("requestor", func(ctx context.Context, params map[string]any) (any, error) {
		return requestorID(ctx, params)
	})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := dispatchAs(t, dispatcher, tc.pid, "requestor", tc.params)
			if tc.refusal != "" {
				if resp.OK {
					t.Fatalf("requestorID = %s, want the refusal %q", resp.Result, tc.refusal)
				}
				if resp.Error != tc.refusal {
					t.Fatalf("refusal = %q, want %q", resp.Error, tc.refusal)
				}
				return
			}
			if !resp.OK {
				t.Fatalf("requestor call failed: %s", resp.Error)
			}
			var got string
			if err := json.Unmarshal(resp.Result, &got); err != nil {
				t.Fatalf("decode requestor %s: %v", resp.Result, err)
			}
			if got != tc.want {
				t.Fatalf("requestorID = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestUnderivableRequestorRefusedBeforeAnyGrantOrCacheUse proves every local
// consent-gated method refuses a socket caller whose session cannot be derived
// before the broker runs: no cache read or write, no consent evaluation, and no
// grant on the local principal or on this process's own session.
func TestUnderivableRequestorRefusedBeforeAnyGrantOrCacheUse(t *testing.T) {
	self := "me@vm"
	sid, err := unix.Getsid(os.Getpid())
	if err != nil {
		t.Fatalf("getsid: %v", err)
	}
	methods := []struct {
		name   string
		method string
		params map[string]any
	}{
		{"prime_auth single", "prime_auth", map[string]any{"browser": "chrome"}},
		{"prime_auth all", "prime_auth", map[string]any{}},
		{"get_cookies single", "get_cookies", map[string]any{"browser": "chrome", "urls": []any{"https://x.com/"}}},
		{"get_cookies union", "get_cookies", map[string]any{"urls": []any{"https://x.com/"}}},
		{"get_web_storage single", "get_web_storage", map[string]any{"browser": "chrome", "urls": []any{"https://x.com/"}}},
		{"get_web_storage all", "get_web_storage", map[string]any{"urls": []any{"https://x.com/"}}},
		{"extract", "extract", map[string]any{"browser": "chrome"}},
		{"bridge_open", "bridge_open", map[string]any{"browser": "chrome"}},
	}
	for _, peer := range []struct {
		name string
		pid  int
	}{
		{"peer outside the pid namespace", 0},
		{"exited peer", exitedPID(t)},
	} {
		for _, m := range methods {
			t.Run(peer.name+"/"+m.name, func(t *testing.T) {
				fakeMesh(t, self)
				st := stateWith(self, "", stateEndpoint(self, "chrome", "Default"))
				consent := &fakeConsent{key: cookie.AesKey("0123456789abcdef")}
				cache := newFakeCache()
				d := New(consent, cache, nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

				resp := dispatchAs(t, d.Dispatcher(), peer.pid, m.method, m.params)
				if resp.OK {
					t.Fatalf("%s served %s, want a refusal", m.method, resp.Result)
				}
				if !strings.HasPrefix(resp.Error, "cannot derive a requestor for socket peer pid "+strconv.Itoa(peer.pid)+" (") || !strings.HasSuffix(resp.Error, requestorHint) {
					t.Fatalf("%s error = %q, want the requestor refusal", m.method, resp.Error)
				}
				if cache.getCalls() != 0 || cache.putCalls() != 0 {
					t.Fatalf("%s touched the cache before refusing: gets=%d puts=%d", m.method, cache.getCalls(), cache.putCalls())
				}
				if len(consent.batchCalls) != 0 || len(consent.promptedReasons) != 0 || consent.unpromptedCalled != 0 || consent.biometricCalls.Load() != 0 {
					t.Fatalf("%s evaluated consent before refusing: batches=%d prompts=%v unprompted=%d biometric=%d",
						m.method, len(consent.batchCalls), consent.promptedReasons, consent.unpromptedCalled, consent.biometricCalls.Load())
				}
				for _, requestor := range []string{"local", "sid:" + strconv.Itoa(sid), "sid:0", "sid:" + strconv.Itoa(peer.pid)} {
					if d.granted(requestor, "chrome") {
						t.Fatalf("%s granted %s after refusing", m.method, requestor)
					}
				}
			})
		}
	}
}

// TestPeerSessionRequestorOverSocket proves the session-id rule over a real unix
// socket: a prime_auth dialed through the synckit transport grants the dialing
// process's session (sid), derived from its SO_PEERCRED pid — never the shared
// local principal — and weaves the dialing process's name into the consent reason.
func TestPeerSessionRequestorOverSocket(t *testing.T) {
	self := "me@vm"
	fakeMesh(t, self)
	st := stateWith(self, "")
	consent := &fakeConsent{key: cookie.AesKey("0123456789abcdef")}
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(currentUser(t))), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	prepareHelperRuntime(t, executable)
	fakeMesh(t, self)
	runtime, err := newHelperRuntime(executable, func(daemonkit.Ctx) (*Daemon, func(context.Context) error, error) {
		return d, func(context.Context) error { return nil }, nil
	})
	if err != nil {
		t.Fatalf("new helper runtime: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runtime.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("runtime: %v", err)
		}
	})
	control := helperClient(t)
	readyCtx, readyCancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer readyCancel()
	if err := awaitBusinessReady(readyCtx, control); err != nil {
		t.Fatalf("await readiness: %v", err)
	}

	client := synckit.NewClient(synckit.ClientConfig{
		Open: func(context.Context) (*daemonkit.Business, error) { return control.Business(), nil },
	})
	defer func() { _ = client.Close() }()
	resp, err := client.Call(context.Background(), &synckit.Request{
		Method: "prime_auth", Params: map[string]any{"browser": "chrome"},
	})
	if err != nil {
		t.Fatalf("call prime_auth: %v", err)
	}
	if !resp.OK {
		t.Fatalf("prime_auth over the socket: %s", resp.Error)
	}

	sid, err := unix.Getsid(os.Getpid())
	if err != nil {
		t.Fatalf("getsid: %v", err)
	}
	if requestor := "sid:" + strconv.Itoa(sid); !d.granted(requestor, "chrome") {
		t.Fatalf("prime over the socket must grant the dialing session %s", requestor)
	}
	if d.granted("local", "chrome") {
		t.Fatal("a socket caller must never land on the shared local principal")
	}
	want := reasonForSelf(t, consentReason)
	if len(consent.promptedReasons) != 1 || consent.promptedReasons[0] != want {
		t.Fatalf("prompt reasons = %v, want [%q]", consent.promptedReasons, want)
	}
}
