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
	"testing"
	"time"

	"github.com/yasyf/daemonkit"
	synckit "github.com/yasyf/synckit/rpc"
	"golang.org/x/sys/unix"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// callOp is synckit's business-lane op; Dispatcher.Handle rejects any other.
const callOp = "synckit.rpc.call"

func exitedPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run true: %v", err)
	}
	return cmd.Process.Pid
}

func TestRequestorIDFromPeerCredentials(t *testing.T) {
	sid, err := unix.Getsid(os.Getpid())
	if err != nil {
		t.Fatalf("getsid: %v", err)
	}
	tests := []struct {
		name   string
		pid    int
		params map[string]any
		want   string
	}{
		{"a token wins over the peer session", os.Getpid(), map[string]any{"requestor": "agent-1"}, "req:agent-1"},
		{"a peer pid keys the grant on its session", os.Getpid(), map[string]any{}, "sid:" + strconv.Itoa(sid)},
		{"a peer outside the pid namespace never borrows the daemon's session", 0, map[string]any{}, "local"},
		{"an exited peer has no session", exitedPID(t), map[string]any{}, "local"},
		{"origin never keys a local method", os.Getpid(), map[string]any{"origin": "them@mac"}, "sid:" + strconv.Itoa(sid)},
	}
	dispatcher := synckit.NewDispatcher()
	dispatcher.Register("requestor", func(ctx context.Context, params map[string]any) (any, error) {
		return requestorID(ctx, params), nil
	})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, err := synckit.EncodeRequest(&synckit.Request{Method: "requestor", Params: tc.params})
			if err != nil {
				t.Fatalf("encode request: %v", err)
			}
			reply, err := dispatcher.Handle(context.Background(), daemonkit.Request{
				Op: callOp, Body: body, Caller: daemonkit.Caller{PID: tc.pid},
			})
			if err != nil {
				t.Fatalf("handle: %v", err)
			}
			resp, err := synckit.DecodeResponse(reply.Body)
			if err != nil {
				t.Fatalf("decode response: %v", err)
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

// TestPeerSessionRequestorOverSocket proves the session-id rule over a real unix
// socket: a prime_auth dialed through the synckit transport grants the dialing
// process's session (sid), derived from its SO_PEERCRED pid, and weaves the
// dialing process's name into the consent reason.
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
	comm := filepath.Base(executable)
	if len(comm) > 15 {
		comm = comm[:15]
	}
	want := consentReason + " for " + comm
	if len(consent.promptedReasons) != 1 || consent.promptedReasons[0] != want {
		t.Fatalf("prompt reasons = %v, want [%q]", consent.promptedReasons, want)
	}
}
