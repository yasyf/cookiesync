//go:build darwin

package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/cookie"
	"github.com/yasyf/daemonkit"
	synckit "github.com/yasyf/synckit/rpc"
)

func ownProcessName(t *testing.T) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("executable: %v", err)
	}
	return filepath.Base(executable)
}

func TestRequestorIDWithoutACallerIsLocal(t *testing.T) {
	tests := []struct {
		name    string
		resolve func(context.Context, map[string]any) (string, error)
		params  map[string]any
	}{
		{"a forged origin is ignored", requestorID, map[string]any{"origin": "you@desktop"}},
		{"an empty requestor token falls through", requestorID, map[string]any{"requestor": ""}},
		{"no token is local", requestorID, map[string]any{}},
		{"an empty origin falls through", peerRequestor, map[string]any{"origin": ""}},
		{"no origin and no token is local", peerRequestor, map[string]any{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := tc.resolve(context.Background(), tc.params); err != nil || got != "local" {
				t.Fatalf("resolve(%v) = %q, %v, want \"local\"", tc.params, got, err)
			}
		})
	}
}

// TestPeerSIDRequestorOverSocket proves the session-id rule over a real unix socket: a
// prime_auth dialed through the synckit transport grants the dialing process's login
// session (sid), never its origin, and weaves the dialing process's name — resolved
// from the captured peer pid, decoupled from the grant key — into the Touch ID reason.
// It is darwin-only: PeerSID is only populated by the darwin peer-credential path, so
// the sid rung cannot be exercised over a socket on other platforms.
func TestPeerSIDRequestorOverSocket(t *testing.T) {
	self := "me@laptop"
	fakeMesh(t, self)
	st := stateWith(self, "")
	consent := &fakeConsent{key: cookie.DeriveKey(cookie.SafeStorageKey("peanuts"))}
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

	sid, err := syscall.Getsid(os.Getpid())
	if err != nil {
		t.Fatalf("getsid: %v", err)
	}
	if requestor := "sid:" + strconv.Itoa(sid); !d.granted(requestor, "chrome") {
		t.Fatalf("prime over the socket must grant the dialing session %s", requestor)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve executable: %v", err)
	}
	want := consentReason + " for " + filepath.Base(exe)
	if len(consent.promptedReasons) != 1 || consent.promptedReasons[0] != want {
		t.Fatalf("prompt reasons = %v, want [%q]", consent.promptedReasons, want)
	}
}
