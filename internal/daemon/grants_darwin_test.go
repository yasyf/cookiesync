//go:build darwin

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
	synckit "github.com/yasyf/synckit/rpc"
)

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

	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := synckit.Listen(sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- synckit.Serve(ctx, ln, d.Dispatcher()) }()
	t.Cleanup(func() {
		cancel()
		if err := <-served; err != nil {
			t.Errorf("serve: %v", err)
		}
	})

	resp, err := synckit.Call(context.Background(), sock, &synckit.Request{
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
