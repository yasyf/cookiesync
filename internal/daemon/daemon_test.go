package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasyf/cookiesync/internal/paths"
	synckit "github.com/yasyf/synckit/rpc"
)

// TestDispatcherRoutesEveryMethod proves the dispatcher binds every method in the
// frozen set to a handler — an unknown method is the only "unknown method" error. Each
// known method is dispatched with a benign params map and asserted NOT to come back as
// unknown; whether the handler itself then succeeds or errors is exercised elsewhere,
// here we only prove routing.
func TestDispatcherRoutesEveryMethod(t *testing.T) {
	me := currentUser(t)
	consent := &fakeConsent{}
	st := stateWith("me@laptop", "")
	d := New(consent, newFakeCache(), nil, staticProbe(liveSession(me)), &recordingRunner{}, fixedState{st: st}, fixedState{st: st})
	dispatcher := d.Dispatcher()

	// Every frozen method must route to a handler. Some reach the nil engine, the
	// store, or the cookie layer and come back as a handler error (or a panic the
	// dispatcher recovers into an error response) — that still proves the method
	// routed. The one thing none may return is "unknown method".
	methods := []string{
		"whoami", "auth_status", "request_consent",
		"extract", "apply", "sync", "reconcile", "prime_auth", "get_cookies",
		// The typed sync contract synckitd drives over the resident socket.
		"svc.capabilities", "svc.list", "svc.reconcile", "svc.sync", "svc.get_state",
	}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			resp := dispatcher.Dispatch(context.Background(), request(method))
			if !resp.OK && strings.Contains(resp.Error, "unknown method") {
				t.Fatalf("method %q did not route: %s", method, resp.Error)
			}
		})
	}

	resp := dispatcher.Dispatch(context.Background(), request("does_not_exist"))
	if resp.OK || !strings.Contains(resp.Error, "unknown method") {
		t.Fatalf("unknown method should be rejected, got ok=%v err=%q", resp.OK, resp.Error)
	}
}

// TestBuildOpensAndDropsTheEnclaveKey proves the daemon's Build opens the per-boot
// Secure-Enclave key at startup (one cache-newkey with a fresh label) and the returned
// closer drops it on shutdown (cache-dropkey with the SAME label), so a leaked wrapped
// blob is unrecoverable off-box. It also proves the cache is emptied on shutdown.
func TestBuildOpensAndDropsTheEnclaveKey(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	binary, logPath := writeFakeCacheHelper(t)
	restore := paths.SetHelperBinaryForTest(binary)
	t.Cleanup(restore)
	fakeMesh(t, "me@laptop")
	ctx := context.Background()

	d, closer, err := Build(ctx)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// A key cached after startup is gone after shutdown (the closer evicts the cache).
	id := endpointID("me@laptop", "chrome", "Default")
	if err := d.cache.Put(ctx, id, []byte("k"), 5_000_000_000); err != nil {
		t.Fatalf("cache Put: %v", err)
	}
	if err := closer(ctx); err != nil {
		t.Fatalf("closer: %v", err)
	}
	if _, ok, _ := d.cache.Get(ctx, id); ok {
		t.Fatalf("cache not evicted on shutdown")
	}

	log := readLog(t, logPath)
	newkey, dropkey := "", ""
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		switch {
		case strings.HasPrefix(line, "cache-newkey "):
			newkey = strings.TrimPrefix(line, "cache-newkey ")
		case strings.HasPrefix(line, "cache-dropkey "):
			dropkey = strings.TrimPrefix(line, "cache-dropkey ")
		}
	}
	if newkey == "" {
		t.Fatalf("Build did not open the Enclave key (no cache-newkey); log:\n%s", log)
	}
	if dropkey == "" {
		t.Fatalf("shutdown did not drop the Enclave key (no cache-dropkey); log:\n%s", log)
	}
	if newkey != dropkey {
		t.Fatalf("dropped label %q != opened label %q (per-boot key not cleaned up)", dropkey, newkey)
	}
}

func request(method string) *synckit.Request {
	return &synckit.Request{Method: method, Params: map[string]any{
		"browser": "chrome", "url": "https://x.com", "nonce": "n", "endpoint": "e", "cookies": []any{},
	}}
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // path is a test-controlled temp file.
	if err != nil {
		// No log file means neither newkey nor dropkey ran; surface as empty so the
		// caller's assertions fail with a clear message.
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("read helper log %s: %v", path, err)
	}
	return string(data)
}

// writeFakeCacheHelper writes an executable fake cookiesync-keyhelper emulating the
// cache-* contract: cache-newkey / cache-dropkey are logged no-op exit-0s, and
// cache-wrap / cache-unwrap XOR stdin to stdout (binary-safe via perl). It returns the
// helper binary path and the log path so a test asserts the per-boot key lifecycle.
func writeFakeCacheHelper(t *testing.T) (binary, logPath string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "cookiesync-keyhelper")
	logPath = filepath.Join(dir, "helper.log")
	body := `#!/bin/sh
verb="$1"
label="$2"
case "$verb" in
cache-newkey|cache-dropkey)
  printf '%s %s\n' "$verb" "$label" >> "` + logPath + `"
  exit 0
  ;;
cache-wrap|cache-unwrap)
  exec /usr/bin/perl -0777 -pe 's/(.)/chr(ord($1)^0x5A)/ges'
  ;;
*)
  echo "unexpected verb $verb" >&2
  exit 99
  ;;
esac
`
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write fake cache helper: %v", err)
	}
	return binary, logPath
}
