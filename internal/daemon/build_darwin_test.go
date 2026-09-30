//go:build darwin

package daemon

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yasyf/synckit/authkit"
)

// TestBuildOpensAndDropsTheEnclaveKey proves the daemon's Build opens the per-boot
// Secure-Enclave key at startup (one cache-newkey with a fresh label) and the returned
// closer drops it on shutdown (cache-dropkey with the SAME label), so a leaked wrapped
// blob is unrecoverable off-box. It also proves the cache is emptied on shutdown.
func TestBuildOpensAndDropsTheEnclaveKey(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	binary, logPath := writeFakeCacheHelper(t)
	t.Setenv(authkit.HelperEnvVar, binary)
	fakeMesh(t, "me@laptop")
	ctx := context.Background()

	_, keyCache, err := build(bridgeTestScope(t))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// A key cached after startup is gone after shutdown (the closer evicts the cache).
	id := endpointID("me@laptop", "chrome", "Default")
	if _, err := keyCache.Put(ctx, id, []byte("k"), 5_000_000_000); err != nil {
		t.Fatalf("cache Put: %v", err)
	}
	if err := keyCache.Close(ctx); err != nil {
		t.Fatalf("closer: %v", err)
	}
	if _, ok, _ := keyCache.Get(ctx, id); ok {
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

// TestBuildDegradedPresenceStartsWithMemoryCache proves a cache-newkey presence
// refusal (helper exit 3) does not kill the daemon: the open warns exactly once —
// carrying the helper's OSStatus diagnostic — and serves degraded, with cached keys
// round-tripping in process memory and the helper touched only for newkey probes.
func TestBuildDegradedPresenceStartsWithMemoryCache(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	binary, logPath := writeStubHelper(t, 3, "keyhelper: cache-newkey failed: interaction not allowed (OSStatus -25308)")
	t.Setenv(authkit.HelperEnvVar, binary)
	fakeMesh(t, "me@laptop")

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx := context.Background()
	_, keyCache, err := build(bridgeTestScope(t))
	if err != nil {
		t.Fatalf("Build with a presence-unavailable helper must degrade, got %v", err)
	}

	const warn = "Secure Enclave presence unavailable — screen locked or no user present; caching keys in process memory until the keybag unlocks"
	if got := strings.Count(logs.String(), warn); got != 1 {
		t.Fatalf("degraded Build must WARN exactly once, got %d in:\n%s", got, logs.String())
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "OSStatus -25308") {
		t.Fatalf("the WARN must log at level WARN with the helper diagnostic, got:\n%s", logs.String())
	}

	id := endpointID("me@laptop", "chrome", "Default")
	if _, err := keyCache.Put(ctx, id, []byte("k"), 5*time.Minute); err != nil {
		t.Fatalf("cache Put on the degraded cache: %v", err)
	}
	if key, ok, err := keyCache.Get(ctx, id); err != nil || !ok || string(key) != "k" {
		t.Fatalf("cache Get = %q, %v, %v, want k true nil", key, ok, err)
	}
	if !keyCache.Degraded() {
		t.Fatalf("the cache must report Degraded while the keybag stays locked")
	}
	if err := keyCache.Close(ctx); err != nil {
		t.Fatalf("closer: %v", err)
	}
	if _, ok, _ := keyCache.Get(ctx, id); ok {
		t.Fatalf("cache not evicted on shutdown")
	}
	// The helper is touched only for newkey probes — the open probe plus the Put's
	// heal re-probe — never wrap/unwrap/dropkey while degraded.
	lines := strings.Split(strings.TrimSpace(readLog(t, logPath)), "\n")
	if len(lines) != 2 {
		t.Fatalf("a degraded open + one Put must probe the helper exactly twice, got:\n%s", readLog(t, logPath))
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "cache-newkey ") {
			t.Fatalf("a degraded session must touch the helper only for newkey probes, got:\n%s", readLog(t, logPath))
		}
	}
	if lines[0] != lines[1] {
		t.Fatalf("the heal re-probe must reuse the open probe's label, got:\n%s", readLog(t, logPath))
	}
}

// TestBuildNoEnclaveStaysFatal proves a genuine cache-newkey refusal (exit 2: no
// Secure Enclave or keygen misconfigured) still fails Build outright, surfacing the
// helper's stderr diagnostic — only the presence refusal degrades.
func TestBuildNoEnclaveStaysFatal(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	binary, _ := writeStubHelper(t, 2, "keyhelper: cache-newkey failed: no Secure Enclave (OSStatus -34018)")
	t.Setenv(authkit.HelperEnvVar, binary)
	fakeMesh(t, "me@laptop")

	d, closer, err := buildDaemon(bridgeTestScope(t))
	if err == nil || !strings.Contains(err.Error(), "cache-newkey exited 2") || !strings.Contains(err.Error(), "OSStatus -34018") {
		t.Fatalf("Build = %v, want the fatal exit-2 error carrying the helper stderr", err)
	}
	if d != nil || closer != nil {
		t.Fatalf("a fatal Build must return no daemon")
	}
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

// writeStubHelper writes a fake cookiesync-keyhelper that logs every invocation, then
// prints stderrMsg and exits with code — the cache-newkey refusal doubles (presence
// exit 3, no-Enclave exit 2) the Build degradation tests drive.
func writeStubHelper(t *testing.T, code int, stderrMsg string) (binary, logPath string) {
	t.Helper()
	dir := t.TempDir()
	binary = filepath.Join(dir, "cookiesync-keyhelper")
	logPath = filepath.Join(dir, "helper.log")
	body := fmt.Sprintf(`#!/bin/sh
printf '%%s %%s\n' "$1" "$2" >> %q
echo %q >&2
exit %d
`, logPath, stderrMsg, code)
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil { //nolint:gosec // test fixture script must be executable.
		t.Fatalf("write stub helper: %v", err)
	}
	return binary, logPath
}
