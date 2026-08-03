package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yasyf/daemonkit"
	"golang.org/x/sync/semaphore"

	"github.com/yasyf/cookiesync/internal/paths"
)

// bridgeTestScope opens a real daemonkit ownership scope over a per-test record
// and returns the Ctx the bridge spawns through — the same value Serve hands
// Prepare, so product code runs unchanged under a test.
func bridgeTestScope(t *testing.T) daemonkit.Ctx {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	owned, err := daemonkit.OwnProcesses(ctx, filepath.Join(t.TempDir(), "children.db"))
	if err != nil {
		t.Fatalf("OwnProcesses: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer closeCancel()
		if err := owned.Close(closeCtx); err != nil {
			t.Errorf("close ownership scope: %v", err)
		}
	})
	return owned.Ctx(ctx)
}

func testBridgeProcessesAt(t *testing.T, rolePath string) *bridgeProcesses {
	t.Helper()
	processes, err := newBridgeProcesses(rolePath, bridgeTestScope(t))
	if err != nil {
		t.Fatalf("newBridgeProcesses: %v", err)
	}
	return processes
}

type blockingRecoveryRunner struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once

	mu     sync.Mutex
	target string
	cmd    string
	stdin  string
}

func (r *blockingRecoveryRunner) Run(ctx context.Context, target, cmd string, stdin []byte) (string, error) {
	r.mu.Lock()
	r.target, r.cmd, r.stdin = target, cmd, string(stdin)
	r.mu.Unlock()
	r.once.Do(func() { close(r.started) })
	select {
	case <-r.release:
		return "", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// TestBridgeRecoverySettlesTheCrashedGenerationsRemoteAuthority proves the
// recovery contract end to end: a tunnel sidecar left by a dead generation is
// discharged by closing the peer's half — with the capability off argv — and the
// sidecar is then removed, taking the empty session with it.
func TestBridgeRecoverySettlesTheCrashedGenerationsRemoteAuthority(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	crashed := testBridgeProcessesAt(t, "/bin/sh")
	const sessionID = "crashed-session"
	if err := crashed.record(bridgeProcessTunnel, sessionID, "you@desktop:chrome:Default", "you@desktop", "cap-b-secret"); err != nil {
		t.Fatalf("record tunnel liability: %v", err)
	}

	next := testBridgeProcessesAt(t, "/bin/sh")
	runner := &blockingRecoveryRunner{started: make(chan struct{}), release: make(chan struct{})}
	close(runner.release)
	if err := next.settleRecovery(t.Context(), runner); err != nil {
		t.Fatalf("settleRecovery: %v", err)
	}

	runner.mu.Lock()
	target, cmd, stdin := runner.target, runner.cmd, runner.stdin
	runner.mu.Unlock()
	if target != "you@desktop" || !strings.Contains(cmd, "bridge_close") || !strings.Contains(stdin, "cap-b-secret") {
		t.Fatalf("remote close = target %q cmd %q stdin %q", target, cmd, stdin)
	}
	if strings.Contains(cmd, "cap-b-secret") {
		t.Fatalf("capability leaked into argv: %q", cmd)
	}
	if _, err := os.Stat(next.sessionDir(sessionID)); !os.IsNotExist(err) {
		t.Fatalf("recovered session residue remains: %v", err)
	}
}

// TestBridgeRecoveryLeavesNoLiabilityUnsettled proves every surviving sidecar is
// discharged, not just the first, and that a local kind settles without reaching
// for a peer.
func TestBridgeRecoveryLeavesNoLiabilityUnsettled(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	crashed := testBridgeProcessesAt(t, "/bin/sh")
	if err := crashed.record(bridgeProcessTunnel, "proxy-session", "you@desktop:chrome:Default", "you@desktop", "cap-b"); err != nil {
		t.Fatal(err)
	}
	if err := crashed.record(bridgeProcessKeepalive, "proxy-session", "you@desktop:chrome:Default", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := crashed.record(bridgeProcessChrome, "local-session", "chrome:Default", "", ""); err != nil {
		t.Fatal(err)
	}

	next := testBridgeProcessesAt(t, "/bin/sh")
	if err := next.settleRecovery(t.Context(), &recordingRunner{}); err != nil {
		t.Fatalf("settleRecovery: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(next.sessionsRoot, "*", "*"+bridgeProcessSuffix))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("sidecars left unsettled: %v", matches)
	}
	entries, err := os.ReadDir(next.sessionsRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("empty sessions remain after recovery: %v", entries)
	}
}

// TestBridgeRecordKeepsOneSidecarPerSessionKind proves the sidecar is keyed on
// session and kind alone: a re-attempt within one session overwrites rather than
// accumulating, so recovery discharges each liability exactly once.
func TestBridgeRecordKeepsOneSidecarPerSessionKind(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	processes := testBridgeProcessesAt(t, "/bin/sh")
	const sessionID = "multi-attempt-session"
	for range 2 {
		if err := processes.record(bridgeProcessTunnel, sessionID, "you@desktop:chrome:Default", "you@desktop", "cap-b-secret"); err != nil {
			t.Fatal(err)
		}
	}
	matches, err := filepath.Glob(filepath.Join(processes.sessionDir(sessionID), "*"+bridgeProcessSuffix))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("sidecars after two attempts = %v, want one liability per session kind", matches)
	}
	metadata, err := processes.loadMetadata()
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata) != 1 || metadata[0].Kind != bridgeProcessTunnel || metadata[0].Capability != "cap-b-secret" {
		t.Fatalf("recovery metadata = %+v, want one exact tunnel liability", metadata)
	}
}

// TestBridgeRecordRefusesMisdeclaredAuthority proves the sidecar cannot record a
// local kind carrying remote authority, nor a tunnel without it, so a malformed
// liability never reaches disk.
func TestBridgeRecordRefusesMisdeclaredAuthority(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	processes := testBridgeProcessesAt(t, "/bin/sh")
	tests := []struct {
		name       string
		kind       bridgeProcessKind
		host       string
		capability string
	}{
		{name: "chrome with remote authority", kind: bridgeProcessChrome, host: "you@desktop", capability: "cap-b"},
		{name: "keepalive with remote authority", kind: bridgeProcessKeepalive, host: "you@desktop", capability: "cap-b"},
		{name: "tunnel without host", kind: bridgeProcessTunnel, capability: "cap-b"},
		{name: "tunnel without capability", kind: bridgeProcessTunnel, host: "you@desktop"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := processes.record(tc.kind, "session", "chrome:Default", tc.host, tc.capability); err == nil {
				t.Fatal("record accepted misdeclared authority")
			}
		})
	}
	matches, err := filepath.Glob(filepath.Join(processes.sessionsRoot, "*", "*"+bridgeProcessSuffix))
	if err != nil || len(matches) != 0 {
		t.Fatalf("refused records reached disk = %v, err %v", matches, err)
	}
}

// TestBridgeRecoveryRefusesMetadataFromAForeignSession proves a sidecar whose
// payload names a different session than its path is refused rather than
// settled, so a moved or forged file cannot redirect a peer close.
func TestBridgeRecoveryRefusesMetadataFromAForeignSession(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	processes := testBridgeProcessesAt(t, "/bin/sh")
	if err := processes.record(bridgeProcessTunnel, "real-session", "you@desktop:chrome:Default", "you@desktop", "cap-b"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(processes.sessionDir("real-session"), bridgeRecoveryFileName(bridgeProcessTunnel)))
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := processes.prepareSessionDir("foreign-session")
	if err != nil {
		t.Fatal(err)
	}
	forged := filepath.Join(foreign, bridgeRecoveryFileName(bridgeProcessTunnel))
	if err := os.WriteFile(forged, raw, 0o600); err != nil { //nolint:gosec // fixed name under the test's own session root.
		t.Fatal(err)
	}
	if _, err := processes.loadMetadata(); err == nil {
		t.Fatal("loadMetadata accepted a sidecar whose path contradicts its payload")
	}
}

// writeLegacySidecar writes one v0.20-format sidecar: the payload carried a
// process-identity tuple, and the file name appended that tuple's digest, so a
// session could hold several per kind.
func writeLegacySidecar(t *testing.T, p *bridgeProcesses, sessionID string, kind bridgeProcessKind, host, capability, salt string) string {
	t.Helper()
	dir, err := p.prepareSessionDir(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"schema": bridgeRecoverySchemaV1, "session_id": sessionID, "kind": kind,
		"process":  map[string]any{"pid": 4242, "start_time": "1000", "boot": "b", "generation": salt},
		"endpoint": "you@desktop:chrome:Default",
	}
	if host != "" {
		payload["host"], payload["capability"] = host, capability
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(salt))
	path := filepath.Join(dir, fmt.Sprintf("%s-%x%s", kind, digest, bridgeProcessSuffix))
	if err := os.WriteFile(path, raw, 0o600); err != nil { //nolint:gosec // fixed name under the test's own session root.
		t.Fatal(err)
	}
	return path
}

// TestBridgeRecoverySettlesLegacySidecars proves a v0.20 sidecar left by a
// pre-upgrade generation is settled rather than dropped: it can name a bridge
// still open on the peer, and the old payload already carried the host and
// capability the close needs. The identity tuple it also carried is ignored.
func TestBridgeRecoverySettlesLegacySidecars(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	crashed := testBridgeProcessesAt(t, "/bin/sh")
	writeLegacySidecar(t, crashed, "legacy-proxy", bridgeProcessTunnel, "you@desktop", "cap-b-secret", "one")
	writeLegacySidecar(t, crashed, "legacy-local", bridgeProcessChrome, "", "", "two")

	next := testBridgeProcessesAt(t, "/bin/sh")
	runner := &blockingRecoveryRunner{started: make(chan struct{}), release: make(chan struct{})}
	close(runner.release)
	if err := next.settleRecovery(t.Context(), runner); err != nil {
		t.Fatalf("settleRecovery over legacy sidecars: %v", err)
	}
	runner.mu.Lock()
	target, cmd, stdin := runner.target, runner.cmd, runner.stdin
	runner.mu.Unlock()
	if target != "you@desktop" || !strings.Contains(cmd, "bridge_close") || !strings.Contains(stdin, "cap-b-secret") {
		t.Fatalf("legacy remote close = target %q cmd %q stdin %q", target, cmd, stdin)
	}
	matches, err := filepath.Glob(filepath.Join(next.sessionsRoot, "*", "*"+bridgeProcessSuffix))
	if err != nil || len(matches) != 0 {
		t.Fatalf("legacy sidecars survived recovery = %v, err %v", matches, err)
	}
}

// TestBridgeRecoverySettlesEveryLegacyAttempt proves the per-attempt multiplicity
// the old format allowed is preserved through recovery: a session that recorded
// several tunnel attempts has every one of them discharged.
func TestBridgeRecoverySettlesEveryLegacyAttempt(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	crashed := testBridgeProcessesAt(t, "/bin/sh")
	for _, salt := range []string{"attempt-one", "attempt-two", "attempt-three"} {
		writeLegacySidecar(t, crashed, "legacy-retries", bridgeProcessTunnel, "you@desktop", "cap-"+salt, salt)
	}
	next := testBridgeProcessesAt(t, "/bin/sh")
	metadata, err := next.loadMetadata()
	if err != nil {
		t.Fatalf("loadMetadata over legacy attempts: %v", err)
	}
	if len(metadata) != 3 {
		t.Fatalf("legacy attempts loaded = %d, want 3", len(metadata))
	}
	runner := &recordingRunner{}
	if err := next.settleRecovery(t.Context(), runner); err != nil {
		t.Fatalf("settleRecovery: %v", err)
	}
	if _, err := os.Stat(next.sessionDir("legacy-retries")); !os.IsNotExist(err) {
		t.Fatalf("legacy session residue remains: %v", err)
	}
}

// TestParseSidecarNameSeparatesTheTwoFormats proves the name alone decides which
// decoder reads a file, and that a name matching neither format is refused
// rather than guessed at.
func TestParseSidecarNameSeparatesTheTwoFormats(t *testing.T) {
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte("x")))
	tests := []struct {
		name       string
		base       string
		wantKind   bridgeProcessKind
		wantLegacy bool
		wantOK     bool
	}{
		{name: "current", base: "tunnel" + bridgeProcessSuffix, wantKind: bridgeProcessTunnel, wantOK: true},
		{name: "legacy", base: "tunnel-" + digest + bridgeProcessSuffix, wantKind: bridgeProcessTunnel, wantLegacy: true, wantOK: true},
		{name: "unknown kind", base: "wormhole" + bridgeProcessSuffix},
		{name: "legacy short digest", base: "tunnel-abc" + bridgeProcessSuffix},
		{name: "legacy non-hex digest", base: "tunnel-" + strings.Repeat("z", 64) + bridgeProcessSuffix},
		{name: "wrong suffix", base: "tunnel.json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSidecarName(tc.base)
			if ok != tc.wantOK {
				t.Fatalf("parseSidecarName(%q) ok = %v, want %v", tc.base, ok, tc.wantOK)
			}
			if ok && (got.kind != tc.wantKind || got.legacy != tc.wantLegacy) {
				t.Fatalf("parseSidecarName(%q) = %+v, want kind %q legacy %v", tc.base, got, tc.wantKind, tc.wantLegacy)
			}
		})
	}
}

// TestBridgeRecoveryRefusesUnknownLegacyFields proves the legacy decoder widens
// for the retired identity tuple and nothing else, so a foreign field in an old
// sidecar is still a loud failure.
func TestBridgeRecoveryRefusesUnknownLegacyFields(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"schema": bridgeRecoverySchemaV1, "session_id": "s", "kind": bridgeProcessChrome,
		"process":  map[string]any{"pid": 1},
		"endpoint": "chrome:Default", "unexpected": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeLegacyRecoveryMetadata(raw); err == nil {
		t.Fatal("decodeLegacyRecoveryMetadata accepted an unknown field")
	}
}

// TestBridgeRecoveryRefusesUnknownMetadataFields proves the sidecar decodes
// strictly, so a field a newer generation added is a loud failure rather than a
// silently dropped liability.
func TestBridgeRecoveryRefusesUnknownMetadataFields(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"schema": bridgeRecoverySchemaV1, "session_id": "s", "kind": bridgeProcessChrome,
		"endpoint": "chrome:Default", "unexpected": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRecoveryMetadata(raw); err == nil {
		t.Fatal("decodeRecoveryMetadata accepted an unknown field")
	}
}

func TestProxyAdmissionReservesBothProcessSlotsAtomically(t *testing.T) {
	if bridgeProcessCapacity < 2*bridgeProxyLimit {
		t.Fatalf("process capacity %d cannot admit %d two-slot proxies", bridgeProcessCapacity, bridgeProxyLimit)
	}
	d := &Daemon{bridgeSlots: semaphore.NewWeighted(bridgeProcessCapacity)}
	for range bridgeProxyLimit {
		if err := d.bridgeSlots.Acquire(t.Context(), 2); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := d.bridgeSlots.Acquire(ctx, 1); err == nil {
		t.Fatal("capacity admitted a partial process behind fully admitted proxies")
	}
	d.bridgeSlots.Release(2 * bridgeProxyLimit)
}
