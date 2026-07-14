package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/synckit/manifest"
)

// passing is a doctorEnv where every check succeeds, for the all-green path.
func passing() doctorEnv {
	ok := func(label string) func(context.Context) check {
		return func(context.Context) check { return check{label: label, ok: true, detail: "ok"} }
	}
	return doctorEnv{
		helper:   ok("key helper"),
		socket:   ok("helper socket"),
		keyCache: ok("key cache"),
		mesh:     ok("mesh"),
		tcc:      func(context.Context) (check, bool) { return check{}, false },
		manifest: ok("manifest"),
		state:    ok("state"),
		tracked:  ok("browsers"),
	}
}

// TestDoctorTCCNoteFollowsPeerPresence proves the informational TCC pointer is omitted
// without peers or on mesh errors and is always an OK line when peers exist.
func TestDoctorTCCNoteFollowsPeerPresence(t *testing.T) {
	tests := []struct {
		name     string
		peers    []string
		meshErr  error
		wantNote bool
	}{
		{name: "no peers"},
		{name: "mesh error", meshErr: errors.New("mesh unavailable")},
		{name: "peer present", peers: []string{"you@desktop"}, wantNote: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resolve := func(context.Context) (string, []string, error) {
				return "you@laptop", tc.peers, tc.meshErr
			}
			result, emitted := checkTCC(context.Background(), resolve)
			if emitted && !result.ok {
				t.Fatal("checkTCC emitted a failing check")
			}
			if emitted != tc.wantNote {
				t.Fatalf("checkTCC emitted = %v, want %v", emitted, tc.wantNote)
			}

			env := passing()
			env.tcc = func(ctx context.Context) (check, bool) {
				return checkTCC(ctx, resolve)
			}
			wantChecks := 7
			if tc.wantNote {
				wantChecks = 8
			}
			if got := len(env.checks(context.Background())); got != wantChecks {
				t.Fatalf("doctor check count = %d, want %d", got, wantChecks)
			}
			var out bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&out)
			if err := runDoctor(cmd, env); err != nil {
				t.Fatalf("runDoctor = %v, want nil", err)
			}
			const line = "OK   peer TCC: cross-host pulls use ssh; if this host times out pulling from a peer, check Full Disk Access for the peer's ssh identity (sshd or tailscaled)"
			if got := strings.Contains(out.String(), line); got != tc.wantNote {
				t.Fatalf("doctor TCC line present = %v, want %v:\n%s", got, tc.wantNote, out.String())
			}
			if strings.Contains(out.String(), "FAIL peer TCC") {
				t.Fatalf("doctor emitted a failing TCC line:\n%s", out.String())
			}
		})
	}
}

// TestDoctorAllGreenExitsZero proves doctor prints an OK line per check and returns no
// error when every check passes.
func TestDoctorAllGreenExitsZero(t *testing.T) {
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runDoctor(cmd, passing()); err != nil {
		t.Fatalf("runDoctor all-green = %v, want nil", err)
	}
	got := out.String()
	for _, label := range []string{"key helper", "helper socket", "key cache", "mesh", "manifest", "state", "browsers"} {
		if !strings.Contains(got, "OK   "+label) {
			t.Errorf("doctor output missing OK line for %q:\n%s", label, got)
		}
	}
	if strings.Contains(got, "FAIL") {
		t.Errorf("doctor all-green output has a FAIL line:\n%s", got)
	}
}

// TestDoctorFailingCheckExitsNonZero proves a failed check prints a FAIL line with its
// detail and makes doctor return an error (exit 1) reporting how many failed.
func TestDoctorFailingCheckExitsNonZero(t *testing.T) {
	env := passing()
	env.helper = func(context.Context) check {
		return check{label: "key helper", detail: "not installed at /Applications/cookiesync-keyhelper.app"}
	}
	env.manifest = func(context.Context) check {
		return check{label: "manifest", detail: "not registered at ~/.config/synckit/manifests/cookiesync.json"}
	}

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err := runDoctor(cmd, env)
	if err == nil {
		t.Fatal("runDoctor with two failing checks = nil error, want non-nil")
	}
	if !strings.Contains(err.Error(), "2 of 7 checks failed") {
		t.Fatalf("doctor error = %v, want \"2 of 7 checks failed\"", err)
	}
	got := out.String()
	if !strings.Contains(got, "FAIL key helper: not installed") {
		t.Errorf("doctor missing helper FAIL detail:\n%s", got)
	}
	if !strings.Contains(got, "FAIL manifest: not registered") {
		t.Errorf("doctor missing manifest FAIL detail:\n%s", got)
	}
	// The passing checks still report OK.
	if !strings.Contains(got, "OK   state") {
		t.Errorf("doctor dropped a passing check:\n%s", got)
	}
}

// TestKeyCacheCheckRendersEveryDaemonState proves keyCacheCheck maps the daemon's
// degradation and screen-lock flags to the exact doctor line: a locked screen is OK
// (unavailable until unlock, or an in-memory degradation that re-primes after unlock),
// and only a degradation while unlocked is a FAIL.
func TestKeyCacheCheckRendersEveryDaemonState(t *testing.T) {
	tests := []struct {
		name       string
		status     keyCacheStatus
		wantOK     bool
		wantDetail string
	}{
		{
			name:       "healthy",
			status:     keyCacheStatus{Degraded: false, Locked: false},
			wantOK:     true,
			wantDetail: "Secure-Enclave wrapped",
		},
		{
			name:       "healthy keybag-locked",
			status:     keyCacheStatus{Degraded: false, Locked: true},
			wantOK:     true,
			wantDetail: "Secure-Enclave wrapped (keybag locked: screen locked or session away)",
		},
		{
			name:       "degraded keybag-locked",
			status:     keyCacheStatus{Degraded: true, Locked: true},
			wantOK:     true,
			wantDetail: "in process memory (keybag locked; re-heals Secure-Enclave wrapped on the next authorization)",
		},
		{
			name:       "degraded unlocked",
			status:     keyCacheStatus{Degraded: true, Locked: false},
			wantOK:     false,
			wantDetail: "degraded after a Secure Enclave presence refusal; run 'cookiesync auth' to re-prime",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := keyCacheCheck(tc.status)
			if got.label != "key cache" {
				t.Fatalf("label = %q, want key cache", got.label)
			}
			if got.ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", got.ok, tc.wantOK)
			}
			if got.detail != tc.wantDetail {
				t.Fatalf("detail = %q, want %q", got.detail, tc.wantDetail)
			}
		})
	}
}

// TestInstallWritesManifest proves install emits the frozen lines and writes a valid
// synckit manifest with the cookiesync action contract, against a temp config home.
func TestInstallWritesManifest(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	out := runRootCmd(t, "install")
	if !strings.Contains(out, "Registered cookiesync manifest") {
		t.Fatalf("install output = %q, want it to contain \"Registered cookiesync manifest\"", out)
	}
	if !strings.Contains(out, "synckitd install") {
		t.Fatalf("install output = %q, want it to point the user at 'synckitd install'", out)
	}

	path, err := manifestPath()
	if err != nil {
		t.Fatalf("manifestPath: %v", err)
	}
	data, err := os.ReadFile(path) //nolint:gosec // path is the test-controlled manifest under a temp config home.
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var m manifest.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("manifest is not valid JSON: %v\n%s", err, data)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("written manifest does not validate: %v", err)
	}
	if m.Name != "cookiesync" || m.Binary != "cookiesync" {
		t.Fatalf("manifest name/binary = %q/%q, want cookiesync/cookiesync", m.Name, m.Binary)
	}
	if time.Duration(m.Watch.Debounce) != watchDebounce {
		t.Fatalf("manifest watch debounce = %v, want %v", time.Duration(m.Watch.Debounce), watchDebounce)
	}
	// The typed service block: synckitd starts `cookiesync rpc-serve` and bridges the
	// svc.* contract to the resident socket, dialing the socket directly.
	if m.Service.Transport != "socket" {
		t.Fatalf("manifest service transport = %q, want socket", m.Service.Transport)
	}
	if len(m.Service.ServeArgs) != 1 || m.Service.ServeArgs[0] != "rpc-serve" {
		t.Fatalf("manifest service serve_args = %v, want [rpc-serve]", m.Service.ServeArgs)
	}
	sock, err := paths.SockPath()
	if err != nil {
		t.Fatalf("SockPath: %v", err)
	}
	if m.Service.Sock != sock {
		t.Fatalf("manifest service sock = %q, want %q (the resident socket)", m.Service.Sock, sock)
	}
	if m.Helper == nil || m.Helper.Command != "helper-serve" {
		t.Fatalf("manifest helper = %+v, want command helper-serve", m.Helper)
	}
}

// TestUninstallRemovesManifest proves uninstall removes the registered manifest and emits
// the frozen line, and is a no-op (not an error) when no manifest is registered.
func TestUninstallRemovesManifest(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	runRootCmd(t, "install")
	if got := runRootCmd(t, "uninstall"); !strings.Contains(got, "Removed cookiesync manifest") {
		t.Fatalf("uninstall output = %q, want \"Removed cookiesync manifest\"", got)
	}
	path, err := manifestPath()
	if err != nil {
		t.Fatalf("manifestPath: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("manifest still present after uninstall: %v", err)
	}
	// A second uninstall is a no-op, not an error.
	if got := runRootCmd(t, "uninstall"); !strings.Contains(got, "Removed cookiesync manifest") {
		t.Fatalf("repeat uninstall output = %q, want the frozen line", got)
	}
}

// runRootCmd runs the root command with args and returns combined stdout+stderr.
func runRootCmd(t *testing.T, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	root := newRoot("test")
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out.String())
	}
	return out.String()
}
