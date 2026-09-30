package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/transfer"
	"github.com/yasyf/synckit/manifest"
)

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
			env.host = func(ctx context.Context) []check {
				var checks []check
				if tcc, ok := checkTCC(ctx, resolve); ok {
					checks = append(checks, tcc)
				}
				return append(checks, check{label: "manifest", ok: true, detail: "ok"})
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
	if bytes.Contains(data, []byte(`"launchd"`)) || bytes.Contains(data, []byte(`"label"`)) {
		t.Fatalf("manifest contains removed service fields:\n%s", data)
	}
	m, err := manifest.Load(path)
	if err != nil {
		t.Fatalf("written manifest does not strictly load: %v", err)
	}
	if m.Name != "cookiesync" || m.Binary != "cookiesync" {
		t.Fatalf("manifest name/binary = %q/%q, want cookiesync/cookiesync", m.Name, m.Binary)
	}
	if time.Duration(m.Watch.Debounce) != watchDebounce {
		t.Fatalf("manifest watch debounce = %v, want %v", time.Duration(m.Watch.Debounce), watchDebounce)
	}
	if m.Service.Kind != "resident" {
		t.Fatalf("manifest service kind = %q, want resident", m.Service.Kind)
	}
	if m.Service.SchemaFingerprint != transfer.Fingerprint {
		t.Fatalf("manifest service fingerprint = %q, want %q", m.Service.SchemaFingerprint, transfer.Fingerprint)
	}
	if m.Helper == nil || m.Helper.Command != "helper-serve" {
		t.Fatalf("manifest helper = %+v, want command helper-serve", m.Helper)
	}
	if m.Helper.SessionType != manifest.SessionTypeAqua {
		t.Fatalf("manifest helper session = %q, want Aqua", m.Helper.SessionType)
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
