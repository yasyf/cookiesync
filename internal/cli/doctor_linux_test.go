package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasyf/cookiesync/internal/cookie"
)

// TestLinuxKeyCacheCheckReportsTheMemoryTier proves the Linux key-cache line reports the
// in-memory tier with its 5 minute cap as healthy whatever the keybag flag says, fails
// when the helper claims a sealed tier, and never mentions an enclave.
func TestLinuxKeyCacheCheckReportsTheMemoryTier(t *testing.T) {
	const memory = "in process memory only; cached keys and grants expire within 5 minutes"
	tests := []struct {
		name   string
		status keyCacheStatus
		want   check
	}{
		{
			name:   "memory tier as the linux helper reports it",
			status: keyCacheStatus{Degraded: true, Locked: true},
			want:   check{label: "key cache", ok: true, detail: memory},
		},
		{
			name:   "memory tier without the keybag flag",
			status: keyCacheStatus{Degraded: true},
			want:   check{label: "key cache", ok: true, detail: memory},
		},
		{
			name:   "sealed tier claim",
			status: keyCacheStatus{},
			want:   check{label: "key cache", detail: "the helper reports a sealed cache tier this host cannot provide; restart it with 'cookiesync install'"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := keyCacheCheck(tc.status)
			if got != tc.want {
				t.Fatalf("keyCacheCheck(%+v) = %+v, want %+v", tc.status, got, tc.want)
			}
			if strings.Contains(strings.ToLower(got.detail), "enclave") {
				t.Fatalf("Linux key-cache line mentions an enclave: %q", got.detail)
			}
		})
	}
}

// TestLinuxDoctorWordingNamesNoMacBackend proves the Linux doctor's help and helper hint
// point at the supervisor, never at the Secure Enclave, Touch ID, or synckitd.
func TestLinuxDoctorWordingNamesNoMacBackend(t *testing.T) {
	for _, text := range []string{doctorShort, socketHint, helperServeShort, installShort, uninstallShort} {
		for _, banned := range []string{"Enclave", "Touch ID", "synckitd", "launchd", "brew"} {
			if strings.Contains(text, banned) {
				t.Errorf("%q mentions %q", text, banned)
			}
		}
	}
	if !strings.Contains(socketHint, "'cookiesync supervise'") {
		t.Fatalf("socketHint = %q, want it to name 'cookiesync supervise'", socketHint)
	}
}

// TestCheckSupervisorWithoutSupervisorFails proves the supervisor line fails with the
// command that starts one when none answers for the helper label.
func TestCheckSupervisorWithoutSupervisorFails(t *testing.T) {
	isolateDaemonkit(t)

	got := checkSupervisor(context.Background())
	if got.ok || got.label != "supervisor" {
		t.Fatalf("checkSupervisor = %+v, want a failing supervisor line", got)
	}
	if !strings.Contains(got.detail, "no supervisor is running") || !strings.Contains(got.detail, "start 'cookiesync supervise'") {
		t.Fatalf("checkSupervisor detail = %q, want the no-supervisor cause and the supervise hint", got.detail)
	}
}

// TestCheckBrowserRoots proves the browser-roots line lists every registry browser in
// name order with its data root and profile count, and passes only when one is present.
func TestCheckBrowserRoots(t *testing.T) {
	tests := []struct {
		name     string
		profiles map[string][]string
		wantOK   bool
		want     func(chrome, chromium string) string
	}{
		{
			name:   "no browser installed",
			wantOK: false,
			want: func(chrome, chromium string) string {
				return "chrome absent at " + chrome + "; chromium absent at " + chromium
			},
		},
		{
			name:     "chrome with two profiles",
			profiles: map[string][]string{"chrome": {"Default", "Profile 1"}},
			wantOK:   true,
			want: func(chrome, chromium string) string {
				return "chrome at " + chrome + " (2 profiles); chromium absent at " + chromium
			},
		},
		{
			name:     "chromium root without a cookie store",
			profiles: map[string][]string{"chromium": {}},
			wantOK:   true,
			want: func(chrome, chromium string) string {
				return "chrome absent at " + chrome + "; chromium at " + chromium + " (0 profiles)"
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			registry, err := cookie.Registry()
			if err != nil {
				t.Fatal(err)
			}
			for name, dirs := range tc.profiles {
				b := registry[cookie.BrowserName(name)]
				if err := os.MkdirAll(b.DataRoot, 0o700); err != nil {
					t.Fatal(err)
				}
				for _, dir := range dirs {
					if err := os.MkdirAll(b.ProfileDir(dir), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(b.CookiesDB(dir), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			got := checkBrowserRoots()
			want := check{
				label:  "browser roots",
				ok:     tc.wantOK,
				detail: tc.want(registry["chrome"].DataRoot, registry["chromium"].DataRoot),
			}
			if got != want {
				t.Fatalf("checkBrowserRoots = %+v, want %+v", got, want)
			}
		})
	}
}

// TestCheckBridgeChrome proves the bridge-chrome line names the Chromium found on PATH
// and fails when PATH holds none.
func TestCheckBridgeChrome(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	if got := checkBridgeChrome(); got.ok || got.label != "bridge chrome" || !strings.Contains(got.detail, "no chrome or chromium on PATH") {
		t.Fatalf("checkBridgeChrome with an empty PATH = %+v, want a failing line naming the missing browser", got)
	}

	chromium := filepath.Join(bin, "chromium")
	if err := os.WriteFile(chromium, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // an executable stand-in is the fixture.
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(chromium)
	if err != nil {
		t.Fatal(err)
	}
	if got := checkBridgeChrome(); got != (check{label: "bridge chrome", ok: true, detail: want}) {
		t.Fatalf("checkBridgeChrome = %+v, want OK at %s", got, want)
	}
}
