package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/service"
)

// passing is a doctorEnv where every check succeeds, for the all-green path.
func passing() doctorEnv {
	ok := func(label string) func(context.Context) check {
		return func(context.Context) check { return check{label: label, ok: true, detail: "ok"} }
	}
	return doctorEnv{
		helper:  ok("key helper"),
		socket:  ok("daemon socket"),
		state:   ok("state"),
		tracked: ok("browsers"),
		agents:  ok("agents"),
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
	for _, label := range []string{"key helper", "daemon socket", "state", "browsers", "agents"} {
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
	env.agents = func(context.Context) check {
		return check{label: "agents", detail: "not installed: com.github.yasyf.cookiesync.watch"}
	}

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err := runDoctor(cmd, env)
	if err == nil {
		t.Fatal("runDoctor with two failing checks = nil error, want non-nil")
	}
	if !strings.Contains(err.Error(), "2 of 5 checks failed") {
		t.Fatalf("doctor error = %v, want \"2 of 5 checks failed\"", err)
	}
	got := out.String()
	if !strings.Contains(got, "FAIL key helper: not installed") {
		t.Errorf("doctor missing helper FAIL detail:\n%s", got)
	}
	if !strings.Contains(got, "FAIL agents: not installed") {
		t.Errorf("doctor missing agents FAIL detail:\n%s", got)
	}
	// The passing checks still report OK.
	if !strings.Contains(got, "OK   state") {
		t.Errorf("doctor dropped a passing check:\n%s", got)
	}
}

// fakeLauncher records bootstrap/bootout so the install CLI path runs without loading a
// real agent.
type fakeLauncher struct {
	bootstrapped int
	bootedOut    int
}

func (f *fakeLauncher) Bootstrap(context.Context, string) error { f.bootstrapped++; return nil }
func (f *fakeLauncher) Bootout(context.Context, string) error   { f.bootedOut++; return nil }

// TestInstallUninstallCLIOutput proves the install/uninstall commands emit the frozen
// lines and drive the launcher, against a temp HOME and a fake launcher — no real agent
// is loaded.
func TestInstallUninstallCLIOutput(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	launcher := &fakeLauncher{}
	prev := newLauncher
	newLauncher = func() service.Launcher { return launcher }
	t.Cleanup(func() { newLauncher = prev })

	// install (full)
	if got := runRootCmd(t, "install"); !strings.Contains(got, "Installed cookiesync agents.") {
		t.Fatalf("install output = %q, want it to contain \"Installed cookiesync agents.\"", got)
	}
	if launcher.bootstrapped != 2 {
		t.Errorf("install bootstrapped %d agents, want 2", launcher.bootstrapped)
	}

	// install --tick-only
	launcher.bootstrapped = 0
	if got := runRootCmd(t, "install", "--tick-only"); !strings.Contains(got, "Installed the cookiesync reconcile tick.") {
		t.Fatalf("install --tick-only output = %q, want the tick line", got)
	}
	if launcher.bootstrapped != 1 {
		t.Errorf("install --tick-only bootstrapped %d agents, want 1", launcher.bootstrapped)
	}

	// uninstall
	if got := runRootCmd(t, "uninstall"); !strings.Contains(got, "Uninstalled cookiesync agents.") {
		t.Fatalf("uninstall output = %q, want \"Uninstalled cookiesync agents.\"", got)
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
