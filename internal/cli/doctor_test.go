package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/yasyf/cookiesync/internal/state"
)

// passing is a doctorEnv where every check succeeds, for the all-green path.
func passing() doctorEnv {
	ok := func(label string) func(context.Context) check {
		return func(context.Context) check { return check{label: label, ok: true, detail: "ok"} }
	}
	return doctorEnv{
		helper:     ok("key helper"),
		socket:     ok("helper socket"),
		keyCache:   ok("key cache"),
		mesh:       ok("mesh"),
		host:       func(ctx context.Context) []check { return []check{ok("manifest")(ctx)} },
		state:      ok("state"),
		tracked:    ok("browsers"),
		quarantine: func(context.Context) []check { return nil },
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
	env.host = func(context.Context) []check {
		return []check{{label: "manifest", detail: "not registered at ~/.config/synckit/manifests/cookiesync.json"}}
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

// TestDoctorQuarantineLines proves quarantineChecks renders one FAIL line per
// quarantined endpoint (sorted, with both counts and the recovery bar), none for a
// healthy ledger, and that a quarantined endpoint fails the doctor run.
func TestDoctorQuarantineLines(t *testing.T) {
	baselines := map[string]state.Baseline{
		"me@laptop:chrome:Default": {Rows: 9000},
		"me@laptop:arc:Default":    {Rows: 9000, Quarantined: true, QuarantinedRows: 12},
		"me@laptop:arc:Work":       {Rows: 1000, Quarantined: true},
	}
	checks := quarantineChecks(baselines)
	if len(checks) != 2 {
		t.Fatalf("quarantineChecks = %d checks, want 2: %+v", len(checks), checks)
	}
	want := []string{
		"me@laptop:arc:Default: rowcount collapsed to 12 vs baseline 9000; excluded from merge inputs until it recovers to >= 4500 rows",
		"me@laptop:arc:Work: rowcount collapsed to 0 vs baseline 1000; excluded from merge inputs until it recovers to >= 500 rows",
	}
	for i, c := range checks {
		if c.ok {
			t.Fatalf("quarantine check %d is OK, want FAIL", i)
		}
		if c.label != "quarantine" || c.detail != want[i] {
			t.Fatalf("check %d = %q: %q, want quarantine: %q", i, c.label, c.detail, want[i])
		}
	}
	if healthy := quarantineChecks(map[string]state.Baseline{"me@laptop:chrome:Default": {Rows: 9000}}); len(healthy) != 0 {
		t.Fatalf("healthy ledger rendered %d quarantine lines, want 0", len(healthy))
	}

	env := passing()
	env.quarantine = func(context.Context) []check { return checks }
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err := runDoctor(cmd, env)
	if err == nil {
		t.Fatal("runDoctor with a quarantined endpoint = nil error, want non-nil")
	}
	if !strings.Contains(out.String(), "FAIL quarantine: "+want[0]) {
		t.Fatalf("doctor output missing quarantine FAIL line:\n%s", out.String())
	}
}
