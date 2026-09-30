package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yasyf/daemonkit/supervise"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/cookiesync/internal/testutil"
)

func isolateDaemonkit(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	t.Setenv("DAEMONKIT_HOME", root)
	return root
}

func runRootCmdErr(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	root := newRoot("test")
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

// TestSuperviseIsAHiddenLinuxCommand proves the root registers exactly one hidden,
// argument-free supervise command on Linux.
func TestSuperviseIsAHiddenLinuxCommand(t *testing.T) {
	root := newRoot("test")
	var found int
	for _, cmd := range root.Commands() {
		if cmd.Name() != "supervise" {
			continue
		}
		found++
		if !cmd.Hidden {
			t.Fatal("supervise is listed in help, want hidden")
		}
		if err := cmd.Args(cmd, []string{"extra"}); err == nil {
			t.Fatal("supervise accepted a positional argument")
		}
	}
	if found != 1 {
		t.Fatalf("root registers %d supervise commands, want 1", found)
	}
}

// TestInstallWithoutSupervisorNamesSupervise proves install on Linux initializes state,
// then refuses with the supervisor sentinel and a message naming the command to run,
// and writes no synckit manifest.
func TestInstallWithoutSupervisorNamesSupervise(t *testing.T) {
	testutil.IsolateHostConfig(t, paths.Config)
	isolateDaemonkit(t)

	out, err := runRootCmdErr(t, "install")
	if !errors.Is(err, supervise.ErrNoSupervisor) {
		t.Fatalf("install error = %v, want supervise.ErrNoSupervisor", err)
	}
	if !strings.Contains(err.Error(), "start 'cookiesync supervise'") {
		t.Fatalf("install error = %q, want it to name 'cookiesync supervise'", err)
	}
	if out != "" {
		t.Fatalf("failed install printed %q, want nothing", out)
	}
	statePath, err := paths.Config.Path()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("install did not initialize state before ensuring: %v", err)
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if _, err := os.Stat(filepath.Join(xdg, "synckit", "manifests", "cookiesync.json")); !os.IsNotExist(err) { //nolint:gosec // G703: XDG_CONFIG_HOME is set by this test.
		t.Fatalf("install wrote a synckit manifest on Linux: %v", err)
	}
}

// TestUninstallWithoutSupervisorIsANoOp proves uninstall succeeds when no supervisor
// runs and nothing was applied, and repeats cleanly.
func TestUninstallWithoutSupervisorIsANoOp(t *testing.T) {
	testutil.IsolateHostConfig(t, paths.Config)
	isolateDaemonkit(t)

	const want = "Stopped the resident helper; 'cookiesync supervise' no longer runs it.\n"
	for range 2 {
		if got := runRootCmd(t, "uninstall"); got != want {
			t.Fatalf("uninstall output = %q, want %q", got, want)
		}
	}
}
