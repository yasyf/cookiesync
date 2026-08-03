package bridge

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/yasyf/daemonkit"
)

const chromeChildTestMarker = "_bridge-chrome-child-test"

const fakeChromeEnv = "COOKIESYNC_FAKE_CHROME"

func TestMain(m *testing.M) {
	if os.Getenv(fakeChromeEnv) != "" && slices.Contains(os.Args, "--remote-debugging-pipe") {
		fakeChromeMain()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeChromeMain() {
	marker := os.Getenv(fakeChromeEnv)
	if err := os.WriteFile(marker, []byte("exec"), 0o600); err != nil { //nolint:gosec // test-owned marker path.
		panic(err)
	}
	commands := os.NewFile(3, "cdp-commands")
	events := os.NewFile(4, "cdp-events")
	reader := bufio.NewReader(commands)
	for {
		frame, err := reader.ReadBytes(0)
		if err != nil {
			return
		}
		var request struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(frame[:len(frame)-1], &request); err != nil {
			panic(err)
		}
		response, err := json.Marshal(map[string]any{
			"id":     request.ID,
			"result": map[string]any{"product": "Chrome/Fake"},
		})
		if err != nil {
			panic(err)
		}
		if _, err := events.Write(append(response, 0)); err != nil {
			return
		}
	}
}

func TestChromeChildRole(t *testing.T) {
	for i, arg := range os.Args {
		if arg != chromeChildTestMarker {
			continue
		}
		if len(os.Args) != i+5 || os.Args[i+1] != "_bridge-chrome-child" {
			t.Fatalf("chrome child test args = %v", os.Args[i:])
		}
		headed := os.Args[i+4] == "true"
		if err := RunChromeChild(os.Args[i+2], os.Args[i+3], headed); err != nil {
			t.Fatal(err)
		}
	}
}

func testSpawner(ctx context.Context, t *testing.T) Spawner {
	t.Helper()
	scopeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	t.Cleanup(cancel)
	owned, err := daemonkit.OwnProcesses(scopeCtx, filepath.Join(t.TempDir(), "processes.db"))
	if err != nil {
		t.Fatalf("OwnProcesses: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer closeCancel()
		if err := owned.Close(closeCtx); err != nil {
			t.Errorf("close ownership scope: %v", err)
		}
	})
	return owned.Ctx(ctx)
}

func launchTestChrome(ctx context.Context, t *testing.T, binary, dataDir string, headed bool) (*Proc, error) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return Launch(ctx, testSpawner(ctx, t), LaunchSpec{
		HostBinary: binary,
		RolePath:   executable,
		RoleArgs:   []string{"-test.run=TestChromeChildRole", "--", chromeChildTestMarker},
		DataDir:    dataDir,
		Headed:     headed,
	})
}

// TestLaunchReportsTheExecedChild proves Launch returns only once the role has
// execed the host binary, and that the pid it reports is that live child — the
// identity every teardown and every recovery sidecar keys on.
func TestLaunchReportsTheExecedChild(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "chrome-exec")
	t.Setenv(fakeChromeEnv, marker)
	launchCtx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	p, err := launchTestChrome(launchCtx, t, executable, filepath.Join(t.TempDir(), "profile"), false)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("fake chrome never execed: %v", err)
	}
	if pid := p.Pid(); pid <= 1 || syscall.Kill(pid, 0) != nil {
		t.Fatalf("reported pid %d is not a live child", pid)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
