package bridge

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/yasyf/daemonkit/proc"
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

func testProcessManager(ctx context.Context, t *testing.T) *proc.Manager {
	t.Helper()
	generation, err := proc.ProcessGeneration()
	if err != nil {
		t.Fatalf("ProcessGeneration: %v", err)
	}
	reaper := &proc.Reaper{
		Store:      &proc.FileStore{Path: filepath.Join(t.TempDir(), "processes.db")},
		Generation: generation,
	}
	manager, err := proc.NewManager(8, reaper)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := manager.ClaimRuntime(); err != nil {
		t.Fatalf("ClaimRuntime: %v", err)
	}
	if err := manager.Recover(ctx); err != nil {
		t.Fatalf("Recover: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := manager.Shutdown(closeCtx); err != nil {
			t.Errorf("process manager Shutdown: %v", err)
		}
	})
	return manager
}

func launchTestChrome(ctx context.Context, t *testing.T, binary, dataDir string, headed bool) (*Proc, error) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return Launch(ctx, testProcessManager(ctx, t), LaunchSpec{
		HostBinary: binary,
		RolePath:   executable,
		RoleArgs:   []string{"-test.run=TestChromeChildRole", "--", chromeChildTestMarker},
		DataDir:    dataDir,
		Headed:     headed,
	})
}

func TestLaunchDoesNotExecBeforeRecorded(t *testing.T) {
	manager := testProcessManager(t.Context(), t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "chrome-exec")
	t.Setenv(fakeChromeEnv, marker)
	recorded := make(chan proc.ProcessReceipt, 1)
	release := make(chan struct{})
	dataDir := filepath.Join(t.TempDir(), "profile")
	launchCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan struct {
		proc *Proc
		err  error
	}, 1)
	go func() {
		p, launchErr := Launch(launchCtx, manager, LaunchSpec{
			HostBinary: executable,
			RolePath:   executable,
			RoleArgs:   []string{"-test.run=TestChromeChildRole", "--", chromeChildTestMarker},
			DataDir:    dataDir,
			Recorded: func(_ context.Context, receipt proc.ProcessReceipt) error {
				recorded <- receipt
				<-release
				return nil
			},
		})
		done <- struct {
			proc *Proc
			err  error
		}{p, launchErr}
	}()
	var receipt proc.ProcessReceipt
	select {
	case receipt = <-recorded:
	case result := <-done:
		t.Fatalf("Launch returned before Recorded callback: %v", result.err)
	case <-launchCtx.Done():
		t.Fatalf("Launch never reached Recorded callback: %v", launchCtx.Err())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("chrome exec raced durable Recorded callback: %v", err)
	}
	close(release)
	result := <-done
	if result.err != nil {
		t.Fatalf("Launch: %v", result.err)
	}
	if result.proc.Pid() != receipt.ProcessIdentity().PID {
		t.Fatalf("managed pid = %d, recorded pid %d", result.proc.Pid(), receipt.ProcessIdentity().PID)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("fake chrome never execed: %v", err)
	}
	if err := result.proc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
