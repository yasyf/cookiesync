package bridge

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/yasyf/daemonkit/proc"
	"github.com/yasyf/daemonkit/supervise"
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

func testProcessPool(ctx context.Context, t *testing.T) *supervise.Pool {
	t.Helper()
	reaper := &proc.Reaper{
		Store:      &proc.FileStore{Path: filepath.Join(t.TempDir(), "processes.db")},
		Generation: fmt.Sprintf("test-%s-%d", t.Name(), time.Now().UnixNano()),
	}
	pool, err := supervise.NewPool(8, reaper)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		pool.Cancel()
		if err := pool.Wait(context.WithoutCancel(ctx)); err != nil {
			t.Errorf("process pool Wait: %v", err)
		}
	})
	return pool
}

func launchTestChrome(ctx context.Context, t *testing.T, binary, dataDir string, headed bool) (*Proc, error) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return Launch(ctx, testProcessPool(ctx, t), LaunchSpec{
		HostBinary: binary,
		RolePath:   executable,
		RoleArgs:   []string{"-test.run=TestChromeChildRole", "--", chromeChildTestMarker},
		DataDir:    dataDir,
		Headed:     headed,
	})
}

func TestLaunchDoesNotExecBeforeRecorded(t *testing.T) {
	pool := testProcessPool(t.Context(), t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "chrome-exec")
	t.Setenv(fakeChromeEnv, marker)
	recorded := make(chan proc.Record, 1)
	release := make(chan struct{})
	dataDir := filepath.Join(t.TempDir(), "profile")
	done := make(chan struct {
		proc *Proc
		err  error
	}, 1)
	go func() {
		p, launchErr := Launch(context.Background(), pool, LaunchSpec{
			HostBinary: executable,
			RolePath:   executable,
			RoleArgs:   []string{"-test.run=TestChromeChildRole", "--", chromeChildTestMarker},
			DataDir:    dataDir,
			Recorded: func(_ context.Context, record proc.Record) error {
				recorded <- record
				<-release
				return nil
			},
		})
		done <- struct {
			proc *Proc
			err  error
		}{p, launchErr}
	}()
	record := <-recorded
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("chrome exec raced durable Recorded callback: %v", err)
	}
	close(release)
	result := <-done
	if result.err != nil {
		t.Fatalf("Launch: %v", result.err)
	}
	if result.proc.Pid() != record.PID {
		t.Fatalf("managed pid = %d, recorded pid %d", result.proc.Pid(), record.PID)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("fake chrome never execed: %v", err)
	}
	if err := result.proc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
