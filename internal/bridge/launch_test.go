package bridge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestCloseContextBudgetsADeadlinelessCaller proves the daemon's failed-open
// cleanup actually terminates Chrome. That path hands the teardown
// context.WithoutCancel(ctx), which drops the deadline along with the
// cancellation, and daemonkit's Stop refuses a context carrying none — refusing
// before it ever demands termination, while closeOnce still consumed the guard
// and os.RemoveAll still took the data dir. The child was left running against
// a deleted user-data-dir, and no later Close could settle it.
func TestCloseContextBudgetsADeadlinelessCaller(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakeChromeEnv, filepath.Join(t.TempDir(), "chrome-exec"))
	launchCtx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	p, err := launchTestChrome(launchCtx, t, executable, filepath.Join(t.TempDir(), "profile"), false)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	pid := p.Pid()
	if err := p.CloseContext(context.WithoutCancel(launchCtx)); err != nil {
		t.Fatalf("CloseContext on a deadline-less caller: %v", err)
	}
	// Stop returns only once the exit is proven, so the pid is reaped by here.
	if syscall.Kill(pid, 0) == nil {
		t.Fatalf("chrome pid %d survived a teardown that reported success", pid)
	}
}

func TestLaunch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: launches a real Chrome")
	}
	bin, err := ResolveHostBinary()
	if err != nil {
		t.Skipf("skipping: Chrome not installed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	proc, err := launchTestChrome(ctx, t, bin, t.TempDir(), false)
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	t.Cleanup(func() { _ = proc.Close() })

	if proc.BrowserUUID() == "" {
		t.Fatal("BrowserUUID is empty")
	}

	conn, err := proc.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	raw, err := conn.Call(ctx, "", "Browser.getVersion", nil)
	if err != nil {
		t.Fatalf("Browser.getVersion: %v", err)
	}
	var ver struct {
		Product string `json:"product"`
	}
	if err := json.Unmarshal(raw, &ver); err != nil {
		t.Fatalf("decode Browser.getVersion result: %v", err)
	}
	if !strings.Contains(ver.Product, "Chrome") {
		t.Fatalf("product %q does not contain %q", ver.Product, "Chrome")
	}

	raw, err = conn.Call(ctx, "", "Target.getTargets", nil)
	if err != nil {
		t.Fatalf("Target.getTargets: %v", err)
	}
	var targets struct {
		TargetInfos []json.RawMessage `json:"targetInfos"`
	}
	if err := json.Unmarshal(raw, &targets); err != nil {
		t.Fatalf("decode Target.getTargets result: %v", err)
	}
}
