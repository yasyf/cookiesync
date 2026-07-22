package bridge

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

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
