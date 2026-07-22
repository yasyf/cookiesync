package daemon

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/bridge"
)

const daemonChromeChildMarker = "_daemon-bridge-chrome-child-test"

func TestDaemonChromeChildRole(t *testing.T) {
	for i, arg := range os.Args {
		if arg != daemonChromeChildMarker {
			continue
		}
		if len(os.Args) != i+5 || os.Args[i+1] != "_bridge-chrome-child" {
			t.Fatalf("chrome child test args = %v", os.Args[i:])
		}
		headed := os.Args[i+4] == "true"
		if err := bridge.RunChromeChild(os.Args[i+2], os.Args[i+3], headed); err != nil {
			t.Fatal(err)
		}
	}
}

func testBridgeProcesses(t *testing.T) *bridgeProcesses {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	processes, err := newBridgeProcessesGeneration(
		executable,
		fmt.Sprintf("test-%s-%d", t.Name(), time.Now().UnixNano()),
	)
	if err != nil {
		t.Fatalf("newBridgeProcessesGeneration: %v", err)
	}
	processes.roleArgs = []string{"-test.run=TestDaemonChromeChildRole", "--", daemonChromeChildMarker}
	t.Cleanup(func() {
		processes.Close()
		processes.Cancel()
		if err := processes.Wait(context.Background()); err != nil {
			t.Errorf("bridge process Wait: %v", err)
		}
	})
	return processes
}
