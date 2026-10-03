package cli

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/yasyf/cookiesync/internal/bridge"
)

const (
	chromeChildRoleEnv = "COOKIESYNC_TEST_CHROME_CHILD_ROLE"
	echoChromeEnv      = "COOKIESYNC_TEST_ECHO_CHROME"
)

func TestMain(m *testing.M) {
	if os.Getenv(echoChromeEnv) != "" && slices.Contains(os.Args, "--remote-debugging-pipe") {
		echoChromeMain()
		os.Exit(0)
	}
	if os.Getenv(chromeChildRoleEnv) != "" {
		Execute("test")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func echoChromeMain() {
	frame, err := bufio.NewReader(os.NewFile(3, "cdp-commands")).ReadBytes(0)
	if err != nil {
		panic(err)
	}
	if _, err := os.NewFile(4, "cdp-events").Write(frame); err != nil {
		panic(err)
	}
}

// TestChromeChildEntryKeepsCDPDescriptors proves the production entry point
// hands Chrome the session's stdio on fds 3 and 4. Dispatched after the root's
// signal handler, the runtime's signal pipe held those descriptors, and mapping
// over them crashed the adapter with "signal_recv: inconsistent state".
func TestChromeChildEntryKeepsCDPDescriptors(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, bridge.ChromeChildVerb, executable, t.TempDir(), "false") //nolint:gosec // re-execs this test binary.
	cmd.Env = append(os.Environ(), chromeChildRoleEnv+"=1", echoChromeEnv+"=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	commands, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	events, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := commands.Write([]byte("ping\x00")); err != nil {
		t.Fatal(err)
	}
	frame, _ := bufio.NewReader(events).ReadBytes(0)
	waitErr := cmd.Wait()
	if string(frame) != "ping\x00" || waitErr != nil {
		t.Fatalf("echoed frame = %q (want %q), exit %v; stderr: %s", frame, "ping\x00", waitErr, stderr.String())
	}
}
