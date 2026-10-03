package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	chromeChildRoleEnv = "COOKIESYNC_TEST_CHROME_CHILD_ROLE"
	echoChromeEnv      = "COOKIESYNC_TEST_ECHO_CHROME"
	clobberMarkerEnv   = "COOKIESYNC_TEST_CLOBBER_MARKER"
)

func TestMain(m *testing.M) {
	if os.Getenv(echoChromeEnv) != "" && slices.Contains(os.Args, "--remote-debugging-pipe") {
		echoChromeMain()
		os.Exit(0)
	}
	if os.Getenv(chromeChildRoleEnv) != "" {
		holdCDPDescriptorsLikeTheRuntime()
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

// holdCDPDescriptorsLikeTheRuntime parks a goroutine in a blocking read on a
// close-on-exec pipe at fds 3 and 4, the shape of darwin's runtime signal pipe.
// Mapping anything over those fds before exec wakes it, and it leaves a marker.
func holdCDPDescriptorsLikeTheRuntime() {
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		panic(err)
	}
	if fds != [2]int{3, 4} {
		panic(fmt.Sprintf("runtime stand-in pipe landed on fds %v, want [3 4]", fds))
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	parked := make(chan struct{})
	go func() {
		close(parked)
		n, err := unix.Read(fds[0], make([]byte, 1))
		_ = os.WriteFile(os.Getenv(clobberMarkerEnv), fmt.Appendf(nil, "read %d %v", n, err), 0o600) //nolint:gosec // test-owned marker path.
	}()
	<-parked
	time.Sleep(50 * time.Millisecond)
}

// TestChromeChildKeepsRuntimeDescriptors proves the production entry hands Chrome
// the session's stdio on fds 3 and 4 without touching descriptors the Go runtime
// holds there. Mapping them with dup2 from Go closed darwin's signal pipe and
// crashed the adapter with "signal_recv: inconsistent state".
func TestChromeChildKeepsRuntimeDescriptors(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "clobbered")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "_bridge-chrome-child", executable, t.TempDir(), "false") //nolint:gosec // re-execs this test binary.
	cmd.Env = append(os.Environ(), chromeChildRoleEnv+"=1", echoChromeEnv+"=1", clobberMarkerEnv+"="+marker)
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
	if got, err := os.ReadFile(marker); err == nil { //nolint:gosec // test-owned marker path.
		t.Fatalf("the adapter overwrote a runtime-held descriptor before exec: %s", got)
	}
}
