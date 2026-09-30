//go:build linux

package bridge

import (
	"errors"
	"os/exec"
	"slices"
	"syscall"
	"testing"
	"time"
)

func TestHandlerTrackerReapsOnlyItsSessionsHandlers(t *testing.T) {
	session, other := t.TempDir(), t.TempDir()
	plain := startHandlerDouble(t, session, "read line")
	stubborn := startHandlerDouble(t, session, "trap '' TERM; read line")
	foreign := startHandlerDouble(t, other, "read line")

	tracker := trackHandlers(session)
	tracker.exitTimeout, tracker.termGrace, tracker.killGrace = 200*time.Millisecond, 500*time.Millisecond, 500*time.Millisecond
	want := []int{plain.Process.Pid, stubborn.Process.Pid}
	slices.Sort(want)
	if got := tracker.tracked(); !slices.Equal(got, want) {
		t.Fatalf("tracked = %v, want the session's doubles %v and never the foreign double %d", got, want, foreign.Process.Pid)
	}

	start := time.Now()
	if err := tracker.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("close took %s, want within the exit, TERM and KILL budgets", elapsed)
	}
	if sig := exitSignal(t, plain); sig != syscall.SIGTERM {
		t.Errorf("plain double exited on %v, want SIGTERM", sig)
	}
	if sig := exitSignal(t, stubborn); sig != syscall.SIGKILL {
		t.Errorf("TERM-ignoring double exited on %v, want SIGKILL", sig)
	}
	if err := foreign.Process.Signal(syscall.Signal(0)); err != nil {
		t.Errorf("foreign double under %s is gone: %v", other, err)
	}
}

func startHandlerDouble(t *testing.T, dataDir, script string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", script, "crashpad-double", crashpadDatabaseArg+crashpadDatabase(dataDir)) //nolint:gosec // G204: a test-owned shell double whose only variable argument is the test's own temp database path.
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start double: %v", err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	return cmd
}

func exitSignal(t *testing.T, cmd *exec.Cmd) syscall.Signal {
	t.Helper()
	err := cmd.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("double %d exited without a signal: %v", cmd.Process.Pid, err)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() {
		t.Fatalf("double %d exited with %v, want a signal", cmd.Process.Pid, exit)
	}
	return status.Signal()
}
