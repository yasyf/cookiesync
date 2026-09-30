//go:build linux

package bridge

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestHandlerTrackerReapsOnlyItsSessionsHandlers(t *testing.T) {
	session, other := t.TempDir(), t.TempDir()
	handler := handlerDoubleExe(t)
	nonce := launchNonce(t)
	plain := startHandlerDouble(t, handler, session, crashpadEnvironment(session, nonce), "read line")
	stubborn := startHandlerDouble(t, handler, session, crashpadEnvironment(session, nonce), "trap '' TERM; read line")
	foreign := startHandlerDouble(t, handler, other, crashpadEnvironment(other, nonce), "read line")

	tracker := trackHandlers(session, nonce)
	closeTracker := closeOnce(t, tracker)
	tracker.exitTimeout, tracker.termGrace, tracker.killGrace = 200*time.Millisecond, 500*time.Millisecond, 500*time.Millisecond
	want := []int{plain.Process.Pid, stubborn.Process.Pid}
	slices.Sort(want)
	if got := tracker.tracked(); !slices.Equal(got, want) {
		t.Fatalf("tracked = %v, want the session's doubles %v and never the foreign double %d", got, want, foreign.Process.Pid)
	}

	start := time.Now()
	if err := closeTracker(); err != nil {
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
	endLiveDouble(t, foreign)
}

func TestHandlerTrackerPreservesCandidatesItDidNotLaunch(t *testing.T) {
	session := t.TempDir()
	database := crashpadDatabase(session)
	handler := handlerDoubleExe(t)
	nonce, another := launchNonce(t), launchNonce(t)
	owned := startHandlerDouble(t, handler, session, crashpadEnvironment(session, nonce), "read line")
	unlaunched := startHandlerDouble(t, handler, session, nil, "read line")
	stranger := startHandlerDouble(t, handler, session, crashpadEnvironment(session, another), "read line")
	shell := startHandlerDouble(t, "/bin/sh", session, crashpadEnvironment(session, nonce), "read line")
	shellExe, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}

	tracker := trackHandlers(session, nonce)
	closeTracker := closeOnce(t, tracker)
	tracker.exitTimeout, tracker.termGrace, tracker.killGrace = 200*time.Millisecond, 500*time.Millisecond, 500*time.Millisecond
	if got, want := tracker.tracked(), []int{owned.Process.Pid}; !slices.Equal(got, want) {
		t.Fatalf("tracked = %v, want only the launched handler double %v", got, want)
	}

	refusals := map[int]string{
		unlaunched.Process.Pid: refusal(t, unlaunched, handler, database, "its environment carries no COOKIESYNC_BRIDGE_LAUNCH"),
		stranger.Process.Pid:   refusal(t, stranger, handler, database, "its environment carries another launch's COOKIESYNC_BRIDGE_LAUNCH"),
		shell.Process.Pid:      refusal(t, shell, shellExe, database, "its executable "+shellExe+" is not chrome_crashpad_handler"),
	}
	lines := make([]string, 0, len(refusals))
	for _, pid := range slices.Sorted(maps.Keys(refusals)) {
		lines = append(lines, refusals[pid])
	}
	want := strings.Join(lines, "\n")
	err = closeTracker()
	if err == nil || err.Error() != want {
		t.Fatalf("close error = %v\nwant the refusal naming every unowned candidate:\n%s", err, want)
	}
	if sig := exitSignal(t, owned); sig != syscall.SIGTERM {
		t.Errorf("launched double exited on %v, want SIGTERM", sig)
	}
	endLiveDouble(t, unlaunched)
	endLiveDouble(t, stranger)
	endLiveDouble(t, shell)
}

func TestHandlerTrackerDropsAnOwnedHandlerOnceItsProcessIsGone(t *testing.T) {
	session := t.TempDir()
	handler := handlerDoubleExe(t)
	nonce := launchNonce(t)
	double := startHandlerDouble(t, handler, session, crashpadEnvironment(session, nonce), "read line")

	tracker := trackHandlers(session, nonce)
	closeOnce(t, tracker)
	if got, want := tracker.tracked(), []int{double.Process.Pid}; !slices.Equal(got, want) {
		t.Fatalf("tracked = %v, want the launched handler double %v", got, want)
	}
	pidfd := tracker.owned[double.Process.Pid].pidfd

	endLiveDouble(t, double)
	tracker.adopt()
	if got := slices.Sorted(maps.Keys(tracker.owned)); len(got) != 0 {
		t.Fatalf("owned = %v after double %d exited and was reaped, want none", got, double.Process.Pid)
	}
	if err := unix.Close(pidfd); !errors.Is(err, unix.EBADF) {
		t.Fatalf("closing the dropped double's pidfd = %v, want %v because the tracker released it", err, unix.EBADF)
	}
}

func TestRefusalsNameOnlyCandidatesStillPresent(t *testing.T) {
	session := t.TempDir()
	database := crashpadDatabase(session)
	handler := handlerDoubleExe(t)
	nonce := launchNonce(t)
	staying := startHandlerDouble(t, handler, session, nil, "read line")
	departing := startHandlerDouble(t, handler, session, nil, "read line")

	tracker := trackHandlers(session, nonce)
	closeOnce(t, tracker)
	if got := tracker.tracked(); len(got) != 0 {
		t.Fatalf("tracked = %v, want neither unlaunched double", got)
	}
	want := []int{staying.Process.Pid, departing.Process.Pid}
	slices.Sort(want)
	if got := slices.Sorted(maps.Keys(tracker.preserved)); !slices.Equal(got, want) {
		t.Fatalf("preserved = %v, want both unlaunched doubles %v", got, want)
	}
	wantRefusal := refusal(t, staying, handler, database, "its environment carries no COOKIESYNC_BRIDGE_LAUNCH")

	endLiveDouble(t, departing)
	err := refusals(tracker.preserved, tracker.database)
	if err == nil || err.Error() != wantRefusal {
		t.Fatalf("refusals = %v\nwant only the candidate still present:\n%s", err, wantRefusal)
	}
	endLiveDouble(t, staying)
}

func closeOnce(t *testing.T, tracker *handlerTracker) func() error {
	t.Helper()
	var once sync.Once
	var err error
	closeTracker := func() error {
		once.Do(func() { err = tracker.close() })
		return err
	}
	t.Cleanup(func() { _ = closeTracker() })
	return closeTracker
}

func refusal(t *testing.T, cmd *exec.Cmd, exe, database, reason string) string {
	t.Helper()
	pid := cmd.Process.Pid
	stat, err := os.ReadFile(procPath(pid, "stat"))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := parseProcStat(stat)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("bridge: refused to reap crashpad candidate %d serving --database=%s (ppid %d pgid %d sid %d start %d exe %q argv %q): %s",
		pid, database, os.Getpid(), unix.Getpgrp(), sessionID(t), identity.start, exe, cmd.Args, reason)
}

func sessionID(t *testing.T) int {
	t.Helper()
	sid, err := unix.Getsid(0)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

func launchNonce(t *testing.T) string {
	t.Helper()
	nonce, err := newLaunchNonce()
	if err != nil {
		t.Fatal(err)
	}
	return nonce
}

func handlerDoubleExe(t *testing.T) string {
	t.Helper()
	shell, err := os.ReadFile("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(t.TempDir(), crashpadHandlerExe)
	writeExecutable(t, exe, string(shell))
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func startHandlerDouble(t *testing.T, exe, dataDir string, env []string, script string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(exe, "-c", script, "crashpad-double", crashpadDatabaseArg+crashpadDatabase(dataDir)) //nolint:gosec // G204: a test-owned shell double whose variable arguments are the test's own executable copy and temp database path.
	cmd.Env = append(slices.DeleteFunc(os.Environ(), carriesLaunch), env...)
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

func endLiveDouble(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Process.Signal(syscall.SIGUSR1); err != nil {
		t.Fatalf("end double %d: %v", cmd.Process.Pid, err)
	}
	if sig := exitSignal(t, cmd); sig != syscall.SIGUSR1 {
		t.Errorf("double %d died of %v before the test ended it, want SIGUSR1", cmd.Process.Pid, sig)
	}
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
