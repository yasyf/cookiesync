package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/yasyf/daemonkit/proc"
	"github.com/yasyf/daemonkit/supervise"
	"golang.org/x/sync/semaphore"

	"github.com/yasyf/cookiesync/internal/paths"
)

type blockingRecoveryRunner struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once

	mu     sync.Mutex
	target string
	cmd    string
	stdin  string
}

func (r *blockingRecoveryRunner) Run(ctx context.Context, target, cmd string, stdin []byte) (string, error) {
	r.mu.Lock()
	r.target, r.cmd, r.stdin = target, cmd, string(stdin)
	r.mu.Unlock()
	r.once.Do(func() { close(r.started) })
	select {
	case <-r.release:
		return "", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func TestBridgeRecoveryReapsLeaderlessGroupBeforeReceiptAcknowledgement(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	old, err := newBridgeProcessesGeneration(executable, "old-generation")
	if err != nil {
		t.Fatal(err)
	}
	old.reaper.Grace = 50 * time.Millisecond
	old.reaper.Settlement = time.Second
	t.Cleanup(func() {
		old.Close()
		old.Cancel()
		_ = old.Wait(context.Background())
	})

	releaseLeader := filepath.Join(t.TempDir(), "release")
	descendantFile := filepath.Join(t.TempDir(), "descendant")
	script := fmt.Sprintf(
		"while [ ! -f %s ]; do sleep 0.01; done; (trap '' TERM; exec sleep 30) & echo $! > %s; exit 0",
		releaseLeader, descendantFile,
	)
	command := exec.Command("/bin/sh", "-c", script) //nolint:gosec // test-owned exact shell fixture.
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	record, err := old.reaper.TrackGroup(t.Context(), command.Process.Pid, proc.RecoveryTask)
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "leaderless-session"
	if err := old.recorded(
		bridgeProcessTunnel, sessionID, "you@desktop:chrome:Default", "you@desktop", "cap-b-secret",
	)(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(releaseLeader, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	descendantRaw, err := os.ReadFile(descendantFile) //nolint:gosec // test-owned exact path.
	if err != nil {
		t.Fatal(err)
	}
	descendant, err := strconv.Atoi(strings.TrimSpace(string(descendantRaw)))
	if err != nil {
		t.Fatal(err)
	}

	next, err := newBridgeProcessesGeneration(executable, "next-generation")
	if err != nil {
		t.Fatal(err)
	}
	next.reaper.Grace = 50 * time.Millisecond
	next.reaper.Settlement = time.Second
	t.Cleanup(func() {
		next.Close()
		next.Cancel()
		_ = next.Wait(context.Background())
	})
	deletionStarted := make(chan struct{})
	deletionRelease := make(chan struct{})
	var deletionOnce sync.Once
	next.syncDir = func(path string) error {
		if path == next.sessionsRoot {
			deletionOnce.Do(func() { close(deletionStarted) })
			<-deletionRelease
		}
		return syncDirectory(path)
	}
	runner := &blockingRecoveryRunner{started: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- next.recover(context.Background(), runner) }()
	select {
	case <-runner.started:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery did not reach remote-close settlement")
	}

	page, err := next.reaper.ReapReceipts(t.Context(), proc.RecoveryTask, proc.ReapReceiptCursor{}, proc.ReapReceiptPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Receipts) != 1 || page.Receipts[0].Record != record {
		t.Fatalf("receipt before product settlement = %+v", page.Receipts)
	}
	metadataName, err := bridgeRecoveryFileName(bridgeProcessTunnel, record)
	if err != nil {
		t.Fatal(err)
	}
	metadataPath := filepath.Join(next.sessionDir(sessionID), metadataName)
	if _, err := os.Stat(metadataPath); err != nil {
		t.Fatalf("product liability disappeared before receipt ack: %v", err)
	}
	close(runner.release)
	select {
	case <-deletionStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("recovery did not durably remove product metadata")
	}
	page, err = next.reaper.ReapReceipts(t.Context(), proc.RecoveryTask, proc.ReapReceiptCursor{}, proc.ReapReceiptPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Receipts) != 1 || page.Receipts[0].Record != record {
		t.Fatalf("receipt acknowledged before parent directory sync = %+v", page.Receipts)
	}
	close(deletionRelease)
	if err := <-done; err != nil {
		t.Fatalf("recover: %v", err)
	}

	page, err = next.reaper.ReapReceipts(t.Context(), proc.RecoveryTask, proc.ReapReceiptCursor{}, proc.ReapReceiptPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Receipts) != 0 {
		t.Fatalf("receipt remained after product settlement: %+v", page.Receipts)
	}
	if _, err := os.Stat(next.sessionDir(sessionID)); !os.IsNotExist(err) {
		t.Fatalf("recovered session residue remains: %v", err)
	}
	runner.mu.Lock()
	target, cmd, stdin := runner.target, runner.cmd, runner.stdin
	runner.mu.Unlock()
	if target != "you@desktop" || !strings.Contains(cmd, "bridge_close") || !strings.Contains(stdin, "cap-b-secret") {
		t.Fatalf("remote close = target %q cmd %q stdin %q", target, cmd, stdin)
	}
	if strings.Contains(cmd, "cap-b-secret") {
		t.Fatalf("capability leaked into argv: %q", cmd)
	}
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(descendant, 0) == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if syscall.Kill(descendant, 0) == nil {
		t.Fatalf("leaderless descendant %d survived recovery", descendant)
	}
}

func TestBridgeRecordedFailsClosedWhenSessionParentSyncFails(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	processes, err := newBridgeProcessesGeneration("/bin/sh", "recorded-sync-generation")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		processes.Close()
		processes.Cancel()
		_ = processes.Wait(context.Background())
	})
	if err := processes.prepareRecoveryRoots(); err != nil {
		t.Fatal(err)
	}
	errSync := errors.New("test session parent sync failure")
	processes.syncDir = func(path string) error {
		if path == processes.sessionsRoot {
			return errSync
		}
		return syncDirectory(path)
	}
	marker := filepath.Join(t.TempDir(), "executed")
	_, err = processes.pool.Start(t.Context(), supervise.ProcessSpec{
		RecoveryClass: proc.RecoveryTask,
		Path:          "/bin/sh",
		Args:          []string{"-c", "printf executed > " + marker},
		Recorded: processes.recorded(
			bridgeProcessChrome, "recorded-sync", "chrome:Default", "", "",
		),
	})
	if !errors.Is(err, errSync) {
		t.Fatalf("Start = %v, want parent sync failure", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("child crossed execution gate after sync failure: %v", err)
	}
	records, err := processes.reaper.Store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("rejected record remains tracked: %+v", records)
	}
}

func TestBridgeRecoveryKeepsOneSidecarPerProcessAttempt(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	processes, err := newBridgeProcessesGeneration("/bin/sh", "attempt-sidecar-generation")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		processes.Close()
		processes.Cancel()
		_ = processes.Wait(context.Background())
	})
	const sessionID = "multi-attempt-session"
	for range 2 {
		process, err := processes.pool.Start(t.Context(), supervise.ProcessSpec{
			RecoveryClass: proc.RecoveryTask,
			Path:          "/bin/sleep",
			Args:          []string{"30"},
			Recorded: processes.recorded(
				bridgeProcessTunnel, sessionID, "you@desktop:chrome:Default", "you@desktop", "cap-b-secret",
			),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := process.Stop(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	matches, err := filepath.Glob(filepath.Join(
		processes.sessionDir(sessionID), string(bridgeProcessTunnel)+"-*"+bridgeProcessSuffix,
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Fatalf("sidecars after two process attempts = %v, want two exact liabilities", matches)
	}
	metadata, err := processes.loadMetadata()
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata) != 2 || metadata[0].Record == metadata[1].Record {
		t.Fatalf("recovery metadata = %+v, want two distinct process records", metadata)
	}
}

func TestBridgeProcessShutdownLeavesNoAuthorityOrMetadata(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	processes, err := newBridgeProcessesGeneration("/bin/sh", "shutdown-generation")
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "shutdown-session"
	process, err := processes.pool.Start(t.Context(), supervise.ProcessSpec{
		RecoveryClass: proc.RecoveryTask,
		Path:          "/bin/sh",
		Args:          []string{"-c", "trap '' TERM; while :; do sleep 1; done"},
		Recorded: processes.recorded(
			bridgeProcessChrome, sessionID, "chrome:Default", "", "",
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(processes.sessionDir(sessionID)); err != nil {
		t.Fatal(err)
	}
	processes.Close()
	processes.Cancel()
	if err := processes.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, err := processes.reaper.Store.Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("shutdown records = %+v", records)
	}
	page, err := processes.reaper.ReapReceipts(t.Context(), proc.RecoveryTask, proc.ReapReceiptCursor{}, proc.ReapReceiptPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Receipts) != 0 {
		t.Fatalf("shutdown receipts = %+v", page.Receipts)
	}
	matches, err := filepath.Glob(filepath.Join(processes.sessionsRoot, "*", "*"+bridgeProcessSuffix))
	if err != nil || len(matches) != 0 {
		t.Fatalf("shutdown metadata = %v, err %v", matches, err)
	}
}

func TestProxyAdmissionReservesBothProcessSlotsAtomically(t *testing.T) {
	if bridgeProcessCapacity < 2*bridgeProxyLimit {
		t.Fatalf("process capacity %d cannot admit %d two-slot proxies", bridgeProcessCapacity, bridgeProxyLimit)
	}
	d := &Daemon{bridgeSlots: semaphore.NewWeighted(bridgeProcessCapacity)}
	for range bridgeProxyLimit {
		if err := d.bridgeSlots.Acquire(t.Context(), 2); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := d.bridgeSlots.Acquire(ctx, 1); err == nil {
		t.Fatal("capacity admitted a partial process behind fully admitted proxies")
	}
	d.bridgeSlots.Release(2 * bridgeProxyLimit)
}
