package daemon

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	dkdaemon "github.com/yasyf/daemonkit/daemon"
	"github.com/yasyf/daemonkit/daemonrole"
	"github.com/yasyf/daemonkit/drain"
	"github.com/yasyf/daemonkit/proc"
	"github.com/yasyf/daemonkit/wire"
	"golang.org/x/sync/semaphore"

	"github.com/yasyf/cookiesync/internal/paths"
	synckit "github.com/yasyf/synckit/rpc"
)

func TestRuntimeRPCServerProtectsLifecycleCapacity(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	const build = "v9.8.7-test"
	server, err := runtimeRPCServer(synckit.NewDispatcher(), executable, build)
	if err != nil {
		t.Fatalf("runtimeRPCServer: %v", err)
	}
	if server.Wire.Build != synckit.Build || server.Wire.LifecycleBuild != build {
		t.Fatalf("server builds = business %q lifecycle %q", server.Wire.Build, server.Wire.LifecycleBuild)
	}
	if server.Wire.ReservedProtectedSessions != 1 {
		t.Fatalf("reserved protected sessions = %d, want 1", server.Wire.ReservedProtectedSessions)
	}
	role, ok := server.Wire.ProtectedSessionClassifier.(daemonrole.Classifier)
	if !ok {
		t.Fatalf("protected classifier = %T, want daemonrole.Classifier", server.Wire.ProtectedSessionClassifier)
	}
	if role.RoleID != helperRoleID || role.RolePath != executable {
		t.Fatalf("helper role = %+v", role)
	}
}

func TestHelperRolePathResolvesStableAlias(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	dir := t.TempDir()
	alias := filepath.Join(dir, paths.ToolName)
	if err := os.Symlink(executable, alias); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	t.Setenv("PATH", dir)
	got, err := helperRolePath()
	if err != nil {
		t.Fatalf("helperRolePath: %v", err)
	}
	if got != alias {
		t.Fatalf("helper role path = %q, want stable alias %q", got, alias)
	}
}

func TestHelperRuntimeActivatesAfterOwnershipAndClosesGeneration(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	socketDir, err := os.MkdirTemp("/tmp", "cookiesync-runtime-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	sock := filepath.Join(socketDir, "rpc.sock")
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	var builds atomic.Int32
	var closes atomic.Int32
	activated := make(chan struct{})
	d := &Daemon{bridges: map[string]session{}, bridgeStop: make(chan struct{})}
	builder := func(context.Context) (*Daemon, func(context.Context) error, error) {
		if _, err := os.Stat(sock); err != nil {
			return nil, nil, errors.New("builder ran before listener ownership")
		}
		builds.Add(1)
		close(activated)
		return d, func(context.Context) error {
			closes.Add(1)
			return nil
		}, nil
	}

	const build = "v9.8.7-test"
	runtime, err := newHelperRuntime(t.Context(), sock, executable, build, builder)
	if err != nil {
		t.Fatalf("newHelperRuntime: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := runtime.WaitReady(readyCtx); err != nil {
		cancel()
		t.Fatalf("WaitReady: %v", err)
	}
	select {
	case <-activated:
	default:
		cancel()
		t.Fatal("runtime published readiness before generation activation")
	}
	health, err := runtime.Health(readyCtx)
	if err != nil {
		cancel()
		t.Fatalf("Health: %v", err)
	}
	if health.Build != build || health.Protocol != int(wire.ProtocolVersion) || health.State != dkdaemon.StateHealthy {
		cancel()
		t.Fatalf("health = %+v", health)
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("runtime.Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runtime did not settle after cancellation")
	}
	if builds.Load() != 1 || closes.Load() != 1 {
		t.Fatalf("generation lifecycle = builds %d closes %d, want 1/1", builds.Load(), closes.Load())
	}
	if !d.bridgeShutdown {
		t.Fatal("bridge generation remained open after runtime shutdown")
	}
}

func TestHelperRuntimeSettlesBridgeRecoveryBeforeReadiness(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	old, err := newBridgeProcessesGeneration(executable, "prior-runtime-generation")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", "-c", "while :; do sleep 1; done")
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	record, err := old.reaper.TrackGroup(t.Context(), command.Process.Pid, proc.RecoveryTask)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.recorded(
		bridgeProcessTunnel, "runtime-recovery", "you@desktop:chrome:Default", "you@desktop", "cap-b-secret",
	)(t.Context(), record); err != nil {
		t.Fatal(err)
	}

	runner := &blockingRecoveryRunner{started: make(chan struct{}), release: make(chan struct{})}
	d := &Daemon{
		runner: runner, bridges: map[string]session{}, bridgeStop: make(chan struct{}),
		bridgeSlots: semaphore.NewWeighted(bridgeProcessCapacity),
	}
	builder := func(context.Context) (*Daemon, func(context.Context) error, error) {
		return d, func(context.Context) error { return nil }, nil
	}
	socketDir, err := os.MkdirTemp("/tmp", "cookiesync-recovery-runtime-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	runtime, err := newHelperRuntime(t.Context(), filepath.Join(socketDir, "rpc.sock"), executable, "v9.8.8-test", builder)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	select {
	case <-runner.started:
	case <-time.After(8 * time.Second):
		cancel()
		t.Fatal("runtime never reached bridge recovery settlement")
	}
	blockedCtx, blockedCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if err := runtime.WaitReady(blockedCtx); !errors.Is(err, context.DeadlineExceeded) {
		blockedCancel()
		cancel()
		t.Fatalf("WaitReady during recovery = %v, want deadline", err)
	}
	blockedCancel()
	close(runner.release)
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if err := runtime.WaitReady(readyCtx); err != nil {
		cancel()
		t.Fatalf("WaitReady after recovery: %v", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("runtime.Run: %v", err)
	}
	page, err := d.processes.reaper.ReapReceipts(t.Context(), proc.RecoveryTask, proc.ReapReceiptCursor{}, proc.ReapReceiptPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Receipts) != 0 {
		t.Fatalf("runtime recovery receipts = %+v", page.Receipts)
	}
	if _, err := os.Stat(d.processes.sessionDir("runtime-recovery")); !os.IsNotExist(err) {
		t.Fatalf("runtime recovery metadata remains: %v", err)
	}
}

func TestHelperRuntimeReapsBridgeProcessesBeforeBuilderFailure(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	old, err := newBridgeProcessesGeneration(executable, "builder-failure-prior-generation")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		old.Close()
		old.Cancel()
		_ = old.Wait(context.Background())
	})
	command := exec.Command("/bin/sh", "-c", "while :; do sleep 1; done")
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	record, err := old.reaper.TrackGroup(t.Context(), command.Process.Pid, proc.RecoveryTask)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.recorded(
		bridgeProcessChrome, "builder-failure-recovery", "chrome:Default", "", "",
	)(t.Context(), record); err != nil {
		t.Fatal(err)
	}

	var reapedBeforeBuilder atomic.Bool
	errBuilder := errors.New("test builder failure")
	builder := func(ctx context.Context) (*Daemon, func(context.Context) error, error) {
		waited := make(chan struct{})
		go func() {
			_ = command.Wait()
			close(waited)
		}()
		select {
		case <-waited:
			records, loadErr := old.reaper.Store.Load(ctx)
			if loadErr == nil && len(records) == 0 {
				reapedBeforeBuilder.Store(true)
			}
		case <-time.After(500 * time.Millisecond):
		}
		return nil, nil, errBuilder
	}
	socketDir, err := os.MkdirTemp("/tmp", "cookiesync-builder-failure-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	runtime, err := newHelperRuntime(t.Context(), filepath.Join(socketDir, "rpc.sock"), executable, "v9.8.9-test", builder)
	if err != nil {
		t.Fatal(err)
	}
	err = runtime.Run(context.Background())
	if !errors.Is(err, errBuilder) {
		t.Fatalf("runtime.Run = %v, want builder failure", err)
	}
	if !reapedBeforeBuilder.Load() {
		t.Fatal("builder ran before prior bridge process authority was settled")
	}
	page, err := old.reaper.ReapReceipts(t.Context(), proc.RecoveryTask, proc.ReapReceiptCursor{}, proc.ReapReceiptPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Receipts) != 1 || page.Receipts[0].Record != record {
		t.Fatalf("builder failure lost durable recovery receipt: %+v", page.Receipts)
	}
}

func TestHelperSessionDrainReleasesKeepaliveAdmission(t *testing.T) {
	d := &Daemon{bridges: map[string]session{}, bridgeStop: make(chan struct{})}
	owner := newHelperOwner()
	owner.set(d, nil)
	server := &helperSessionServer{Server: &wire.Server{}, owner: owner}
	intake := &drain.Intake{}
	release, err := intake.Admit()
	if err != nil {
		t.Fatalf("Admit: %v", err)
	}
	handlerDone := make(chan struct{})
	go func() {
		defer release()
		_, _ = d.handleBridgeKeepalive(context.Background(), map[string]any{"capability": "cap-a"})
		close(handlerDone)
	}()
	select {
	case <-handlerDone:
		t.Fatal("keepalive returned before runtime drain")
	case <-time.After(50 * time.Millisecond):
	}

	intake.Close()
	if err := server.CloseIntake(); err != nil {
		t.Fatalf("CloseIntake: %v", err)
	}
	settleCtx, settleCancel := context.WithTimeout(context.Background(), time.Second)
	defer settleCancel()
	if err := intake.Settle(settleCtx); err != nil {
		t.Fatalf("Settle with live keepalive: %v", err)
	}
	if err := owner.Wait(settleCtx); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	select {
	case <-handlerDone:
	default:
		t.Fatal("keepalive admission settled before handler returned")
	}
}

func TestOnlyErrorDoesNotHideCleanupFailure(t *testing.T) {
	if !onlyError(errors.Join(context.Canceled), context.Canceled) {
		t.Fatal("pure cancellation was not recognized")
	}
	cleanup := errors.New("cleanup failed")
	if onlyError(errors.Join(context.Canceled, cleanup), context.Canceled) {
		t.Fatal("cleanup failure was hidden behind cancellation")
	}
}
