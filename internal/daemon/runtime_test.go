package daemon

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	dkdaemon "github.com/yasyf/daemonkit/daemon"
	"github.com/yasyf/daemonkit/proc"
	"github.com/yasyf/daemonkit/wire"
	"github.com/yasyf/daemonkit/worker"
	"golang.org/x/sync/semaphore"

	"github.com/yasyf/cookiesync/internal/paths"
	synckit "github.com/yasyf/synckit/rpc"
)

func TestRuntimeRPCServerUsesExactSuiteIdentity(t *testing.T) {
	if !strings.HasPrefix(synckit.WireBuild, "com.yasyf.synckit.rpc/") || !strings.HasSuffix(synckit.WireBuild, "/v1") {
		t.Fatalf("wire build = %q, want fingerprinted v1 suite", synckit.WireBuild)
	}
}

func waitRuntimeHealth(ctx context.Context, sock string) (synckit.RuntimeHealth, error) {
	client := synckit.NewClient(synckit.ClientConfig{Dial: wire.UnixDialer(sock), WireBuild: synckit.WireBuild})
	defer func() { _ = client.Close() }()
	var last error
	for {
		probeCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		health, err := client.RuntimeHealth(probeCtx)
		cancel()
		if err == nil && health.Ready {
			return health, nil
		}
		if err != nil {
			last = err
		}
		select {
		case <-ctx.Done():
			return synckit.RuntimeHealth{}, errors.Join(ctx.Err(), last)
		case <-time.After(10 * time.Millisecond):
		}
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

func prepareHelperRuntime(t *testing.T, executable string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Symlink(executable, filepath.Join(dir, "synckitd")); err != nil {
		t.Fatalf("Symlink synckitd: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
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
	prepareHelperRuntime(t, executable)

	var builds atomic.Int32
	var closes atomic.Int32
	activated := make(chan struct{})
	d := &Daemon{bridges: map[string]session{}, bridgeStop: make(chan struct{})}
	builder := func(context.Context, *worker.Pool) (*Daemon, func(context.Context) error, error) {
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
	runtime, err := newHelperRuntime(sock, executable, build, builder)
	if err != nil {
		t.Fatalf("newHelperRuntime: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()

	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	health, err := waitRuntimeHealth(readyCtx, sock)
	if err != nil {
		cancel()
		t.Fatalf("wait runtime health: %v", err)
	}
	select {
	case <-activated:
	default:
		cancel()
		t.Fatal("runtime published readiness before generation activation")
	}
	if health.RuntimeBuild != build || health.RuntimeProtocol != int(synckit.Version) ||
		health.ProcessGeneration == "" || health.State != string(dkdaemon.StateHealthy) || !health.Ready {
		cancel()
		t.Fatalf("health = %+v", health)
	}
	client := synckit.NewClient(synckit.ClientConfig{Dial: wire.UnixDialer(sock), WireBuild: synckit.WireBuild})
	defer func() { _ = client.Close() }()
	observed, err := client.RuntimeHealth(readyCtx)
	if err != nil {
		cancel()
		t.Fatalf("RuntimeHealth: %v", err)
	}
	if observed != health {
		cancel()
		t.Fatalf("observed health = %+v, runtime health = %+v", observed, health)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
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

func TestHelperRuntimeDrainsKeepaliveBeforeAdmissionSettlement(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	prepareHelperRuntime(t, executable)
	socketDir, err := os.MkdirTemp("/tmp", "cookiesync-drain-runtime-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	sock := filepath.Join(socketDir, "rpc.sock")
	d := &Daemon{bridges: map[string]session{}, bridgeStop: make(chan struct{})}
	builder := func(context.Context, *worker.Pool) (*Daemon, func(context.Context) error, error) {
		return d, func(context.Context) error { return nil }, nil
	}
	runtime, err := newHelperRuntime(sock, executable, "v9.8.7-drain-test", builder)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if _, err := waitRuntimeHealth(readyCtx, sock); err != nil {
		cancel()
		t.Fatalf("WaitReady: %v", err)
	}
	client := synckit.NewClient(synckit.ClientConfig{Dial: wire.UnixDialer(sock), WireBuild: synckit.WireBuild})
	defer func() { _ = client.Close() }()
	type callResult struct {
		response *synckit.Response
		err      error
	}
	callDone := make(chan callResult, 1)
	go func() {
		response, callErr := client.Call(context.Background(), &synckit.Request{
			Method: "bridge_keepalive", Params: map[string]any{"capability": "cap-a"},
		})
		callDone <- callResult{response: response, err: callErr}
	}()
	select {
	case result := <-callDone:
		cancel()
		t.Fatalf("keepalive returned before runtime drain: response=%+v err=%v", result.response, result.err)
	case <-time.After(100 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runtime.Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runtime admission settlement waited on the live keepalive")
	}
	select {
	case result := <-callDone:
		if result.err != nil || result.response == nil || !result.response.OK {
			t.Fatalf("drained keepalive response=%+v err=%v", result.response, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("drained keepalive did not return")
	}
	if !d.bridgeShutdown {
		t.Fatal("runtime drain did not close the bridge generation")
	}
}

func TestHelperRuntimeSettlesBridgeRecoveryBeforeReadiness(t *testing.T) {
	t.Setenv(paths.ConfigDirEnv, t.TempDir())
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	prepareHelperRuntime(t, executable)
	old, err := newBridgeProcessesGeneration(executable, bridgeTestGeneration("prior-runtime-generation"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", "-c", "while :; do sleep 1; done")
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	record, err := old.reaper.TrackGroup(t.Context(), command.Process.Pid, proc.RecoveryTaskID)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.writeMetadata(t.Context(), bridgeRecoveryMetadata{
		Schema: bridgeRecoverySchemaV1, SessionID: "runtime-recovery", Kind: bridgeProcessTunnel,
		Process: bridgeIdentityFromRecord(record), Endpoint: "you@desktop:chrome:Default",
		Host: "you@desktop", Capability: "cap-b-secret",
	}); err != nil {
		t.Fatal(err)
	}

	runner := &blockingRecoveryRunner{started: make(chan struct{}), release: make(chan struct{})}
	d := &Daemon{
		runner: runner, bridges: map[string]session{}, bridgeStop: make(chan struct{}),
		bridgeSlots: semaphore.NewWeighted(bridgeProcessCapacity),
	}
	builder := func(context.Context, *worker.Pool) (*Daemon, func(context.Context) error, error) {
		return d, func(context.Context) error { return nil }, nil
	}
	socketDir, err := os.MkdirTemp("/tmp", "cookiesync-recovery-runtime-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	sock := filepath.Join(socketDir, "rpc.sock")
	runtime, err := newHelperRuntime(sock, executable, "v9.8.8-test", builder)
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
	if _, err := waitRuntimeHealth(blockedCtx, sock); !errors.Is(err, context.DeadlineExceeded) {
		blockedCancel()
		cancel()
		t.Fatalf("runtime health during recovery = %v, want deadline", err)
	}
	blockedCancel()
	close(runner.release)
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if _, err := waitRuntimeHealth(readyCtx, sock); err != nil {
		cancel()
		t.Fatalf("WaitReady after recovery: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runtime.Run: %v", err)
	}
	page, err := d.processes.reaper.ReapReceipts(t.Context(), proc.RecoveryTaskID, proc.ReapReceiptCursor{}, proc.ReapReceiptPageLimit)
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
	prepareHelperRuntime(t, executable)
	old, err := newBridgeProcessesGeneration(executable, bridgeTestGeneration("builder-failure-prior-generation"))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", "-c", "while :; do sleep 1; done")
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })
	record, err := old.reaper.TrackGroup(t.Context(), command.Process.Pid, proc.RecoveryTaskID)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.writeMetadata(t.Context(), bridgeRecoveryMetadata{
		Schema: bridgeRecoverySchemaV1, SessionID: "builder-failure-recovery", Kind: bridgeProcessChrome,
		Process: bridgeIdentityFromRecord(record), Endpoint: "chrome:Default",
	}); err != nil {
		t.Fatal(err)
	}

	var reapedBeforeBuilder atomic.Bool
	errBuilder := errors.New("test builder failure")
	builder := func(ctx context.Context, _ *worker.Pool) (*Daemon, func(context.Context) error, error) {
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
	runtime, err := newHelperRuntime(filepath.Join(socketDir, "rpc.sock"), executable, "v9.8.9-test", builder)
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
	page, err := old.reaper.ReapReceipts(t.Context(), proc.RecoveryTaskID, proc.ReapReceiptCursor{}, proc.ReapReceiptPageLimit)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Receipts) != 1 || page.Receipts[0].Record != record {
		t.Fatalf("builder failure lost durable recovery receipt: %+v", page.Receipts)
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
