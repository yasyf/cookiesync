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

	"github.com/yasyf/daemonkit"
	"golang.org/x/sync/semaphore"

	"github.com/yasyf/cookiesync/internal/paths"
	"github.com/yasyf/synckit/helperruntime"
	synckit "github.com/yasyf/synckit/rpc"
)

func TestRuntimeRPCServerUsesExactSuiteIdentity(t *testing.T) {
	if !strings.HasPrefix(synckit.WireBuild, "com.yasyf.synckit.rpc/") || !strings.HasSuffix(synckit.WireBuild, "/v1") {
		t.Fatalf("wire build = %q, want fingerprinted v1 suite", synckit.WireBuild)
	}
}

// TestHelperSpecCarriesTheWholePayload pins the frame contract both ends of a
// session must agree on: the helper states no MaxFrame, so the spec takes
// synckit's, whose detail ceiling still carries a whole rpc payload.
func TestHelperSpecCarriesTheWholePayload(t *testing.T) {
	spec, err := helperruntime.Spec(paths.ToolName, daemonkit.Program{}, 0)
	if err != nil {
		t.Fatalf("helperruntime.Spec: %v", err)
	}
	if got := daemonkit.MaxDetail(spec.MaxFrame); got < synckit.MaxPayload {
		t.Fatalf("MaxDetail(%d) = %d, want at least the rpc payload ceiling %d", spec.MaxFrame, got, synckit.MaxPayload)
	}
}

// helperClient opens the resident helper the same way every cookiesync caller
// does — by name, never by path.
func helperClient(t *testing.T) *daemonkit.Client {
	t.Helper()
	spec, err := helperruntime.Spec(paths.ToolName, daemonkit.Program{}, 0)
	if err != nil {
		t.Fatalf("helperruntime.Spec: %v", err)
	}
	client, err := daemonkit.Open(spec)
	if err != nil {
		t.Fatalf("open resident helper: %v", err)
	}
	return client
}

// readinessProbe is a method no dispatcher registers. A well-formed refusal is
// still a dispatched reply, so it proves the helper is past the phase gate
// without touching product state.
const readinessProbe = "__cookiesync_readiness_probe__"

// awaitBusinessReady blocks until the helper dispatches over its business lane.
// Readiness is observed there rather than through Control.WaitReady because
// these tests serve the runtime in the test's own process, and daemonkit
// refuses to pin its own pid on the control lane — the business lane runs the
// same-EUID floor and the Trust.Serving verify, but no self-pin.
func awaitBusinessReady(ctx context.Context, client *daemonkit.Client) error {
	lane := synckit.NewClient(synckit.ClientConfig{
		Open: func(context.Context) (*daemonkit.Business, error) { return client.Business(), nil },
	})
	defer func() { _ = lane.Close() }()
	var last error
	for {
		probeCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		_, err := lane.Call(probeCtx, &synckit.Request{Method: readinessProbe})
		cancel()
		if err == nil {
			return nil
		}
		last = err
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), last)
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

// prepareHelperRuntime isolates one runtime's whole footprint. DAEMONKIT_HOME
// is the daemonkit-reached state root — HOME no longer reaches it — and it must
// stay short: the label plus /daemon.sock has to fit darwin's 104-byte
// sun_path, which a macOS t.TempDir() blows on its own.
func prepareHelperRuntime(t *testing.T, executable string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Symlink(executable, filepath.Join(dir, "synckitd")); err != nil {
		t.Fatalf("Symlink synckitd: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv(paths.ConfigDirEnv, t.TempDir())

	home, err := os.MkdirTemp("/tmp", "cs-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("DAEMONKIT_HOME", home)
}

func TestHelperRuntimeActivatesAfterOwnershipAndClosesGeneration(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	prepareHelperRuntime(t, executable)

	var builds atomic.Int32
	var closes atomic.Int32
	activated := make(chan struct{})
	d := &Daemon{bridges: map[string]session{}, bridgeStop: make(chan struct{})}
	builder := func(daemonkit.Ctx) (*Daemon, func(context.Context) error, error) {
		builds.Add(1)
		close(activated)
		return d, func(context.Context) error {
			closes.Add(1)
			return nil
		}, nil
	}

	runtime, err := newHelperRuntime(executable, builder)
	if err != nil {
		t.Fatalf("newHelperRuntime: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()

	client := helperClient(t)
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer readyCancel()
	if err := awaitBusinessReady(readyCtx, client); err != nil {
		cancel()
		t.Fatalf("await readiness: %v", err)
	}
	select {
	case <-activated:
	default:
		cancel()
		t.Fatal("runtime published readiness before generation activation")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runtime.Run: %v", err)
		}
	case <-time.After(30 * time.Second):
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
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	prepareHelperRuntime(t, executable)
	d := &Daemon{bridges: map[string]session{}, bridgeStop: make(chan struct{})}
	builder := func(daemonkit.Ctx) (*Daemon, func(context.Context) error, error) {
		return d, func(context.Context) error { return nil }, nil
	}
	runtime, err := newHelperRuntime(executable, builder)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()

	control := helperClient(t)
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer readyCancel()
	if err := awaitBusinessReady(readyCtx, control); err != nil {
		cancel()
		t.Fatalf("await readiness: %v", err)
	}

	client := synckit.NewClient(synckit.ClientConfig{
		Open: func(context.Context) (*daemonkit.Business, error) { return control.Business(), nil },
	})
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
	case <-time.After(30 * time.Second):
		t.Fatal("runtime admission settlement waited on the live keepalive")
	}
	select {
	case result := <-callDone:
		if result.err != nil || result.response == nil || !result.response.OK {
			t.Fatalf("drained keepalive response=%+v err=%v", result.response, result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("drained keepalive did not return")
	}
	if !d.bridgeShutdown {
		t.Fatal("runtime drain did not close the bridge generation")
	}
}

// TestHelperRuntimeSettlesBridgeRecoveryBeforeReadiness proves the crashed
// generation's product liabilities are discharged before this one answers: the
// peer's half of a leaked tunnel is closed, and only then is readiness
// published.
func TestHelperRuntimeSettlesBridgeRecoveryBeforeReadiness(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	prepareHelperRuntime(t, executable)
	crashed := testBridgeProcessesAt(t, executable)
	if err := crashed.record(
		bridgeProcessTunnel, "runtime-recovery", "you@desktop:chrome:Default", "you@desktop", "cap-b-secret",
	); err != nil {
		t.Fatal(err)
	}

	runner := &blockingRecoveryRunner{started: make(chan struct{}), release: make(chan struct{})}
	d := &Daemon{
		runner: runner, bridges: map[string]session{}, bridgeStop: make(chan struct{}),
		bridgeSlots: semaphore.NewWeighted(bridgeProcessCapacity),
	}
	builder := func(daemonkit.Ctx) (*Daemon, func(context.Context) error, error) {
		return d, func(context.Context) error { return nil }, nil
	}
	runtime, err := newHelperRuntime(executable, builder)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	select {
	case <-runner.started:
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatal("runtime never reached bridge recovery settlement")
	}

	client := helperClient(t)
	blockedCtx, blockedCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	if err := awaitBusinessReady(blockedCtx, client); !errors.Is(err, context.DeadlineExceeded) {
		blockedCancel()
		cancel()
		t.Fatalf("readiness during recovery = %v, want deadline", err)
	}
	blockedCancel()

	close(runner.release)
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer readyCancel()
	if err := awaitBusinessReady(readyCtx, client); err != nil {
		cancel()
		t.Fatalf("await readiness after recovery: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runtime.Run: %v", err)
	}
	if _, err := os.Stat(d.processes.sessionDir("runtime-recovery")); !os.IsNotExist(err) {
		t.Fatalf("runtime recovery metadata remains: %v", err)
	}
}

// TestHelperRuntimeReclaimsBridgeProcessesBeforeTheBuilderRuns proves the
// ordering the whole recovery design rests on: the prior generation's children
// are settled and reported through Ctx.Reclaimed before product preparation
// begins, so a sidecar the builder finds on disk always names a dead process.
func TestHelperRuntimeReclaimsBridgeProcessesBeforeTheBuilderRuns(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	prepareHelperRuntime(t, executable)

	command := exec.Command("/bin/sh", "-c", "while :; do sleep 1; done") //nolint:gosec // test-owned exact shell fixture.
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill() })

	var reclaimedAlive atomic.Bool
	errBuilder := errors.New("test builder failure")
	builder := func(c daemonkit.Ctx) (*Daemon, func(context.Context) error, error) {
		for _, entry := range c.Reclaimed {
			if syscall.Kill(entry.PID, 0) == nil {
				reclaimedAlive.Store(true)
			}
		}
		return nil, nil, errBuilder
	}
	runtime, err := newHelperRuntime(executable, builder)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(context.Background()); !errors.Is(err, errBuilder) {
		t.Fatalf("runtime.Run = %v, want builder failure", err)
	}
	if reclaimedAlive.Load() {
		t.Fatal("a child reported as reclaimed was still alive when the builder ran")
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
