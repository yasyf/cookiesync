//go:build linux

package bridge

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	crashpadDiscoveryWindow = 3 * time.Second
	crashpadDiscoveryPoll   = 250 * time.Millisecond
	crashpadExitTimeout     = 5 * time.Second
	crashpadTermGrace       = 2 * time.Second
	crashpadKillGrace       = time.Second
)

// Chrome keys its crash database off the default profile location and ignores
// --user-data-dir (crbug.com/40447560); BREAKPAD_DUMP_LOCATION is its supported
// override, and it is what puts this session's dataDir into every crashpad
// handler's argv.
func crashpadEnvironment(dataDir string) []string {
	return []string{"BREAKPAD_DUMP_LOCATION=" + crashpadDatabase(dataDir)}
}

type ownedHandler struct {
	pid   int
	pidfd int
}

type handlerTracker struct {
	database    string
	exitTimeout time.Duration
	termGrace   time.Duration
	killGrace   time.Duration
	stop        chan struct{}
	settled     chan struct{}

	mu    sync.Mutex
	owned map[int]ownedHandler
	err   error
}

func trackHandlers(dataDir string) *handlerTracker {
	t := &handlerTracker{
		database:    crashpadDatabase(dataDir),
		exitTimeout: crashpadExitTimeout,
		termGrace:   crashpadTermGrace,
		killGrace:   crashpadKillGrace,
		stop:        make(chan struct{}),
		settled:     make(chan struct{}),
		owned:       map[int]ownedHandler{},
	}
	go t.discover()
	return t
}

func (t *handlerTracker) discover() {
	defer close(t.settled)
	window := time.NewTimer(crashpadDiscoveryWindow)
	defer window.Stop()
	ticker := time.NewTicker(crashpadDiscoveryPoll)
	defer ticker.Stop()
	for {
		t.adopt()
		select {
		case <-t.stop:
			return
		case <-window.C:
			return
		case <-ticker.C:
		}
	}
}

func (t *handlerTracker) adopt() {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.record(fmt.Errorf("bridge: list /proc: %w", err))
		return
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || t.owns(pid) || !t.serves(pid) {
			continue
		}
		pidfd, err := unix.PidfdOpen(pid, 0)
		if errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			t.record(fmt.Errorf("bridge: pin crashpad handler %d: %w", pid, err))
			return
		}
		if !t.serves(pid) {
			_ = unix.Close(pidfd)
			continue
		}
		t.mu.Lock()
		t.owned[pid] = ownedHandler{pid: pid, pidfd: pidfd}
		t.mu.Unlock()
	}
}

func (t *handlerTracker) serves(pid int) bool {
	cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return false
	}
	return servesCrashpadDatabase(parseCmdline(cmdline), t.database)
}

func (t *handlerTracker) owns(pid int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.owned[pid]
	return ok
}

func (t *handlerTracker) record(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.err = errors.Join(t.err, err)
}

func (t *handlerTracker) tracked() []int {
	<-t.settled
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Sorted(maps.Keys(t.owned))
}

func (t *handlerTracker) close() error {
	close(t.stop)
	<-t.settled
	t.adopt()
	t.mu.Lock()
	defer t.mu.Unlock()
	handlers := slices.SortedFunc(maps.Values(t.owned), func(a, b ownedHandler) int { return cmp.Compare(a.pid, b.pid) })
	err := errors.Join(t.err, reap(handlers, t.exitTimeout, t.termGrace, t.killGrace))
	for _, h := range handlers {
		err = errors.Join(err, unix.Close(h.pidfd))
	}
	return err
}

func reap(handlers []ownedHandler, exitTimeout, termGrace, killGrace time.Duration) error {
	alive, err := awaitExit(handlers, exitTimeout)
	if err != nil {
		return err
	}
	alive, err = signalAndAwait(alive, unix.SIGTERM, termGrace)
	if err != nil {
		return err
	}
	alive, err = signalAndAwait(alive, unix.SIGKILL, killGrace)
	if err != nil {
		return err
	}
	errs := make([]error, 0, len(alive))
	for _, h := range alive {
		errs = append(errs, fmt.Errorf("bridge: crashpad handler %d survived SIGKILL", h.pid))
	}
	return errors.Join(errs...)
}

func signalAndAwait(handlers []ownedHandler, sig unix.Signal, grace time.Duration) ([]ownedHandler, error) {
	for _, h := range handlers {
		if err := unix.PidfdSendSignal(h.pidfd, sig, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
			return nil, fmt.Errorf("bridge: send %s to crashpad handler %d: %w", sig, h.pid, err)
		}
	}
	return awaitExit(handlers, grace)
}

func awaitExit(handlers []ownedHandler, timeout time.Duration) ([]ownedHandler, error) {
	deadline := time.Now().Add(timeout)
	pending := handlers
	for len(pending) > 0 {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		fds := make([]unix.PollFd, len(pending))
		for i, h := range pending {
			fds[i] = unix.PollFd{Fd: int32(h.pidfd), Events: unix.POLLIN} //nolint:gosec // G115: a pidfd is a descriptor, which the kernel bounds to int32.
		}
		n, err := unix.Poll(fds, int(remaining.Milliseconds()))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("bridge: poll crashpad handlers: %w", err)
		}
		if n == 0 {
			break
		}
		still := make([]ownedHandler, 0, len(pending))
		for i, h := range pending {
			if fds[i].Revents&unix.POLLIN == 0 {
				still = append(still, h)
			}
		}
		pending = still
	}
	return pending, nil
}
